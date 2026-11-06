//! Splitting a composefs deployment into an image set.
//!
//! An image can ask for parts of its root filesystem, such as
//! `/usr/lib/modules`, to become composefs images of their own by listing
//! them in [`IMAGE_SET_CONF`].  The deployment is then an image set: the rest
//! of the root filesystem (with an empty directory for each split-out part)
//! and one image per part, stacked as overlayfs lower layers over the same
//! object store.  The set's manifest digest is what `composefs.digest=` pins
//! and what names the deployment, so one digest still covers every file, and
//! an image that changes only one part shares the other parts' images with
//! the deployments before it.
//!
//! Each deployment's set has a ref of its own in the repository
//! ([`deployment_ref`]), which keeps it and its component images alive
//! through any repository GC, and which bootc's GC removes with the
//! deployment.
//!
//! This is experimental and only supported with BLS (Type 1) boot entries.
//!
//! # Compatibility
//!
//! A bootc that predates image sets can't parse `composefs.digest=set1-...`:
//! its status fails on the BLS entry of a set deployment, and with it
//! upgrade, rollback and GC.  And the first set written marks the repository
//! with composefs-rs's `image_sets` incompatible feature, which an older
//! composefs-rs refuses, so that its GC can't delete what only sets keep
//! alive: from then on, the initramfs of a deployment whose bootc predates
//! image sets (the rollback deployment when the first set is staged, or a
//! pinned one) can't open the repository, and that deployment doesn't boot.
//! Adopting image sets therefore takes a bootc that knows them first, and an
//! image that asks for them after, once no older deployment is needed.

use std::ffi::OsStr;

use anyhow::{Context, Result};
use bootc_initramfs_setup::ComposefsRootKind;
use composefs::erofs::format::FormatVersion;
use composefs::fsverity::{FsVerityHashValue, Sha512HashValue};
use composefs::image_set::{ImageSet, ImageSetComponent, ROOT_TARGET, validate_target};
use composefs::mountcompat::LOWERDIR_OPTION_MAX;
use composefs::tree::{FileSystem, ImageError, RegularFile};
use composefs_boot::BootOps as _;
use composefs_ctl::composefs;
use composefs_ctl::composefs_boot;
use fn_error_context::context;

use crate::bootc_composefs::status::RootFormat;
use crate::store::ComposefsRepository;

/// The file listing the directories an image wants as separate images,
/// relative to the root.  One absolute path per line; empty lines and lines
/// starting with `#` are ignored.
pub(crate) const IMAGE_SET_CONF: &str = "usr/lib/bootc/composefs-image-set.conf";

/// The most directories [`IMAGE_SET_CONF`] may list.
///
/// setup-root mounts a set with all its images in one `lowerdir` option on
/// kernels before 6.15 (bootc's default `pre-6.15` build), which takes at
/// most [`LOWERDIR_OPTION_MAX`] bytes.  With file descriptors of up to 4
/// digits, each component takes at most 19 bytes (`/proc/self/fd/NNNN:`) and
/// the object store 20 (`::/proc/self/fd/NNNN`), so the root and 8 more
/// components fit.
const MAX_SPLIT_DIRECTORIES: usize = 8;
const _: () = assert!((MAX_SPLIT_DIRECTORIES + 1) * 19 + 20 <= LOWERDIR_OPTION_MAX);

/// The prefix of the ref that keeps each image set deployment's set alive.
pub(crate) const IMAGE_SET_REF_PREFIX: &str = "bootc/";

/// The name of the image set ref of the deployment `id`.
pub(crate) fn deployment_ref(id: &str) -> String {
    format!("{IMAGE_SET_REF_PREFIX}{id}")
}

/// Parses [`IMAGE_SET_CONF`] into the directories to split out, in order.
fn parse_image_set_conf(text: &str) -> Result<Vec<String>> {
    let mut targets: Vec<String> = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let target = line.to_string();
        // Let composefs-rs's own rules decide what a valid target is
        validate_target(&target)
            .with_context(|| format!("{IMAGE_SET_CONF}: invalid path {line:?}"))?;
        anyhow::ensure!(
            target != ROOT_TARGET,
            "{IMAGE_SET_CONF}: the root directory can't be split out"
        );
        if let Some(other) = targets.iter().find(|other| {
            let (a, b) = (other.as_str(), target.as_str());
            a == b || b.starts_with(&format!("{a}/")) || a.starts_with(&format!("{b}/"))
        }) {
            anyhow::bail!("{IMAGE_SET_CONF}: {target} overlaps {other}");
        }
        targets.push(target);
    }
    anyhow::ensure!(
        targets.len() <= MAX_SPLIT_DIRECTORIES,
        "{IMAGE_SET_CONF} lists {} directories, but at most {MAX_SPLIT_DIRECTORIES} can be split \
         out: on kernels before 6.15 all of a set's images must fit in one {LOWERDIR_OPTION_MAX}-byte \
         overlayfs option",
        targets.len()
    );
    Ok(targets)
}

/// The regular file at `path` in `fs`, if there is one.
fn get_file<'a>(
    fs: &'a FileSystem<Sha512HashValue>,
    path: &str,
) -> Result<Option<&'a RegularFile<Sha512HashValue>>> {
    match fs.root.split(OsStr::new(path)) {
        Ok((dir, name)) => Ok(dir.get_file_opt(name, &fs.leaves)?),
        Err(ImageError::NotFound(_)) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

/// The directories `fs` asks to split out, empty if it doesn't use an image set.
#[context("Reading {IMAGE_SET_CONF}")]
pub(crate) fn image_set_targets(
    fs: &FileSystem<Sha512HashValue>,
    repo: &ComposefsRepository,
) -> Result<Vec<String>> {
    let Some(file) = get_file(fs, IMAGE_SET_CONF)? else {
        return Ok(Vec::new());
    };
    let data = match file {
        RegularFile::Inline(data) => data.to_vec(),
        RegularFile::External(id, _) | RegularFile::ExternalNoVerity(id, _) => {
            repo.read_object(id)?
        }
        RegularFile::Sparse(_) => anyhow::bail!("unexpected sparse file"),
    };
    parse_image_set_conf(std::str::from_utf8(&data).context("not UTF-8")?)
}

/// The components of the image set a deployment of `fs` is, or `None` if it
/// isn't one.  `fs` is the image's filesystem as read from its OCI config;
/// the components are split from a boot-transformed copy of it.
///
/// Both [`commit_image_set`] (install and upgrade) and
/// [`compute_image_set_id`] (the update check) start from this, so that they
/// name the deployment by the same digest.
#[context("Preparing image set")]
pub(crate) fn boot_image_set_parts(
    fs: &FileSystem<Sha512HashValue>,
    repo: &ComposefsRepository,
) -> Result<Option<Vec<(String, FileSystem<Sha512HashValue>)>>> {
    let targets = image_set_targets(fs, repo)?;
    if targets.is_empty() {
        return Ok(None);
    }
    let mut boot_fs = fs.clone();
    boot_fs
        .transform_for_boot(repo)
        .context("Preparing image set for boot")?;
    let parts = split_into_components(boot_fs, &targets)?;
    tracing::debug!("Image set for {}", targets.join(", "));
    Ok(Some(parts))
}

/// Splits a boot-transformed filesystem into the components of an image set:
/// the root first, then each of `targets` in order.
#[context("Splitting the root filesystem into an image set")]
fn split_into_components(
    mut fs: FileSystem<Sha512HashValue>,
    targets: &[String],
) -> Result<Vec<(String, FileSystem<Sha512HashValue>)>> {
    let mut parts = Vec::with_capacity(targets.len());
    for target in targets {
        let part = fs
            .split_off(OsStr::new(target))
            .with_context(|| format!("Splitting off {target}"))?;
        parts.push((target.clone(), part));
    }
    parts.insert(0, (ROOT_TARGET.to_string(), fs));
    Ok(parts)
}

fn image_set_from(
    parts: &[(String, FileSystem<Sha512HashValue>)],
    version: FormatVersion,
    mut image_id: impl FnMut(&FileSystem<Sha512HashValue>) -> Result<Sha512HashValue>,
) -> Result<ImageSet<Sha512HashValue>> {
    let components = parts
        .iter()
        .map(|(target, fs)| {
            Ok(ImageSetComponent {
                digest: image_id(fs)?,
                format: version,
                target: target.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ImageSet::new(components)?)
}

/// The digest the image set for `parts` would have, without writing anything.
pub(crate) fn compute_image_set_id(
    parts: &[(String, FileSystem<Sha512HashValue>)],
    version: FormatVersion,
) -> Result<Sha512HashValue> {
    let set = image_set_from(parts, version, |fs| Ok(fs.compute_image_id(version)))?;
    Ok(set.compute_id())
}

/// Writes each component as an image of the repository's EROFS format and
/// the set's manifest, with the ref [`deployment_ref`] of the deployment it
/// names, returning the set's digest.
#[context("Writing image set")]
pub(crate) fn commit_image_set(
    repo: &ComposefsRepository,
    parts: &[(String, FileSystem<Sha512HashValue>)],
) -> Result<Sha512HashValue> {
    let version = repo.erofs_version();
    let set = image_set_from(parts, version, |fs| {
        fs.commit_image_version(repo, version, None)
    })?;
    for (component, (target, _)) in set.components().iter().zip(parts) {
        tracing::debug!(
            "Image set component {target}: {}",
            component.digest.to_hex()
        );
    }
    let id = set.compute_id();
    repo.write_image_set(Some(&deployment_ref(&id.to_hex())), &set)
}

/// What the deployment named `id` is: an image set if the repository has
/// one of that digest, else an image of the repository's EROFS format.
pub(crate) fn deployment_root_format(repo: &ComposefsRepository, id: &str) -> Result<RootFormat> {
    Ok(match ComposefsRootKind::of_deployment(repo, id)? {
        ComposefsRootKind::ImageSet => RootFormat::ImageSet,
        ComposefsRootKind::Image => repo.erofs_version().into(),
    })
}

/// The deployments that have an image set ref.
fn deployments_with_refs(repo: &ComposefsRepository) -> Result<Vec<String>> {
    Ok(repo
        .list_image_set_refs(IMAGE_SET_REF_PREFIX)?
        .into_iter()
        .map(|(id, _)| id)
        .collect())
}

/// Adds the image set ref of each image set deployment in `live` that lacks
/// one (written before deployments had refs, or removed since).
///
/// A deployment whose set can't be looked up or given its ref is skipped
/// with a warning rather than failing the GC around this: bootc's own
/// repository GC keeps it anyway, as one of its roots, and only a GC without
/// those roots would miss the ref.
#[context("Adding missing image set refs")]
pub(crate) fn add_missing_deployment_refs(
    repo: &ComposefsRepository,
    live: &[String],
    dry_run: bool,
) -> Result<()> {
    let refs = deployments_with_refs(repo)?;
    for id in live.iter().filter(|id| !refs.contains(id)) {
        let add = || -> Result<bool> {
            if deployment_root_format(repo, id)? != RootFormat::ImageSet {
                return Ok(false);
            }
            if !dry_run {
                let (set, _) = repo.open_image_set(id)?;
                repo.write_image_set(Some(&deployment_ref(id)), &set)?;
            }
            Ok(true)
        };
        match add() {
            Ok(false) => {}
            Ok(true) if dry_run => {
                tracing::info!("Would add the missing image set ref of deployment {id}")
            }
            Ok(true) => tracing::info!("Added the missing image set ref of deployment {id}"),
            Err(err) => tracing::warn!(
                "Can't restore the image set ref of deployment {id}, so only GC by bootc \
                 keeps it: {err:#}"
            ),
        }
    }
    Ok(())
}

/// Removes the image set refs of deployments not in `live`.
#[context("Removing stale image set refs")]
pub(crate) fn remove_stale_deployment_refs(
    repo: &ComposefsRepository,
    live: &[String],
    dry_run: bool,
) -> Result<()> {
    for id in deployments_with_refs(repo)?
        .iter()
        .filter(|id| !live.contains(id))
    {
        tracing::debug!("Removing the image set ref of deployment {id}");
        if !dry_run {
            repo.remove_image_set_ref(&deployment_ref(id))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use composefs::tree::{Directory, Inode, LeafContent, Stat};

    use super::*;

    #[test]
    fn test_parse_image_set_conf() {
        let ok = [
            ("", vec![]),
            ("# nothing\n\n", vec![]),
            ("/usr/lib/modules\n", vec!["/usr/lib/modules"]),
            (
                "  /usr/lib/modules  \n# firmware too\n/usr/lib/firmware",
                vec!["/usr/lib/modules", "/usr/lib/firmware"],
            ),
        ];
        for (text, expected) in ok {
            assert_eq!(parse_image_set_conf(text).unwrap(), expected, "{text:?}");
        }

        let bad = [
            ("/", "root directory"),
            ("usr/lib/modules", "invalid path"),
            ("/usr/lib/modules/", "invalid path"),
            ("/usr/../etc", "invalid path"),
            ("/ab/x", "named like the whiteout stubs"),
            ("/usr/lib\n/usr/lib/modules", "overlaps /usr/lib"),
            ("/usr/lib/modules\n/usr/lib", "overlaps /usr/lib/modules"),
            ("/usr/lib/modules\n/usr/lib/modules", "overlaps"),
        ];
        let too_many = (0..=MAX_SPLIT_DIRECTORIES)
            .map(|i| format!("/usr/lib/split{i}\n"))
            .collect::<String>();
        let bad = bad
            .into_iter()
            .map(|(text, expected)| (text.to_string(), expected))
            .chain([(
                too_many,
                "lists 9 directories, but at most 8 can be split out",
            )]);
        for (text, expected) in bad {
            let err = parse_image_set_conf(&text).unwrap_err();
            assert!(format!("{err:#}").contains(expected), "{text:?}: {err:#}");
        }
        // Siblings sharing a prefix don't overlap
        assert_eq!(
            parse_image_set_conf("/usr/lib/mod\n/usr/lib/modules").unwrap(),
            ["/usr/lib/mod", "/usr/lib/modules"]
        );
    }

    fn stat(mtime: i64) -> Stat {
        Stat {
            st_mode: 0o755,
            st_uid: 0,
            st_gid: 0,
            st_mtim_sec: mtime,
            st_mtim_nsec: 0,
            xattrs: Default::default(),
        }
    }

    /// `/usr/lib/modules/<kver>/foo.ko` and `/usr/bin/sh`, with `conf` as
    /// [`IMAGE_SET_CONF`] if given, and the `/boot` and `/sysroot` that
    /// `transform_for_boot()` empties.
    fn test_fs(kver: &str, conf: Option<&str>) -> FileSystem<Sha512HashValue> {
        let mut fs = FileSystem::new(stat(1));
        let kver_dir = format!("usr/lib/modules/{kver}");
        for dir in [
            "boot",
            "sysroot",
            "usr",
            "usr/lib",
            "usr/lib/bootc",
            "usr/lib/modules",
            "usr/bin",
            kver_dir.as_str(),
        ] {
            let (parent, name) = fs.root.split_mut(OsStr::new(dir)).unwrap();
            parent.insert(name, Inode::Directory(Box::new(Directory::new(stat(2)))));
        }
        let mut files = vec![
            (
                format!("usr/lib/modules/{kver}/foo.ko"),
                kver.as_bytes().to_vec(),
            ),
            ("usr/bin/sh".to_string(), b"sh".to_vec()),
        ];
        if let Some(conf) = conf {
            files.push((IMAGE_SET_CONF.to_string(), conf.as_bytes().to_vec()));
        }
        for (path, data) in files {
            let leaf = fs.push_leaf(
                stat(3),
                LeafContent::Regular(RegularFile::Inline(data.into())),
            );
            let (parent, name) = fs.root.split_mut(OsStr::new(&path)).unwrap();
            parent.insert(name, Inode::leaf(leaf));
        }
        fs
    }

    #[test]
    fn test_split_into_components() -> Result<()> {
        let targets = ["/usr/lib/modules".to_string()];
        let parts = split_into_components(test_fs("6.12", None), &targets)?;
        let names: Vec<_> = parts.iter().map(|(target, _)| target.as_str()).collect();
        assert_eq!(names, ["/", "/usr/lib/modules"]);

        let (root, modules) = (&parts[0].1, &parts[1].1);
        assert!(get_file(root, "usr/bin/sh")?.is_some());
        let empty = root.root.get_directory(OsStr::new("usr/lib/modules"))?;
        assert_eq!(empty.entries().count(), 0);
        assert!(get_file(modules, "usr/lib/modules/6.12/foo.ko")?.is_some());
        assert!(get_file(root, "usr/lib/modules/6.12/foo.ko")?.is_none());
        assert!(
            modules
                .root
                .get_directory_opt(OsStr::new("usr/bin"))?
                .is_none()
        );

        let err =
            split_into_components(test_fs("6.12", None), &["/usr/lib/nope".into()]).unwrap_err();
        assert!(format!("{err:#}").contains("Splitting off /usr/lib/nope"));
        Ok(())
    }

    #[test]
    fn test_image_set_id_tracks_only_changed_component() -> Result<()> {
        let targets = ["/usr/lib/modules".to_string()];
        let version = FormatVersion::V1;
        let ids = |kver: &str| -> Result<(Sha512HashValue, Vec<Sha512HashValue>)> {
            let parts = split_into_components(test_fs(kver, None), &targets)?;
            let images = parts
                .iter()
                .map(|(_, fs)| fs.compute_image_id(version))
                .collect();
            Ok((compute_image_set_id(&parts, version)?, images))
        };
        let (set_a, images_a) = ids("6.12")?;
        let (set_b, images_b) = ids("6.13")?;
        // A different kernel only changes the modules image, and the set
        assert_eq!(images_a[0], images_b[0]);
        assert_ne!(images_a[1], images_b[1]);
        assert_ne!(set_a, set_b);
        assert_eq!(ids("6.12")?.0, set_a);
        Ok(())
    }

    #[test]
    fn test_image_set_targets_from_fs() -> Result<()> {
        let (_td, repo) = super::super::digest::new_temp_composefs_repo(FormatVersion::V1)?;
        assert!(image_set_targets(&test_fs("6.12", None), &repo)?.is_empty());
        assert_eq!(
            image_set_targets(&test_fs("6.12", Some("/usr/lib/modules\n")), &repo)?,
            ["/usr/lib/modules"]
        );
        let err = image_set_targets(&test_fs("6.12", Some("/\n")), &repo).unwrap_err();
        assert!(format!("{err:#}").contains(IMAGE_SET_CONF));
        Ok(())
    }

    #[test]
    fn test_committed_and_computed_ids_agree() -> Result<()> {
        // The update check computes the digest that install and upgrade
        // commit, for either EROFS format.
        for version in [FormatVersion::V1, FormatVersion::V2] {
            let (_td, repo) = super::super::digest::new_temp_composefs_repo(version)?;
            assert!(boot_image_set_parts(&test_fs("6.12", None), &repo)?.is_none());
            let fs = test_fs("6.12", Some("/usr/lib/modules\n"));
            let parts = boot_image_set_parts(&fs, &repo)?.expect("an image set");
            let computed = compute_image_set_id(&parts, repo.erofs_version())?;
            assert_eq!(commit_image_set(&repo, &parts)?, computed, "{version:?}");
            let (set, _) = repo.open_image_set(&computed.to_hex())?;
            assert_eq!(set.components().len(), 2);
            assert!(set.components().iter().all(|c| c.format == version));
        }
        Ok(())
    }

    #[test]
    fn test_image_set_ref_lives_with_deployment() -> Result<()> {
        let (td, repo) = super::super::digest::new_temp_composefs_repo(FormatVersion::V1)?;
        let fs = test_fs("6.12", Some("/usr/lib/modules\n"));
        let parts = boot_image_set_parts(&fs, &repo)?.expect("an image set");
        let id = commit_image_set(&repo, &parts)?.to_hex();
        let (set, _) = repo.open_image_set(&id)?;
        let set_alive = || -> Result<bool> {
            match repo.open_image_set(&id) {
                Ok(_) => Ok(true),
                Err(err) if err.downcast_ref::<composefs::ImageNotFound>().is_some() => Ok(false),
                Err(err) => Err(err),
            }
        };

        // A repository GC with no roots of bootc's, like `bootc internals cfs
        // gc`, keeps the set of a live deployment through its ref.
        repo.gc(&[])?;
        assert!(set_alive()?);
        assert_eq!(deployment_root_format(&repo, &id)?, RootFormat::ImageSet);

        // A live deployment that lost its ref gets it back...
        repo.remove_image_set_ref(&deployment_ref(&id))?;
        add_missing_deployment_refs(&repo, &[id.clone()], true)?;
        assert!(repo.list_image_set_refs(IMAGE_SET_REF_PREFIX)?.is_empty());
        add_missing_deployment_refs(&repo, &[id.clone()], false)?;
        assert_eq!(repo.list_image_set_refs(IMAGE_SET_REF_PREFIX)?.len(), 1);
        repo.gc(&[])?;
        assert!(set_alive()?);

        // A set that can't be read doesn't get one, but doesn't fail GC either.
        let set_link = td.path().join("repo/image-sets").join(&id);
        let manifest = std::fs::read_link(&set_link)?;
        let root_image = std::fs::read_link(
            td.path()
                .join("repo/images")
                .join(set.components()[0].digest.to_hex()),
        )?;
        repo.remove_image_set_ref(&deployment_ref(&id))?;
        std::fs::remove_file(&set_link)?;
        std::os::unix::fs::symlink(&root_image, &set_link)?;
        add_missing_deployment_refs(&repo, &[id.clone()], false)?;
        assert!(repo.list_image_set_refs(IMAGE_SET_REF_PREFIX)?.is_empty());
        std::fs::remove_file(&set_link)?;
        std::os::unix::fs::symlink(&manifest, &set_link)?;
        add_missing_deployment_refs(&repo, &[id.clone()], false)?;

        // ...and once the deployment is gone, so are its ref and its set.
        remove_stale_deployment_refs(&repo, &[], true)?;
        assert_eq!(repo.list_image_set_refs(IMAGE_SET_REF_PREFIX)?.len(), 1);
        remove_stale_deployment_refs(&repo, &[], false)?;
        assert!(repo.list_image_set_refs(IMAGE_SET_REF_PREFIX)?.is_empty());
        repo.gc(&[])?;
        assert!(!set_alive()?);
        assert_eq!(
            deployment_root_format(&repo, &id)?,
            RootFormat::Image(FormatVersion::V1)
        );
        Ok(())
    }
}
