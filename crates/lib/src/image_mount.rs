//! Read-only access to the image content of a booted or staged deployment.
//!
//! This deliberately does not assemble deployment state: in particular, it
//! never bind-mounts `/var` or the deployment's mutable `/etc` over the image.

use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;

use anyhow::{Context, Result, bail, ensure};
use camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::cap_std::{ambient_authority, fs::Dir};
use clap::{Args, ValueEnum};
use composefs_ctl::composefs::fsverity::{FsVerityHashValue, Sha512HashValue};
use ostree::gio;
use ostree_ext::{ostree, ostree_prepareroot};
use rustix::fs::{AtFlags, CWD, Mode, OFlags, StatxFlags, openat, statx};
use rustix::mount::{
    MoveMountFlags, OpenTreeFlags, UnmountFlags, move_mount, open_tree, unmount as unmount_path,
};

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
#[clap(rename_all = "lowercase")]
pub(crate) enum Deployment {
    Booted,
    Staged,
}

#[derive(Debug, Args, PartialEq, Eq)]
pub(crate) struct MountOpts {
    /// Select exactly the booted deployment or the pending staged deployment.
    #[arg(long, value_enum)]
    pub(crate) deployment: Deployment,

    /// Absolute directory path inside the selected image to expose (`/` selects its root).
    /// No path component may be a symlink.
    #[arg(long, value_parser = crate::cli::parse_absolute_path)]
    pub(crate) source: Utf8PathBuf,

    /// Existing empty absolute directory to mount the selected image content on.
    #[arg(long, value_parser = crate::cli::parse_absolute_path)]
    pub(crate) target: Utf8PathBuf,
}

#[derive(Debug, Args, PartialEq, Eq)]
pub(crate) struct UnmountOpts {
    /// Named mountpoint to unmount (non-recursive; bootc provenance is not checked).
    #[arg(value_parser = crate::cli::parse_absolute_path)]
    pub(crate) target: Utf8PathBuf,
}

struct MountedImageRoot {
    root: ImageRoot,
    // Keep the composefs repository open while cloning and attaching its tree.
    _storage: StorageGuard,
}

enum ImageRoot {
    /// A detached mount of the image (composefs, also for OSTree).
    Detached(OwnedFd),
    /// A plain OSTree checkout in the attached /sysroot. Its /etc is
    /// deployment-local state rather than image content.
    Checkout(Dir),
}

enum StorageGuard {
    Composefs {
        _repo: crate::store::ComposefsRepository,
    },
    // OSTree's sysroot lock can't be taken without writing to /sysroot; see
    // mount_ostree_image().
    Ostree,
}

pub(crate) fn mount(opts: MountOpts) -> Result<()> {
    source_relative_path(&opts.source)?;
    let composefs_booted = crate::bootc_composefs::status::composefs_booted()?;
    // Select only from the active backend. These lookups are deliberately
    // narrower than `status::get_host()`: they do not initialize storage,
    // migrate repository metadata, configure the ESP, or change namespaces.
    let image = if let Some(booted) = composefs_booted {
        let (id, allow_missing_fsverity) = match opts.deployment {
            Deployment::Booted => (booted.digest.to_string(), booted.allow_missing_fsverity),
            Deployment::Staged => (
                staged_composefs_deployment_id(&booted.digest)?,
                booted.allow_missing_fsverity,
            ),
        };
        mount_composefs_image(&opts, id, allow_missing_fsverity)?
    } else {
        mount_ostree_image(&opts)?
    };
    let MountedImageRoot { root, _storage } = image;

    let (image_root, detached_tree) = match &root {
        ImageRoot::Detached(tree) => {
            // Restrict the whole tree up front, since the pre-6.15 fallback
            // below briefly attaches all of it.
            bootc_initramfs_setup::set_mount_tree_readonly_nosymfollow(tree)
                .context("Making selected image read-only and preventing symlink traversal")?;
            let image_root = Dir::reopen_dir(tree).context("Opening selected image root")?;
            (image_root, Some(tree))
        }
        ImageRoot::Checkout(deployment) => {
            ensure_source_outside_checkout_etc(&opts.source)?;
            let image_root = deployment
                .try_clone()
                .context("Opening selected OSTree checkout")?;
            (image_root, None)
        }
    };
    let source = open_source(&image_root, &opts.source)?;
    // Open once and retain this descriptor through validation and attachment.
    // This avoids checking one pathname and mounting on a replacement object.
    let (resolved_target, target, target_parent) = open_target(&opts.target, true)?;
    ensure_not_root_target(&target, &opts.target)?;
    let target_parent = target_parent.context("mount target must not be filesystem root")?;
    let source_metadata = source.metadata().context("Inspecting image source")?;
    let target_metadata = target
        .metadata()
        .with_context(|| format!("Inspecting mount target {}", opts.target))?;
    ensure!(
        source_metadata.is_dir() && target_metadata.is_dir(),
        "image source {} and target {} must both be directories",
        opts.source,
        opts.target
    );

    // Check immediately before cloning and attaching, so a changed target
    // cannot silently hide newly-added contents or stack another mount.
    ensure_directory_empty(&target, &opts.target)?;
    ensure_not_mountpoint(&target, &target_parent, &opts.target)?;

    // A checkout is cloned straight from /sysroot, which works on any kernel.
    let source_tree = match (clone_source(&source), detached_tree) {
        (Ok(source_tree), _) => source_tree,
        (Err(rustix::io::Errno::INVAL), Some(tree)) => {
            clone_source_via_target(tree, &source, &target, &target_parent, &resolved_target)?
        }
        (Err(e), _) => {
            return Err(e).with_context(|| format!("Cloning image source {}", opts.source));
        }
    };
    bootc_initramfs_setup::set_mount_tree_readonly_nosymfollow(&source_tree)
        .context("Making selected image content read-only and preventing symlink traversal")?;

    move_mount(
        &source_tree,
        "",
        &target,
        "",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
    )
    .with_context(|| format!("Attaching image source {} at {}", opts.source, opts.target))?;

    Ok(())
}

fn clone_source(source: &std::fs::File) -> rustix::io::Result<OwnedFd> {
    let source_path = format!("/proc/self/fd/{}", source.as_raw_fd());
    open_tree(
        CWD,
        source_path.as_str(),
        OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
    )
}

/// Before Linux 6.15, open_tree() can only clone from mounts in the caller's
/// mount namespace, not from a detached tree such as a freshly mounted image.
/// Attach the image root at the (validated, empty) target for the moment,
/// clone the source from there, then detach the root again. The root is
/// image content only, already restricted like the final mount.
fn clone_source_via_target(
    tree: &OwnedFd,
    source: &std::fs::File,
    target: &std::fs::File,
    target_parent: &std::fs::File,
    resolved_target: &Utf8Path,
) -> Result<OwnedFd> {
    let name = resolved_target
        .file_name()
        .context("Mount target has no final path component")?;
    move_mount(
        tree,
        "",
        target,
        "",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
    )
    .with_context(|| format!("Temporarily attaching image root at {resolved_target}"))?;
    let cloned = clone_source(source);
    // The descriptors for the image root keep it busy, so detach it lazily.
    let detached = unmount_path(
        format!("/proc/self/fd/{}/{name}", target_parent.as_raw_fd()).as_str(),
        UnmountFlags::DETACH | UnmountFlags::NOFOLLOW,
    )
    .with_context(|| {
        format!("Detaching temporary image root from {resolved_target}; unmount it by hand")
    });
    match (cloned, detached) {
        (Ok(cloned), Ok(())) => Ok(cloned),
        (Err(e), Ok(())) => Err(e).context("Cloning image source from the attached image root"),
        (Ok(_), Err(e)) => Err(e),
        (Err(clone_err), Err(e)) => Err(e.context(format!(
            "after cloning the image source failed: {clone_err}"
        ))),
    }
}

/// Read the composefs staged selector without constructing `BootedStorage`.
/// The staged ID is valid only when it names a distinct deployment with local
/// composefs state and a parseable origin file.
fn staged_composefs_deployment_id(booted_id: &str) -> Result<String> {
    use crate::composefs_consts::{
        COMPOSEFS_STAGED_DEPLOYMENT_FNAME, COMPOSEFS_TRANSIENT_STATE_DIR,
    };

    let staged_path =
        format!("{COMPOSEFS_TRANSIENT_STATE_DIR}/{COMPOSEFS_STAGED_DEPLOYMENT_FNAME}");
    let staged_json = match std::fs::read_to_string(&staged_path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("No staged composefs deployment found")
        }
        Err(e) => {
            return Err(e).with_context(|| {
                format!("Reading staged composefs deployment selector {staged_path}")
            });
        }
    };
    let id = staged_composefs_id_from_json(&staged_json, booted_id)?;

    let sysroot = Dir::open_ambient_dir("/sysroot", ambient_authority())
        .context("Opening booted system sysroot")?;
    let origin = crate::bootc_composefs::state::read_origin(&sysroot, &id)?.ok_or_else(|| {
        anyhow::anyhow!("No composefs state or origin for staged deployment {id}")
    })?;
    let boot_type = origin
        .get::<String>(
            crate::composefs_consts::ORIGIN_KEY_BOOT,
            crate::composefs_consts::ORIGIN_KEY_BOOT_TYPE,
        )
        .ok_or_else(|| {
            anyhow::anyhow!("Staged composefs deployment {id} has no boot type in its origin")
        })?;
    crate::bootc_composefs::boot::BootType::try_from(boot_type.as_str())
        .context("Parsing staged composefs deployment boot type")?;
    Ok(id)
}

fn staged_composefs_id_from_json(contents: &str, booted_id: &str) -> Result<String> {
    let staged: crate::bootc_composefs::status::StagedDeployment =
        serde_json::from_str(contents).context("Parsing staged composefs deployment selector")?;
    let id = Sha512HashValue::from_hex(&staged.depl_id)
        .context("Parsing staged composefs deployment ID")?
        .to_hex();
    ensure!(id != booted_id, "No staged composefs deployment found");
    Ok(id)
}

fn mount_composefs_image(
    opts: &MountOpts,
    id: String,
    allow_missing_fsverity: bool,
) -> Result<MountedImageRoot> {
    let sysroot = Dir::open_ambient_dir("/sysroot", ambient_authority())
        .context("Opening booted system sysroot")?;
    let mut repo = crate::bootc_composefs::repo::open_composefs_repo(&sysroot)
        .context("Opening existing composefs repository")?;
    if allow_missing_fsverity {
        repo.set_insecure();
    }
    let tree = repo
        .mount(&id)
        .with_context(|| format!("Mounting {:?} composefs deployment {id}", opts.deployment))?;
    Ok(MountedImageRoot {
        root: ImageRoot::Detached(tree),
        _storage: StorageGuard::Composefs { _repo: repo },
    })
}

fn mount_ostree_image(opts: &MountOpts) -> Result<MountedImageRoot> {
    // Load the booted sysroot read-only. In particular, do not call
    // prepare_for_write(): it remounts /sysroot read-write in a private mount
    // namespace, where the final mount would not be visible to the caller.
    // For the same reason, OSTree's sysroot lock is not taken: it needs a
    // writable /sysroot, since the lock file is created and removed on each
    // use. A cleanup that removes the selected deployment concurrently makes
    // the steps below fail.
    //
    // OSTree only finds the booted deployment when loading the default
    // sysroot path, so don't go through a /proc/self/fd path here.
    let sysroot_dir = Dir::open_ambient_dir("/sysroot", ambient_authority())
        .context("Opening booted system sysroot")?;
    let sysroot = ostree::Sysroot::new_default();
    sysroot
        .load(gio::Cancellable::NONE)
        .context("Loading booted OSTree sysroot")?;

    let deployment = match opts.deployment {
        Deployment::Booted => sysroot
            .require_booted_deployment()
            .context("No booted OSTree deployment found")?
            .clone(),
        Deployment::Staged => {
            let booted = sysroot
                .require_booted_deployment()
                .context("No booted OSTree deployment found")?;
            sysroot
                .deployments()
                .into_iter()
                .find(|deployment| deployment.is_staged() && deployment.osname() == booted.osname())
                .ok_or_else(|| anyhow::anyhow!("No staged OSTree deployment found"))?
        }
    };
    let deployment_path = sysroot.deployment_dirpath(&deployment);
    let deployment_dir = sysroot_dir
        .open_dir(deployment_path.as_str())
        .with_context(|| format!("Opening selected OSTree deployment {deployment_path}"))?;
    let repo = sysroot_dir
        .open_dir("ostree/repo")
        .context("Opening booted OSTree repository")?;
    let config = ostree_prepareroot::load_config_from_root(&deployment_dir)
        .context("Loading selected deployment's prepare-root.conf")?;
    let root = match ostree_prepareroot::mount_composefs(
        &deployment_dir,
        &repo,
        deployment.csum().as_str(),
        config.as_ref(),
    )
    .context("Mounting selected OSTree deployment image")?
    {
        Some(tree) => ImageRoot::Detached(tree),
        None => ImageRoot::Checkout(deployment_dir),
    };
    Ok(MountedImageRoot {
        root,
        _storage: StorageGuard::Ostree,
    })
}

/// Refuse sources that would expose an OSTree checkout's /etc, which holds the
/// deployment's merged configuration rather than image content. The image's
/// default configuration remains available at `/usr/etc`.
fn ensure_source_outside_checkout_etc(source: &Utf8Path) -> Result<()> {
    let relative = source_relative_path(source)?;
    let first = relative.components().find_map(|component| match component {
        camino::Utf8Component::Normal(component) => Some(component),
        _ => None,
    });
    ensure!(
        !matches!(first, None | Some("etc")),
        "image source {source} would expose the deployment's /etc in an OSTree deployment \
         without composefs; select a path outside /etc (image defaults are in /usr/etc)"
    );
    Ok(())
}

fn open_source(root: &Dir, source: &Utf8Path) -> Result<std::fs::File> {
    let relative = source_relative_path(source)?;
    let components = relative
        .components()
        .filter_map(|component| match component {
            camino::Utf8Component::Normal(component) => Some(component),
            _ => None,
        })
        .collect::<Vec<_>>();

    let mut parent: Option<OwnedFd> = None;
    if components.is_empty() {
        let fd = openat(
            root,
            ".",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("Opening image root")?;
        return Ok(std::fs::File::from(fd));
    }

    for (index, component) in components.iter().enumerate() {
        let fd = match &parent {
            Some(parent) => openat(
                parent,
                *component,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ),
            None => openat(
                root,
                *component,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ),
        }
        .with_context(|| format!("Opening image source component {component} in {source}"))?;
        let file = std::fs::File::from(fd);
        let metadata = file
            .metadata()
            .with_context(|| format!("Inspecting image source component {component}"))?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "image source path components must not be symlinks: {source}"
        );
        if index + 1 < components.len() {
            ensure!(
                metadata.is_dir(),
                "image source path component {component} is not a directory"
            );
            parent = Some(file.into());
        } else {
            return Ok(file);
        }
    }
    unreachable!("non-empty component list returns from the loop")
}

fn source_relative_path(source: &Utf8Path) -> Result<Utf8PathBuf> {
    ensure!(
        source.is_absolute(),
        "image source must be absolute: {source}"
    );
    for component in source.components() {
        if matches!(component, camino::Utf8Component::ParentDir) {
            bail!("image source must not contain `..`: {source}");
        }
    }
    source
        .strip_prefix("/")
        .map(|path| path.to_owned())
        .with_context(|| format!("Invalid absolute image source {source}"))
}

pub(crate) fn unmount(opts: UnmountOpts) -> Result<()> {
    let (resolved, target, parent) = open_target(&opts.target, false)?;
    ensure_not_root_target(&target, &opts.target)?;
    let parent = parent.context("Refusing to unmount the root filesystem")?;
    ensure!(
        mount_id(&target)? != mount_id(&parent)?,
        "{} is not a mountpoint",
        opts.target
    );
    // Any descriptor for the mount root, even O_PATH, holds a reference to the
    // mount that makes a non-lazy unmount fail with EBUSY. Release it and
    // unmount by name relative to the retained parent instead, so the path
    // is still resolved from the directory validated above.
    drop(target);
    let name = resolved
        .file_name()
        .context("Mount target has no final path component")?;
    let fd_path = format!("/proc/self/fd/{}/{name}", parent.as_raw_fd());
    unmount_path(fd_path.as_str(), UnmountFlags::NOFOLLOW)
        .with_context(|| format!("Unmounting {}", opts.target))?;
    Ok(())
}

/// Resolve symlinks in a caller-supplied target first: bootc systems commonly
/// have some, such as /mnt -> var/mnt or /home -> var/home. The result is then
/// opened without following any, so a concurrent change to the path fails
/// rather than redirecting the operation.
fn open_target(
    path: &Utf8Path,
    final_directory: bool,
) -> Result<(Utf8PathBuf, std::fs::File, Option<std::fs::File>)> {
    let resolved = path
        .canonicalize_utf8()
        .with_context(|| format!("Resolving target {path}"))?;
    let (target, parent) = open_path_no_symlinks(&resolved, final_directory)?;
    Ok((resolved, target, parent))
}

/// Resolve an absolute path one component at a time, retaining the parent
/// descriptor so checks and mount attachment refer to the same directory.
fn open_path_no_symlinks(
    path: &Utf8Path,
    final_directory: bool,
) -> Result<(std::fs::File, Option<std::fs::File>)> {
    ensure!(path.is_absolute(), "target path must be absolute: {path}");
    ensure!(
        path.components().all(|component| !matches!(
            component,
            camino::Utf8Component::ParentDir | camino::Utf8Component::Prefix(_)
        )),
        "target path must not contain `..`: {path}"
    );
    let components = path
        .components()
        .filter_map(|component| match component {
            camino::Utf8Component::RootDir => None,
            camino::Utf8Component::Normal(component) => Some(component.to_owned()),
            camino::Utf8Component::CurDir => None,
            camino::Utf8Component::ParentDir | camino::Utf8Component::Prefix(_) => unreachable!(),
        })
        .collect::<Vec<_>>();

    let root = openat(
        CWD,
        "/",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("Opening filesystem root")?;
    let mut parent = std::fs::File::from(root);
    if components.is_empty() {
        ensure!(!final_directory, "mount target must not be filesystem root");
        return Ok((parent, None));
    }

    for (index, component) in components.iter().enumerate() {
        let final_component = index + 1 == components.len();
        let mut flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        if !final_component || final_directory {
            flags |= OFlags::DIRECTORY;
        }
        let fd = openat(&parent, component.as_str(), flags, Mode::empty())
            .with_context(|| format!("Opening target path component {component} in {path}"))?;
        let current = std::fs::File::from(fd);
        let metadata = current
            .metadata()
            .with_context(|| format!("Inspecting target path component {component} in {path}"))?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "target path components must not be symlinks: {path}"
        );
        if final_component {
            return Ok((current, Some(parent)));
        }
        parent = current;
    }
    unreachable!("non-empty component list returns from the loop")
}

fn ensure_directory_empty(target: &impl AsFd, path: &Utf8Path) -> Result<()> {
    let mut entries = Dir::reopen_dir(target)
        .with_context(|| format!("Opening mount target directory {path}"))?
        .entries()?;
    ensure!(
        entries.next().is_none(),
        "mount target {path} must be empty"
    );
    Ok(())
}

/// Compare Linux mount IDs for a directory and its parent. A different ID
/// means the target is already a mountpoint, including an overmount.
fn ensure_not_mountpoint(target: &impl AsFd, parent: &impl AsFd, path: &Utf8Path) -> Result<()> {
    let target_mount_id = mount_id(target)?;
    let parent_mount_id = mount_id(parent)?;
    ensure!(
        target_mount_id == parent_mount_id,
        "mount target {path} is already a mountpoint"
    );
    Ok(())
}

fn mount_id(fd: &impl AsFd) -> Result<u64> {
    let stat = statx(fd.as_fd(), "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)
        .context("Reading mount ID with statx")?;
    ensure!(
        stat.stx_mask & StatxFlags::MNT_ID.bits() == StatxFlags::MNT_ID.bits(),
        "kernel did not provide mount IDs via statx (STATX_MNT_ID is required)"
    );
    Ok(stat.stx_mnt_id)
}

fn ensure_not_root_target(target: &std::fs::File, path: &Utf8Path) -> Result<()> {
    let root = openat(CWD, "/", OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
        .context("Opening filesystem root")?;
    let root = std::fs::File::from(root);
    let target_metadata = target
        .metadata()
        .with_context(|| format!("Inspecting target {path}"))?;
    let root_metadata = root.metadata().context("Inspecting filesystem root")?;
    ensure!(
        target_metadata.dev() != root_metadata.dev()
            || target_metadata.ino() != root_metadata.ino(),
        "Refusing to mount or unmount the root filesystem"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Deployment, MountOpts, UnmountOpts, ensure_directory_empty, ensure_not_mountpoint,
        ensure_not_root_target, open_path_no_symlinks, open_source, open_target,
        source_relative_path,
    };
    use crate::cli::{ImageOpts, InstallOpts, Opt};
    use camino::{Utf8Path, Utf8PathBuf};
    use cap_std_ext::cap_std::ambient_authority;
    use clap::Parser;
    use std::os::unix::fs::{MetadataExt, symlink};

    fn open_existing_path(path: &Utf8Path) -> anyhow::Result<std::fs::File> {
        open_target(path, false).map(|(_, target, _)| target)
    }

    fn open_mount_target(
        path: &Utf8Path,
    ) -> anyhow::Result<(std::fs::File, Option<std::fs::File>)> {
        open_target(path, true).map(|(_, target, parent)| (target, parent))
    }

    #[test]
    fn parses_image_mount_and_unmount_without_changing_install_mount() {
        let parsed = Opt::try_parse_from([
            "bootc",
            "image",
            "mount",
            "--deployment",
            "staged",
            "--source",
            "/usr",
            "--target",
            "/mnt/image",
        ])
        .unwrap();
        assert!(matches!(
            parsed,
            Opt::Image(ImageOpts::Mount(MountOpts {
                deployment: Deployment::Staged,
                ..
            }))
        ));
        assert!(matches!(
            Opt::try_parse_from(["bootc", "image", "unmount", "/mnt/image"]).unwrap(),
            Opt::Image(ImageOpts::Unmount(UnmountOpts { .. }))
        ));
        assert!(matches!(
            Opt::try_parse_from([
                "bootc",
                "install",
                "mount",
                "--sysroot",
                "/sysroot",
                "--latest",
                "/mnt/installed"
            ])
            .unwrap(),
            Opt::Install(InstallOpts::Mount(_))
        ));
    }

    #[test]
    fn source_paths_must_stay_beneath_image_root() {
        for path in ["relative", "/usr/../etc", "/../../etc"] {
            assert!(source_relative_path(Utf8Path::new(path)).is_err(), "{path}");
        }
        assert_eq!(
            source_relative_path(Utf8Path::new("/usr/bin"))
                .unwrap()
                .as_str(),
            "usr/bin"
        );
        assert_eq!(
            source_relative_path(Utf8Path::new("/")).unwrap().as_str(),
            ""
        );
    }

    #[test]
    fn refuses_root_as_mount_or_unmount_target() {
        let root = open_existing_path(Utf8Path::new("/")).unwrap();
        assert!(ensure_not_root_target(&root, Utf8Path::new("/")).is_err());

        let temp = tempfile::tempdir().unwrap();
        let target = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        let target_fd = open_existing_path(&target).unwrap();
        assert!(ensure_not_root_target(&target_fd, &target).is_ok());

        let root_alias = temp.path().join("root-alias");
        symlink("/", &root_alias).unwrap();
        let root_alias = Utf8PathBuf::from_path_buf(root_alias).unwrap();
        let root_alias_fd = open_existing_path(&root_alias).unwrap();
        assert!(ensure_not_root_target(&root_alias_fd, &root_alias).is_err());
    }

    #[test]
    fn unmount_refuses_non_mountpoints() {
        let temp = tempfile::tempdir().unwrap();
        let target = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        let err = super::unmount(UnmountOpts { target }).unwrap_err();
        assert!(
            format!("{err:#}").contains("is not a mountpoint"),
            "{err:#}"
        );
    }

    #[test]
    fn checkout_sources_must_not_include_deployment_etc() {
        for (source, allowed) in [
            ("/", false),
            ("/etc", false),
            ("/etc/ostree", false),
            ("/./etc", false),
            ("/usr", true),
            ("/usr/etc", true),
            ("/opt/etc", true),
            ("/etcetera", true),
        ] {
            assert_eq!(
                super::ensure_source_outside_checkout_etc(Utf8Path::new(source)).is_ok(),
                allowed,
                "{source}"
            );
        }
    }

    #[test]
    fn source_lookup_rejects_symlink_components_and_preserves_file_directory_matches() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("real-dir")).unwrap();
        std::fs::write(temp.path().join("real-file"), b"image").unwrap();
        symlink("/", temp.path().join("absolute-link")).unwrap();
        symlink("real-file", temp.path().join("file-link")).unwrap();
        let root =
            cap_std_ext::cap_std::fs::Dir::open_ambient_dir(temp.path(), ambient_authority())
                .unwrap();

        assert!(open_source(&root, Utf8Path::new("/absolute-link/etc")).is_err());
        assert!(open_source(&root, Utf8Path::new("/file-link")).is_err());
        assert!(
            open_source(&root, Utf8Path::new("/real-file"))
                .unwrap()
                .metadata()
                .unwrap()
                .is_file()
        );
        assert!(
            open_source(&root, Utf8Path::new("/real-dir"))
                .unwrap()
                .metadata()
                .unwrap()
                .is_dir()
        );
        assert!(
            open_source(&root, Utf8Path::new("/"))
                .unwrap()
                .metadata()
                .unwrap()
                .is_dir()
        );
    }

    #[test]
    fn mount_target_must_be_empty_and_symlinks_resolve_to_it() {
        let temp = tempfile::tempdir().unwrap();
        let target_path = Utf8PathBuf::from_path_buf(temp.path().join("empty")).unwrap();
        std::fs::create_dir(&target_path).unwrap();
        let (target, parent) = open_mount_target(&target_path).unwrap();
        ensure_directory_empty(&target, &target_path).unwrap();
        ensure_not_mountpoint(&target, parent.as_ref().unwrap(), &target_path).unwrap();

        std::fs::write(target_path.join("existing"), b"content").unwrap();
        assert!(ensure_directory_empty(&target, &target_path).is_err());

        let linked_target = temp.path().join("linked-target");
        symlink(&target_path, &linked_target).unwrap();
        let linked_target = Utf8PathBuf::from_path_buf(linked_target).unwrap();
        let linked_parent = temp.path().join("linked-parent");
        symlink(temp.path(), &linked_parent).unwrap();
        let nested_target = Utf8PathBuf::from_path_buf(linked_parent.join("empty")).unwrap();
        let target_ino = target.metadata().unwrap().ino();
        for path in [&linked_target, &nested_target] {
            let (resolved, _) = open_mount_target(path).unwrap();
            assert_eq!(resolved.metadata().unwrap().ino(), target_ino, "{path}");
        }

        // Without resolution first, symlinks in the path are refused.
        assert!(open_path_no_symlinks(&linked_target, true).is_err());
        assert!(open_path_no_symlinks(&nested_target, true).is_err());
        assert!(open_mount_target(&target_path.join("missing")).is_err());
    }

    #[test]
    fn staged_composefs_selector_requires_a_valid_distinct_digest() {
        let booted = "aa".repeat(64);
        let staged = "bb".repeat(64);
        let valid_json = format!(r#"{{"depl_id":"{staged}","finalization_locked":false}}"#);
        assert_eq!(
            super::staged_composefs_id_from_json(&valid_json, &booted).unwrap(),
            staged
        );
        assert!(super::staged_composefs_id_from_json(&valid_json, &staged).is_err());
        assert!(super::staged_composefs_id_from_json("{}", &booted).is_err());
        assert!(
            super::staged_composefs_id_from_json(
                r#"{"depl_id":"not-a-digest","finalization_locked":false}"#,
                &booted
            )
            .is_err()
        );
    }
}
