//! Kernel modules as a composefs image of their own.
//!
//! Experimental, see <https://github.com/bootc-dev/bootc/issues/2584>.
//!
//! A bootable image may ship its kernel modules in [`KMODS_PAYLOAD_DIR`]
//! instead of `/usr/lib/modules`. Since `/boot` is emptied before the
//! composefs digest of the root filesystem is computed, the modules then
//! don't change that digest: a root filesystem can be built and digested
//! once, and combined with different kernels.
//!
//! The modules become a second composefs image, whose digest the UKI pins
//! next to the root's with `bootc.kmods=`
//! ([`bootc_initramfs_setup::KARG_KMODS`]). The initramfs mounts it on
//! `/usr/lib/modules`.

use std::ffi::OsStr;

use anyhow::{Context, Result};
use composefs::erofs::format::FormatVersion;
use composefs::fsverity::{FsVerityHashValue, Sha512HashValue};
use composefs::generic_tree::Inode;
use composefs::tree::FileSystem;
use composefs_boot::bootloader::{BootEntry as ComposefsBootEntry, PEType};
use composefs_ctl::composefs;
use composefs_ctl::composefs_boot;

use bootc_initramfs_setup::{KARG_KMODS, MODULES_DIR, parse_kmods_digest};

use crate::bootc_composefs::boot::read_uki_cmdline;

/// Where an image ships kernel modules that are not part of the root
/// filesystem's digest, relative to the root. Its layout is that of
/// `/usr/lib/modules`.
pub(crate) const KMODS_PAYLOAD_DIR: &str = "boot/bootc/modules";

/// Prefix of the repository ref that keeps a kernel modules image alive.
const KMODS_REF_PREFIX: &str = "bootc-kmods-";

/// Build the kernel modules filesystem from the filesystem of a whole image,
/// or `None` if the image has no [`KMODS_PAYLOAD_DIR`].
///
/// To get the same SELinux labels as modules in `/usr/lib/modules`, the
/// payload is labeled at that path, by `label` with the image's own policy.
/// The root of the result is that directory.
///
/// Errors if the image's `/usr/lib/modules`, where the result is mounted,
/// is missing or not empty.
pub(crate) fn kmods_filesystem(
    image: &FileSystem<Sha512HashValue>,
    label: impl FnOnce(&mut FileSystem<Sha512HashValue>) -> Result<()>,
) -> Result<Option<FileSystem<Sha512HashValue>>> {
    if image
        .root
        .get_directory_opt(OsStr::new(KMODS_PAYLOAD_DIR))?
        .is_none()
    {
        return Ok(None);
    }

    // The modules image is mounted on /usr/lib/modules: the rootfs needs it as
    // a mount point, and anything in it would be hidden (and still digested).
    let mountpoint = image
        .root
        .get_directory_opt(OsStr::new(MODULES_DIR))?
        .ok_or_else(|| anyhow::anyhow!("/{MODULES_DIR} must exist as a mount point"))?;
    if mountpoint.entries().next().is_some() {
        anyhow::bail!("/{MODULES_DIR} must be empty when the modules are in /{KMODS_PAYLOAD_DIR}");
    }

    // Move rather than copy the payload, so that no file is reachable (and
    // labeled) through both paths.
    let mut fs = image.clone();
    let payload = take_dir(&mut fs, KMODS_PAYLOAD_DIR)?;
    let (parent, name) = split_path(MODULES_DIR);
    fs.root
        .get_directory_mut(OsStr::new(parent))
        .with_context(|| format!("Opening /{parent}"))?
        .insert(OsStr::new(name), Inode::Directory(Box::new(payload)));
    label(&mut fs).context("Labeling kernel modules")?;

    let mut modules = take_dir(&mut fs, MODULES_DIR)?;
    // The payload directory is typically created by the COPY that adds the
    // modules, with the build time as its mtime. Use the newest mtime of its
    // entries instead, so that the digest only depends on the modules.
    let newest = modules
        .entries()
        .map(|(_, inode)| {
            let stat = inode.stat(&fs.leaves);
            (stat.st_mtim_sec, stat.st_mtim_nsec)
        })
        .max();
    if let Some((sec, nsec)) = newest {
        modules.stat.st_mtim_sec = sec;
        modules.stat.st_mtim_nsec = nsec;
    }
    fs.root = modules;
    fs.compact();
    Ok(Some(fs))
}

fn split_path(path: &str) -> (&str, &str) {
    path.rsplit_once('/')
        .expect("invariant: path has a parent directory")
}

/// Remove the directory at `path` from `fs` and return it.
fn take_dir(
    fs: &mut FileSystem<Sha512HashValue>,
    path: &str,
) -> Result<composefs::tree::Directory<Sha512HashValue>> {
    let (parent, name) = split_path(path);
    match fs
        .root
        .get_directory_mut(OsStr::new(parent))?
        .pop(OsStr::new(name))
    {
        Some(Inode::Directory(dir)) => Ok(*dir),
        _ => anyhow::bail!("/{path} is not a directory"),
    }
}

/// The cmdline of the image's primary UKI, if it has one.
fn primary_uki_cmdline(
    repo: &crate::store::ComposefsRepository,
    entries: &[ComposefsBootEntry<Sha512HashValue>],
) -> Result<Option<String>> {
    let primary = entries.iter().find_map(|entry| match entry {
        ComposefsBootEntry::Type2(entry) if matches!(entry.pe_type, PEType::Uki) => Some(entry),
        _ => None,
    });
    primary
        .map(|entry| read_uki_cmdline(repo, &entry.file))
        .transpose()
}

/// Write the kernel modules image of a pulled image into the repository, if
/// the image ships one, and return its digest.
///
/// The modules and the UKI must agree: modules need a UKI that pins them
/// with `bootc.kmods=`, the image generated here must match that digest, and
/// a pin needs modules. That way a mismatch is found now rather than by a
/// system that fails to boot.
#[fn_error_context::context("Preparing kernel modules image")]
pub(crate) fn ensure_kmods_image(
    repo: &crate::store::ComposefsRepository,
    image: &FileSystem<Sha512HashValue>,
    entries: &[ComposefsBootEntry<Sha512HashValue>],
) -> Result<Option<Sha512HashValue>> {
    let cmdline = primary_uki_cmdline(repo, entries)?;
    let pinned = cmdline
        .as_deref()
        .map(parse_kmods_digest)
        .transpose()?
        .flatten();
    let has_payload = image
        .root
        .get_directory_opt(OsStr::new(KMODS_PAYLOAD_DIR))?
        .is_some();
    let pinned = match (pinned, has_payload, cmdline.is_some()) {
        (None, false, _) => return Ok(None),
        (Some(pinned), true, _) => pinned,
        (Some(_), false, _) => {
            anyhow::bail!("The UKI has {KARG_KMODS}=, but the image has no /{KMODS_PAYLOAD_DIR}")
        }
        (None, true, true) => {
            anyhow::bail!("The image has /{KMODS_PAYLOAD_DIR}, but its UKI has no {KARG_KMODS}=")
        }
        (None, true, false) => {
            anyhow::bail!("/{KMODS_PAYLOAD_DIR} is only supported with a UKI, and none was found")
        }
    };

    let kmods = kmods_filesystem(image, |fs| {
        composefs_boot::selabel::selabel(fs, repo).map(drop)
    })?
    .expect("invariant: payload checked above");

    // The UKI pins one EROFS format; find which.
    let mut computed = Vec::new();
    for version in [FormatVersion::V1, FormatVersion::V2] {
        let (data, id) = kmods.compute_image_bytes(version);
        if id == pinned {
            let name = format!("{KMODS_REF_PREFIX}{}", id.to_hex());
            repo.write_image(Some(&name), &data)?;
            tracing::info!("Kernel modules image: {}", pinned.to_hex());
            return Ok(Some(pinned));
        }
        computed.push(format!("{version:?}: {}", id.to_hex()));
    }
    anyhow::bail!(
        "The UKI pins kernel modules image {}, but /{KMODS_PAYLOAD_DIR} gives {}",
        pinned.to_hex(),
        computed.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use composefs::dumpfile::dumpfile_to_filesystem;

    const IMAGE: &str = "\
/ 0 40755 2 0 0 0 0.0 - - -
/boot 0 40755 2 0 0 0 0.0 - - -
/boot/bootc 0 40755 2 0 0 0 0.0 - - -
/boot/bootc/modules 0 40755 2 0 0 0 999.0 - - -
/boot/bootc/modules/6.1.0 0 40755 2 0 0 0 5.0 - - -
/boot/bootc/modules/6.1.0/modules.dep 3 100644 1 0 0 0 0.0 - dep -
/boot/bootc/modules/6.1.0/a.ko 1 100644 1 0 0 0 0.0 - a -
/usr 0 40755 2 0 0 0 0.0 - - -
/usr/bin 0 40755 2 0 0 0 0.0 - - -
/usr/bin/true 6 100755 1 0 0 0 0.0 - rootfs -
/usr/lib 0 40755 2 0 0 0 0.0 - - -
/usr/lib/modules 0 40755 2 0 0 0 0.0 - - -
";

    #[test]
    fn test_kmods_filesystem() -> Result<()> {
        let image = dumpfile_to_filesystem::<Sha512HashValue>(IMAGE)?;

        let mut labeled_at_runtime_path = false;
        let kmods = kmods_filesystem(&image, |fs| {
            // Only reachable at its runtime path while labeling
            labeled_at_runtime_path = fs
                .root
                .get_directory_opt(OsStr::new("usr/lib/modules/6.1.0"))?
                .is_some()
                && fs
                    .root
                    .get_directory_opt(OsStr::new(KMODS_PAYLOAD_DIR))?
                    .is_none();
            Ok(())
        })?
        .expect("payload present");
        assert!(labeled_at_runtime_path);
        // The root takes the newest mtime of its entries
        assert_eq!(kmods.root.stat.st_mtim_sec, 5);
        // Only the payload's files are left
        assert_eq!(kmods.leaves.len(), 2);
        let kver_dir = kmods.root.get_directory(OsStr::new("6.1.0"))?;
        assert!(
            kver_dir
                .get_file_opt(OsStr::new("a.ko"), &kmods.leaves)?
                .is_some()
        );
        // The source image is unchanged
        assert!(
            image
                .root
                .get_directory_opt(OsStr::new(KMODS_PAYLOAD_DIR))?
                .is_some()
        );

        // The digest depends on the modules only, not on the rest of the
        // image or on when the payload directory was created
        let other = IMAGE
            .replace(
                "/usr/bin/true 6 100755 1 0 0 0 0.0 - rootfs -",
                "/usr/bin/false 5 100755 1 0 0 0 0.0 - other -",
            )
            .replace(
                "/boot/bootc/modules 0 40755 2 0 0 0 999.0",
                "/boot/bootc/modules 0 40755 2 0 0 0 1234.0",
            );
        let other = dumpfile_to_filesystem::<Sha512HashValue>(&other)?;
        let other = kmods_filesystem(&other, |_| Ok(()))?.expect("payload present");
        for version in [FormatVersion::V1, FormatVersion::V2] {
            assert_eq!(
                kmods.compute_image_id(version),
                other.compute_image_id(version)
            );
        }

        // The rootfs must have an empty /usr/lib/modules to mount on
        let missing = IMAGE.replace("/usr/lib/modules 0 40755 2 0 0 0 0.0 - - -\n", "");
        let nonempty = format!("{IMAGE}/usr/lib/modules/old 0 40755 2 0 0 0 0.0 - - -\n");
        for bad in [missing, nonempty] {
            let bad = dumpfile_to_filesystem::<Sha512HashValue>(&bad)?;
            assert!(kmods_filesystem(&bad, |_| Ok(())).is_err());
        }

        // No payload, no image
        let plain = dumpfile_to_filesystem::<Sha512HashValue>(
            "/ 0 40755 2 0 0 0 0.0 - - -\n/usr 0 40755 2 0 0 0 0.0 - - -\n",
        )?;
        assert!(kmods_filesystem(&plain, |_| Ok(()))?.is_none());
        Ok(())
    }
}
