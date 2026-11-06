//! Read `/proc/self/mountinfo` and select mounts nested beneath the source `/var`.
//!
//! The byte-oriented parser preserves non-UTF-8 Unix paths and decodes kernel
//! escapes. The `procfs` crate requires UTF-8 and leaves escaped mountpoint
//! paths undecoded; bootc-mount/findmnt exposes `String` targets and invokes
//! external `findmnt`, so neither preserves arbitrary path bytes. There is no
//! standard-library mountinfo API.

use std::{
    collections::BTreeSet,
    os::unix::ffi::OsStringExt,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};

/// Read one snapshot and return the paths of mounts nested beneath `src_var`.
///
/// `src_var` is the canonical path used to open the source directory;
/// mountinfo paths are already kernel-canonical.
pub(super) fn nested_mountpoints_for(src_var: &Path) -> Result<BTreeSet<PathBuf>> {
    let snapshot = read_mountinfo_snapshot()?;
    nested_mountpoints(src_var, parse_mountinfo(&snapshot)?)
}

/// Read one complete installer mount namespace snapshot.
fn read_mountinfo_snapshot() -> Result<Vec<u8>> {
    std::fs::read("/proc/self/mountinfo")
        .context("Reading installer /proc/self/mountinfo for /var migration")
}

fn nested_mountpoints(
    src_var: &Path,
    mountpoints: impl IntoIterator<Item = PathBuf>,
) -> Result<BTreeSet<PathBuf>> {
    anyhow::ensure!(src_var.is_absolute(), "Source /var path must be absolute");
    let mut nested = BTreeSet::new();
    for mountpoint in mountpoints {
        let Ok(relative) = mountpoint.strip_prefix(src_var) else {
            continue;
        };
        // The mount on /var itself is not a nested mount. Only child paths are
        // filtered; Path::strip_prefix provides component-safe containment.
        if relative.as_os_str().is_empty() {
            continue;
        }
        anyhow::ensure!(
            relative
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
            "Invalid nested mountpoint below {}: {}",
            src_var.display(),
            mountpoint.display()
        );
        nested.insert(relative.to_path_buf());
    }
    Ok(nested)
}

/// The mountpoint is the fifth space-separated field of a mountinfo record
/// (see proc_pid_mountinfo(5)).
const MOUNTINFO_MOUNTPOINT_FIELD: usize = 4;

/// Extract the mountpoints from the byte-oriented Linux mountinfo format
/// without requiring UTF-8.
///
/// Only the mountpoint is used, so the other fields are not validated: the
/// snapshot covers the whole installer mount namespace, and a record this code
/// has no interest in (e.g. a mount with an empty source, which the kernel
/// prints as two consecutive spaces) must not fail the migration. The fields
/// before the mountpoint are never empty, so splitting on single spaces finds
/// it reliably.
fn parse_mountinfo(data: &[u8]) -> Result<Vec<PathBuf>> {
    let mountpoints = data
        .split(|byte| *byte == b'\n')
        .enumerate()
        .filter(|(_, line)| !line.is_empty())
        .map(|(index, line)| {
            let field = line
                .split(|byte| *byte == b' ')
                .nth(MOUNTINFO_MOUNTPOINT_FIELD)
                .with_context(|| {
                    format!("Malformed mountinfo line {}: no mountpoint", index + 1)
                })?;
            Ok(PathBuf::from(std::ffi::OsString::from_vec(
                decode_mountinfo_escapes(field),
            )))
        })
        .collect::<Result<Vec<_>>>()?;
    anyhow::ensure!(!mountpoints.is_empty(), "Mountinfo contained no records");
    Ok(mountpoints)
}

/// Decode the kernel's `\ooo` octal escapes (it escapes space, tab, newline
/// and backslash). Anything else is kept as is.
fn decode_mountinfo_escapes(value: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut rest = value;
    while let Some((&byte, tail)) = rest.split_first() {
        let escaped = (byte == b'\\')
            .then(|| tail.get(..3))
            .flatten()
            .filter(|digits| digits.iter().all(|digit| (b'0'..=b'7').contains(digit)))
            .and_then(|digits| {
                let value = digits
                    .iter()
                    .fold(0u16, |acc, digit| acc * 8 + u16::from(digit - b'0'));
                u8::try_from(value).ok()
            });
        match escaped {
            Some(escaped) => {
                decoded.push(escaped);
                rest = &tail[3..];
            }
            None => {
                decoded.push(byte);
                rest = tail;
            }
        }
    }
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::ffi::OsStrExt};

    #[test]
    fn mountinfo_decodes_escaped_and_non_utf8_paths() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_var = temp.path().join("var");
        fs::create_dir(&src_var)?;
        let source = src_var.as_os_str().as_bytes();
        let mut mountinfo = format!(
            "36 0 0:32 / {0} rw,relatime - tmpfs tmpfs rw\n37 25 0:33 / {0}/rpc\\040pipefs rw - nfs nfs rw\n",
            src_var.display()
        )
        .into_bytes();
        mountinfo.extend_from_slice(b"38 25 0:34 / ");
        mountinfo.extend_from_slice(source);
        mountinfo.extend_from_slice(b"/\xffstate rw - tmpfs tmpfs rw\n");
        let parsed = parse_mountinfo(&mountinfo)?;
        let escaped_name = src_var.join("rpc pipefs");
        assert_eq!(parsed[1], escaped_name);
        let mut non_utf8 = source.to_vec();
        non_utf8.extend_from_slice(b"/\xffstate");
        assert_eq!(parsed[2].as_os_str().as_bytes(), non_utf8);

        let nested = nested_mountpoints(&src_var, parsed)?;
        assert_eq!(
            nested,
            BTreeSet::from([
                PathBuf::from("rpc pipefs"),
                PathBuf::from(std::ffi::OsStr::from_bytes(b"\xffstate"))
            ])
        );
        Ok(())
    }

    #[test]
    fn unrelated_mount_records_do_not_change_nested_mount_selection() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let src_var = temp.path().join("target/var");
        fs::create_dir_all(&src_var)?;
        let base = format!(
            "36 0 0:32 / {0} rw - tmpfs tmpfs rw\n37 25 0:33 / {0}/lib/data rw - nfs nfs rw\n",
            src_var.display()
        );
        let with_unrelated = format!(
            "21 0 0:21 / / rw - overlay overlay rw\n{base}38 25 0:34 / /unrelated rw - tmpfs tmpfs rw\n"
        );

        let selected = |mountinfo: &str| -> Result<BTreeSet<PathBuf>> {
            nested_mountpoints(&src_var, parse_mountinfo(mountinfo.as_bytes())?)
        };
        assert_eq!(
            selected(&base)?,
            BTreeSet::from([PathBuf::from("lib/data")])
        );
        assert_eq!(selected(&with_unrelated)?, selected(&base)?);
        Ok(())
    }

    #[test]
    fn mountinfo_allows_relative_and_noncanonical_roots_with_valid_nested_mountpoints() -> Result<()>
    {
        let temp = tempfile::tempdir()?;
        let src_var = temp.path().join("target/var");
        fs::create_dir_all(&src_var)?;

        for root in ["/some/../root", "relative/root"] {
            let mountinfo = format!(
                "36 0 0:32 / {0} rw - tmpfs tmpfs rw\n37 25 0:33 {1} {0}/lib/data rw - nfs nfs rw\n",
                src_var.display(),
                root
            );

            assert_eq!(
                nested_mountpoints(&src_var, parse_mountinfo(mountinfo.as_bytes())?)?,
                BTreeSet::from([PathBuf::from("lib/data")]),
                "root field {root:?} should not affect mountpoint selection"
            );
        }
        Ok(())
    }

    #[test]
    fn mountinfo_accepts_records_it_does_not_use() -> Result<()> {
        // Real records from a 6.12 kernel and podman: a tmpfs mounted with an
        // empty source (two spaces before the options), optional fields, and
        // escapes in fields other than the mountpoint.
        let mountinfo = concat!(
            "21 1 0:21 / / rw - overlay overlay rw\n",
            "36 21 0:32 / /target/var rw shared:1 master:2 - xfs /dev/vda3 rw\n",
            "37 36 0:33 / /target/var/lib/empty-src rw,relatime shared:3 - tmpfs  rw,inode64\n",
            "38 21 0:34 /some\\134dir /unrelated\\040dir rw - fuse.x a\\040b rw\n",
            "39 36 0:35 / /target/var/odd\\9name rw - tmpfs tmpfs rw\n",
            "40 36 0:36 / /target/var/gone\\040(deleted) rw - tmpfs tmpfs rw\n",
        );
        let parsed = parse_mountinfo(mountinfo.as_bytes())?;
        assert_eq!(parsed[3], PathBuf::from("/unrelated dir"));
        assert_eq!(
            nested_mountpoints(Path::new("/target/var"), parsed)?,
            BTreeSet::from([
                PathBuf::from("lib/empty-src"),
                PathBuf::from("odd\\9name"),
                PathBuf::from("gone (deleted)"),
            ])
        );
        Ok(())
    }

    #[test]
    fn mountinfo_rejects_records_without_a_mountpoint() {
        for mountinfo in [b"".as_slice(), b"\n", b"36 25 0:32 /\n"] {
            assert!(
                parse_mountinfo(mountinfo).is_err(),
                "accepted {mountinfo:?}"
            );
        }
    }

    #[test]
    fn nested_mountpoint_detection_is_component_safe() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir()?;
        let src_var = temp.path().join("target/var");
        fs::create_dir_all(&src_var)?;
        let alias = temp.path().join("var-alias");
        symlink(&src_var, &alias)?;
        let paths = [
            src_var.clone(),
            src_var.join("lib/data"),
            temp.path().join("target/var-old/other"),
            PathBuf::from("/elsewhere/var/mount"),
        ];
        let canonical_src_var = fs::canonicalize(&alias)?;
        assert_eq!(
            nested_mountpoints(&canonical_src_var, paths)?,
            BTreeSet::from([PathBuf::from("lib/data")])
        );
        Ok(())
    }
}
