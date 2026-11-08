//! Boot entry checks for `bootc internals fsck` on composefs systems.
//!
//! A boot entry whose composefs argument is strict (no `?`) only boots if
//! the EROFS image it names has fs-verity: the initramfs enforces that (see
//! <https://github.com/bootc-dev/bootc/pull/2629>). bootc 1.16.0 through
//! 1.16.14 nevertheless wrote strict entries when installing with
//! `install to-filesystem` or `to-existing-root` onto a filesystem without
//! fs-verity, such as ext4 created without `-O verity`. Those entries, and
//! the ones later upgrades copy the policy to, fail to boot once the
//! initramfs enforces fs-verity.
//!
//! This module finds them, reading each entry's command line the way the
//! initramfs does, and can add `?` to the BLS ones.

use std::os::fd::AsFd;

use anyhow::{Context, Result};
use bootc_initramfs_setup::{
    composefs_candidates_policy, parse_composefs_candidates, select_composefs_candidate,
};
use bootc_mount::tempmount::TempMount;
use camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::cap_std::ambient_authority;
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt;
use composefs::fsverity::{
    CompareVerityError, FsVerityHashValue, MeasureVerityError, Sha512HashValue,
};
use composefs::repository::{ImageNotFound, IntegrityPolicy, VerityState};
use composefs_boot::cmdline::{KARG_COMPOSEFS_DIGEST, KARG_V2};
use composefs_ctl::{composefs, composefs_boot};
use fn_error_context::context;
use linux_kernel_cmdline::utf8::{Cmdline, Parameter};

use crate::bootc_composefs::boot::{BOOTC_UKI_DIR, mount_esp_readonly, mount_esp_writable};
use crate::composefs_consts::{TYPE1_ENT_PATH, TYPE1_ENT_PATH_STAGED};
use crate::store::{COMPOSEFS, ComposefsRepository, Storage, find_booted_from_esp};

/// The BLS key holding the kernel command line.
const BLS_OPTIONS_KEY: &str = "options";

/// What opening a candidate's image found, as the initramfs would with a
/// strict command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ImageState {
    /// The image has fs-verity, with the expected digest.
    Verified,
    /// The filesystem holding the image doesn't support fs-verity.
    FilesystemNotSupported,
    /// The filesystem supports fs-verity, but the image doesn't have it.
    VerityMissing,
    /// Anything else, such as a digest mismatch.
    Failed(String),
}

/// How the initramfs would treat a command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// No composefs argument, so not a composefs boot entry.
    NotComposefs,
    /// The arguments have `?`, so fs-verity is optional.
    Relaxed,
    /// Strict, and the image the initramfs picks has fs-verity.
    Verified,
    /// Strict, but the image the initramfs picks has no fs-verity, so the
    /// entry fails to boot.
    StrictWithoutFsverity {
        /// The image's digest
        image: String,
        /// Whether the filesystem supports fs-verity at all
        filesystem_supports_fsverity: bool,
    },
    /// None of the candidates' images exist.
    NoImage(String),
    /// The initramfs would refuse the entry for another reason, e.g.
    /// arguments with mixed policies or a digest mismatch.
    Unbootable(String),
}

/// Classify a command line the way the initramfs's `setup_root` reads it:
/// the candidates in order, the first whose image exists wins. `open`
/// returns `None` for a digest without an image.
pub(crate) fn classify_cmdline(
    cmdline: &str,
    mut open: impl FnMut(&Sha512HashValue) -> Option<ImageState>,
) -> Verdict {
    let candidates = match parse_composefs_candidates(cmdline) {
        Ok(c) if c.is_empty() => return Verdict::NotComposefs,
        Ok(c) => c,
        Err(e) => return Verdict::Unbootable(format!("{e:#}")),
    };
    match composefs_candidates_policy(&candidates) {
        Ok(true) => return Verdict::Relaxed,
        Ok(false) => {}
        Err(e) => return Verdict::Unbootable(format!("{e:#}")),
    }
    let (state, candidate) =
        match select_composefs_candidate(&candidates, |candidate| Ok(open(candidate.digest()))) {
            Ok(r) => r,
            Err(e) => return Verdict::NoImage(format!("{e:#}")),
        };
    let image = candidate.digest().to_hex();
    match state {
        ImageState::Verified => Verdict::Verified,
        ImageState::FilesystemNotSupported => Verdict::StrictWithoutFsverity {
            image,
            filesystem_supports_fsverity: false,
        },
        ImageState::VerityMissing => Verdict::StrictWithoutFsverity {
            image,
            filesystem_supports_fsverity: true,
        },
        ImageState::Failed(e) => Verdict::Unbootable(format!("image {image}: {e}")),
    }
}

/// Open the composefs repository requiring fs-verity, as the initramfs does
/// for a strict command line. Returns it and whether `meta.json` has
/// fs-verity.
#[context("Opening composefs repository")]
fn open_strict_repo(physical_root: &Dir) -> Result<(ComposefsRepository, bool)> {
    let mut repo = ComposefsRepository::open_path(physical_root, COMPOSEFS)?;
    // Until a policy is set, it's the one detected from meta.json.
    let meta_json_has_fsverity = !repo.is_insecure();
    repo.set_integrity_policy(IntegrityPolicy::Explicit(VerityState::Enabled))?;
    Ok((repo, meta_json_has_fsverity))
}

/// Open the image named by `digest` like the initramfs does.
fn open_image(repo: &ComposefsRepository, digest: &Sha512HashValue) -> Option<ImageState> {
    let e = match repo.open_digest(digest) {
        Ok(_) => return Some(ImageState::Verified),
        Err(e) => e,
    };
    if e.downcast_ref::<ImageNotFound>().is_some() {
        return None;
    }
    let state = match e.downcast_ref::<CompareVerityError>() {
        Some(CompareVerityError::Measure(MeasureVerityError::FilesystemNotSupported)) => {
            ImageState::FilesystemNotSupported
        }
        Some(CompareVerityError::Measure(MeasureVerityError::VerityMissing)) => {
            ImageState::VerityMissing
        }
        _ => ImageState::Failed(format!("{e:#}")),
    };
    Some(state)
}

/// A directory that may hold boot entries: the ESP or a boot directory.
#[derive(Debug)]
pub(crate) struct BootDir {
    /// Where it is, for messages
    pub(crate) label: String,
    pub(crate) dir: Dir,
}

/// Drop boot directories that are the same directory as an earlier one,
/// e.g. the ESP mounted on `/boot`.
fn dedup_boot_dirs(dirs: Vec<BootDir>) -> Result<Vec<BootDir>> {
    let mut seen = Vec::new();
    let mut r = Vec::new();
    for d in dirs {
        let st =
            rustix::fs::fstat(d.dir.as_fd()).with_context(|| format!("Querying {}", d.label))?;
        let id = (st.st_dev, st.st_ino);
        if !seen.contains(&id) {
            seen.push(id);
            r.push(d);
        }
    }
    Ok(r)
}

/// The kind of boot entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryKind {
    /// A BLS (Type #1) entry with an `options` line
    Bls,
    /// A UKI, whose command line is embedded
    Uki,
}

/// A boot entry's command line.
#[derive(Debug)]
pub(crate) struct BootEntry {
    pub(crate) kind: EntryKind,
    /// The entry's path in its boot directory
    pub(crate) path: Utf8PathBuf,
    pub(crate) cmdline: String,
}

/// The kernel command line of a BLS entry: its `options` lines, joined as
/// the Boot Loader Specification says. `parsers::bls_config` isn't used
/// because it rejects entries bootc didn't write and keeps only the last
/// `options` line.
fn bls_options(contents: &str) -> Option<String> {
    let options = contents
        .lines()
        .filter_map(|line| {
            let (key, value) = line.trim().split_once(char::is_whitespace)?;
            (key == BLS_OPTIONS_KEY).then(|| value.trim())
        })
        .collect::<Vec<_>>();
    (!options.is_empty()).then(|| options.join(" "))
}

/// List the BLS entries in `entries/` and `entries.staged/`, and the
/// command lines of bootc's UKIs, in a boot directory.
#[context("Listing boot entries")]
pub(crate) fn list_boot_entries(boot: &Dir) -> Result<Vec<BootEntry>> {
    let mut r = Vec::new();
    for entries in [TYPE1_ENT_PATH, TYPE1_ENT_PATH_STAGED] {
        let Some(dir) = boot.open_dir_optional(entries)? else {
            continue;
        };
        for ent in dir.entries_utf8()? {
            let ent = ent?;
            let name = ent.file_name()?;
            if !name.ends_with(".conf") || !ent.file_type()?.is_file() {
                continue;
            }
            let contents = dir
                .read_to_string(&name)
                .with_context(|| format!("Reading {entries}/{name}"))?;
            if let Some(cmdline) = bls_options(&contents) {
                r.push(BootEntry {
                    kind: EntryKind::Bls,
                    path: Utf8Path::new(entries).join(name),
                    cmdline,
                });
            }
        }
    }
    if let Some(dir) = boot.open_dir_optional(BOOTC_UKI_DIR)? {
        for ent in dir.entries_utf8()? {
            let ent = ent?;
            let name = ent.file_name()?;
            if !name.ends_with(".efi") || !ent.file_type()?.is_file() {
                continue;
            }
            let mut uki = dir
                .open(&name)
                .with_context(|| format!("Opening {BOOTC_UKI_DIR}/{name}"))?;
            let cmdline = match composefs_boot::uki::get_cmdline_buffered(&mut uki) {
                Ok(c) => c,
                // The command line then comes from the boot loader
                Err(composefs_boot::uki::UkiError::MissingSection(_)) => continue,
                Err(e) => {
                    return Err(e).with_context(|| format!("Reading {BOOTC_UKI_DIR}/{name}"));
                }
            };
            r.push(BootEntry {
                kind: EntryKind::Uki,
                path: Utf8Path::new(BOOTC_UKI_DIR).join(name),
                cmdline,
            });
        }
    }
    r.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(r)
}

/// A boot entry and how it would boot.
#[derive(Debug)]
pub(crate) struct EntryReport {
    pub(crate) kind: EntryKind,
    /// The entry's path, prefixed with its boot directory's label
    pub(crate) path: String,
    pub(crate) verdict: Verdict,
}

/// The result of checking a system's boot entries.
#[derive(Debug)]
pub(crate) struct BootPolicyReport {
    pub(crate) entries: Vec<EntryReport>,
    /// The boot directories searched
    pub(crate) searched: Vec<String>,
    /// Whether `composefs/meta.json` has fs-verity
    pub(crate) meta_json_has_fsverity: bool,
}

/// Check every composefs boot entry in `boot_dirs` against the composefs
/// repository in `physical_root`.
#[context("Checking composefs boot entries")]
pub(crate) fn check_boot_entries(
    physical_root: &Dir,
    boot_dirs: &[BootDir],
) -> Result<BootPolicyReport> {
    let (repo, meta_json_has_fsverity) = open_strict_repo(physical_root)?;
    let mut entries = Vec::new();
    for boot in boot_dirs {
        for entry in list_boot_entries(&boot.dir)? {
            let verdict = classify_cmdline(&entry.cmdline, |digest| open_image(&repo, digest));
            if verdict == Verdict::NotComposefs {
                continue;
            }
            entries.push(EntryReport {
                kind: entry.kind,
                path: format!("{}/{}", boot.label, entry.path),
                verdict,
            });
        }
    }
    Ok(BootPolicyReport {
        entries,
        searched: boot_dirs.iter().map(|b| b.label.clone()).collect(),
        meta_json_has_fsverity,
    })
}

/// Add `?` to every strict composefs argument of a kernel command line.
fn relax_cmdline(cmdline: &str) -> String {
    Cmdline::from(cmdline)
        .iter_str()
        .map(|param| {
            let Some(p) = Parameter::parse(param) else {
                return param.to_owned();
            };
            let key = p.key();
            match p.value() {
                Some(value)
                    if (&*key == KARG_V2 || &*key == KARG_COMPOSEFS_DIGEST)
                        && !value.starts_with('?') =>
                {
                    format!("{}=?{value}", &*key)
                }
                _ => param.to_owned(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Split `s` before its first character matching `f`, or at its end.
fn split_at_first(s: &str, f: impl Fn(char) -> bool) -> (&str, &str) {
    s.find(f).map_or((s, ""), |i| s.split_at(i))
}

/// Add `?` to the composefs arguments on the `options` lines of a BLS entry,
/// leaving every other line as it is. Returns `None` if nothing changed.
pub(crate) fn relax_bls_entry(contents: &str) -> Option<String> {
    let mut changed = false;
    let r = contents
        .split_inclusive('\n')
        .map(|line| {
            let (body, ending) = split_at_first(line, |c| c == '\r' || c == '\n');
            let (indent, body) = split_at_first(body, |c| !c.is_whitespace());
            let Some(rest) = body.strip_prefix(BLS_OPTIONS_KEY) else {
                return line.to_owned();
            };
            let (separator, value) = split_at_first(rest, |c| !c.is_whitespace());
            if separator.is_empty() {
                // A longer key, such as "optionsfoo"
                return line.to_owned();
            }
            let value = value.trim_end();
            let relaxed = relax_cmdline(value);
            if relaxed == value {
                return line.to_owned();
            }
            changed = true;
            format!("{indent}{BLS_OPTIONS_KEY}{separator}{relaxed}{ending}")
        })
        .collect::<String>();
    changed.then_some(r)
}

/// Add `?` to the BLS entries that `classify` finds strict without
/// fs-verity on a filesystem that can't do fs-verity, writing each to a
/// temporary file and renaming it over the entry. Returns the paths of the
/// changed entries.
fn repair_bls_entries_with(
    boot_dirs: &[BootDir],
    mut classify: impl FnMut(&str) -> Verdict,
) -> Result<Vec<String>> {
    let mut repaired = Vec::new();
    for boot in boot_dirs {
        for entry in list_boot_entries(&boot.dir)? {
            if entry.kind != EntryKind::Bls {
                continue;
            }
            let fixable = matches!(
                classify(&entry.cmdline),
                Verdict::StrictWithoutFsverity {
                    filesystem_supports_fsverity: false,
                    ..
                }
            );
            if !fixable {
                continue;
            }
            let path = format!("{}/{}", boot.label, entry.path);
            let write = || -> Result<bool> {
                let contents = boot.dir.read_to_string(&entry.path)?;
                let Some(relaxed) = relax_bls_entry(&contents) else {
                    return Ok(false);
                };
                let perms = boot.dir.metadata(&entry.path)?.permissions();
                boot.dir
                    .atomic_write_with_perms(&entry.path, relaxed, perms)?;
                Ok(true)
            };
            match write() {
                Ok(true) => repaired.push(path),
                Ok(false) => {}
                Err(e) => {
                    let done = if repaired.is_empty() {
                        "none".to_owned()
                    } else {
                        repaired.join(", ")
                    };
                    return Err(e.context(format!("Rewriting {path} (already rewritten: {done})")));
                }
            }
        }
    }
    Ok(repaired)
}

/// Add `?` to the BLS entries that are strict, but whose image lacks
/// fs-verity because the filesystem doesn't support it. Returns the paths
/// of the changed entries.
#[context("Adding '?' to boot entries")]
pub(crate) fn repair_bls_entries(
    physical_root: &Dir,
    boot_dirs: &[BootDir],
) -> Result<Vec<String>> {
    let (repo, _) = open_strict_repo(physical_root)?;
    repair_bls_entries_with(boot_dirs, |cmdline| {
        classify_cmdline(cmdline, |digest| open_image(&repo, digest))
    })
}

/// The boot directories of a booted composefs system: the ESP, and the GRUB
/// boot directory if that's elsewhere.
pub(crate) fn boot_dirs_from_storage(storage: &Storage) -> Result<Vec<BootDir>> {
    let mut dirs = Vec::new();
    if let Some(esp) = &storage.esp {
        dirs.push(BootDir {
            label: "ESP".into(),
            dir: esp.fd.try_clone()?,
        });
    }
    if let Some(boot) = &storage.boot_dir {
        let label = storage
            .require_grub_boot_path()
            .map(|p| p.to_string())
            .unwrap_or_else(|_| "boot".into());
        dirs.push(BootDir {
            label,
            dir: boot.try_clone()?,
        });
    }
    dedup_boot_dirs(dirs)
}

/// The filesystem type of the topmost mount on the mountpoint `path`.
fn topmost_fstype(path: &str) -> Result<Option<String>> {
    let mounts = bootc_mount::run_findmnt(&["--mountpoint"], None, Some(path))?;
    // A mount stacked on another one shows up as its child
    let mut top = mounts.filesystems.into_iter().last();
    while let Some(child) = top
        .as_mut()
        .and_then(|m| m.children.take())
        .and_then(|c| c.into_iter().filter(|c| c.target == path).last())
    {
        top = Some(child);
    }
    Ok(top.map(|m| m.fstype))
}

/// The physical root and boot directories of a host whose root filesystem
/// is at `target`, for running from a container like
/// `install to-existing-root` does.
pub(crate) struct HostLayout {
    pub(crate) physical_root: Dir,
    pub(crate) boot_dirs: Vec<BootDir>,
    /// Keeps the ESP mounted
    _esp: Option<TempMount>,
}

impl HostLayout {
    /// Open the host's layout under `target`, writable if `writable`.
    #[context("Opening the host's boot directories under {target}")]
    pub(crate) fn open(target: &Utf8Path, writable: bool) -> Result<Self> {
        use crate::utils::open_dir_remount_rw;

        let root = Dir::open_ambient_dir(target, ambient_authority())
            .with_context(|| format!("Opening {target}; run the container with -v /:{target}"))?;
        let open = |dir: &Dir, path: &str| -> Result<Dir> {
            if writable {
                open_dir_remount_rw(dir, path.into())
            } else {
                dir.open_dir(path)
                    .with_context(|| format!("Opening {path}"))
            }
        };
        let physical_root = open(&root, crate::store::SYSROOT)?;

        let mut dirs = Vec::new();
        let mut esp = None;
        if std::path::Path::new("/sys/firmware/efi").try_exists()? {
            crate::install::setup_sys_mount("efivarfs", crate::install::EFIVARFS)?;
            // lsblk needs the host's udev database to find the ESP's partition UUID
            bootc_mount::ensure_mirrored_host_mount("/run/udev")?;
            let device = find_booted_from_esp(&physical_root)?;
            let mount = if writable {
                mount_esp_writable(&device)?
            } else {
                mount_esp_readonly(&device)?
            };
            dirs.push(BootDir {
                label: format!("ESP ({device})"),
                dir: mount.fd.try_clone()?,
            });
            esp = Some(mount);
        }
        // A separate boot partition, or the ESP mounted on /boot. Skip an
        // automount that wasn't triggered (systemd-gpt-auto's for the ESP,
        // typically): it can't be triggered from here, and the ESP was
        // mounted above.
        let boot_path = format!("{target}/{}", crate::install::BOOT);
        if root.is_mountpoint(crate::install::BOOT)? == Some(true)
            && topmost_fstype(&boot_path)?.as_deref() != Some("autofs")
        {
            dirs.push(BootDir {
                label: boot_path,
                dir: open(&root, crate::install::BOOT)?,
            });
        }
        if let Some(dir) = physical_root.open_dir_optional(crate::install::BOOT)? {
            dirs.push(BootDir {
                label: format!(
                    "{target}/{}/{}",
                    crate::store::SYSROOT,
                    crate::install::BOOT
                ),
                dir,
            });
        }
        Ok(Self {
            physical_root,
            boot_dirs: dedup_boot_dirs(dirs)?,
            _esp: esp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::{cap_std, cap_tempfile};
    use composefs_boot::cmdline::ComposefsCmdline;

    fn digest(byte: u8) -> Sha512HashValue {
        Sha512HashValue::from_hex(format!("{byte:02x}").repeat(64)).unwrap()
    }

    fn v1(byte: u8, insecure: bool) -> String {
        ComposefsCmdline::new_v1(digest(byte), insecure).to_cmdline_arg()
    }

    fn v2(byte: u8, insecure: bool) -> String {
        ComposefsCmdline::new_v2(digest(byte), insecure).to_cmdline_arg()
    }

    fn without_fsverity(byte: u8, filesystem_supports_fsverity: bool) -> Verdict {
        Verdict::StrictWithoutFsverity {
            image: digest(byte).to_hex(),
            filesystem_supports_fsverity,
        }
    }

    /// The C5 matrix: command line, the images that exist and their state,
    /// and the verdict.
    #[test]
    fn test_classify_cmdline() {
        use ImageState::*;
        let no_fs_verity = FilesystemNotSupported;
        let cases: Vec<(&str, String, Vec<(u8, ImageState)>, Verdict)> = vec![
            (
                "not composefs",
                "root=UUID=abc rw".into(),
                vec![],
                Verdict::NotComposefs,
            ),
            (
                "relaxed v2",
                v2(1, true),
                vec![(1, no_fs_verity.clone())],
                Verdict::Relaxed,
            ),
            (
                "relaxed v1, no image",
                v1(1, true),
                vec![],
                Verdict::Relaxed,
            ),
            (
                "strict, verified",
                v2(1, false),
                vec![(1, Verified)],
                Verdict::Verified,
            ),
            (
                "strict on a filesystem without fs-verity",
                format!("root=UUID=abc rw {}", v2(1, false)),
                vec![(1, no_fs_verity.clone())],
                without_fsverity(1, false),
            ),
            (
                "strict, filesystem has fs-verity but the image doesn't",
                v1(1, false),
                vec![(1, VerityMissing)],
                without_fsverity(1, true),
            ),
            (
                "1.16.0 dual argument, only the composefs= image exists",
                format!("{} {}", v1(1, false), v2(2, false)),
                vec![(2, no_fs_verity.clone())],
                without_fsverity(2, false),
            ),
            (
                "dual argument, only the composefs= image exists, verified",
                format!("{} {}", v1(1, false), v2(2, false)),
                vec![(2, Verified)],
                Verdict::Verified,
            ),
            (
                "dual argument, the first existing image wins",
                format!("{} {}", v1(1, false), v2(2, false)),
                vec![(1, no_fs_verity.clone()), (2, Verified)],
                without_fsverity(1, false),
            ),
            (
                "dual argument, both relaxed",
                format!("{} {}", v1(1, true), v2(2, true)),
                vec![(2, no_fs_verity.clone())],
                Verdict::Relaxed,
            ),
            (
                "mixed policy",
                format!("{} {}", v1(1, false), v2(2, true)),
                vec![(1, Verified)],
                Verdict::Unbootable("composefs candidates have mixed fs-verity policy".into()),
            ),
            (
                "digest mismatch",
                v2(1, false),
                vec![(1, Failed("mismatch".into()))],
                Verdict::Unbootable(format!("image {}: mismatch", digest(1).to_hex())),
            ),
        ];
        for (name, cmdline, images, expected) in cases {
            let verdict = classify_cmdline(&cmdline, |d| {
                images
                    .iter()
                    .find(|(b, _)| digest(*b) == *d)
                    .map(|(_, state)| state.clone())
            });
            assert_eq!(verdict, expected, "case {name}");
        }

        // These depend on the error text, so only check the variant
        let verdict = classify_cmdline(&v2(1, false), |_| None);
        assert!(matches!(verdict, Verdict::NoImage(_)), "{verdict:?}");
        let verdict = classify_cmdline("composefs=nothex", |_| None);
        assert!(matches!(verdict, Verdict::Unbootable(_)), "{verdict:?}");
    }

    #[test]
    fn test_bls_options() {
        let cases = [
            ("title x\nlinux /vmlinuz\n", None),
            ("options a=b c\n", Some("a=b c")),
            ("  options\ta=b  \n", Some("a=b")),
            ("options a\noptions b\n", Some("a b")),
            ("optionsx a\n", None),
        ];
        for (contents, expected) in cases {
            assert_eq!(bls_options(contents).as_deref(), expected, "{contents:?}");
        }
    }

    #[test]
    fn test_relax_bls_entry() {
        let strict2 = v2(1, false);
        let relaxed2 = v2(1, true);
        let strict1 = v1(2, false);
        let relaxed1 = v1(2, true);
        let cases = [
            (
                "v2",
                format!("title t\nversion 1\noptions root=UUID=abc rw {strict2}\nlinux /l\n"),
                Some(format!(
                    "title t\nversion 1\noptions root=UUID=abc rw {relaxed2}\nlinux /l\n"
                )),
            ),
            (
                "dual, no trailing newline",
                format!("options {strict1} {strict2} quiet"),
                Some(format!("options {relaxed1} {relaxed2} quiet")),
            ),
            ("already relaxed", format!("options {relaxed2}\n"), None),
            ("not composefs", "options root=UUID=abc rw\n".into(), None),
            (
                "keeps the separator, CRLF",
                format!("options\t{strict2}\r\n"),
                Some(format!("options\t{relaxed2}\r\n")),
            ),
            (
                "only options lines",
                format!("title {strict2}\noptions {strict2}\n"),
                Some(format!("title {strict2}\noptions {relaxed2}\n")),
            ),
        ];
        for (name, contents, expected) in cases {
            assert_eq!(relax_bls_entry(&contents), expected, "case {name}");
        }
    }

    #[test]
    fn test_repair_bls_entries() -> Result<()> {
        let td = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        td.create_dir_all(TYPE1_ENT_PATH)?;
        td.create_dir_all(TYPE1_ENT_PATH_STAGED)?;
        td.create_dir_all(BOOTC_UKI_DIR)?;
        // The test's verdicts go by the digest
        let unsupported = v2(1, false);
        let missing = v2(2, false);
        let verified = v2(3, false);
        let entry = |karg: &str| format!("title t\nversion 1\nlinux /l\noptions rw {karg}\n");
        let files = [
            (format!("{TYPE1_ENT_PATH}/a.conf"), entry(&unsupported)),
            (format!("{TYPE1_ENT_PATH}/b.conf"), entry(&missing)),
            (format!("{TYPE1_ENT_PATH}/c.conf"), entry(&verified)),
            (
                format!("{TYPE1_ENT_PATH_STAGED}/d.conf"),
                entry(&unsupported),
            ),
            // Not an entry
            (format!("{TYPE1_ENT_PATH}/e.txt"), entry(&unsupported)),
        ];
        for (path, contents) in &files {
            td.write(path, contents)?;
        }
        let boot_dirs = [BootDir {
            label: "boot".into(),
            dir: td.try_clone()?,
        }];
        let classify = |cmdline: &str| {
            classify_cmdline(cmdline, |d| {
                Some(match d {
                    d if *d == digest(1) => ImageState::FilesystemNotSupported,
                    d if *d == digest(2) => ImageState::VerityMissing,
                    _ => ImageState::Verified,
                })
            })
        };
        let repaired = repair_bls_entries_with(&boot_dirs, classify)?;
        assert_eq!(
            repaired,
            [
                format!("boot/{TYPE1_ENT_PATH}/a.conf"),
                format!("boot/{TYPE1_ENT_PATH_STAGED}/d.conf"),
            ]
        );
        let relaxed = entry(&v2(1, true));
        for (path, contents) in &files {
            let expected = if path.ends_with("a.conf") || path.ends_with("d.conf") {
                &relaxed
            } else {
                contents
            };
            assert_eq!(&td.read_to_string(path)?, expected, "{path}");
        }
        // A second run has nothing left to do
        assert!(repair_bls_entries_with(&boot_dirs, classify)?.is_empty());
        Ok(())
    }

    /// Check entries against a real repository, so that a change in how
    /// composefs-rs reports a missing image or missing fs-verity shows up.
    #[test]
    fn test_check_boot_entries() -> Result<()> {
        use composefs::fsverity::{Algorithm, compute_verity};
        use composefs::repository::RepositoryConfig;

        let td = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        let config = RepositoryConfig::new(Algorithm::SHA512).set_insecure();
        drop(ComposefsRepository::init_path(&*td, COMPOSEFS, config)?);
        td.create_dir_all(format!("{COMPOSEFS}/images"))?;
        let data = b"image without fs-verity";
        let present = compute_verity::<Sha512HashValue>(data);
        td.write(format!("{COMPOSEFS}/images/{}", present.to_hex()), data)?;
        let karg = |digest: &Sha512HashValue, insecure| {
            ComposefsCmdline::new_v2(digest.clone(), insecure).to_cmdline_arg()
        };
        let strict = karg(&present, false);
        let entries = [
            ("a", strict.clone()),
            ("b", karg(&present, true)),
            ("c", karg(&digest(9), false)),
            // 1.16.0's dual argument: only the composefs= image exists
            ("d", format!("{} {strict}", v1(9, false))),
            ("e", "root=UUID=abc rw".into()),
        ];
        td.create_dir_all(format!("boot/{TYPE1_ENT_PATH}"))?;
        for (name, options) in &entries {
            td.write(
                format!("boot/{TYPE1_ENT_PATH}/{name}.conf"),
                format!("title t\noptions {options}\n"),
            )?;
        }
        let boot_dirs = [BootDir {
            label: "boot".into(),
            dir: td.open_dir("boot")?,
        }];
        let report = check_boot_entries(&td, &boot_dirs)?;
        assert!(!report.meta_json_has_fsverity);
        assert_eq!(report.searched, ["boot"]);
        let verdicts = report
            .entries
            .iter()
            .map(|e| (e.path.as_str(), &e.verdict))
            .collect::<Vec<_>>();
        let path = |name| format!("boot/{TYPE1_ENT_PATH}/{name}.conf");
        // Whether the filesystem supports fs-verity depends on where the
        // temporary directory is.
        let without = |v: &Verdict| matches!(v, Verdict::StrictWithoutFsverity { image, .. } if *image == present.to_hex());
        assert_eq!(verdicts.len(), 4, "{verdicts:?}");
        assert_eq!(verdicts[0].0, path("a"));
        assert!(without(verdicts[0].1), "{verdicts:?}");
        assert_eq!(verdicts[1], (path("b").as_str(), &Verdict::Relaxed));
        assert_eq!(verdicts[2].0, path("c"));
        assert!(matches!(verdicts[2].1, Verdict::NoImage(_)), "{verdicts:?}");
        assert_eq!(verdicts[3].0, path("d"));
        assert!(without(verdicts[3].1), "{verdicts:?}");
        Ok(())
    }

    #[test]
    fn test_list_boot_entries() -> Result<()> {
        let td = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        // Nothing there at all
        assert!(list_boot_entries(&td)?.is_empty());
        td.create_dir_all(TYPE1_ENT_PATH)?;
        td.create_dir_all(BOOTC_UKI_DIR)?;
        td.write(format!("{TYPE1_ENT_PATH}/a.conf"), "options rw\n")?;
        td.write(format!("{TYPE1_ENT_PATH}/uki.conf"), "efi /EFI/x.efi\n")?;
        // Not a UKI, so reading it fails
        td.write(format!("{BOOTC_UKI_DIR}/x.efi"), "not a PE file")?;
        assert!(list_boot_entries(&td).is_err());
        td.remove_file(format!("{BOOTC_UKI_DIR}/x.efi"))?;
        let entries = list_boot_entries(&td)?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, EntryKind::Bls);
        assert_eq!(entries[0].path, format!("{TYPE1_ENT_PATH}/a.conf"));
        assert_eq!(entries[0].cmdline, "rw");
        Ok(())
    }
}
