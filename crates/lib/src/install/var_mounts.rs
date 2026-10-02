//! Initialize caller-mounted /var filesystems from the installed deployment.

use std::cell::Cell;
use std::process::Command;

use anyhow::{Context, Result, bail};
use bootc_mount::Filesystem;
use bootc_utils::CommandRunExt;
use camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::{cap_std::fs::Dir, cmdext::CapStdExtCommandExt, dirext::CapStdExtDirExt};
use rustix::fs::{Mode, OFlags};

use super::{LOST_AND_FOUND, MountSpec};

/// Advertised by `bootc --version`, so that tools preparing a target for
/// `install to-filesystem` know that /var filesystems are initialized.
/// Older versions leave such filesystems empty, or reject them entirely.
pub(super) const FEATURE: &str = "install-var-mount";

const VAR: &str = "var";

/// The path of a mount (relative to /var) from the installation root.
pub(super) fn target_path(mount: &Utf8Path) -> Utf8PathBuf {
    if mount.as_str().is_empty() {
        VAR.into()
    } else {
        Utf8Path::new(VAR).join(mount)
    }
}

/// What to do about /var in the target of `install to-filesystem`.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Plan {
    /// Leave /var alone, as bootc did before supporting separate /var.
    Disabled,
    /// Initialize whatever filesystems the caller already mounted at or below /var.
    CallerMounted,
    /// Mount this source at /var, then initialize it.
    Mount(String),
}

/// Filesystems that we are willing to mount on /var when we discover a
/// Variable Data Partition, as opposed to e.g. LUKS, LVM or swap signatures.
const MOUNTABLE_FSTYPES: &[&str] = &["ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs"];

/// Decide the plan from `--var-mount-spec` (or its config file equivalent).
///
/// An empty spec disables everything, including discovery of a DPS Variable
/// Data Partition on the disk(s) backing the root, which is used when no
/// spec was given and nothing is mounted at or below /var yet.
///
/// If `cannot_record` is set, the installed system has no way to be told to
/// mount /var (sealed UKIs have a fixed command line), so a spec is an
/// error and discovery is skipped.
pub(super) fn plan(
    configured: Option<&str>,
    caller_mounts: bool,
    cannot_record: bool,
    find_var_partition: impl FnOnce() -> Result<Option<bootc_blockdev::Device>>,
) -> Result<Plan> {
    match configured {
        Some("") => return Ok(Plan::Disabled),
        Some(spec) if cannot_record => bail!(
            "Cannot mount {spec} on /var: this installation cannot record the mount \
             (composefs with a UKI has a fixed kernel command line); mount it before \
             installing and set it up in the image instead"
        ),
        Some(spec) => return Ok(Plan::Mount(spec.to_owned())),
        None if caller_mounts => return Ok(Plan::CallerMounted),
        None => {}
    }
    // Discovery is opportunistic: failing to probe the disks is not a reason
    // to fail an install that never asked for a separate /var.
    let part = match find_var_partition() {
        Ok(Some(part)) => part,
        Ok(None) => return Ok(Plan::CallerMounted),
        Err(e) => {
            tracing::warn!("Looking for a Variable Data Partition: {e:#}");
            return Ok(Plan::CallerMounted);
        }
    };
    if cannot_record {
        tracing::warn!(
            "Ignoring Variable Data Partition {}: the mount cannot be recorded in a composefs UKI",
            part.path()
        );
        return Ok(Plan::CallerMounted);
    }
    // gpt-auto-generator only mounts a /var partition whose PARTUUID matches
    // the machine-id, so we always record the mount ourselves.
    match (&part.partuuid, part.fstype.as_deref()) {
        (Some(partuuid), Some(fstype)) if MOUNTABLE_FSTYPES.contains(&fstype) => {
            println!("Using Variable Data Partition {} for /var", part.path());
            Ok(Plan::Mount(format!("PARTUUID={partuuid}")))
        }
        _ => {
            tracing::warn!(
                "Ignoring Variable Data Partition {}: its contents ({}) are not a supported filesystem",
                part.path(),
                part.fstype.as_deref().unwrap_or("empty")
            );
            Ok(Plan::CallerMounted)
        }
    }
}

/// A /var filesystem that bootc mounted itself. Dropping it undoes the mount
/// (and the creation of the mountpoint), so an error does not leave it behind.
#[derive(Debug)]
pub(super) struct Mounted {
    /// How the booted system should mount it.
    pub(super) spec: MountSpec,
    root_path: Utf8PathBuf,
    root: Dir,
    /// We mounted it (it was not already a mountpoint).
    mounted: Cell<bool>,
    /// We created the mountpoint directory.
    created: Cell<bool>,
}

/// Mount `source` on the target's /var, unless something is mounted there already.
pub(super) fn mount(root_path: &Utf8Path, root: &Dir, source: &str) -> Result<Mounted> {
    let var = root_path.join(VAR);
    let existing = discover(root_path)?;
    let var_is_mount = existing.iter().any(|m| m.as_str().is_empty());
    // Mounting over caller mounts below /var would hide them.
    if !var_is_mount && !existing.is_empty() {
        bail!(
            "Cannot mount {source} on {var}: {} is already mounted below it",
            root_path.join(target_path(&existing[0]))
        );
    }
    let created = match root.symlink_metadata_optional(VAR)? {
        Some(meta) if meta.is_dir() => false,
        Some(_) => bail!("{var} exists but is not a directory"),
        None => {
            root.create_dir(VAR)
                .with_context(|| format!("Creating {var}"))?;
            true
        }
    };
    if var_is_mount {
        check_mounted_matches(&var, source)?;
    }
    let guard = Mounted {
        spec: MountSpec::new(source, "/var"),
        root_path: root_path.to_owned(),
        root: root.try_clone()?,
        mounted: Cell::new(false),
        created: Cell::new(created),
    };
    if !var_is_mount {
        println!("Mounting {source} on {var}");
        bootc_mount::mount(source, &var)?;
        guard.mounted.set(true);
    }
    Ok(guard)
}

/// Resolve a mount source (`/dev/...`, `UUID=...`, `LABEL=...`) to a canonical device path.
fn resolve_source(source: &str) -> Result<Utf8PathBuf> {
    let dev = if source.starts_with('/') {
        source.to_owned()
    } else {
        Command::new("findfs")
            .arg(source)
            .run_get_string()
            .with_context(|| format!("Resolving {source}"))?
            .trim()
            .to_owned()
    };
    Utf8Path::new(&dev)
        .canonicalize_utf8()
        .with_context(|| format!("Resolving {dev}"))
}

/// A caller already mounted /var: make sure it is the filesystem the
/// spec names, since we record the spec for the booted system.
fn check_mounted_matches(var: &Utf8Path, source: &str) -> Result<()> {
    let mounted = bootc_mount::inspect_filesystem(var)?;
    // btrfs sources look like /dev/vda3[/subvol]
    let mounted_source = mounted.source.split('[').next().unwrap_or_default();
    if !mounted_source.starts_with("/dev/") {
        bail!(
            "/var is already mounted from {} (not a block device), which cannot match \
             --var-mount-spec {source}",
            mounted.source
        );
    }
    if resolve_source(source)? != resolve_source(mounted_source)? {
        bail!(
            "/var is already mounted from {} but --var-mount-spec names {source}",
            mounted.source
        );
    }
    Ok(())
}

impl Mounted {
    /// Undo [`mount`], leaving the target as we found it.
    pub(super) fn unmount(&self) -> Result<()> {
        let path = self.root_path.join(VAR);
        if self.mounted.get() {
            Command::new("umount")
                .arg(&path)
                .run_inherited_with_cmd_context()?;
            self.mounted.set(false);
        }
        if self.created.get() {
            self.root
                .remove_dir(VAR)
                .with_context(|| format!("Removing {path}"))?;
            self.created.set(false);
        }
        Ok(())
    }
}

impl Drop for Mounted {
    fn drop(&mut self) {
        if let Err(e) = self.unmount() {
            tracing::warn!("Cleaning up /var mount: {e:#}");
            // Do not leave a mounted /var behind on the target: detach it lazily.
            if self.mounted.get() {
                let path = self.root_path.join(VAR);
                match Command::new("umount")
                    .arg("--lazy")
                    .arg(&path)
                    .run_inherited()
                {
                    Ok(()) => {
                        self.mounted.set(false);
                        if let Err(e) = self.unmount() {
                            tracing::warn!("Cleaning up /var mountpoint: {e:#}");
                        }
                    }
                    Err(e) => tracing::warn!("Lazily unmounting {path}: {e:#}"),
                }
            }
        }
    }
}

/// Mount paths relative to /var, including the empty path for /var itself.
pub(super) fn discover(root: &Utf8Path) -> Result<Vec<Utf8PathBuf>> {
    let root = root
        .canonicalize_utf8()
        .context("Resolving installation root")?;
    let mounts =
        bootc_mount::run_findmnt(&["--submounts", "--mountpoint"], None, Some(root.as_str()))?;
    let mut paths = Vec::new();
    collect(&root.join(VAR), &mounts.filesystems, &mut paths);
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn collect(var: &Utf8Path, mounts: &[Filesystem], paths: &mut Vec<Utf8PathBuf>) {
    for mount in mounts {
        // An error here only means the mount is outside the target's /var.
        if let Ok(path) = Utf8Path::new(&mount.target).strip_prefix(var) {
            paths.push(path.to_owned());
        }
        if let Some(children) = &mount.children {
            collect(var, children, paths);
        }
    }
}

/// A fresh mount tree may contain lost+found and directories needed to reach
/// child mounts. Everything else is existing state, which we must preserve.
fn is_empty_mount_tree(dir: &Dir, path: &Utf8Path, mounts: &[Utf8PathBuf]) -> Result<bool> {
    let context = || format!("Reading /{}", target_path(path));
    for entry in dir.entries().with_context(context)? {
        let entry = entry.with_context(context)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Ok(false);
        };
        let child = path.join(name);
        if !entry.file_type().with_context(context)?.is_dir() {
            return Ok(false);
        }
        let child_dir = dir.open_dir(name).with_context(context)?;
        if name == LOST_AND_FOUND && mounts.iter().any(|m| m == path) {
            let mut entries = child_dir.entries().with_context(context)?;
            if entries.next().transpose().with_context(context)?.is_some() {
                return Ok(false);
            }
        } else if mounts.iter().any(|m| m.starts_with(&child)) {
            if !is_empty_mount_tree(&child_dir, &child, mounts)? {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Check that a mountpoint and its ancestors are directories (not symlinks)
/// in the image's /var. Mounting on a symlinked path would not correspond to
/// the image's /var layout. Returns false if the image lacks the path.
fn check_source_path(source: &Dir, path: &Utf8Path) -> Result<bool> {
    let mut dir = source.try_clone()?;
    let mut walked = Utf8PathBuf::new();
    for component in path.iter() {
        walked.push(component);
        let Some(meta) = dir.symlink_metadata_optional(component)? else {
            return Ok(false);
        };
        if !meta.is_dir() {
            bail!(
                "Cannot initialize /{}: /{} in the image is a symlink or not a directory",
                target_path(path),
                target_path(&walked)
            );
        }
        dir = dir.open_dir(component)?;
    }
    Ok(true)
}

/// Copy each top-level mount tree once, with all its nested mounts in place.
/// Existing state is never merged or replaced. A tree with existing content
/// (including content in a nested mount) is left untouched in its entirety.
///
/// Returns the mounts that were initialized, or left empty because the image
/// has no content for them. These still need labeling and finalization.
pub(super) fn populate(
    root: &Dir,
    source: &Utf8Path,
    mounts: &[Utf8PathBuf],
) -> Result<Vec<Utf8PathBuf>> {
    let mut prepared = Vec::new();
    if mounts.is_empty() {
        return Ok(prepared);
    }
    let source_dir = root
        .open_dir(source)
        .with_context(|| format!("Opening {source}"))?;
    for mount in mounts {
        if mounts
            .iter()
            .any(|parent| parent != mount && mount.starts_with(parent))
        {
            continue;
        }
        let tree: Vec<_> = mounts
            .iter()
            .filter(|m| m.starts_with(mount))
            .cloned()
            .collect();
        let target = target_path(mount);
        let target_dir = root
            .open_dir(&target)
            .with_context(|| format!("Opening /{target}"))?;
        if !is_empty_mount_tree(&target_dir, mount, mounts)? {
            println!("Preserving existing contents of /{target} and its child mounts");
            continue;
        }
        if !check_source_path(&source_dir, mount)? {
            println!("No initial content for /{target} in the image");
            prepared.extend(tree);
            continue;
        }
        // Also validate nested mounts, which cp would otherwise reach implicitly.
        for nested in tree.iter().filter(|m| *m != mount) {
            check_source_path(&source_dir, nested)?;
        }
        println!("Initializing /{target} from the image");
        // cp -a preserves ownership, modes, and xattrs (including SELinux
        // labels). Hardlinks cannot span destination filesystems: materialize
        // regular files independently when the destination has nested mounts.
        let mut cp = Command::new("cp");
        cp.args(["--archive", "--reflink=auto"]);
        if tree.len() > 1 {
            cp.arg("--no-preserve=links");
        }
        cp.arg("--")
            .arg(source.join(mount).join("."))
            .arg(target.join("."))
            .cwd_dir(root.try_clone()?)
            .run_capture_stderr()
            .with_context(|| format!("Initializing /{target}"))?;
        prepared.extend(tree);
    }
    Ok(prepared)
}

/// Flush the filesystems of the given mounts, surfacing writeback errors.
pub(super) fn sync(root: &Dir, mounts: &[Utf8PathBuf]) -> Result<()> {
    for mount in mounts {
        let path = target_path(mount);
        // cap-std opens directories with O_PATH, which syncfs() rejects.
        let fd = rustix::fs::openat(
            root,
            path.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("Opening /{path}"))?;
        rustix::fs::syncfs(&fd).with_context(|| format!("Syncing /{path}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::cap_std::ambient_authority;
    use cap_std_ext::cap_std::fs::{MetadataExt, Permissions, PermissionsExt};
    use cap_std_ext::cap_tempfile::TempDir;

    fn partition(fstype: Option<&str>) -> bootc_blockdev::Device {
        serde_json::from_value(serde_json::json!({
            "name": "vda4", "path": "/dev/vda4", "size": 1, "partuuid": "abcd",
            "fstype": fstype,
        }))
        .unwrap()
    }

    #[test]
    fn test_plan() {
        let none = || Ok(None);
        let part = |fstype| move || Ok(Some(partition(fstype)));
        let mount = |s: &str| Plan::Mount(s.into());
        // An empty spec wins over discovery; an explicit one skips it.
        assert_eq!(
            plan(Some(""), false, false, part(Some("ext4"))).unwrap(),
            Plan::Disabled
        );
        assert_eq!(
            plan(Some("UUID=1"), false, false, none).unwrap(),
            mount("UUID=1")
        );
        assert_eq!(plan(None, false, false, none).unwrap(), Plan::CallerMounted);
        // Discovery needs a filesystem we can mount
        assert_eq!(
            plan(None, false, false, part(Some("xfs"))).unwrap(),
            mount("PARTUUID=abcd")
        );
        for fstype in [None, Some("crypto_LUKS"), Some("swap"), Some("LVM2_member")] {
            assert_eq!(
                plan(None, false, false, part(fstype)).unwrap(),
                Plan::CallerMounted,
                "{fstype:?}"
            );
        }
        // Discovery is for when the caller mounted nothing at /var
        assert_eq!(
            plan(None, true, false, part(Some("ext4"))).unwrap(),
            Plan::CallerMounted
        );
        // Without a way to record the mount, discovery is skipped and a spec is an error
        assert_eq!(
            plan(None, false, true, part(Some("ext4"))).unwrap(),
            Plan::CallerMounted
        );
        assert!(plan(Some("UUID=1"), false, true, none).is_err());
        assert_eq!(plan(Some(""), false, true, none).unwrap(), Plan::Disabled);
        // Failing to look for a partition is not fatal, unless a spec was given
        let fails = || anyhow::bail!("lsblk failed");
        assert_eq!(
            plan(None, false, false, fails).unwrap(),
            Plan::CallerMounted
        );
        assert_eq!(
            plan(Some("UUID=1"), false, false, fails).unwrap(),
            mount("UUID=1")
        );
    }

    #[test]
    fn populate_var_mounts() -> Result<()> {
        for (mounts, existing) in [
            (vec![""], false),
            (vec!["", "opt", "opt/app"], false),
            (vec!["opt", "opt/app"], false),
            (vec!["opt", "opt/app"], true),
            (vec!["opt/app"], false),
        ] {
            let root = TempDir::new(ambient_authority())?;
            root.create_dir_all("state/var/opt/app")?;
            root.write("state/var/opt/app/seed", "image seed")?;
            root.set_permissions("state/var/opt/app/seed", Permissions::from_mode(0o640))?;
            root.write("state/var/opt/parent", "parent seed")?;
            root.symlink_contents("seed", "state/var/opt/app/link")?;
            let mounts: Vec<Utf8PathBuf> = mounts.into_iter().map(Into::into).collect();
            for mount in &mounts {
                root.create_dir_all(Utf8Path::new("var").join(mount).join("lost+found"))?;
            }
            if existing {
                root.write("var/opt/app/seed", "existing state")?;
            }
            let initialized = populate(&root, "state/var".into(), &mounts)?;
            assert_eq!(initialized, if existing { vec![] } else { mounts.clone() });
            assert_eq!(
                root.read_to_string("var/opt/app/seed")?,
                if existing {
                    "existing state"
                } else {
                    "image seed"
                }
            );
            if existing {
                assert!(!root.try_exists("var/opt/parent")?);
            } else {
                assert_eq!(root.metadata("var/opt/app/seed")?.mode() & 0o777, 0o640);
                assert_eq!(
                    root.read_link("var/opt/app/link")?,
                    std::path::Path::new("seed")
                );
            }
            // A later invocation must not merge a different image into state.
            root.write("state/var/opt/app/new-file", "new image")?;
            assert!(populate(&root, "state/var".into(), &mounts)?.is_empty());
            assert!(!root.try_exists("var/opt/app/new-file")?);
        }
        Ok(())
    }

    #[test]
    fn prepare_unseeded_mount() -> Result<()> {
        // The image has no /var/srv; the empty mount still needs labeling.
        let root = TempDir::new(ambient_authority())?;
        root.create_dir_all("state/var/opt")?;
        root.create_dir_all("var/srv/lost+found")?;
        let mounts = vec![Utf8PathBuf::from("srv")];
        assert_eq!(populate(&root, "state/var".into(), &mounts)?, mounts);
        Ok(())
    }

    #[test]
    fn source_symlink() -> Result<()> {
        // Only trees that would be initialized are validated.
        for existing in [false, true] {
            let root = TempDir::new(ambient_authority())?;
            root.create_dir_all("state/var")?;
            root.create_dir_all("var/opt/app")?;
            root.symlink_contents("/outside", "state/var/opt")?;
            if existing {
                root.write("var/opt/app/data", "existing state")?;
            }
            let result = populate(&root, "state/var".into(), &["opt/app".into()]);
            if existing {
                assert!(result?.is_empty());
            } else {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "Cannot initialize /var/opt/app: /var/opt in the image is a symlink or not a directory"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn empty_mount_tree() -> Result<()> {
        // Entries below /var (a trailing slash denotes a directory), mounts
        // relative to /var, and whether the /var tree counts as empty.
        let cases: &[(&[&str], &[&str], bool)] = &[
            (&[], &[""], true),
            (&["lost+found/"], &[""], true),
            (&["lost+found/", "lost+found/x"], &[""], false),
            (&["file"], &[""], false),
            (&["tmp/"], &[""], false),
            (
                &["lib/", "lib/app/", "lib/app/lost+found/"],
                &["", "lib/app"],
                true,
            ),
            (&["lib/", "lib/lost+found/"], &["", "lib/app"], false),
            (&["lib/", "tmp/"], &["", "lib/app"], false),
            (&["lib/app/", "lib/app/state"], &["", "lib/app"], false),
        ];
        for (entries, mounts, expected) in cases {
            let root = TempDir::new(ambient_authority())?;
            for entry in *entries {
                match entry.strip_suffix('/') {
                    Some(dir) => root.create_dir_all(dir)?,
                    None => root.write(entry, "data")?,
                }
            }
            let mounts: Vec<Utf8PathBuf> = mounts.iter().map(|m| Utf8PathBuf::from(*m)).collect();
            assert_eq!(
                is_empty_mount_tree(&root, "".into(), &mounts)?,
                *expected,
                "{entries:?} {mounts:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn sync_mounts() -> Result<()> {
        let root = TempDir::new(ambient_authority())?;
        root.create_dir_all("var/lib/app")?;
        sync(&root, &["".into(), "lib/app".into()])?;
        let err = sync(&root, &["missing".into()]).unwrap_err();
        assert_eq!(err.to_string(), "Opening /var/missing");
        Ok(())
    }

    #[test]
    fn target_paths() {
        assert_eq!(target_path("".into()), "var");
        assert_eq!(target_path("lib/app".into()), "var/lib/app");
    }

    #[test]
    fn preserve_non_utf8_state() -> Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let root = TempDir::new(ambient_authority())?;
        root.create_dir_all("state/var/opt")?;
        root.write("state/var/opt/seed", "image")?;
        root.create_dir_all("var/opt")?;
        let target = root.open_dir("var/opt")?;
        let name = std::ffi::OsStr::from_bytes(b"existing-\xff");
        target.write(name, "existing state")?;
        populate(&root, "state/var".into(), &["opt".into()])?;
        assert_eq!(target.read_to_string(name)?, "existing state");
        assert!(!target.try_exists("seed")?);
        Ok(())
    }

    #[test]
    fn collect_only_target_var_mounts() -> Result<()> {
        let mounts: bootc_mount::Findmnt = serde_json::from_value(serde_json::json!({
            "filesystems": [{
                "source": "/dev/root", "target": "/target with spaces", "maj:min": "0:1",
                "fstype": "ext4", "options": "rw", "children": [
                    {"source": "/dev/a", "target": "/target with spaces/var/opt",
                     "maj:min": "0:2", "fstype": "ext4", "options": "rw", "children": [
                        {"source": "/dev/b", "target": "/target with spaces/var/opt/app",
                         "maj:min": "0:3", "fstype": "xfs", "options": "rw"}
                    ]},
                    {"source": "/dev/c", "target": "/target with spaces/variable",
                     "maj:min": "0:4", "fstype": "ext4", "options": "rw"},
                    {"source": "/dev/d", "target": "/other/var/opt",
                     "maj:min": "0:5", "fstype": "ext4", "options": "rw"}
                ]
            }]
        }))?;
        let mut paths = Vec::new();
        collect(
            "/target with spaces/var".into(),
            &mounts.filesystems,
            &mut paths,
        );
        assert_eq!(paths, vec![Utf8PathBuf::from("opt"), "opt/app".into()]);
        Ok(())
    }

    #[test]
    #[ignore = "requires a private user/mount namespace; run with unshare -Urnm"]
    fn mounted_var_filesystems() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = Utf8Path::from_path(temp.path()).unwrap();
        Command::new("mount")
            .args(["--bind", path.as_str(), path.as_str()])
            .run_capture_stderr()?;
        let result = (|| -> Result<()> {
            assert!(discover(path)?.is_empty());
            let root = Dir::open_ambient_dir(path, ambient_authority())?;
            root.create_dir_all("state/var/opt/app")?;
            root.write("state/var/opt/app/seed", "seed")?;
            root.set_permissions("state/var/opt/app/seed", Permissions::from_mode(0o640))?;
            root.hard_link("state/var/opt/app/seed", &root, "state/var/parent-link")?;
            root.hard_link(
                "state/var/opt/app/seed",
                &root,
                "state/var/opt/app/same-volume-link",
            )?;
            root.symlink_contents("seed", "state/var/opt/app/symlink")?;
            root.create_dir("var")?;
            Command::new("mount")
                .args(["-t", "tmpfs", "tmpfs"])
                .arg(path.join("var"))
                .run_capture_stderr()?;
            root.create_dir_all("var/opt/app")?;
            Command::new("mount")
                .args(["-t", "tmpfs", "tmpfs"])
                .arg(path.join("var/opt/app"))
                .run_capture_stderr()?;
            let mounts = discover(path)?;
            assert_eq!(mounts, vec![Utf8PathBuf::new(), "opt/app".into()]);
            assert_eq!(populate(&root, "state/var".into(), &mounts)?, mounts);
            for file in [
                "var/parent-link",
                "var/opt/app/seed",
                "var/opt/app/same-volume-link",
            ] {
                assert_eq!(root.read_to_string(file)?, "seed");
                assert_eq!(root.metadata(file)?.mode() & 0o777, 0o640);
            }
            assert_ne!(
                root.metadata("var/parent-link")?.dev(),
                root.metadata("var/opt/app/seed")?.dev()
            );
            assert_eq!(
                root.read_link("var/opt/app/symlink")?,
                std::path::Path::new("seed")
            );
            root.write("var/opt/app/seed", "existing state")?;
            assert!(populate(&root, "state/var".into(), &mounts)?.is_empty());
            assert_eq!(root.read_to_string("var/opt/app/seed")?, "existing state");
            Ok(())
        })();
        let unmount = bootc_mount::unmount_recursive(path);
        result?;
        unmount
    }
}
