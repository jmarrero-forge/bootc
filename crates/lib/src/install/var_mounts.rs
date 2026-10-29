//! Initialize caller-mounted /var filesystems from the image's /var.

use std::ffi::CString;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{Context, Result, bail};
use bootc_mount::Filesystem;
use bootc_mount::tempmount::TempMount;
use bootc_utils::CommandRunExt;
use camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::{
    cap_std::{
        ambient_authority,
        fs::{Dir, Permissions, PermissionsExt as _},
    },
    dirext::CapStdExtDirExt,
};
use libsystemd::logging::Priority;
use ostree_ext::ostree;
use rustix::fs::{Mode, OFlags};
use rustix::mount::{MountFlags, MountPropagationFlags, mount, mount_change};
use rustix::thread::{UnshareFlags, unshare_unsafe};

use super::LOST_AND_FOUND;

/// Listed by `bootc --version`, so that tools preparing a target for
/// `install to-filesystem` know they can pass `--initialize-var-mounts`.
/// Older versions leave /var filesystems empty, or reject them entirely.
pub(crate) const FEATURE: &str = "initialize-var-mounts";

/// Listed by `bootc --version` for `bootc state initialize-var`.
pub(crate) const STATE_FEATURE: &str = "state-initialize-var";

const VAR: &str = "var";

/// Journal message ID of the events of initializing /var filesystems from
/// the image: filled, skipped because they hold data, or failed.
const VAR_INIT_JOURNAL_ID: &str = "a3dbd7d2ce1341feb6f6003a98eb6657";

/// Marks a stateroot var whose /var at boot is a filesystem that
/// `--initialize-var-mounts` found mounted on the target's /var: composefs
/// setup-root then leaves /var to that filesystem's fstab entry instead of
/// bind-mounting the stateroot var over it. See
/// [`bootc_initramfs_setup::VAR_MOUNTS_MARKER`].
pub(crate) const VAR_MOUNTS_MARKER: &str = bootc_initramfs_setup::VAR_MOUNTS_MARKER;

/// Write [`VAR_MOUNTS_MARKER`] into the stateroot var at `var` (relative to
/// `root`), labeled as /var's, when `mounts` (relative to /var) include a
/// filesystem on /var itself, whether it gets filled or holds data already.
pub(crate) fn mark_var_filesystem(
    root: &Dir,
    var: &Utf8Path,
    mounts: &[Utf8PathBuf],
    policy: Option<&ostree::SePolicy>,
) -> Result<()> {
    if !mounts.iter().any(|m| m.as_str().is_empty()) {
        return Ok(());
    }
    let dir = root
        .open_dir(var)
        .with_context(|| format!("Opening {var}"))?;
    dir.atomic_write_with_perms(VAR_MOUNTS_MARKER, b"", Permissions::from_mode(0o644))
        .with_context(|| format!("Writing {var}/{VAR_MOUNTS_MARKER}"))?;
    if let Some(policy) = policy {
        let path = Utf8Path::new("/var").join(VAR_MOUNTS_MARKER);
        let label = crate::lsm::require_label(policy, &path, libc::S_IFREG | 0o644)?;
        crate::lsm::set_security_selinux_path(&dir, VAR_MOUNTS_MARKER.into(), label.as_bytes())
            .with_context(|| format!("SELinux labeling of {var}/{VAR_MOUNTS_MARKER}"))?;
    }
    Ok(())
}

/// The path of a mount (relative to /var) from the installation root.
pub(crate) fn target_path(mount: &Utf8Path) -> Utf8PathBuf {
    if mount.as_str().is_empty() {
        VAR.into()
    } else {
        Utf8Path::new(VAR).join(mount)
    }
}

/// Mount paths relative to /var, including the empty path for /var itself.
pub(crate) fn discover(root: &Utf8Path) -> Result<Vec<Utf8PathBuf>> {
    discover_matching(root, |_| true)
}

/// Like [`discover`], but only the filesystems for which `keep` is true.
fn discover_matching(root: &Utf8Path, keep: fn(&Filesystem) -> bool) -> Result<Vec<Utf8PathBuf>> {
    let root = root
        .canonicalize_utf8()
        .context("Resolving installation root")?;
    let mounts =
        bootc_mount::run_findmnt(&["--submounts", "--mountpoint"], None, Some(root.as_str()))?;
    let mut paths = Vec::new();
    collect(&root.join(VAR), &mounts.filesystems, keep, &mut paths);
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn collect(
    var: &Utf8Path,
    mounts: &[Filesystem],
    keep: fn(&Filesystem) -> bool,
    paths: &mut Vec<Utf8PathBuf>,
) {
    for mount in mounts {
        // An error here only means the mount is outside the target's /var.
        if let Ok(path) = Utf8Path::new(&mount.target).strip_prefix(var) {
            if keep(mount) {
                paths.push(path.to_owned());
            }
        }
        if let Some(children) = &mount.children {
            collect(var, children, keep, paths);
        }
    }
}

/// Whether a filesystem is a block device's filesystem mounted at its root, or /var
/// itself (on ostree and composefs a bind mount of the state directory). On
/// a booted system, /var also holds other software's mounts, such as
/// container tmpfs mounts, network filesystems and bind mounts of host
/// directories, which aren't ours to fill or label.
fn is_block_backed(fs: &Filesystem) -> bool {
    fs.source.starts_with("/dev/") && (!fs.source.contains('[') || fs.target == "/var")
}

/// The filesystems directly below `parent` among `mounts`: the ones with no
/// other filesystem in between.
fn children<'a>(parent: &Utf8Path, mounts: &'a [Utf8PathBuf]) -> Vec<&'a Utf8PathBuf> {
    let below = |m: &Utf8Path, p: &Utf8Path| m != p && m.starts_with(p);
    mounts
        .iter()
        .filter(|m| below(m, parent))
        .filter(|m| {
            !mounts
                .iter()
                .any(|between| below(between, parent) && below(m, between))
        })
        .collect()
}

/// Whether the filesystem mounted at `root` (relative to /var) holds no
/// state yet. `dir` is its directory at `path`. A fresh filesystem may
/// contain an empty lost+found, and directories leading to the mountpoints
/// of the filesystems nested in it; their content is their own.
fn is_empty_fs(
    dir: &Dir,
    root: &Utf8Path,
    path: &Utf8Path,
    nested: &[&Utf8PathBuf],
) -> Result<bool> {
    let context = || format!("Reading /{}", target_path(path));
    for entry in dir.entries().with_context(context)? {
        let entry = entry.with_context(context)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Ok(false);
        };
        if !entry.file_type().with_context(context)?.is_dir() {
            return Ok(false);
        }
        let child = path.join(name);
        if nested.iter().any(|m| **m == child) {
            continue;
        }
        let child_dir = dir.open_dir(name).with_context(context)?;
        if name == LOST_AND_FOUND && path == root {
            let mut entries = child_dir.entries().with_context(context)?;
            if entries.next().transpose().with_context(context)?.is_some() {
                return Ok(false);
            }
        } else if nested.iter().any(|m| m.starts_with(&child)) {
            if !is_empty_fs(&child_dir, root, &child, nested)? {
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

/// The image's /var, as the source of initial /var content.
#[derive(Debug)]
pub(crate) struct ImageVar {
    /// Absolute path of the image's /var.
    path: Utf8PathBuf,
    /// Whether files that share an inode are hardlinks in the image. An
    /// ostree commit doesn't record hardlinks: identical files share one
    /// object, so its checkouts link files the image keeps separate.
    hardlinks: bool,
    /// Keeps a composefs image mounted while we copy from it.
    _mount: Option<TempMount>,
}

impl ImageVar {
    /// The /var of an ostree deployment checkout, `deployment` being the
    /// absolute path of its directory.
    pub(crate) fn ostree(deployment: &Utf8Path) -> Self {
        Self {
            path: deployment.join(VAR),
            hardlinks: false,
            _mount: None,
        }
    }

    /// The /var of the composefs image `id` in the repository of `sysroot`.
    pub(crate) fn composefs(sysroot: &Dir, id: &str, allow_missing_fsverity: bool) -> Result<Self> {
        let sysroot = sysroot.reopen_as_ownedfd()?;
        let image =
            bootc_initramfs_setup::mount_composefs_image(&sysroot, id, allow_missing_fsverity)
                .with_context(|| format!("Mounting composefs image {id}"))?;
        let mount = TempMount::mount_fd(image)?;
        let root =
            Utf8Path::from_path(mount.dir.path()).context("Non-UTF-8 temporary directory")?;
        Ok(Self {
            path: root.join(VAR),
            hardlinks: true,
            _mount: Some(mount),
        })
    }
}

/// The name of the only directory in `dir`, such as the deployment of a
/// fresh installation.
pub(crate) fn only_dir(dir: &Dir) -> Result<String> {
    let mut found = None;
    for entry in dir.entries()? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name
            .into_string()
            .map_err(|n| anyhow::anyhow!("Non-UTF-8 name {n:?}"))?;
        if let Some(prev) = found.replace(name) {
            bail!("Expected one deployment, found {prev} and more");
        }
    }
    found.context("No deployment found")
}

/// A private view in which `cp` copies the image's content for one
/// filesystem, so that each file lands on the filesystem that holds it at
/// boot.
#[derive(Debug, Default, PartialEq, Eq)]
struct CopyView {
    /// Paths in the image's /var to cover with an empty read-only tmpfs: the
    /// content of other filesystems, so it isn't copied here.
    hide_source: Vec<Utf8PathBuf>,
    /// Mountpoints of other filesystems in the target to cover with a
    /// scratch tmpfs, so that copying their (hidden) source directories
    /// doesn't change their roots.
    hide_target: Vec<Utf8PathBuf>,
}

impl CopyView {
    /// Copy `source` to `target` with `cp --archive` in a private mount
    /// namespace set up as described by `self`.
    fn copy(&self, source: &Utf8Path, target: &Utf8Path, hardlinks: bool) -> Result<()> {
        let cstrings = |paths: &[Utf8PathBuf]| -> Result<Vec<CString>> {
            Ok(paths
                .iter()
                .map(|p| CString::new(p.as_str()))
                .collect::<Result<_, _>>()?)
        };
        // Allocate everything up front: the pre_exec hook below must not.
        let hide_source = cstrings(&self.hide_source)?;
        let hide_target = cstrings(&self.hide_target)?;

        let mut cp = Command::new("cp");
        // cp -a preserves ownership, modes, and xattrs (including SELinux
        // labels).
        cp.args(["--archive", "--reflink=auto"]);
        if !hardlinks {
            cp.arg("--no-preserve=links");
        }
        cp.arg("--").arg(source.join(".")).arg(target.join("."));
        if *self == Self::default() {
            return cp.run_capture_stderr();
        }
        // SAFETY: The hook runs between fork and exec, and only makes
        // syscalls on the strings allocated above.
        #[allow(unsafe_code)]
        unsafe {
            cp.pre_exec(move || {
                unshare_unsafe(UnshareFlags::NEWNS)?;
                // Keep our mounts from propagating anywhere else.
                mount_change(
                    c"/",
                    MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
                )?;
                for path in &hide_source {
                    mount(
                        c"tmpfs",
                        path.as_c_str(),
                        c"tmpfs",
                        MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV,
                        Some(c"mode=0755"),
                    )?;
                }
                for path in &hide_target {
                    mount(
                        c"tmpfs",
                        path.as_c_str(),
                        c"tmpfs",
                        MountFlags::NOSUID | MountFlags::NODEV,
                        Some(c"mode=0755,size=1m"),
                    )?;
                }
                Ok(())
            });
        }
        cp.run_capture_stderr().with_context(|| {
            format!(
                "Copying with {} hidden",
                self.hide_source
                    .iter()
                    .chain(&self.hide_target)
                    .map(|p| p.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
    }
}

/// Give the directory `dst` the ownership, mode, extended attributes (such as
/// ACLs, but not the SELinux label) and timestamps of `src`, as `cp -a` would.
fn copy_dir_metadata(src: &Utf8Path, dst: &Utf8Path) -> Result<()> {
    use rustix::fs::{AtFlags, Timespec, Timestamps, XattrFlags};
    let context = || format!("Copying the metadata of {src} to {dst}");
    let meta = src.symlink_metadata().with_context(context)?;
    std::os::unix::fs::lchown(dst, Some(meta.uid()), Some(meta.gid())).with_context(context)?;
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(meta.mode() & 0o7777))
        .with_context(context)?;
    let mut names =
        vec![0u8; rustix::fs::llistxattr(src.as_str(), &mut [0u8; 0][..]).with_context(context)?];
    let len = rustix::fs::llistxattr(src.as_str(), &mut names[..]).with_context(context)?;
    names.truncate(len);
    // Like cp -a, skip what can't be set. The SELinux label is set when the
    // stateroot var is relabeled afterwards anyway.
    for name in names
        .split(|b| *b == 0)
        .filter(|n| !n.is_empty() && *n != b"security.selinux")
    {
        let name = CString::new(name)?;
        let mut value = vec![
            0u8;
            rustix::fs::lgetxattr(src.as_str(), &name, &mut [0u8; 0][..])
                .with_context(context)?
        ];
        let len =
            rustix::fs::lgetxattr(src.as_str(), &name, &mut value[..]).with_context(context)?;
        match rustix::fs::lsetxattr(dst.as_str(), &name, &value[..len], XattrFlags::empty()) {
            Ok(()) => {}
            Err(e @ (rustix::io::Errno::NOTSUP | rustix::io::Errno::PERM)) => {
                tracing::debug!("Not copying {name:?} to {dst}: {e}");
            }
            Err(e) => return Err(e).with_context(context),
        }
    }
    let time = |sec, nsec| Timespec {
        tv_sec: sec,
        tv_nsec: nsec as _,
    };
    let times = Timestamps {
        last_access: time(meta.atime(), meta.atime_nsec()),
        last_modification: time(meta.mtime(), meta.mtime_nsec()),
    };
    rustix::fs::utimensat(
        rustix::fs::CWD,
        dst.as_str(),
        &times,
        AtFlags::SYMLINK_NOFOLLOW,
    )
    .with_context(context)?;
    Ok(())
}

/// What [`populate`] initialized, or left empty because the image has no
/// content for it. These still need labeling and syncing.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Prepared {
    /// The stateroot's var, which is /var at boot unless a filesystem is
    /// mounted there.
    pub(crate) stateroot_var: bool,
    /// Mounts, relative to /var.
    pub(crate) mounts: Vec<Utf8PathBuf>,
}

/// Fill each empty filesystem of /var as it will be at boot with its part of
/// the image's /var, one `cp` per filesystem: the filesystems in `mounts`
/// (relative to /var, below `root_path`), and a stateroot var that
/// `--defer-var` left unseeded (`stateroot_var`, relative to `root_path`)
/// unless one is mounted on /var. Content below a mountpoint goes only to
/// the filesystem mounted there, so each file is stored once. Hardlinks within one
/// filesystem are kept where the source has them; those spanning filesystems
/// become separate files. Filesystems that already hold data are left alone,
/// but empty filesystems below and above them are still filled.
///
/// What was filled, or left empty for lack of image content, is recorded in
/// `prepared` as it goes, so that after an error the filesystems completed
/// before it can still be finished: see [`finish`].
pub(crate) fn populate(
    root: &Dir,
    root_path: &Utf8Path,
    stateroot_var: Option<&Utf8Path>,
    mounts: &[Utf8PathBuf],
    source: &ImageVar,
    prepared: &mut Prepared,
) -> Result<()> {
    populate_targets(
        root,
        root_path,
        stateroot_var,
        mounts,
        mounts,
        source,
        prepared,
    )
}

/// [`populate`], filling only the `targets` among `mounts`; the others are
/// still boundaries, hidden from the copies and not counted as data.
fn populate_targets(
    root: &Dir,
    root_path: &Utf8Path,
    stateroot_var: Option<&Utf8Path>,
    mounts: &[Utf8PathBuf],
    targets: &[Utf8PathBuf],
    source: &ImageVar,
    prepared: &mut Prepared,
) -> Result<()> {
    let stateroot_var = stateroot_var.filter(|_| !mounts.iter().any(|m| m.as_str().is_empty()));
    if targets.is_empty() && stateroot_var.is_none() {
        return Ok(());
    }
    let root_path = root_path
        .canonicalize_utf8()
        .with_context(|| format!("Resolving {root_path}"))?;
    let source_dir = Dir::open_ambient_dir(&source.path, ambient_authority())
        .with_context(|| format!("Opening {}", source.path))?;
    if let Some(var) = stateroot_var {
        // It only holds the marker (and on ostree, libostree's
        // .ostree-selabeled stamp), which the image's /var doesn't have.
        // The mountpoints are not mounted here: they get an empty
        // directory, like the image's, and no content.
        let mut view = CopyView::default();
        for m in children("".into(), mounts) {
            if check_source_path(&source_dir, m)? {
                view.hide_source.push(source.path.join(m));
            }
        }
        println!("Initializing /var from the image");
        logged_copy(
            &view,
            &source.path,
            &root_path,
            CopyTarget::StaterootVar(var),
            source.hardlinks,
        )?;
        let target = root_path.join(var);
        // cp gave them the metadata of what hid the image's directories
        for hidden in &view.hide_source {
            let path = hidden.strip_prefix(&source.path)?;
            copy_dir_metadata(hidden, &target.join(path))?;
        }
        prepared.stateroot_var = true;
    }
    for mount in targets {
        let target = target_path(mount);
        let nested = children(mount, mounts);
        let target_dir = root
            .open_dir(&target)
            .with_context(|| format!("Opening /{target}"))?;
        if !is_empty_fs(&target_dir, mount, mount, &nested)? {
            let fs = mount_source(&root_path.join(&target));
            let msg = format!("Not initializing /{target} ({fs}) from the image: it holds data");
            println!("{msg}");
            journal_var_event(Priority::Notice, &msg, &target, &fs);
            continue;
        }
        if !check_source_path(&source_dir, mount)? {
            println!("No initial content for /{target} in the image");
            prepared.mounts.push(mount.clone());
            continue;
        }
        let mut view = CopyView::default();
        for m in nested {
            if check_source_path(&source_dir, m)? {
                view.hide_source.push(source.path.join(m));
                view.hide_target.push(root_path.join(target_path(m)));
            }
        }
        println!("Initializing /{target} from the image");
        logged_copy(
            &view,
            &source.path.join(mount),
            &root_path,
            CopyTarget::Mount(mount),
            source.hardlinks,
        )?;
        prepared.mounts.push(mount.clone());
    }
    Ok(())
}

/// Run `finish_one` on each of `items`, whatever fails, then return
/// `populated`: its error first if there is one, followed by the finishing
/// errors.
fn finish_with<T>(
    items: impl IntoIterator<Item = T>,
    mut finish_one: impl FnMut(T) -> Vec<anyhow::Error>,
    populated: Result<()>,
) -> Result<()> {
    let errors: Vec<_> = items.into_iter().flat_map(&mut finish_one).collect();
    if errors.is_empty() {
        return populated;
    }
    let finishing = errors
        .iter()
        .map(|e| format!("{e:#}"))
        .collect::<Vec<_>>()
        .join("; ");
    Err(match populated {
        Err(e) => anyhow::anyhow!(
            "{e:#}; finishing the filesystems initialized before that also failed: {finishing}"
        ),
        Ok(()) => anyhow::anyhow!("Finishing the initialized filesystems failed: {finishing}"),
    })
}

/// Something [`populate`] prepared, to finish.
enum Finishing<'a> {
    /// The deferred stateroot var, to label as /var
    StaterootVar(&'a Utf8Path),
    /// A filesystem mounted below /var, to label and sync
    Mount(&'a Utf8Path),
}

/// What [`finish`] does to what [`populate`] prepared: [`Finish`] does it,
/// tests record it.
trait Finisher {
    /// SELinux label the deferred stateroot var at `var` (relative to the
    /// root) as /var
    fn label_stateroot_var(&mut self, var: &Utf8Path) -> Result<()>;
    /// SELinux label the filesystem at `mount` (relative to /var)
    fn label(&mut self, mount: &Utf8Path) -> Result<()>;
    /// Flush the filesystem at `mount` (relative to /var)
    fn sync(&mut self, mount: &Utf8Path) -> Result<()>;
}

/// Labels with the `policy`, if there is one, and syncs.
struct Finish<'a> {
    root: &'a Dir,
    policy: Option<&'a ostree::SePolicy>,
}

impl Finisher for Finish<'_> {
    fn label_stateroot_var(&mut self, var: &Utf8Path) -> Result<()> {
        let Some(policy) = self.policy else {
            return Ok(());
        };
        // Like libostree does when it seeds /var.
        crate::lsm::relabel_recurse(self.root, var, Some("/var".into()), policy)
            .context("SELinux labeling of /var")
    }

    fn label(&mut self, mount: &Utf8Path) -> Result<()> {
        self.policy
            .map_or(Ok(()), |policy| label(self.root, mount, policy))
    }

    fn sync(&mut self, mount: &Utf8Path) -> Result<()> {
        sync(self.root, mount)
    }
}

/// Label (given a `policy`) what [`populate`] prepared, and sync each
/// filesystem, then return its result, `populated`. The `stateroot_var` is
/// the one passed to it. Filesystems it completed before failing are
/// finished too, since a retry leaves them alone as holding data, and one
/// failing doesn't stop the others.
pub(crate) fn finish(
    root: &Dir,
    stateroot_var: Option<&Utf8Path>,
    prepared: &Prepared,
    policy: Option<&ostree::SePolicy>,
    populated: Result<()>,
) -> Result<()> {
    finish_using(
        &mut Finish { root, policy },
        stateroot_var,
        prepared,
        populated,
    )
}

/// [`finish`] with `finisher`: each filesystem is synced even when
/// labeling it failed.
fn finish_using(
    finisher: &mut impl Finisher,
    stateroot_var: Option<&Utf8Path>,
    prepared: &Prepared,
    populated: Result<()>,
) -> Result<()> {
    let stateroot_var = stateroot_var
        .filter(|_| prepared.stateroot_var)
        .map(Finishing::StaterootVar);
    let mounts = prepared
        .mounts
        .iter()
        .map(|m| Finishing::Mount(m.as_path()));
    finish_with(
        stateroot_var.into_iter().chain(mounts),
        |item| match item {
            Finishing::StaterootVar(var) => finisher
                .label_stateroot_var(var)
                .err()
                .into_iter()
                .collect(),
            Finishing::Mount(mount) => [finisher.label(mount), finisher.sync(mount)]
                .into_iter()
                .filter_map(Result::err)
                .collect(),
        },
        populated,
    )
}

/// The source of the filesystem mounted at `path`, to name it in messages.
fn mount_source(path: &Utf8Path) -> String {
    bootc_mount::inspect_filesystem(path)
        .map(|fs| fs.source)
        .unwrap_or_else(|e| {
            tracing::debug!("Inspecting {path}: {e:#}");
            "unknown source".into()
        })
}

/// Log an event of initializing the filesystem at `/{target}` (from `fs`)
/// to the journal.
fn journal_var_event(priority: Priority, msg: &str, target: &Utf8Path, fs: &str) {
    let mount = format!("/{target}");
    crate::journal::journal_send(
        priority,
        msg,
        [
            ("MESSAGE_ID", VAR_INIT_JOURNAL_ID),
            ("BOOTC_VAR_MOUNT", mount.as_str()),
            ("BOOTC_VAR_SOURCE", fs),
        ]
        .into_iter(),
    );
}

/// What a copy fills, for its messages and journal entries.
#[derive(Clone, Copy)]
enum CopyTarget<'a> {
    /// The filesystem mounted at this path (relative to /var) at boot
    Mount(&'a Utf8Path),
    /// The deferred stateroot var at this path (relative to the root),
    /// which is /var at boot
    StaterootVar(&'a Utf8Path),
}

/// Copy `source` into `target` (below `root_path`) with `view`, logging the
/// result to the journal. A failed copy may leave the target partly filled.
/// A filesystem then counts as holding data in later runs, so the error
/// says so; the stateroot var is filled only at installation.
fn logged_copy(
    view: &CopyView,
    source: &Utf8Path,
    root_path: &Utf8Path,
    target: CopyTarget,
    hardlinks: bool,
) -> Result<()> {
    let (path, name, boot_path) = match target {
        CopyTarget::Mount(mount) => {
            let target = target_path(mount);
            (root_path.join(&target), format!("/{target}"), target)
        }
        CopyTarget::StaterootVar(var) => (
            root_path.join(var),
            format!("/var (the deployment's state directory, /{var})"),
            VAR.into(),
        ),
    };
    let fs = mount_source(&path);
    match view.copy(source, &path, hardlinks) {
        Ok(()) => {
            let msg = format!("Initialized {name} ({fs}) from the image");
            journal_var_event(Priority::Info, &msg, &boot_path, &fs);
            Ok(())
        }
        Err(e) => {
            let msg = match target {
                CopyTarget::Mount(_) => format!(
                    "Initializing {name} ({fs}) from the image failed, which may have left \
                     it partly filled. Only empty filesystems are initialized, so a partly \
                     filled one will not be initialized again: empty it (e.g. recreate the \
                     filesystem) and run this again, or complete it by hand"
                ),
                CopyTarget::StaterootVar(_) => format!(
                    "Initializing {name} ({fs}) from the image failed, which may have left \
                     it partly filled. This is part of the installation: install again \
                     onto a fresh root filesystem"
                ),
            };
            journal_var_event(Priority::Error, &format!("{msg}: {e:#}"), &boot_path, &fs);
            Err(e.context(msg))
        }
    }
}

/// SELinux label a filesystem that [`populate`] prepared, by its path at
/// boot.
fn label(root: &Dir, mount: &Utf8Path, policy: &ostree::SePolicy) -> Result<()> {
    let mut path = target_path(mount);
    // These are fresh filesystems; label their roots unconditionally.
    // Without selinuxfs (e.g. in an osbuild buildroot), an inode without
    // a label still reports the kernel's unlabeled context, which the
    // walk below would take as labeled.
    for p in fresh_roots(root, &path)? {
        let meta = root.symlink_metadata(&p)?;
        crate::lsm::relabel(root, &meta, &p, None, policy)
            .with_context(|| format!("SELinux labeling of /{p}"))?;
    }
    crate::lsm::ensure_dir_labeled_recurse(root, &mut path, policy, None)
        .with_context(|| format!("SELinux labeling of /{path}"))
}

/// What [`label`] labels unconditionally in the fresh filesystem at `path`:
/// its root, and its lost+found, unless that is a mountpoint, which belongs
/// to another filesystem (the walk skips mountpoints too).
fn fresh_roots(root: &Dir, path: &Utf8Path) -> Result<Vec<Utf8PathBuf>> {
    let lost_found = path.join(LOST_AND_FOUND);
    let mut roots = vec![path.to_owned()];
    if root.symlink_metadata_optional(&lost_found)?.is_some()
        && root
            .is_mountpoint(&lost_found)
            .with_context(|| format!("Checking /{lost_found}"))?
            != Some(true)
    {
        roots.push(lost_found);
    }
    Ok(roots)
}

/// Implementation of `bootc state initialize-var`: on a booted system, fill
/// the empty filesystems mounted at or below `scope` in /var from the booted
/// deployment's image, like `install to-filesystem --initialize-var-mounts`
/// does at installation.
pub(crate) async fn initialize_booted(scope: &Utf8Path) -> Result<()> {
    let resolved = scope
        .canonicalize_utf8()
        .with_context(|| format!("Resolving {scope}"))?;
    let scope = resolved
        .strip_prefix(Utf8Path::new("/").join(VAR))
        .map_err(|_| anyhow::anyhow!("{resolved} is not in /var"))?;
    // Every mount is a boundary; only block-device filesystems are filled.
    let mounts = discover("/".into())?;
    let eligible = discover_matching("/".into(), is_block_backed)?;
    // Fail early, before setting up the image
    scope_targets(scope, &mounts, &eligible)?;
    let storage = crate::cli::get_storage().await?;
    let source = match storage.kind()? {
        crate::store::BootedStorageKind::Ostree(booted) => {
            let deployment = booted.sysroot.deployment_dirpath(&booted.deployment);
            let deployment = storage.physical_root_path.join(deployment.as_str());
            let deployment_dir = Dir::open_ambient_dir(&deployment, ambient_authority())
                .with_context(|| format!("Opening {deployment}"))?;
            // Something mounted there would not be the image's /var.
            if deployment_dir.is_mountpoint(VAR)? == Some(true) {
                bail!("{deployment}/{VAR} is a mountpoint");
            }
            ImageVar::ostree(&deployment)
        }
        crate::store::BootedStorageKind::Composefs(booted) => ImageVar::composefs(
            &storage.physical_root,
            &booted.cmdline.digest,
            booted.cmdline.allow_missing_fsverity,
        )?,
    };
    let root = Dir::open_ambient_dir("/", ambient_authority())?;
    let policy = if crate::lsm::selinux_enabled() {
        crate::lsm::new_sepolicy_at(&root)?
    } else {
        None
    };
    let mut prepared = Prepared::default();
    let populated = populate_scope(
        &root,
        "/".into(),
        scope,
        &mounts,
        &eligible,
        &source,
        &mut prepared,
    );
    drop(source);
    finish(&root, None, &prepared, policy.as_ref(), populated)
}

/// The filesystems among `eligible` (relative to /var, like all of
/// `mounts`) at or below `scope`, or an error naming what is mounted there
/// if none is.
fn scope_targets(
    scope: &Utf8Path,
    mounts: &[Utf8PathBuf],
    eligible: &[Utf8PathBuf],
) -> Result<Vec<Utf8PathBuf>> {
    let in_scope = |m: &&Utf8PathBuf| m.starts_with(scope);
    let targets: Vec<_> = eligible.iter().filter(in_scope).cloned().collect();
    if targets.is_empty() {
        let scope = Utf8Path::new("/").join(target_path(scope));
        let found: Vec<_> = mounts
            .iter()
            .filter(in_scope)
            .map(|m| format!("/{}", target_path(m)))
            .collect();
        if found.is_empty() {
            bail!("No filesystem is mounted at or below {scope}");
        }
        bail!(
            "No filesystem that bootc initializes is mounted at or below {scope}, only {}: \
             it initializes block-device filesystems mounted from their root",
            found.join(", ")
        );
    }
    Ok(targets)
}

/// Day two: fill the `eligible` filesystems at or below `scope` with
/// [`populate_targets`], keeping all of `mounts` as boundaries: a tmpfs or
/// network filesystem mounted below an empty volume is left alone, and
/// doesn't make the volume count as holding data.
fn populate_scope(
    root: &Dir,
    root_path: &Utf8Path,
    scope: &Utf8Path,
    mounts: &[Utf8PathBuf],
    eligible: &[Utf8PathBuf],
    source: &ImageVar,
    prepared: &mut Prepared,
) -> Result<()> {
    let targets = scope_targets(scope, mounts, eligible)?;
    populate_targets(root, root_path, None, mounts, &targets, source, prepared)
}

/// Flush the filesystem of a mount, surfacing writeback errors.
fn sync(root: &Dir, mount: &Utf8Path) -> Result<()> {
    let path = target_path(mount);
    // cap-std opens directories with O_PATH, which syncfs() rejects.
    let fd = rustix::fs::openat(
        root,
        path.as_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("Opening /{path}"))?;
    rustix::fs::syncfs(&fd).with_context(|| format!("Syncing /{path}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::cap_std::fs::{MetadataExt, Permissions, PermissionsExt};
    use cap_std_ext::cap_tempfile::TempDir;

    /// [`populate`] into a fresh [`Prepared`].
    fn populated(
        root: &Dir,
        root_path: &Utf8Path,
        stateroot_var: Option<&Utf8Path>,
        mounts: &[Utf8PathBuf],
        source: &ImageVar,
    ) -> Result<Prepared> {
        let mut prepared = Prepared::default();
        populate(
            root,
            root_path,
            stateroot_var,
            mounts,
            source,
            &mut prepared,
        )?;
        Ok(prepared)
    }

    fn paths(p: &[&str]) -> Vec<Utf8PathBuf> {
        p.iter().map(Utf8PathBuf::from).collect()
    }

    #[test]
    fn nested_filesystems() {
        let mounts = paths(&["", "lib", "opt", "opt/app", "opt/app/data/x", "optional"]);
        // (parent, its direct children)
        let cases: &[(&str, &[&str])] = &[
            ("", &["lib", "opt", "optional"]),
            ("opt", &["opt/app"]),
            ("opt/app", &["opt/app/data/x"]),
            ("lib", &[]),
            ("srv", &[]),
        ];
        for (parent, expected) in cases {
            let got: Vec<&str> = children(Utf8Path::new(parent), &mounts)
                .into_iter()
                .map(|p| p.as_str())
                .collect();
            assert_eq!(&got, expected, "{parent}");
        }
        // Without a /var filesystem, the top-level ones have no parent.
        let mounts = paths(&["opt/app", "lib/appdb"]);
        assert_eq!(children("".into(), &mounts).len(), 2);
    }

    #[test]
    fn empty_filesystem() -> Result<()> {
        // Entries below /var (a trailing slash denotes a directory), mounts
        // relative to /var, and whether the /var filesystem counts as empty.
        // Nested filesystems are judged on their own.
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
            (
                &["lib/", "lib/app/", "lib/app/state"],
                &["", "lib/app"],
                true,
            ),
            (&["lib/", "lib/lost+found/"], &["", "lib/app"], false),
            (&["lib/", "tmp/"], &["", "lib/app"], false),
            (&["lib/", "lib/state"], &["", "lib/app"], false),
        ];
        for (entries, mounts, expected) in cases {
            let root = TempDir::new(ambient_authority())?;
            for entry in *entries {
                match entry.strip_suffix('/') {
                    Some(dir) => root.create_dir_all(dir)?,
                    None => root.write(entry, "data")?,
                }
            }
            let mounts = paths(mounts);
            let nested = children("".into(), &mounts);
            assert_eq!(
                is_empty_fs(&root, "".into(), "".into(), &nested)?,
                *expected,
                "{entries:?} {mounts:?}"
            );
        }
        Ok(())
    }

    /// A temporary installation root.
    struct TestRoot {
        _temp: tempfile::TempDir,
        dir: Dir,
        path: Utf8PathBuf,
    }

    impl std::ops::Deref for TestRoot {
        type Target = Dir;
        fn deref(&self) -> &Dir {
            &self.dir
        }
    }

    impl TestRoot {
        fn new() -> Result<Self> {
            let temp = tempfile::tempdir()?;
            let path = Utf8PathBuf::try_from(temp.path().to_owned())?;
            let dir = Dir::open_ambient_dir(&path, ambient_authority())?;
            Ok(Self {
                _temp: temp,
                dir,
                path,
            })
        }

        /// The image's /var, at `image/var`.
        fn image(&self) -> ImageVar {
            ImageVar {
                path: self.path.join("image/var"),
                hardlinks: true,
                _mount: None,
            }
        }

        fn populate(&self, mounts: &[Utf8PathBuf]) -> Result<Vec<Utf8PathBuf>> {
            let prepared = populated(&self.dir, &self.path, None, mounts, &self.image())?;
            assert!(!prepared.stateroot_var);
            Ok(prepared.mounts)
        }
    }

    /// A root with some image content.
    fn image_root() -> Result<TestRoot> {
        let root = TestRoot::new()?;
        root.create_dir_all("image/var/opt/app")?;
        root.write("image/var/opt/app/seed", "image seed")?;
        root.set_permissions("image/var/opt/app/seed", Permissions::from_mode(0o640))?;
        root.write("image/var/opt/parent", "parent seed")?;
        root.symlink_contents("seed", "image/var/opt/app/link")?;
        Ok(root)
    }

    #[test]
    fn populate_single_filesystem() -> Result<()> {
        // Copying with nested filesystems needs a mount namespace; see
        // mounted_var_filesystems below.
        for (mount, existing) in [
            ("", false),
            ("opt", false),
            ("opt", true),
            ("opt/app", false),
        ] {
            let root = image_root()?;
            let mounts = paths(&[mount]);
            root.create_dir_all(target_path(mount.into()).join("lost+found"))?;
            if existing {
                root.create_dir_all("var/opt/app")?;
                root.write("var/opt/app/seed", "existing state")?;
            }
            let initialized = root.populate(&mounts)?;
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
            root.write("image/var/opt/app/new-file", "new image")?;
            assert!(root.populate(&mounts)?.is_empty());
            assert!(!root.try_exists("var/opt/app/new-file")?);
        }
        Ok(())
    }

    #[test]
    fn populate_failure() -> Result<()> {
        if rustix::process::geteuid().is_root() {
            // root reads the unreadable file below anyway
            return Ok(());
        }
        let root = image_root()?;
        root.write("image/var/opt/app/secret", "secret")?;
        root.set_permissions("image/var/opt/app/secret", Permissions::from_mode(0o000))?;
        root.create_dir_all("var/opt/app")?;
        let mounts = paths(&["opt/app"]);
        let err = root.populate(&mounts).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.starts_with("Initializing /var/opt/app (") && msg.contains("partly filled"),
            "{msg}"
        );
        // cp copied what it could
        assert_eq!(root.read_to_string("var/opt/app/seed")?, "image seed");
        // A later run leaves it alone
        assert!(root.populate(&mounts)?.is_empty());
        assert!(!root.try_exists("var/opt/app/secret")?);
        Ok(())
    }

    #[test]
    fn populate_failure_after_success() -> Result<()> {
        // The first filesystem is filled, the second fails (its path in the
        // image is a symlink, which also stops root): the first must still be
        // finished, since a retry leaves it alone.
        let root = image_root()?;
        root.create_dir_all("image/var/srv")?;
        root.symlink_contents("elsewhere", "image/var/srv/b")?;
        root.create_dir_all("var/opt/app")?;
        root.create_dir_all("var/srv/b")?;
        let mounts = paths(&["opt/app", "srv/b"]);
        let mut prepared = Prepared::default();
        let populated = populate(
            &root,
            &root.path,
            None,
            &mounts,
            &root.image(),
            &mut prepared,
        );
        let copy_error = format!("{:#}", populated.as_ref().unwrap_err());
        assert!(copy_error.contains("/var/srv"), "{copy_error}");
        assert_eq!(prepared.mounts, paths(&["opt/app"]));
        assert_eq!(root.read_to_string("var/opt/app/seed")?, "image seed");
        let mut recorder = Recorder::default();
        let err = finish_using(&mut recorder, None, &prepared, populated).unwrap_err();
        assert_eq!(recorder.calls, ["label opt/app", "sync opt/app"]);
        assert_eq!(format!("{err:#}"), copy_error);
        // The real thing: sync works on a temporary directory
        finish(&root, None, &prepared, None, Ok(()))?;
        Ok(())
    }

    /// A [`Finisher`] that records what it is asked to do, failing the
    /// calls in `fail`.
    #[derive(Default)]
    struct Recorder {
        calls: Vec<String>,
        fail: Vec<&'static str>,
    }

    impl Recorder {
        fn call(&mut self, call: String) -> Result<()> {
            let failed = self.fail.contains(&call.as_str());
            self.calls.push(call);
            if failed {
                bail!("{} failed", self.calls.last().unwrap());
            }
            Ok(())
        }
    }

    impl Finisher for Recorder {
        fn label_stateroot_var(&mut self, var: &Utf8Path) -> Result<()> {
            self.call(format!("label {var} as /var"))
        }

        fn label(&mut self, mount: &Utf8Path) -> Result<()> {
            self.call(format!("label {mount}"))
        }

        fn sync(&mut self, mount: &Utf8Path) -> Result<()> {
            self.call(format!("sync {mount}"))
        }
    }

    #[test]
    fn finish_after_failure() {
        // Labeling the stateroot var fails, and the first filesystem, and
        // syncing the second: each filesystem is still synced, and finished,
        // and the errors are reported after the copy error.
        let prepared = Prepared {
            stateroot_var: true,
            mounts: paths(&["opt/app", "srv"]),
        };
        let stateroot_var = Some(Utf8Path::new("state/var"));
        for populated in [Ok(()), Err(anyhow::anyhow!("copy failed"))] {
            let copy_failed = populated.is_err();
            let mut recorder = Recorder {
                fail: vec!["label state/var as /var", "label opt/app", "sync srv"],
                ..Default::default()
            };
            let err = finish_using(&mut recorder, stateroot_var, &prepared, populated)
                .unwrap_err()
                .to_string();
            assert_eq!(
                recorder.calls,
                [
                    "label state/var as /var",
                    "label opt/app",
                    "sync opt/app",
                    "label srv",
                    "sync srv"
                ]
            );
            let failures = "label state/var as /var failed; label opt/app failed; sync srv failed";
            let expected = if copy_failed {
                format!(
                    "copy failed; finishing the filesystems initialized before that also failed: {failures}"
                )
            } else {
                format!("Finishing the initialized filesystems failed: {failures}")
            };
            assert_eq!(err, expected);
        }
        // A stateroot var that populate didn't fill isn't labeled
        let mut recorder = Recorder::default();
        let unfilled = Prepared {
            stateroot_var: false,
            ..Default::default()
        };
        finish_using(&mut recorder, stateroot_var, &unfilled, Ok(())).unwrap();
        assert!(recorder.calls.is_empty());
        // Nothing to finish, or nothing failing: populate's result as is
        let err = finish_using(
            &mut Recorder::default(),
            stateroot_var,
            &prepared,
            Err(anyhow::anyhow!("copy failed")),
        );
        assert_eq!(err.unwrap_err().to_string(), "copy failed");
    }

    #[test]
    fn finish_labels_and_syncs() -> Result<()> {
        // The real finisher, with a policy of its own
        use crate::lsm::testutil::*;
        const OTHER: &str = "system_u:object_r:default_t:s0";
        const VAR: &str = "system_u:object_r:var_t:s0";
        const APP: &str = "system_u:object_r:usr_t:s0";
        let root = TestRoot::new()?;
        root.create_dir("policy")?;
        let policy = file_contexts_policy(
            &root.open_dir("policy")?,
            &format!("/.*\t{OTHER}\n/var(/.*)?\t{VAR}\n/var/opt/app(/.*)?\t{APP}\n"),
        )?;
        let app = ["var/opt/app", "var/opt/app/data", "var/opt/app/data/f"];
        root.create_dir_all("var/opt/app/data")?;
        root.write("var/opt/app/data/f", "")?;
        if let Some(why) = cannot_label(&root, "var/opt/app/data/f", APP) {
            eprintln!("skipping finish_labels_and_syncs: {why}");
            return Ok(());
        }
        assert!(is_unlabeled(&root, "var/opt/app/data/f")?);
        // Without a policy, nothing is labeled
        for p in app {
            unlabel(&root, p)?;
        }
        Finish {
            root: &root,
            policy: None,
        }
        .label("opt/app".into())?;
        for p in app {
            assert!(is_unlabeled(&root, p)?, "{p}");
        }
        let mut finish = Finish {
            root: &root,
            policy: Some(&policy),
        };
        finish.label("opt/app".into())?;
        for p in app {
            assert_eq!(label(&root, p)?, APP, "{p}");
        }
        // Syncing opens the filesystem: a missing one fails
        finish.sync("opt/app".into())?;
        assert!(finish.sync("missing".into()).is_err());
        // The stateroot var is labeled as /var, whatever its path
        root.create_dir_all("state/var/lib")?;
        for p in ["state/var", "state/var/lib"] {
            unlabel(&root, p)?;
        }
        finish.label_stateroot_var("state/var".into())?;
        for p in ["state/var", "state/var/lib"] {
            assert_eq!(label(&root, p)?, VAR, "{p}");
        }
        Ok(())
    }

    #[test]
    fn prepare_unseeded_mount() -> Result<()> {
        // The image has no /var/srv; the empty mount still needs labeling.
        let root = image_root()?;
        root.create_dir_all("var/srv/lost+found")?;
        let mounts = paths(&["srv"]);
        assert_eq!(root.populate(&mounts)?, mounts);
        Ok(())
    }

    #[test]
    fn source_symlink() -> Result<()> {
        // Only filesystems that would be initialized are validated.
        for existing in [false, true] {
            let root = TestRoot::new()?;
            root.create_dir_all("image/var")?;
            root.create_dir_all("var/opt/app")?;
            root.symlink_contents("/outside", "image/var/opt")?;
            if existing {
                root.write("var/opt/app/data", "existing state")?;
            }
            let result = root.populate(&paths(&["opt/app"]));
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
    fn deferred_stateroot_var() -> Result<()> {
        // (mounts, whether the stateroot var is filled)
        let cases: &[(&[&str], bool)] = &[
            (&[], true),
            (&["srv"], true),
            // Hidden at boot by a /var filesystem
            (&[""], false),
        ];
        for (mounts, filled) in cases {
            let root = image_root()?;
            root.create_dir_all("state")?;
            crate::install::defer_var::mark(&root, "state/var".into(), None)?;
            let mounts = paths(mounts);
            for m in &mounts {
                root.create_dir_all(target_path(m))?;
            }
            let prepared = populated(
                &root,
                &root.path,
                Some("state/var".into()),
                &mounts,
                &root.image(),
            )?;
            assert_eq!(prepared.stateroot_var, *filled, "{mounts:?}");
            assert_eq!(
                root.try_exists("state/var/opt/app/seed")?,
                *filled,
                "{mounts:?}"
            );
            let marker = Utf8Path::new("state/var").join(crate::install::defer_var::MARKER);
            assert!(root.try_exists(marker)?);
        }
        Ok(())
    }

    #[test]
    fn deferred_stateroot_var_failure() -> Result<()> {
        // A file where the image has a directory stops cp, also as root
        let root = image_root()?;
        root.create_dir_all("state")?;
        crate::install::defer_var::mark(&root, "state/var".into(), None)?;
        root.write("state/var/opt", "not a directory")?;
        let mut prepared = Prepared::default();
        let err = populate(
            &root,
            &root.path,
            Some("state/var".into()),
            &[],
            &root.image(),
            &mut prepared,
        )
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.starts_with("Initializing /var (the deployment's state directory, /state/var) ("),
            "{msg}"
        );
        assert!(
            msg.contains(
                "partly filled. This is part of the installation: install again onto a fresh \
                 root filesystem: "
            ),
            "{msg}"
        );
        assert!(!prepared.stateroot_var);
        Ok(())
    }

    #[test]
    fn deployment_dir() -> Result<()> {
        let root = TempDir::new(ambient_authority())?;
        assert_eq!(
            only_dir(&root).unwrap_err().to_string(),
            "No deployment found"
        );
        root.create_dir("abc.0")?;
        root.write("abc.0.origin", "")?;
        assert_eq!(only_dir(&root)?, "abc.0");
        root.create_dir("def.0")?;
        assert!(only_dir(&root).is_err());
        Ok(())
    }

    #[test]
    fn sync_mounts() -> Result<()> {
        let root = TempDir::new(ambient_authority())?;
        root.create_dir_all("var/lib/app")?;
        sync(&root, "".into())?;
        sync(&root, "lib/app".into())?;
        let err = sync(&root, "missing".into()).unwrap_err();
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
        let root = image_root()?;
        root.create_dir_all("var/opt")?;
        let target = root.open_dir("var/opt")?;
        let name = std::ffi::OsStr::from_bytes(b"existing-\xff");
        target.write(name, "existing state")?;
        root.populate(&paths(&["opt"]))?;
        assert_eq!(target.read_to_string(name)?, "existing state");
        assert!(!target.try_exists("parent")?);
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
            |_| true,
            &mut paths,
        );
        assert_eq!(paths, vec![Utf8PathBuf::from("opt"), "opt/app".into()]);
        Ok(())
    }

    #[test]
    fn var_filesystem_marker() -> Result<()> {
        // Only a filesystem on /var itself gets the stateroot var marked
        for (mounts, marked) in [
            (&[][..], false),
            (&["opt/app"][..], false),
            (&[""][..], true),
            (&["", "opt/app"][..], true),
        ] {
            let root = TempDir::new(ambient_authority())?;
            root.create_dir_all("state/var")?;
            mark_var_filesystem(&root, "state/var".into(), &paths(mounts), None)?;
            let marker = Utf8Path::new("state/var").join(VAR_MOUNTS_MARKER);
            assert_eq!(root.try_exists(&marker)?, marked, "{mounts:?}");
        }
        Ok(())
    }

    #[test]
    fn day_two_targets() {
        let mounts = paths(&["", "opt/app", "opt/app/cache", "srv/nfs"]);
        let eligible = paths(&["", "opt/app"]);
        let targets = |scope: &str| {
            scope_targets(scope.into(), &mounts, &eligible).map_err(|e| e.to_string())
        };
        let ineligible = |scope: &str, found: &str| -> Result<Vec<Utf8PathBuf>, String> {
            Err(format!(
                "No filesystem that bootc initializes is mounted at or below {scope}, only \
                 {found}: it initializes block-device filesystems mounted from their root"
            ))
        };
        assert_eq!(targets(""), Ok(paths(&["", "opt/app"])));
        assert_eq!(targets("opt"), Ok(paths(&["opt/app"])));
        assert_eq!(targets("opt/app"), Ok(paths(&["opt/app"])));
        assert_eq!(
            targets("opt/app/cache"),
            ineligible("/var/opt/app/cache", "/var/opt/app/cache")
        );
        assert_eq!(targets("srv"), ineligible("/var/srv", "/var/srv/nfs"));
        assert_eq!(
            targets("log"),
            Err("No filesystem is mounted at or below /var/log".into())
        );
    }

    #[test]
    fn collect_block_backed() -> Result<()> {
        // A booted system's /var: only block-backed filesystems are ours.
        let mounts: bootc_mount::Findmnt = serde_json::from_value(serde_json::json!({
            "filesystems": [{
                "source": "/dev/vda4[/ostree/deploy/default/var]", "target": "/var",
                "maj:min": "0:1", "fstype": "ext4", "options": "rw", "children": [
                    {"source": "/dev/mapper/vg_data-app", "target": "/var/opt/app",
                     "maj:min": "0:2", "fstype": "xfs", "options": "rw"},
                    {"source": "shm", "target": "/var/lib/containers/storage/overlay-containers/x/userdata/shm",
                     "maj:min": "0:3", "fstype": "tmpfs", "options": "rw"},
                    {"source": "sunrpc", "target": "/var/lib/nfs/rpc_pipefs",
                     "maj:min": "0:4", "fstype": "rpc_pipefs", "options": "rw"},
                    {"source": "server:/export", "target": "/var/srv/nfs",
                     "maj:min": "0:5", "fstype": "nfs4", "options": "rw"},
                    {"source": "/dev/vda4[/ostree/deploy/default/var/lib/kubelet/x]",
                     "target": "/var/lib/kubelet/pods/p/volume-subpaths/v",
                     "maj:min": "0:1", "fstype": "ext4", "options": "rw"}
                ]
            }]
        }))?;
        let mut paths = Vec::new();
        collect(
            "/var".into(),
            &mounts.filesystems,
            is_block_backed,
            &mut paths,
        );
        assert_eq!(paths, vec![Utf8PathBuf::new(), "opt/app".into()]);
        Ok(())
    }

    /// Runs [`mounted_var_filesystems`] in a private user and mount
    /// namespace, so that it runs with the other tests. It is skipped, with
    /// a message, where unprivileged user namespaces aren't available.
    #[test]
    fn mounted_var_filesystems_unshared() -> Result<()> {
        const NAME: &str = "install::var_mounts::tests::mounted_var_filesystems";
        let probe = Command::new("unshare").args(["-Urnm", "true"]).output();
        if !probe.as_ref().is_ok_and(|o| o.status.success()) {
            eprintln!("skipping {NAME}: unshare -Urnm is not available here: {probe:?}");
            return Ok(());
        }
        let out = Command::new("unshare")
            .arg("-Urnm")
            .arg(std::env::current_exe()?)
            .args(["--exact", NAME, "--ignored", "--test-threads=1"])
            .output()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "{stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires a private user/mount namespace; mounted_var_filesystems_unshared runs it"]
    fn mounted_var_filesystems() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = Utf8Path::from_path(temp.path()).unwrap();
        Command::new("mount")
            .args(["--bind", path.as_str(), path.as_str()])
            .run_capture_stderr()?;
        let tmpfs = |p: &str| {
            Command::new("mount")
                .args(["-t", "tmpfs", "tmpfs"])
                .arg(path.join(p))
                .run_capture_stderr()
        };
        let result = (|| -> Result<()> {
            assert!(discover(path)?.is_empty());
            let root = Dir::open_ambient_dir(path, ambient_authority())?;
            // The root and lost+found of a fresh filesystem are labeled
            // unconditionally, but not a lost+found something is mounted on
            root.create_dir_all("fresh/lost+found")?;
            let fresh = |p: &str| fresh_roots(&root, Utf8Path::new(p));
            assert_eq!(fresh("fresh")?, paths(&["fresh", "fresh/lost+found"]));
            tmpfs("fresh/lost+found")?;
            assert_eq!(fresh("fresh")?, paths(&["fresh"]));
            root.create_dir_all("image/var/opt/app/data")?;
            root.write("image/var/opt/app/seed", "seed")?;
            root.set_permissions("image/var/opt/app/seed", Permissions::from_mode(0o640))?;
            root.set_permissions("image/var/opt/app", Permissions::from_mode(0o750))?;
            rustix::fs::lsetxattr(
                path.join("image/var/opt/app").as_str(),
                c"user.test",
                b"image",
                rustix::fs::XattrFlags::empty(),
            )?;
            root.hard_link("image/var/opt/app/seed", &root, "image/var/parent-link")?;
            root.hard_link(
                "image/var/opt/app/seed",
                &root,
                "image/var/opt/app/same-volume-link",
            )?;
            root.symlink_contents("seed", "image/var/opt/app/symlink")?;
            root.write("image/var/opt/app/data/db", "image db")?;
            root.write("image/var/opt/top", "top")?;
            let image = ImageVar {
                path: path.join("image/var"),
                hardlinks: true,
                _mount: None,
            };
            // /var, with /var/opt/app below it, and /var/opt/app/data below
            // that, which already has data.
            root.create_dir("var")?;
            tmpfs("var")?;
            root.create_dir_all("var/opt/app")?;
            tmpfs("var/opt/app")?;
            root.create_dir_all("var/opt/app/data")?;
            tmpfs("var/opt/app/data")?;
            root.write("var/opt/app/data/existing", "existing state")?;
            root.set_permissions("var/opt/app/data", Permissions::from_mode(0o700))?;
            let mounts = discover(path)?;
            assert_eq!(mounts, paths(&["", "opt/app", "opt/app/data"]));
            assert_eq!(
                populated(&root, path, None, &mounts, &image)?.mounts,
                paths(&["", "opt/app"])
            );
            // Copying /var/opt/app didn't touch the root of the volume
            // mounted below it either: it was hidden
            assert_eq!(root.metadata("var/opt/app/data")?.mode() & 0o7777, 0o700);
            for file in [
                "var/parent-link",
                "var/opt/app/seed",
                "var/opt/app/same-volume-link",
            ] {
                assert_eq!(root.read_to_string(file)?, "seed");
                assert_eq!(root.metadata(file)?.mode() & 0o777, 0o640);
            }
            // Each file is on the filesystem that holds it at boot. Hardlinks
            // stay within one filesystem and are split across them.
            let dev = |p: &str| root.metadata(p).map(|m| m.dev());
            let ino = |p: &str| root.metadata(p).map(|m| m.ino());
            assert_ne!(dev("var/parent-link")?, dev("var/opt/app/seed")?);
            assert_eq!(dev("var/opt/top")?, dev("var")?);
            assert_eq!(
                ino("var/opt/app/seed")?,
                ino("var/opt/app/same-volume-link")?
            );
            assert_eq!(root.metadata("var/opt/app")?.mode() & 0o777, 0o750);
            assert_eq!(
                root.read_link("var/opt/app/symlink")?,
                std::path::Path::new("seed")
            );
            // The non-empty nested filesystem is left alone, and nothing of
            // it lands on its parent.
            assert!(!root.try_exists("var/opt/app/data/db")?);
            assert_eq!(
                root.read_to_string("var/opt/app/data/existing")?,
                "existing state"
            );
            Command::new("umount")
                .arg(path.join("var/opt/app/data"))
                .run_capture_stderr()?;
            assert_eq!(root.read_dir("var/opt/app/data")?.count(), 0);
            tmpfs("var/opt/app/data")?;
            root.write("var/opt/app/seed", "existing state")?;
            let mounts = discover(path)?;
            assert_eq!(
                populated(&root, path, None, &mounts, &image)?.mounts,
                paths(&["opt/app/data"])
            );
            assert_eq!(root.read_to_string("var/opt/app/seed")?, "existing state");
            assert_eq!(root.read_to_string("var/opt/app/data/db")?, "image db");

            // No /var filesystem: a deferred stateroot var gets everything
            // but what the nested filesystems hold, which goes only there.
            bootc_mount::unmount_recursive(&path.join("var"))?;
            root.create_dir_all("var/opt/app")?;
            tmpfs("var/opt/app")?;
            crate::install::defer_var::mark(&root, "state/var".into(), None)?;
            let mounts = discover(path)?;
            assert_eq!(mounts, paths(&["opt/app"]));
            let prepared = populated(&root, path, Some("state/var".into()), &mounts, &image)?;
            assert!(prepared.stateroot_var);
            assert_eq!(prepared.mounts, mounts);
            assert_eq!(root.read_to_string("state/var/opt/top")?, "top");
            assert_eq!(root.read_to_string("state/var/parent-link")?, "seed");
            assert_eq!(root.read_to_string("var/opt/app/seed")?, "seed");
            // Only the mountpoint, like the image's
            assert_eq!(root.read_dir("state/var/opt/app")?.count(), 0);
            assert_eq!(root.metadata("state/var/opt/app")?.mode() & 0o777, 0o750);
            let mut value = [0u8; 16];
            let len = rustix::fs::lgetxattr(
                path.join("state/var/opt/app").as_str(),
                c"user.test",
                &mut value[..],
            )?;
            assert_eq!(&value[..len], b"image");

            // Day two: an empty volume with a foreign mount below it (a
            // tmpfs, which isn't eligible) is filled around that mount, which
            // is left alone.
            root.create_dir_all("image/var/srv/vol/cache")?;
            root.write("image/var/srv/vol/seed", "vol seed")?;
            root.write("image/var/srv/vol/cache/x", "image cache")?;
            root.create_dir_all("var/srv/vol")?;
            tmpfs("var/srv/vol")?;
            root.create_dir_all("var/srv/vol/cache")?;
            tmpfs("var/srv/vol/cache")?;
            root.write("var/srv/vol/cache/own", "foreign")?;
            let mounts = discover(path)?;
            assert_eq!(mounts, paths(&["opt/app", "srv/vol", "srv/vol/cache"]));
            let eligible = paths(&["opt/app", "srv/vol"]);
            let mut prepared = Prepared::default();
            populate_scope(
                &root,
                path,
                "srv".into(),
                &mounts,
                &eligible,
                &image,
                &mut prepared,
            )?;
            assert_eq!(prepared.mounts, paths(&["srv/vol"]));
            assert_eq!(root.read_to_string("var/srv/vol/seed")?, "vol seed");
            assert_eq!(root.read_to_string("var/srv/vol/cache/own")?, "foreign");
            assert!(!root.try_exists("var/srv/vol/cache/x")?);
            Ok(())
        })();
        let unmount = bootc_mount::unmount_recursive(path);
        result?;
        unmount
    }
}
