//! Mount helpers for bootc-initramfs

use std::{
    ffi::OsString,
    fmt::Debug,
    io::ErrorKind,
    os::fd::{AsFd, AsRawFd, OwnedFd},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::Parser;
use rustix::{
    fs::{CWD, Mode, OFlags, major, minor, mkdirat, openat, stat, symlink},
    io::Errno,
    mount::{
        FsMountFlags, MountAttrFlags, OpenTreeFlags, UnmountFlags, fsconfig_create,
        fsconfig_set_string, fsmount, open_tree, unmount,
    },
    path,
};

use serde::Deserialize;

use composefs::{
    fsverity::{FsVerityHashValue, Sha512HashValue},
    mount::FsHandle,
    mountcompat::{overlayfs_set_fd, overlayfs_set_lower_and_data_fds, prepare_mount},
    repository::{ImageNotFound, Repository},
};
use composefs_boot::cmdline::{ComposefsCmdline, KARG_COMPOSEFS_DIGEST, KARG_V2};
use composefs_ctl::composefs;
use composefs_ctl::composefs_boot;

use fn_error_context::context;

use linux_kernel_cmdline::utf8::Cmdline;

// mount_setattr syscall support
const MOUNT_ATTR_RDONLY: u64 = 0x00000001;

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// Set mount attributes using mount_setattr syscall
#[context("Setting mount attributes")]
#[allow(unsafe_code)]
fn mount_setattr(fd: impl AsFd, flags: libc::c_int, attr: &MountAttr) -> Result<()> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            fd.as_fd().as_raw_fd(),
            c"".as_ptr(),
            flags,
            attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    if ret == -1 {
        Err(std::io::Error::last_os_error())?;
    }
    Ok(())
}

/// Set a detached mount tree read-only without reopening its path.
#[context("Setting mount readonly")]
pub fn set_mount_readonly(fd: impl AsFd) -> Result<()> {
    let attr = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    mount_setattr(fd, libc::AT_EMPTY_PATH, &attr)
}

/// Set a mount and every mount below it read-only.
#[context("Setting mount tree readonly")]
pub fn set_mount_tree_readonly(fd: impl AsFd) -> Result<()> {
    let attr = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    mount_setattr(fd, libc::AT_EMPTY_PATH | libc::AT_RECURSIVE, &attr)
}

/// Types of mounts supported by the configuration
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MountType {
    /// No mount; "root" is an alias meaning this dir is part of the root mount
    #[serde(alias = "root")]
    None,
    /// Bind mount
    Bind,
    /// Overlay mount
    Overlay,
    /// Transient mount; "volatile" is an alias (Unix convention for tmpfs)
    #[serde(alias = "volatile")]
    Transient,
}

#[derive(Debug, Default, Deserialize, PartialEq)]
struct RootConfig {
    #[serde(default)]
    transient: bool,
}

/// Configuration for mount operations
#[derive(Debug, Default, Deserialize, PartialEq)]
pub struct MountConfig {
    /// The type of mount to use
    pub mount: Option<MountType>,
    #[serde(default)]
    /// Whether this mount should be transient (temporary)
    pub transient: bool,
}

/// The setup-root configuration, see `bootc-setup-root-conf(5)`.
#[derive(Debug, Deserialize, Default, PartialEq)]
pub struct Config {
    /// How `/etc` is mounted
    #[serde(default)]
    pub etc: MountConfig,
    /// How `/var` is mounted
    #[serde(default)]
    pub var: MountConfig,
    #[serde(default)]
    root: RootConfig,
}

/// Default path to the setup-root configuration file, relative to the booted root.
pub const SETUP_ROOT_CONF_PATH: &str = "/usr/lib/composefs/setup-root-conf.toml";

/// Returns `true` if the configuration at `path` requests a transient `/etc`
/// overlay.  Used by the systemd generator to decide whether to emit the
/// SELinux relabel unit *before* those mounts exist (the generator runs before
/// `local-fs.target`).
///
/// Returns `false` if the file is absent or unreadable (safe default: no unit
/// emitted for non-transient systems).
pub fn config_has_transient_submounts(path: &std::path::Path) -> bool {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!("Could not read {}: {e:#}", path.display());
            return false;
        }
    };
    let config: Config = match toml::from_str(&text) {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("Could not parse {}: {e:#}", path.display());
            return false;
        }
    };
    // Only /etc overlay triggers the relabel unit.
    let is_transient = |mc: &MountConfig| match mc.mount {
        Some(mt) => mt == MountType::Transient,
        None => mc.transient,
    };
    is_transient(&config.etc)
}

/// Command-line arguments
#[derive(Parser, Debug)]
pub struct Args {
    #[arg(help = "Execute this command (for testing)")]
    /// Execute this command (for testing)
    pub cmd: Vec<OsString>,

    #[arg(
        long,
        default_value = "/sysroot",
        help = "sysroot directory in initramfs"
    )]
    /// sysroot directory in initramfs
    pub sysroot: PathBuf,

    #[arg(
        long,
        default_value = "/usr/lib/composefs/setup-root-conf.toml",
        help = "Config path (for testing)"
    )]
    /// Config path (for testing)
    pub config: PathBuf,

    // we want to test in a userns, but can't mount erofs there
    #[arg(long, help = "Bind mount root-fs from (for testing)")]
    /// Bind mount root-fs from (for testing)
    pub root_fs: Option<PathBuf>,

    #[arg(long, help = "Kernel commandline args (for testing)")]
    /// Kernel commandline args (for testing)
    pub cmdline: Option<Cmdline<'static>>,

    #[arg(long, help = "Mountpoint (don't replace sysroot, for testing)")]
    /// Mountpoint (don't replace sysroot, for testing)
    pub target: Option<PathBuf>,
}

/// Wrapper around [`composefs::mount::mount_at`]
pub fn mount_at_wrapper(
    fs_fd: impl AsFd,
    dirfd: impl AsFd,
    path: impl path::Arg + Debug + Clone,
) -> Result<()> {
    composefs::mount::mount_at(fs_fd, dirfd, path.clone())
        .with_context(|| format!("Mounting at path {path:?}"))
}

/// Wrapper around [`rustix::fs::openat`]
#[context("Opening dir {name:?}")]
pub fn open_dir(dirfd: impl AsFd, name: impl AsRef<Path> + Debug) -> Result<OwnedFd> {
    let res = openat(
        dirfd,
        name.as_ref(),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    );

    Ok(res?)
}

#[context("Ensure dir")]
fn ensure_dir(dirfd: impl AsFd, name: &str, mode: Option<rustix::fs::Mode>) -> Result<OwnedFd> {
    match mkdirat(dirfd.as_fd(), name, mode.unwrap_or(0o700.into())) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(err) => Err(err).with_context(|| format!("Creating dir {name}"))?,
    }

    open_dir(dirfd, name)
}

#[context("Bind mounting to path {path}")]
fn bind_mount(fd: impl AsFd, path: &str) -> Result<OwnedFd> {
    let res = open_tree(
        fd.as_fd(),
        path,
        OpenTreeFlags::OPEN_TREE_CLONE
            | OpenTreeFlags::OPEN_TREE_CLOEXEC
            | OpenTreeFlags::AT_EMPTY_PATH,
    );

    Ok(res?)
}

/// Mount a tmpfs to use as the upper layer for an overlay.
///
/// TODO: sync these options with systemd's root mounting, there's some tweaks there for default tmpfs
/// and we may want to make this configurable anyways i nthe future
///
/// See <https://github.com/containers/bootc/issues/1992>.
#[context("Mounting tmpfs for overlay")]
fn mount_tmpfs_for_overlay() -> Result<OwnedFd> {
    let tmpfs = FsHandle::open("tmpfs")?;
    fsconfig_create(tmpfs.as_fd())?;
    Ok(fsmount(
        tmpfs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?)
}

/// Build an overlayfs fsmount fd from an existing state dir (upper+work).
///
/// upper is 0755: the merged view inherits permissions from upperdir, so 0700
/// would make the mountpoint inaccessible to non-root processes.  work is
/// kernel-internal and never visible; 0700 is fine.
/// See: <https://github.com/composefs/composefs-rs/issues/287>
fn build_overlay_fd(
    base: impl AsFd,
    state: impl AsFd,
    source: &str,
    mount_attr_flags: Option<MountAttrFlags>,
) -> Result<OwnedFd> {
    let upper = ensure_dir(state.as_fd(), "upper", Some(0o755.into()))?;
    let work = ensure_dir(state.as_fd(), "work", Some(0o700.into()))?;

    let overlayfs = FsHandle::open("overlay")?;
    fsconfig_set_string(overlayfs.as_fd(), "source", source)?;
    overlayfs_set_fd(overlayfs.as_fd(), "workdir", work.as_fd())?;
    overlayfs_set_fd(overlayfs.as_fd(), "upperdir", upper.as_fd())?;
    overlayfs_set_lower_and_data_fds(&overlayfs, base.as_fd(), &[])?;
    fsconfig_create(overlayfs.as_fd())?;
    Ok(fsmount(
        overlayfs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        mount_attr_flags.unwrap_or(MountAttrFlags::empty()),
    )?)
}

/// Mount a persistent state directory as an overlay on top of `base`,
/// attaching the result immediately at `.` relative to `base`.
#[context("Mounting state as overlay")]
fn overlay_state(
    base: impl AsFd,
    state: impl AsFd,
    source: &str,
    mount_attr_flags: Option<MountAttrFlags>,
) -> Result<()> {
    let fs = build_overlay_fd(&base, state, source, mount_attr_flags)?;
    mount_at_wrapper(fs, base, ".").context("Moving mount")
}

/// Creates a transient overlayfs with the passed-in fd as the lowerdir.
///
/// Returns a detached (not yet attached) `OwnedFd` for the overlay mount.
/// The caller is responsible for attaching it to the filesystem tree.
///
/// `source` is used verbatim as the overlay's `source` fsconfig option and
/// appears in `/proc/self/mountinfo`.  For the composefs root, pass
/// `"transient:composefs=<digest_hex>"` so that `composefs_booted()` can
/// recover the verity digest from the mount source after switch-root.  For
/// non-root transient mounts (e.g. `/usr`, `/var`) pass `"transient"`.
///
/// The SELinux label on `/` is fixed after boot by
/// `bootc-early-overlay-relabel.service`; no initramfs-side xattr write is
/// needed (kernel `fs_use_trans tmpfs` relabeling at policy-load time would
/// overwrite anything written here).
#[context("Creating transient overlayfs")]
pub fn overlay_transient(
    base: impl AsFd,
    source: &str,
    mount_attr_flags: Option<MountAttrFlags>,
) -> Result<OwnedFd> {
    let tmpfs = mount_tmpfs_for_overlay()?;
    let state = prepare_mount(tmpfs)?;
    build_overlay_fd(base, state, source, mount_attr_flags)
}

#[context("Opening rootfs")]
fn open_root_fs(path: &Path) -> Result<OwnedFd> {
    let rootfs = open_tree(
        CWD,
        path,
        OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
    )?;

    set_mount_readonly(&rootfs)?;

    Ok(rootfs)
}

/// Prepares a floating mount for composefs and returns the fd
///
/// # Arguments
/// * sysroot                - fd for /sysroot
/// * name                   - Name of the EROFS image to be mounted
/// * allow_missing_fsverity - Whether to allow mount without fsverity support
#[context("Mounting composefs image")]
pub fn mount_composefs_image(
    sysroot: &OwnedFd,
    name: &str,
    allow_missing_fsverity: bool,
) -> Result<OwnedFd> {
    // Use open_upgrade to handle upgrades from older composefs-rs versions
    // that lack meta.json: it infers the algorithm and verity mode from
    // existing objects, writes meta.json, and opens normally.
    let (mut repo, _upgraded) = Repository::<Sha512HashValue>::open_upgrade(sysroot, "composefs")?;
    if allow_missing_fsverity {
        repo.set_insecure();
    }
    let rootfs = repo
        .mount(name)
        .context("Failed to mount composefs image")?;

    set_mount_readonly(&rootfs)?;

    Ok(rootfs)
}

fn parse_composefs_candidates(cmdline: &str) -> Result<Vec<ComposefsCmdline<Sha512HashValue>>> {
    let mut candidates = Vec::new();
    let mut seen_legacy = false;

    // The repository policy is deliberately kept separate from the cmdline:
    // the '?' marker only requests that policy, and setup_root decides below
    // whether the repository permits it.  Parse the cmdline with the kernel
    // parser so quoted parameters remain a single parameter.
    for parameter in Cmdline::from(cmdline).iter() {
        let key = parameter.key();
        if &*key != KARG_COMPOSEFS_DIGEST && &*key != KARG_V2 {
            continue;
        }

        let value = parameter
            .value()
            .ok_or_else(|| anyhow::anyhow!("{key}= composefs kernel argument has no value"))?;
        if &*key == KARG_V2 {
            anyhow::ensure!(
                !seen_legacy,
                "duplicate {KARG_V2}= composefs kernel argument"
            );
            seen_legacy = true;
        }

        let parameter = format!("{key}={value}");
        if let Some(candidate) = ComposefsCmdline::<Sha512HashValue>::from_cmdline(&parameter)? {
            candidates.push(candidate);
        }
    }
    Ok(candidates)
}

fn select_composefs_candidate<T>(
    candidates: &[ComposefsCmdline<Sha512HashValue>],
    mut mount: impl FnMut(&ComposefsCmdline<Sha512HashValue>) -> Result<Option<T>>,
) -> Result<(T, ComposefsCmdline<Sha512HashValue>)> {
    for candidate in candidates {
        if let Some(mounted) = mount(candidate)? {
            return Ok((mounted, candidate.clone()));
        }
    }
    let tried = candidates
        .iter()
        .map(|candidate| candidate.digest().to_hex())
        .collect::<Vec<_>>()
        .join(", ");
    anyhow::bail!("no composefs image found (tried: {tried})")
}

fn mount_composefs_candidate(
    sysroot: &OwnedFd,
    candidate: &ComposefsCmdline<Sha512HashValue>,
    allow_missing_fsverity: bool,
) -> Result<Option<OwnedFd>> {
    // `allow_missing_fsverity` is repository policy, not a trust decision
    // supplied by the kernel command line.  A cmdline '?' may only request
    // the already-permitted insecure mode; it must never weaken strict policy.
    if candidate.is_insecure() && !allow_missing_fsverity {
        anyhow::bail!(
            "composefs candidate requests insecure fs-verity, but the repository policy is strict"
        );
    }

    match mount_composefs_image(
        sysroot,
        &candidate.digest().to_hex(),
        allow_missing_fsverity,
    ) {
        Ok(rootfs) => Ok(Some(rootfs)),
        Err(error) if error.downcast_ref::<ImageNotFound>().is_some() => Ok(None),
        Err(error) => Err(error),
    }
}

/// Mounts a subdirectory with the specified configuration
#[context("Mounting subdirectory")]
pub fn mount_subdir(
    new_root: impl AsFd,
    state: impl AsFd,
    subdir: &str,
    config: MountConfig,
    default: MountType,
) -> Result<()> {
    let mount_type = match config.mount {
        Some(mt) => mt,
        None => match config.transient {
            true => MountType::Transient,
            false => default,
        },
    };

    match mount_type {
        MountType::None => Ok(()),
        MountType::Bind => Ok(mount_at_wrapper(
            bind_mount(&state, subdir)?,
            &new_root,
            subdir,
        )?),
        MountType::Overlay => overlay_state(
            open_dir(&new_root, subdir)?,
            open_dir(&state, subdir)?,
            "overlay",
            None,
        ),
        MountType::Transient => {
            // For subdirectory transient mounts, create the overlay and immediately
            // attach it at the subdirectory path in new_root.
            let subdir_fd = open_dir(&new_root, subdir)?;
            let overlay_fd = overlay_transient(subdir_fd.as_fd(), "transient", None)?;
            mount_at_wrapper(overlay_fd, &new_root, subdir)
        }
    }
}

#[context("GPT workaround")]
/// Workaround for /dev/gpt-auto-root
pub fn gpt_workaround() -> Result<()> {
    // https://github.com/systemd/systemd/issues/35017
    let rootdev = stat("/dev/gpt-auto-root");

    let rootdev = match rootdev {
        Ok(r) => r,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => Err(e)?,
    };

    let target = format!(
        "/dev/block/{}:{}",
        major(rootdev.st_rdev),
        minor(rootdev.st_rdev)
    );
    // Handle the case where the symlink was already created before bootc
    // runs, e.g. by ostree-prepare-root
    // (https://github.com/ostreedev/ostree/pull/3608).
    match symlink(target, "/run/systemd/volatile-root") {
        Ok(()) | Err(Errno::EXIST) => Ok(()),
        Err(err) => Err(err).context("Creating /run/systemd/volatile-root"),
    }
}

/// The fstab, relative to the root.
const FSTAB: &str = "etc/fstab";

/// Written into the stateroot's var by `bootc install --defer-var`, before
/// the first deployment: the image's /var was not copied there.
pub const DEFER_VAR_MARKER: &str = ".bootc-defer-var";

/// Written into the stateroot's var by `bootc install
/// --initialize-var-mounts` when a filesystem is mounted on /var itself:
/// bootc filled (or left alone) that filesystem, which is /var at boot.
pub const VAR_MOUNTS_MARKER: &str = ".bootc-var-mounts";

/// The markers by which setup-root leaves a /var that the fstab mounts to
/// systemd.
const VAR_MARKERS: [&str; 2] = [DEFER_VAR_MARKER, VAR_MOUNTS_MARKER];

/// Read the regular file at `path` below `root`, resolving symlinks (also
/// absolute ones) within `root`, as the booted system will see it; `None`
/// if there is none, or it isn't a regular file.
fn read_in_root(root: impl AsFd, path: &str) -> Result<Option<Vec<u8>>> {
    use rustix::fs::{FileType, ResolveFlags, openat2};
    use std::io::Read;
    /// openat2(2) fails with EAGAIN when a concurrent rename might have let
    /// `..` escape the root; it suggests retrying.
    const ATTEMPTS: usize = 5;
    let open = || {
        openat2(
            &root,
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            ResolveFlags::IN_ROOT,
        )
    };
    let mut opened = open();
    for _ in 1..ATTEMPTS {
        if !matches!(opened, Err(Errno::AGAIN)) {
            break;
        }
        opened = open();
    }
    let fd = match opened {
        Ok(fd) => fd,
        Err(Errno::NOENT | Errno::NOTDIR | Errno::NXIO | Errno::NODEV) => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("Opening /{path}")),
    };
    let st = rustix::fs::fstat(&fd).with_context(|| format!("Querying /{path}"))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Ok(None);
    }
    let mut content = Vec::new();
    std::fs::File::from(fd)
        .read_to_end(&mut content)
        .with_context(|| format!("Reading /{path}"))?;
    Ok(Some(content))
}

/// Whether an fstab has a mount entry for /var, as systemd would mount
/// it: like libmount, only lines with at least a source, a mountpoint and
/// a filesystem type are entries, and swap entries don't mount anything.
/// Like ostree's system generator in `fstab_has_mount_entry()` (through
/// glibc's getmntent), fields are separated by spaces and tabs, and mount
/// options don't matter: `noauto` still counts.
fn fstab_mounts_var(fstab: &str) -> bool {
    fstab
        .lines()
        .filter_map(|line| {
            let mut fields = line.split([' ', '\t']).filter(|f| !f.is_empty());
            let spec = fields.next()?;
            if spec.starts_with('#') {
                return None;
            }
            Some((fields.next()?, fields.next()?))
        })
        .any(|(file, vfstype)| {
            vfstype != "swap"
                && file.starts_with('/')
                && file.split('/').filter(|p| !p.is_empty()).eq(["var"])
        })
}

/// Whether the fstab below `root` has a mount entry for /var. This runs on
/// every composefs boot, which must not fail over the fstab: it is read as
/// bytes and decoded lossily (the paths compared are ASCII), and when it
/// can't be read, the default /var bind mount is kept, with a warning.
fn root_fstab_mounts_var(root: impl AsFd) -> bool {
    match read_in_root(root, FSTAB) {
        Ok(fstab) => fstab.is_some_and(|f| fstab_mounts_var(&String::from_utf8_lossy(&f))),
        Err(e) => {
            // No tracing subscriber in the initramfs; stderr reaches the journal.
            eprintln!("warning: {e:#}; bind-mounting /var from the deployment state");
            false
        }
    }
}

/// Whether the deployment `state` directory's var (a symlink to the
/// stateroot's) has one of [`VAR_MARKERS`], written at installation when
/// the caller or bootc provides /var. Errors count as no.
fn var_marked(state: impl AsFd) -> bool {
    VAR_MARKERS.iter().any(|name| {
        let marker = format!("var/{name}");
        match rustix::fs::accessat(
            &state,
            marker.as_str(),
            rustix::fs::Access::EXISTS,
            rustix::fs::AtFlags::empty(),
        ) {
            Ok(()) => true,
            Err(Errno::NOENT) => false,
            Err(e) => {
                eprintln!("warning: checking for {marker}: {e}; assuming it isn't there");
                false
            }
        }
    })
}

/// Whether to leave /var to the fstab instead of bind-mounting the state's
/// var over it: only without an explicit `[var]` setting, for a /var that
/// installation marked as provided (`marked`: by the caller with
/// `--defer-var`, or by bootc on a /var filesystem with
/// `--initialize-var-mounts`), and when the fstab mounts /var
/// (`fstab_mounts_var`). The checks run in that order, and only as far as
/// needed.
fn leave_var_to_fstab(
    var: &MountConfig,
    marked: impl FnOnce() -> bool,
    fstab_mounts_var: impl FnOnce() -> bool,
) -> bool {
    var.mount.is_none() && !var.transient && marked() && fstab_mounts_var()
}

/// The `[var]` configuration to mount /var with: `var` as configured, or
/// `mount = "none"` when [`leave_var_to_fstab`] says so for the deployment
/// `state` directory and the fstab of `root`, the root as it will be after
/// switch-root (with /etc mounted).
fn var_config(var: MountConfig, state: impl AsFd, root: impl AsFd) -> MountConfig {
    if leave_var_to_fstab(&var, || var_marked(&state), || root_fstab_mounts_var(&root)) {
        eprintln!(
            "/var was provided at installation and /etc/fstab mounts it: not bind-mounting the deployment state's var"
        );
        MountConfig {
            mount: Some(MountType::None),
            ..var
        }
    } else {
        var
    }
}

/// Sets up /sysroot for switch-root
#[context("Setting up /sysroot")]
pub fn setup_root(args: Args) -> Result<()> {
    let config = match std::fs::read_to_string(args.config) {
        Ok(text) => toml::from_str(&text)?,
        Err(err) if err.kind() == ErrorKind::NotFound => Config::default(),
        Err(err) => Err(err)?,
    };

    let sysroot = open_dir(CWD, &args.sysroot)
        .with_context(|| format!("Failed to open sysroot {:?}", args.sysroot))?;

    let cmdline = args
        .cmdline
        .unwrap_or(Cmdline::from_proc().context("Failed to read cmdline")?);

    // Auto-detect systemd.volatile=state: if the kernel cmdline requests a
    // volatile /var via the systemd fstab-generator, skip our initramfs
    // bind-mount of /var from the deployment state directory.  This leaves
    // /var as an empty directory from the composefs image so that
    // systemd-fstab-generator can mount a fresh tmpfs there at local-fs.target.
    // An explicit `[var] mount = "none"` in setup-root-conf.toml has the same
    // effect; the cmdline check is a convenience so users only need the kargs.d
    // entry without also editing setup-root-conf.toml.
    let config = {
        let mut config = config;
        // value_of returns None for a missing key, Some("") for a bare flag,
        // or Some("state") / Some("overlay") / Some("yes") for key=value form.
        let volatile_val = cmdline.value_of("systemd.volatile");
        let var_volatile = matches!(volatile_val, Some("state") | Some("overlay"));
        if var_volatile && config.var.mount.is_none() && !config.var.transient {
            tracing::debug!(
                "systemd.volatile={} detected; skipping /var state bind-mount",
                volatile_val.unwrap_or("")
            );
            config.var.mount = Some(MountType::None);
        }
        config
    };

    let candidates =
        parse_composefs_candidates(&cmdline).context("Failed to parse composefs cmdline")?;
    if candidates.is_empty() {
        anyhow::bail!("No composefs image in cmdline");
    }
    let allow_missing_fsverity = candidates[0].is_insecure();
    if candidates
        .iter()
        .any(|candidate| candidate.is_insecure() != allow_missing_fsverity)
    {
        anyhow::bail!("composefs candidates have mixed fs-verity policy");
    }

    let (new_root, composefs_info) = match &args.root_fs {
        Some(path) => (
            open_root_fs(path).context("Failed to clone specified root fs")?,
            candidates[0].clone(),
        ),
        None => select_composefs_candidate(&candidates, |candidate| {
            mount_composefs_candidate(&sysroot, candidate, allow_missing_fsverity)
        })?,
    };

    // we need to clone this before the next step to make sure we get the old one
    let sysroot_clone = bind_mount(&sysroot, "")?;

    set_mount_readonly(&sysroot_clone)?;

    let mount_target = args.target.unwrap_or(args.sysroot.clone());

    // Ideally we build the new root filesystem together before we mount it, but that only works on
    // 6.15 and later.  Before 6.15 we can't mount into a floating tree, so mount it first.  This
    // will leave an abandoned clone of the sysroot mounted under it, but that's OK for now.
    if cfg!(feature = "pre-6.15") {
        mount_at_wrapper(&new_root, CWD, &mount_target)?;
    }

    // When transient root is enabled, place an overlay on top of the composefs.
    // On pre-6.15, since the composefs is already attached at `mount_target`,
    // the overlay is also immediately attached there.  We then open the overlay
    // via its path so that subsequent mounts target the visible merged tree.
    //
    // On 6.15+, the whole tree is assembled in floating mode; `overlay_transient`
    // returns a detached overlay fd that we can directly mount into.
    //
    // `new_root` always refers to the composefs fd; mounting via it after the
    // overlay is in place would land in the hidden lower layer.
    let transient_overlay_fd: Option<OwnedFd> = if config.root.transient {
        let overlay_fd = overlay_transient(
            &new_root,
            &format!("transient:composefs={}", composefs_info.digest().to_hex()),
            None,
        )?;

        if cfg!(feature = "pre-6.15") {
            // In pre-6.15, the composefs is already attached at `mount_target`.
            // Attach the overlay on top of it, then reopen the path to get a
            // dirfd that resolves through the overlay (not the hidden composefs).
            mount_at_wrapper(&overlay_fd, CWD, &mount_target)
                .context("Moving transient overlay onto sysroot")?;
            Some(open_dir(CWD, &mount_target).context("Opening attached overlay root")?)
        } else {
            // On 6.15+ we assemble in floating mode; use the detached overlay fd
            // directly for subsequent mounts into the tree.
            Some(overlay_fd)
        }
    } else {
        None
    };

    // When transient root is active the overlay sits on top of the composefs.
    // Mounts placed via `new_root` would land in the composefs lower layer and
    // be invisible from the running system.  Use the overlay fd for all
    // post-overlay mounts (sysroot, etc, var) so they appear in the merged view.
    let visible_root: &dyn AsFd = transient_overlay_fd
        .as_ref()
        .map_or(&new_root as &dyn AsFd, |fd| fd as &dyn AsFd);

    // Mount the physical sysroot (with the composefs repo) into the new root
    // so that `bootc status` and other tools can find it after switch-root.
    match composefs::mount::mount_at(&sysroot_clone, visible_root, "sysroot") {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(err) => Err(err)?,
    }

    // etc + var
    let state = open_dir(
        open_dir(&sysroot, "state/deploy")?,
        composefs_info.digest().to_hex(),
    )?;
    mount_subdir(visible_root, &state, "etc", config.etc, MountType::Bind)?;
    // /var is bind-mounted from the deployment state directory by default.
    // The systemd.volatile=state cmdline detection above (or an explicit
    // [var] mount = "none" in setup-root-conf.toml) can change this to
    // MountType::None, which skips the bind-mount entirely and leaves /var
    // as an empty directory from the composefs image for systemd to fill.
    //
    // So does an fstab entry for /var on a system installed with
    // --defer-var, or with --initialize-var-mounts onto a /var filesystem,
    // like in ostree's generator: binding the state directory's var over it
    // would make systemd consider /var mounted, and the filesystem would go
    // unused. Other systems keep the bind mount, as they had it before. An
    // explicit [var] setting wins. The fstab is read through the /etc mounted
    // above, so that an overlay's whiteouts, opaque directories and
    // metadata-only copy-ups count as they will after switch-root.
    let var = var_config(config.var, &state, visible_root);
    mount_subdir(visible_root, &state, "var", var, MountType::Bind)?;

    if cfg!(not(feature = "pre-6.15")) {
        // Replace the /sysroot with the new composed root filesystem.
        // When a transient overlay is active, mount it rather than the bare
        // composefs so the running system sees the writable merged view.
        unmount(&args.sysroot, UnmountFlags::DETACH)?;
        mount_at_wrapper(visible_root, CWD, &mount_target)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml: &str) -> Config {
        toml::from_str(toml).expect("TOML parse failed")
    }

    #[test]
    fn test_read_in_root() -> Result<()> {
        use cap_std_ext::cap_std::ambient_authority;
        use cap_std_ext::cap_tempfile::TempDir;
        const TEXT: &[u8] = b"UUID=v /var ext4 defaults 0 0\n";
        let td = TempDir::new(ambient_authority())?;
        td.create_dir_all("usr/etc")?;
        td.write("usr/etc/fstab", TEXT)?;
        td.write("fstab", TEXT)?;
        // Absolute and relative symlinks resolve below the root (cap-std
        // refuses to create absolute ones)
        let symlink = |target: &str, name: &str| rustix::fs::symlinkat(target, &*td, name);
        symlink("/usr/etc/fstab", "abs")?;
        symlink("usr/etc/fstab", "rel")?;
        symlink("/usr/etc", "etc")?;
        symlink("/missing", "dangling")?;
        td.create_dir("dir")?;
        rustix::fs::mknodat(
            &*td,
            "fifo",
            rustix::fs::FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )?;
        // Opening a socket fails with ENXIO
        let _socket = std::os::unix::net::UnixListener::bind(format!(
            "/proc/self/fd/{}/socket",
            td.as_raw_fd()
        ))?;
        for (name, expected) in [
            ("fstab", Some(TEXT)),
            ("abs", Some(TEXT)),
            ("rel", Some(TEXT)),
            ("etc/fstab", Some(TEXT)),
            ("missing", None),
            ("dangling", None),
            ("fstab/x", None),
            ("dir", None),
            ("fifo", None),
            ("socket", None),
        ] {
            assert_eq!(read_in_root(&*td, name)?.as_deref(), expected, "{name}");
        }
        // An absolute target outside the root doesn't resolve on the host
        symlink("/etc/os-release", "host")?;
        assert_eq!(read_in_root(&*td, "host")?, None);
        // A symlink loop is an error
        symlink("loop", "loop")?;
        assert!(read_in_root(&*td, "loop").is_err());
        Ok(())
    }

    #[test]
    fn test_root_fstab_mounts_var() -> Result<()> {
        use cap_std_ext::cap_std::ambient_authority;
        use cap_std_ext::cap_tempfile::TempDir;
        for (fstab, expected) in [
            (None, false),
            (Some(&b"UUID=v /var ext4 defaults 0 0\n"[..]), true),
            // Not UTF-8: a Latin-1 comment, and a stray byte in an entry
            (
                Some(&b"# caf\xe9\nUUID=v /var ext4 defaults 0 0\n"[..]),
                true,
            ),
            (Some(&b"UUID=\xff /var ext4 defaults 0 0\n"[..]), true),
            (Some(&b"UUID=\xff /var/log ext4 defaults 0 0\n"[..]), false),
        ] {
            let td = TempDir::new(ambient_authority())?;
            td.create_dir("etc")?;
            if let Some(fstab) = fstab {
                td.write(FSTAB, fstab)?;
            }
            assert_eq!(root_fstab_mounts_var(&*td), expected, "{fstab:?}");
        }
        // An fstab that can't be read keeps the bind mount, also for root
        let td = TempDir::new(ambient_authority())?;
        td.create_dir("etc")?;
        td.symlink("fstab", FSTAB)?;
        assert!(read_in_root(&*td, FSTAB).is_err());
        assert!(!root_fstab_mounts_var(&*td));
        Ok(())
    }

    #[test]
    fn test_fstab_mounts_var() {
        let cases = [
            ("", false),
            ("UUID=abc /var ext4 defaults 0 0", true),
            ("UUID=abc\t/var/\txfs defaults 0 0\n", true),
            ("  /dev/vg/var //var ext4 defaults", true),
            ("UUID=abc /var ext4", true),
            // noauto still counts, as in ostree's fstab_has_mount_entry()
            ("UUID=abc /var ext4 noauto 0 0", true),
            ("UUID=abc /var ext4 x-systemd.automount 0 0", true),
            ("# UUID=abc /var ext4 defaults 0 0", false),
            ("#UUID=abc /var ext4 defaults 0 0", false),
            ("  #UUID=abc /var ext4 defaults 0 0", false),
            // Not a mount record: too few fields, or swap
            ("UUID=abc /var", false),
            ("/swapfile /var swap defaults 0 0", false),
            // Only spaces and tabs separate fields
            ("UUID=abc\u{2003}/var ext4 defaults 0 0", false),
            ("UUID=abc\u{a0}/var\u{a0}ext4 defaults 0 0", false),
            ("UUID=abc /var/log ext4 defaults 0 0", false),
            ("UUID=abc /variable ext4 defaults 0 0", false),
            ("UUID=abc var ext4 defaults 0 0", false),
            ("UUID=abc /var/.. ext4 defaults 0 0", false),
            (
                "UUID=r / ext4 defaults 0 0\nUUID=b /boot ext4 defaults 0 0",
                false,
            ),
            (
                "UUID=r / ext4 defaults 0 0\nUUID=v /var ext4 defaults 0 0",
                true,
            ),
        ];
        for (fstab, expected) in cases {
            assert_eq!(fstab_mounts_var(fstab), expected, "{fstab:?}");
        }
    }

    #[test]
    fn test_var_marked() -> Result<()> {
        use cap_std_ext::cap_std::ambient_authority;
        use cap_std_ext::cap_tempfile::TempDir;
        // A deployment state directory's var is a relative symlink to the
        // stateroot's, as write_composefs_state() makes it
        for (markers, expected) in [
            (&[][..], false),
            (&[DEFER_VAR_MARKER][..], true),
            (&[VAR_MOUNTS_MARKER][..], true),
            (&[DEFER_VAR_MARKER, VAR_MOUNTS_MARKER][..], true),
            (&[".ostree-selabeled"][..], false),
        ] {
            let td = TempDir::new(ambient_authority())?;
            td.create_dir_all("state/os/default/var")?;
            td.create_dir_all("state/deploy/abc")?;
            td.symlink("../../os/default/var", "state/deploy/abc/var")?;
            for marker in markers {
                td.write(format!("state/os/default/var/{marker}"), "")?;
            }
            let state = td.open_dir("state/deploy/abc")?;
            assert_eq!(var_marked(&state), expected, "{markers:?}");
        }
        Ok(())
    }

    #[test]
    fn test_var_config() -> Result<()> {
        use cap_std_ext::cap_std::ambient_authority;
        use cap_std_ext::cap_tempfile::TempDir;
        const VAR_FSTAB: &str = "UUID=v /var ext4 defaults 0 0\n";
        // (marker, fstab mounts /var, [var] config, expected mount)
        let cases = [
            (Some(DEFER_VAR_MARKER), true, None, Some(MountType::None)),
            (Some(VAR_MOUNTS_MARKER), true, None, Some(MountType::None)),
            (Some(DEFER_VAR_MARKER), false, None, None),
            (None, true, None, None),
            (
                Some(VAR_MOUNTS_MARKER),
                true,
                Some(MountType::Bind),
                Some(MountType::Bind),
            ),
        ];
        for (marker, fstab, mount, expected) in cases {
            let td = TempDir::new(ambient_authority())?;
            td.create_dir_all("state/os/default/var")?;
            td.create_dir_all("state/deploy/abc")?;
            td.symlink("../../os/default/var", "state/deploy/abc/var")?;
            if let Some(marker) = marker {
                td.write(format!("state/os/default/var/{marker}"), "")?;
            }
            td.create_dir_all("root/etc")?;
            if fstab {
                td.write("root/etc/fstab", VAR_FSTAB)?;
            }
            let var = MountConfig {
                mount,
                transient: false,
            };
            let got = var_config(var, td.open_dir("state/deploy/abc")?, td.open_dir("root")?);
            assert_eq!(got.mount, expected, "{marker:?} {fstab} {mount:?}");
            assert!(!got.transient);
        }
        Ok(())
    }

    #[test]
    fn test_leave_var_to_fstab() {
        use MountType::{Bind, Overlay};
        let config = |mount, transient| MountConfig { mount, transient };
        // (config, /var marked as provided, fstab mounts /var, expected)
        let cases = [
            // An explicit [var] setting wins, whatever the rest
            (config(Some(Bind), false), true, true, false),
            (config(Some(MountType::None), false), false, false, false),
            (config(Some(Overlay), false), true, true, false),
            // So does transient
            (config(None, true), true, true, false),
            // Marked (--defer-var, or --initialize-var-mounts onto a /var
            // filesystem), and fstab mounts /var: leave it to fstab
            (config(None, false), true, true, true),
            // Otherwise keep the bind mount
            (config(None, false), false, true, false),
            (config(None, false), true, false, false),
            (config(None, false), false, false, false),
        ];
        for (var, marked, fstab, expected) in cases {
            assert_eq!(
                leave_var_to_fstab(&var, || marked, || fstab),
                expected,
                "{var:?} {marked} {fstab}"
            );
        }
        // The fstab is only read for a marked /var without a [var] setting
        let never = || -> bool { panic!("checked needlessly") };
        assert!(!leave_var_to_fstab(
            &config(Some(Bind), false),
            never,
            never
        ));
        assert!(!leave_var_to_fstab(&config(None, false), || false, never));
    }

    #[test]
    fn test_config_defaults() {
        let config = parse("");
        assert_eq!(
            config,
            Config {
                etc: MountConfig {
                    mount: None,
                    transient: false
                },
                var: MountConfig {
                    mount: None,
                    transient: false
                },
                root: RootConfig { transient: false },
            }
        );
    }

    #[test]
    fn test_mounttype_none() {
        let config = parse("[etc]\nmount = \"none\"");
        assert_eq!(config.etc.mount, Some(MountType::None));
    }

    #[test]
    fn test_mounttype_root_alias() {
        let config = parse("[etc]\nmount = \"root\"");
        assert_eq!(config.etc.mount, Some(MountType::None));
    }

    #[test]
    fn test_etc_transient_flag() {
        let config = parse("[etc]\ntransient = true");
        assert_eq!(config.etc.transient, true);
        assert_eq!(config.etc.mount, None);
    }

    #[test]
    fn test_var_none() {
        // mount = "none" skips the state bind-mount; combine with
        // systemd.volatile=state karg to get a fresh tmpfs on every boot.
        let config = parse("[var]\nmount = \"none\"");
        assert_eq!(config.var.mount, Some(MountType::None));
    }

    #[test]
    fn test_root_transient() {
        let config = parse("[root]\ntransient = true");
        assert_eq!(config.root.transient, true);
    }

    #[test]
    fn test_combined_config() {
        let config = parse("[root]\ntransient = true\n[etc]\nmount = \"root\"");
        assert_eq!(config.root.transient, true);
        assert_eq!(config.etc.mount, Some(MountType::None));
    }

    fn v1(digest: Sha512HashValue, insecure: bool) -> String {
        ComposefsCmdline::new_v1(digest, insecure).to_cmdline_arg()
    }

    fn v2(digest: Sha512HashValue, insecure: bool) -> String {
        ComposefsCmdline::new_v2(digest, insecure).to_cmdline_arg()
    }

    #[test]
    fn test_composefs_candidate_priority_and_selected_state() {
        let v1_digest = Sha512HashValue::EMPTY;
        let v2_digest = Sha512HashValue::from_hex("aa".repeat(64)).unwrap();
        let cmdline = format!(
            "quiet {} {}",
            v1(v1_digest.clone(), false),
            v2(v2_digest.clone(), false)
        );
        let candidates = parse_composefs_candidates(&cmdline).unwrap();
        let (selected, selected_cmdline) = select_composefs_candidate(&candidates, |candidate| {
            Ok((candidate.digest() == &v2_digest).then_some(candidate.digest().to_hex()))
        })
        .unwrap();
        assert_eq!(selected, v2_digest.to_hex());
        assert_eq!(selected_cmdline.digest(), &v2_digest);

        let (selected, _) = select_composefs_candidate(&candidates, |candidate| {
            Ok(Some(candidate.digest().to_hex()))
        })
        .unwrap();
        assert_eq!(selected, v1_digest.to_hex());
    }

    #[test]
    fn test_composefs_candidate_parse_and_policy_errors() {
        let malformed = ["composefs=not-a-digest", "composefs.digest=v9-sha512-12:aa"];
        for cmdline in malformed {
            assert!(
                parse_composefs_candidates(cmdline).is_err(),
                "expected parse error for {cmdline:?}"
            );
        }

        let strict = parse_composefs_candidates(&v1(Sha512HashValue::EMPTY, false)).unwrap();
        let insecure = parse_composefs_candidates(&v2(Sha512HashValue::EMPTY, true)).unwrap();
        assert_ne!(strict[0].is_insecure(), insecure[0].is_insecure());
    }

    #[test]
    fn test_composefs_candidate_parser_cases() {
        let first = Sha512HashValue::EMPTY;
        let second = Sha512HashValue::from_hex("aa".repeat(64)).unwrap();
        let cases = [
            ("single v1", v1(first.clone(), false), vec![first.clone()]),
            ("single v2", v2(first.clone(), false), vec![first.clone()]),
            (
                "dual preserves cmdline order",
                format!("{} {}", v2(first.clone(), false), v1(second.clone(), false)),
                vec![first.clone(), second.clone()],
            ),
            (
                "quoted parameter",
                format!("quiet \"{}\" rw", v1(first.clone(), false)),
                vec![first.clone()],
            ),
            (
                "skips sha256 descriptor",
                format!(
                    "composefs.digest=v1-sha256-12:{} {} {}",
                    "aa".repeat(32),
                    v1(first.clone(), false),
                    v2(second.clone(), false)
                ),
                vec![first.clone(), second.clone()],
            ),
        ];

        for (name, cmdline, expected_digests) in cases {
            let candidates = parse_composefs_candidates(&cmdline)
                .unwrap_or_else(|error| panic!("{name} unexpectedly failed: {error:#}"));
            assert_eq!(
                candidates
                    .iter()
                    .map(|candidate| candidate.digest().clone())
                    .collect::<Vec<_>>(),
                expected_digests,
                "case {name}"
            );
        }

        let duplicate_cases = [
            format!("{} {}", v2(first.clone(), false), v2(second.clone(), false)),
            format!("{} {}", v2(first.clone(), false), v2(first.clone(), false)),
        ];
        for cmdline in duplicate_cases {
            assert!(
                parse_composefs_candidates(&cmdline).is_err(),
                "duplicate recognized key accepted: {cmdline}"
            );
        }

        let irrelevant = [
            "quiet splash rw",
            "root=UUID=abc composefs.digest=v1-sha256-12:aa",
        ];
        for cmdline in irrelevant {
            assert!(
                parse_composefs_candidates(cmdline).unwrap().is_empty(),
                "irrelevant argument was treated as a candidate: {cmdline}"
            );
        }
    }
}
