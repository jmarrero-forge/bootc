//! Builder for running commands inside a target os tree using a
//! mount namespace + chroot. Requires `CAP_SYS_ADMIN`.

use std::borrow::Cow;
use std::ffi::{CStr, CString, OsStr};
use std::fs::create_dir_all;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{Context, Result};
use cap_std_ext::camino::Utf8Path;
use rustix::fs::{CWD, Mode, OFlags, mkdirat, openat, symlinkat};
use rustix::io::Errno;
use rustix::mount::{
    MountFlags, MountPropagationFlags, UnmountFlags, mount, mount_bind, mount_bind_recursive,
    mount_change, mount_remount, unmount,
};
use rustix::process::{
    Pid, Resource, Signal, WaitOptions, chdir, chroot, getpid, getppid, getrlimit, pivot_root,
    set_parent_process_death_signal, setsid, waitpid,
};
use rustix::thread::{
    CapabilitySet, UnshareFlags, capabilities, remove_capability_from_bounding_set,
    set_capabilities, unshare_unsafe,
};

use crate::CommandRunExt;

/// Device nodes bound from the host into an isolated command's `/dev`. The
/// command has no controlling terminal, so opening `tty` fails (ENXIO).
const ISOLATED_DEV_NODES: [&str; 6] = ["null", "zero", "full", "random", "urandom", "tty"];
/// Symlinks in an isolated command's `/dev`, as (name, target).
const ISOLATED_DEV_LINKS: [(&str, &CStr); 5] = [
    ("ptmx", c"pts/ptmx"),
    ("fd", c"/proc/self/fd"),
    ("stdin", c"/proc/self/fd/0"),
    ("stdout", c"/proc/self/fd/1"),
    ("stderr", c"/proc/self/fd/2"),
];
/// Parts of an isolated command's `/proc` that change the host's kernel or
/// devices, made read-only (as container runtimes do) where they exist.
const ISOLATED_PROC_READONLY: [&str; 6] = ["asound", "bus", "fs", "irq", "sys", "sysrq-trigger"];
/// Capabilities an isolated command doesn't get: those for administering the
/// kernel, devices, the host's network or its security policy, and those
/// that reach outside the root (raw device nodes, open_by_handle_at).
/// Installing packages, scriptlets included, needs none of them.
pub const ISOLATED_DROPPED_CAPS: CapabilitySet = CapabilitySet::AUDIT_CONTROL
    .union(CapabilitySet::AUDIT_READ)
    .union(CapabilitySet::BPF)
    .union(CapabilitySet::BLOCK_SUSPEND)
    .union(CapabilitySet::CHECKPOINT_RESTORE)
    .union(CapabilitySet::DAC_READ_SEARCH)
    .union(CapabilitySet::LINUX_IMMUTABLE)
    .union(CapabilitySet::MAC_ADMIN)
    .union(CapabilitySet::MAC_OVERRIDE)
    .union(CapabilitySet::MKNOD)
    .union(CapabilitySet::NET_ADMIN)
    .union(CapabilitySet::PERFMON)
    .union(CapabilitySet::SYS_ADMIN)
    .union(CapabilitySet::SYS_BOOT)
    .union(CapabilitySet::SYSLOG)
    .union(CapabilitySet::SYS_MODULE)
    .union(CapabilitySet::SYS_PACCT)
    .union(CapabilitySet::SYS_PTRACE)
    .union(CapabilitySet::SYS_RAWIO)
    .union(CapabilitySet::SYS_TTY_CONFIG)
    .union(CapabilitySet::SYS_TIME)
    .union(CapabilitySet::WAKE_ALARM);

/// Whether a [`ChrootCmd::bind`] mount also carries over mounts nested
/// under its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindMode {
    /// A plain bind mount: only `source` itself is bound. Mounts nested
    /// under `source` on the host (e.g. an ESP mounted under a `/boot`
    /// source) are *not* carried over, leaving the corresponding
    /// mountpoint directories under `target` empty.
    Default,
    /// A recursive bind mount: mounts nested under `source` on the host
    /// are also visible under `target` inside the chroot.
    Recursive,
}

/// Builder for running commands inside a target directory using a
/// mount namespace + chroot.
#[derive(Debug)]
pub struct ChrootCmd<'a> {
    /// The target directory to use as root for the chroot.
    chroot_path: Cow<'a, Utf8Path>,
    /// Bind mounts in format (host source, chroot-relative target, mode).
    bind_mounts: Vec<(&'a str, &'a str, BindMode)>,
    /// Environment variables to set on the spawned command.
    env_vars: Vec<(&'a str, &'a str)>,
    /// Whether the command is isolated from the host (see [`Self::isolate`]).
    isolate: bool,
}

impl<'a> ChrootCmd<'a> {
    /// Create a new `ChrootCmd` builder with a root directory.
    pub fn new(path: &'a Utf8Path) -> Self {
        Self {
            chroot_path: Cow::Borrowed(path),
            bind_mounts: Vec::new(),
            env_vars: Vec::new(),
            isolate: false,
        }
    }

    /// Add a bind mount from `source` (on the host) to `target` (a path
    /// inside the chroot, e.g. `/sysroot`). See [`BindMode`] for the
    /// difference between recursive and non-recursive bind mounts.
    pub fn bind(
        mut self,
        source: &'a impl AsRef<Utf8Path>,
        target: &'a impl AsRef<Utf8Path>,
        mode: BindMode,
    ) -> Self {
        self.bind_mounts
            .push((source.as_ref().as_str(), target.as_ref().as_str(), mode));
        self
    }

    /// Set an environment variable for the child. The chrooted
    /// command runs with a cleared environment, isolating it from
    /// the buildroot — callers must set every variable they want
    /// the child to see.
    pub fn setenv(mut self, key: &'a str, value: &'a str) -> Self {
        self.env_vars.push((key, value));
        self
    }

    /// Isolate the command from the host, for changing a root that isn't
    /// booted, such as a package manager installing into a staging root.
    ///
    /// The command runs as PID 1 of new PID, UTS and IPC namespaces, in
    /// the root through `pivot_root` (so it can't chroot its way out), with
    /// a procfs of its own whose `/proc/sys`, `/proc/irq` and the like
    /// are read-only. `/run` is a fresh tmpfs, so it can't reach the host's
    /// systemd, D-Bus or udev, and nothing it writes there outlives it.
    /// `/sys` is a fresh read-only sysfs, without the host's mounts under
    /// it (`/sys/fs/selinux`, cgroups), and `/dev` a tmpfs with only the
    /// basic nodes (null, zero, full, random, urandom, tty), a devpts
    /// instance of its own and `/dev/shm`. The capabilities in
    /// [`ISOLATED_DROPPED_CAPS`] are dropped. It runs in a session of its
    /// own, without a controlling terminal (so it can't push input into the
    /// caller's through `TIOCSTI`), and gets none of the caller's file
    /// descriptors but its stdio, which it inherits as usual. When the
    /// command exits, or the caller dies, whatever it left running is killed
    /// with its PID namespace.
    ///
    /// This is not a hardened sandbox: the command still runs as root with
    /// the host's network, and can change whatever is bound into the root.
    pub fn isolate(mut self) -> Self {
        self.isolate = true;
        self
    }

    /// Set `$PATH` to a reasonable default covering the standard
    /// system binary directories.
    pub fn set_default_path(self) -> Self {
        self.setenv(
            "PATH",
            "/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin",
        )
    }

    /// Build the underlying [`Command`] with the mount-namespace
    /// setup and chroot installed as a `pre_exec` hook.
    fn build_command<S: AsRef<OsStr>>(self, args: impl IntoIterator<Item = S>) -> Result<Command> {
        let mut args_iter = args.into_iter();
        let program = args_iter
            .next()
            .context("ChrootCmd requires the program as the first arg")?;

        // mount() requires its target directories to exist.
        let proc_target = self.chroot_path.join("proc");
        let dev_target = self.chroot_path.join("dev");
        let sys_target = self.chroot_path.join("sys");
        let run_target = self.chroot_path.join("run");
        for p in [&proc_target, &dev_target, &sys_target, &run_target] {
            create_dir_all(p).with_context(|| format!("Creating {p}"))?;
        }

        // Convert paths to CStrings up front so the pre_exec closure
        // below stays allocation-free.
        let isolated = self
            .isolate
            .then(|| IsolatedPaths::new(&proc_target, &dev_target))
            .transpose()?;
        let proc_target = CString::new(proc_target.as_str())?;
        let dev_target = CString::new(dev_target.as_str())?;
        let sys_target = CString::new(sys_target.as_str())?;
        let run_target = CString::new(run_target.as_str())?;

        let user_binds: Vec<(CString, CString, BindMode)> = self
            .bind_mounts
            .iter()
            .map(|(src, tgt, mode)| -> Result<_> {
                let tgt_in_chroot = self.chroot_path.join(tgt.trim_start_matches('/'));
                create_dir_all(&tgt_in_chroot)
                    .with_context(|| format!("Creating bind target {tgt_in_chroot}"))?;
                Ok((
                    CString::new(*src)?,
                    CString::new(tgt_in_chroot.as_str())?,
                    *mode,
                ))
            })
            .collect::<Result<_>>()?;

        let chroot_cstr = CString::new(self.chroot_path.as_str())?;
        let caller = getpid();

        let mut cmd = Command::new(program);
        cmd.args(args_iter);
        cmd.env_clear().envs(self.env_vars.iter().copied());

        // SAFETY: All operations below are safe to invoke between
        // fork and exec — only rustix-wrapped syscalls and iteration
        // over CStrings allocated above, and for an isolated command
        // the fork in fork_pid1.
        #[allow(unsafe_code)]
        unsafe {
            cmd.pre_exec(move || {
                let mut namespaces = UnshareFlags::NEWNS;
                if isolated.is_some() {
                    namespaces |=
                        UnshareFlags::NEWPID | UnshareFlags::NEWUTS | UnshareFlags::NEWIPC;
                }
                unshare_unsafe(namespaces)?;

                // Recursively mark every mount in our new namespace as
                // PRIVATE. This both prevents the mounts we add below
                // from leaking back to the host, and ensures that those
                // mounts inherit PRIVATE propagation from their parent.
                mount_change(
                    c"/",
                    MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
                )?;

                // Bind-mount the chroot target onto itself so that `/`
                // appears as a real mount point after chroot. Without
                // this, tools that inspect mounts (e.g. `findmnt
                // --mountpoint /`, which bootupd uses behind
                // `--filesystem /`) fail because the chroot dir is a
                // plain subdirectory of its parent mount and has no
                // mountinfo entry of its own.
                mount_bind_recursive(chroot_cstr.as_c_str(), chroot_cstr.as_c_str())?;

                // Setup API filesystems
                // See https://systemd.io/API_FILE_SYSTEMS/
                if let Some(isolated) = &isolated {
                    // /proc is mounted by PID 1 below, for its namespace.
                    isolated.mount_dev()?;
                    mount(
                        c"sysfs",
                        sys_target.as_c_str(),
                        c"sysfs",
                        MountFlags::RDONLY
                            | MountFlags::NOSUID
                            | MountFlags::NODEV
                            | MountFlags::NOEXEC,
                        None,
                    )?;
                    mount(
                        c"tmpfs",
                        run_target.as_c_str(),
                        c"tmpfs",
                        MountFlags::NOSUID | MountFlags::NODEV,
                        Some(c"mode=0755"),
                    )?;
                } else {
                    mount(
                        c"proc",
                        proc_target.as_c_str(),
                        c"proc",
                        MountFlags::empty(),
                        None,
                    )?;
                    mount_bind_recursive(c"/dev", dev_target.as_c_str())?;
                    mount_bind_recursive(c"/sys", sys_target.as_c_str())?;
                    // /run carries the udev database, which lsblk/libblkid
                    // use to resolve partition GUIDs and other device
                    // properties.
                    mount_bind_recursive(c"/run", run_target.as_c_str())?;
                }

                for (src, tgt, mode) in &user_binds {
                    match mode {
                        BindMode::Recursive => {
                            mount_bind_recursive(src.as_c_str(), tgt.as_c_str())?
                        }
                        BindMode::Default => mount_bind(src.as_c_str(), tgt.as_c_str())?,
                    }
                }

                if let Some(isolated) = &isolated {
                    // From here on, this is PID 1 of the new namespace.
                    fork_pid1(caller)?;
                    isolated.mount_proc()?;
                    // pivot_root rather than chroot, and detach the old
                    // root, so that chrooting again can't climb out to it.
                    chdir(chroot_cstr.as_c_str())?;
                    pivot_root(c".", c".")?;
                    unmount(c".", UnmountFlags::DETACH)?;
                    chdir(c"/")?;
                    drop_isolated_capabilities()?;
                    setsid()?;
                    // A descriptor the caller left open, such as one for a
                    // host directory, would reach outside the root. Marking
                    // them close-on-exec rather than closing them keeps the
                    // pipe on which `Command::spawn` waits for the exec
                    // (already close-on-exec) working.
                    close_fd_range(3, u32::MAX, FdAction::SetCloexec);
                } else {
                    chroot(chroot_cstr.as_c_str())?;
                    chdir(c"/")?;
                }

                Ok(())
            });
        }

        Ok(cmd)
    }

    /// Run the specified command inside the chroot, inheriting stdio.
    /// `args` must include the program as its first element.
    pub fn run<S: AsRef<OsStr>>(self, args: impl IntoIterator<Item = S>) -> Result<()> {
        self.build_command(args)?
            .log_debug()
            .run_inherited_with_cmd_context()
    }

    /// Run the specified command inside the chroot and capture stdout
    /// as a string. `args` must include the program as its first
    /// element.
    pub fn run_get_string<S: AsRef<OsStr>>(
        self,
        args: impl IntoIterator<Item = S>,
    ) -> Result<String> {
        self.build_command(args)?.log_debug().run_get_string()
    }
}

/// The paths an isolated command's `/dev` and `/proc` are set up at, as C
/// strings, so that the setup between fork and exec doesn't allocate.
#[derive(Debug)]
struct IsolatedPaths {
    dev: CString,
    /// (host node, node in the root)
    dev_nodes: Vec<(CString, CString)>,
    dev_pts: CString,
    dev_shm: CString,
    /// (link in the root, its target)
    dev_links: Vec<(CString, &'static CStr)>,
    proc: CString,
    proc_readonly: Vec<CString>,
}

impl IsolatedPaths {
    fn new(proc: &Utf8Path, dev: &Utf8Path) -> Result<Self> {
        let c = |p: &Utf8Path| {
            CString::new(p.as_str()).with_context(|| format!("{p} contains a NUL byte"))
        };
        Ok(Self {
            dev: c(dev)?,
            dev_nodes: ISOLATED_DEV_NODES
                .iter()
                .map(|n| Ok((c(&Utf8Path::new("/dev").join(n))?, c(&dev.join(n))?)))
                .collect::<Result<_>>()?,
            dev_pts: c(&dev.join("pts"))?,
            dev_shm: c(&dev.join("shm"))?,
            dev_links: ISOLATED_DEV_LINKS
                .iter()
                .map(|(name, target)| Ok((c(&dev.join(name))?, *target)))
                .collect::<Result<_>>()?,
            proc: c(proc)?,
            proc_readonly: ISOLATED_PROC_READONLY
                .iter()
                .map(|p| c(&proc.join(p)))
                .collect::<Result<_>>()?,
        })
    }

    /// Mounts a minimal `/dev`. Runs between fork and exec, so it doesn't
    /// allocate.
    fn mount_dev(&self) -> io::Result<()> {
        mount(
            c"tmpfs",
            self.dev.as_c_str(),
            c"tmpfs",
            MountFlags::NOSUID | MountFlags::NOEXEC,
            Some(c"mode=0755"),
        )?;
        for (host, node) in &self.dev_nodes {
            // A bind mount needs a file to mount over.
            drop(openat(
                CWD,
                node.as_c_str(),
                OFlags::CREATE | OFlags::WRONLY | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o644),
            )?);
            mount_bind(host.as_c_str(), node.as_c_str())?;
        }
        mkdirat(CWD, self.dev_pts.as_c_str(), Mode::from_raw_mode(0o755))?;
        mount(
            c"devpts",
            self.dev_pts.as_c_str(),
            c"devpts",
            MountFlags::NOSUID | MountFlags::NOEXEC,
            Some(c"newinstance,ptmxmode=0666,mode=0620,gid=5"),
        )?;
        mkdirat(CWD, self.dev_shm.as_c_str(), Mode::from_raw_mode(0o1777))?;
        mount(
            c"tmpfs",
            self.dev_shm.as_c_str(),
            c"tmpfs",
            MountFlags::NOSUID | MountFlags::NODEV,
            Some(c"mode=1777"),
        )?;
        for (link, target) in &self.dev_links {
            symlinkat(*target, CWD, link.as_c_str())?;
        }
        Ok(())
    }

    /// Mounts a procfs for the current PID namespace, with the parts that
    /// change the host's kernel read-only. Runs between fork and exec, so
    /// it doesn't allocate.
    fn mount_proc(&self) -> io::Result<()> {
        mount(
            c"proc",
            self.proc.as_c_str(),
            c"proc",
            MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
            None,
        )?;
        for p in &self.proc_readonly {
            match mount_bind(p.as_c_str(), p.as_c_str()) {
                Ok(()) => {}
                Err(Errno::NOENT) => continue,
                Err(e) => return Err(e.into()),
            }
            mount_remount(
                p.as_c_str(),
                MountFlags::BIND
                    | MountFlags::RDONLY
                    | MountFlags::NOSUID
                    | MountFlags::NODEV
                    | MountFlags::NOEXEC,
                c"",
            )?;
        }
        Ok(())
    }
}

/// Called between fork and exec once the PID namespace is unshared, which
/// only children enter: forks again, and returns in the child, the
/// namespace's PID 1, which goes on to exec the command. This process stays
/// outside, waits for PID 1 and exits with its status, so that the caller
/// sees the command's. If the caller (`caller`) dies, so does this process,
/// and with it PID 1, whose exit kills the rest of the namespace.
fn fork_pid1(caller: Pid) -> io::Result<()> {
    set_parent_process_death_signal(Some(Signal::KILL))?;
    if getppid() != Some(caller) {
        // The caller died before that took effect.
        exit_now(EXIT_WAIT_FAILED);
    }
    // PID 1 can't see this process, so it checks that this process is
    // still there through a pipe that only this process keeps open.
    let mut alive = [0 as libc::c_int; 2];
    // SAFETY: pipe2 writes two descriptors to the array it is given.
    #[allow(unsafe_code)]
    if unsafe { libc::pipe2(alive.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let [alive_read, alive_write] = alive;
    // SAFETY: between fork and exec we are single-threaded, and both
    // processes only make async-signal-safe calls from here on. Like the
    // fork in `Command::spawn`, this runs whatever pthread_atfork handlers
    // the process registered; it is single-threaded here, so no other thread
    // can hold their locks.
    #[allow(unsafe_code)]
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    let Some(pid) = Pid::from_raw(pid) else {
        set_parent_process_death_signal(Some(Signal::KILL))?;
        let mut byte = 0u8;
        // SAFETY: both descriptors are this process's own, and read writes
        // at most one byte to `byte`.
        #[allow(unsafe_code)]
        let n = unsafe {
            libc::close(alive_write);
            let n = libc::read(alive_read, (&raw mut byte).cast(), 1);
            libc::close(alive_read);
            n
        };
        if n == 0 {
            // No writer left: the parent died before the signal was set.
            exit_now(EXIT_WAIT_FAILED);
        }
        return Ok(());
    };
    close_fds_except(alive_write);
    let status = loop {
        match waitpid(Some(pid), WaitOptions::empty()) {
            Ok(Some((_, status))) => break status,
            Err(Errno::INTR) => continue,
            _ => exit_now(EXIT_WAIT_FAILED),
        }
    };
    let code = status
        .exit_status()
        .or_else(|| status.terminating_signal().map(|s| 128 + s))
        .unwrap_or(EXIT_WAIT_FAILED);
    exit_now(code)
}

/// The exit status of the process waiting for an isolated command's PID 1,
/// if it can't tell how PID 1 exited.
const EXIT_WAIT_FAILED: i32 = 127;

/// Closes every file descriptor from 3 up but `keep`. That includes the
/// pipe on which `Command::spawn` waits for the exec, which the process
/// waiting for PID 1 would otherwise hold open until the command exits.
fn close_fds_except(keep: libc::c_int) {
    let keep = keep as u32;
    close_fd_range(3, keep.saturating_sub(1), FdAction::Close);
    close_fd_range(keep + 1, u32::MAX, FdAction::Close);
}

/// What [`close_fd_range`] does with each descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FdAction {
    Close,
    SetCloexec,
}

/// Closes, or marks close-on-exec, every file descriptor in `first..=last`.
/// Doesn't allocate, so it can run between fork and exec.
fn close_fd_range(first: u32, last: u32, action: FdAction) {
    if first > last {
        return;
    }
    let flags = match action {
        FdAction::Close => 0,
        FdAction::SetCloexec => libc::CLOSE_RANGE_CLOEXEC,
    };
    // SAFETY: close_range only closes descriptors or sets their
    // close-on-exec flag, and the callers use none of them after this.
    #[allow(unsafe_code)]
    let r = unsafe { libc::syscall(libc::SYS_close_range, first, last, flags) };
    if r == 0 {
        return;
    }
    // Kernels before 5.9 have no close_range, and before 5.11 no
    // CLOSE_RANGE_CLOEXEC. Descriptors stay below the hard limit on open
    // files, or below fs.nr_open's default if the limit was lowered after
    // they were opened.
    let limit = getrlimit(Resource::Nofile)
        .maximum
        .map_or(FALLBACK_FD_LIMIT, |m| m.min(u64::from(u32::MAX)) as u32)
        .max(FALLBACK_FD_LIMIT);
    for fd in first..=last.min(limit.saturating_sub(1)) {
        let fd = fd as libc::c_int;
        // SAFETY: as above.
        #[allow(unsafe_code)]
        unsafe {
            match action {
                FdAction::Close => libc::close(fd),
                FdAction::SetCloexec => libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC),
            }
        };
    }
}

/// The least bound on file descriptors for [`close_fd_range`]'s fallback:
/// fs.nr_open's default.
const FALLBACK_FD_LIMIT: u32 = 1 << 20;

fn exit_now(code: i32) -> ! {
    // SAFETY: _exit is async-signal-safe and skips the exit handlers and
    // destructors, which belong to the parent process.
    #[allow(unsafe_code)]
    unsafe {
        libc::_exit(code)
    }
}

/// Drops [`ISOLATED_DROPPED_CAPS`] from the bounding set, which limits what
/// root gets on exec, and clears the inheritable set, whose capabilities
/// root would keep on exec despite it.
fn drop_isolated_capabilities() -> io::Result<()> {
    for cap in ISOLATED_DROPPED_CAPS.iter() {
        match remove_capability_from_bounding_set(cap) {
            // One that the kernel doesn't know about.
            Ok(()) | Err(Errno::INVAL) => {}
            Err(e) => return Err(e.into()),
        }
    }
    let mut sets = capabilities(None)?;
    sets.inheritable = CapabilitySet::empty();
    set_capabilities(None, sets)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::camino::Utf8PathBuf;

    fn tmp_root() -> (tempfile::TempDir, Utf8PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).unwrap();
        (dir, path)
    }

    #[test]
    fn builder_accumulates_binds_and_env() {
        let (_keep, root) = tmp_root();
        let src = root.join("src");
        let non_recursive_src = root.join("non-recursive-src");
        let cmd = ChrootCmd::new(&root)
            .bind(&src, &"/boot", BindMode::Recursive)
            .bind(&non_recursive_src, &"/sysroot", BindMode::Default)
            .setenv("FOO", "bar")
            .set_default_path();
        assert_eq!(cmd.bind_mounts.len(), 2);
        assert_eq!(
            cmd.bind_mounts[0],
            (src.as_str(), "/boot", BindMode::Recursive)
        );
        assert_eq!(
            cmd.bind_mounts[1],
            (non_recursive_src.as_str(), "/sysroot", BindMode::Default)
        );
        // setenv + set_default_path
        assert_eq!(cmd.env_vars.len(), 2);
        assert!(cmd.env_vars.iter().any(|(k, _)| *k == "PATH"));
        assert!(cmd.env_vars.iter().any(|(k, v)| *k == "FOO" && *v == "bar"));
    }

    #[test]
    fn build_command_creates_api_mount_dirs() {
        let (_keep, root) = tmp_root();
        // No user binds — just the API mount targets.
        let cmd = ChrootCmd::new(&root).build_command(["/bin/true"]).unwrap();
        for sub in ["proc", "dev", "sys", "run"] {
            assert!(
                root.join(sub).is_dir(),
                "API mount dir {sub} not created in {root}"
            );
        }
        assert_eq!(cmd.get_program(), "/bin/true");
    }

    #[test]
    fn isolated_paths_are_in_the_root() {
        let (_keep, root) = tmp_root();
        let paths = IsolatedPaths::new(&root.join("proc"), &root.join("dev")).unwrap();
        let c = |s: &str| CString::new(s).unwrap();
        assert_eq!(
            paths.dev_nodes[0],
            (c("/dev/null"), c(&format!("{root}/dev/null")))
        );
        assert_eq!(
            paths.dev_links[0],
            (c(&format!("{root}/dev/ptmx")), c"pts/ptmx")
        );
        assert!(
            paths
                .proc_readonly
                .contains(&c(&format!("{root}/proc/sys")))
        );
        let cmd = ChrootCmd::new(&root)
            .isolate()
            .build_command(["/bin/true"])
            .unwrap();
        assert_eq!(cmd.get_program(), "/bin/true");
    }

    #[test]
    fn build_command_creates_user_bind_targets() {
        let (_keep, root) = tmp_root();
        let (_keep2, src_root) = tmp_root();
        ChrootCmd::new(&root)
            .bind(&src_root, &"/sysroot", BindMode::Recursive)
            .build_command(["/bin/true"])
            .unwrap();
        assert!(root.join("sysroot").is_dir());
    }

    #[test]
    fn build_command_rejects_empty_args() {
        let (_keep, root) = tmp_root();
        let err = ChrootCmd::new(&root)
            .build_command(std::iter::empty::<&str>())
            .unwrap_err();
        assert!(
            err.to_string().contains("ChrootCmd requires the program"),
            "unexpected error: {err}"
        );
    }
}
