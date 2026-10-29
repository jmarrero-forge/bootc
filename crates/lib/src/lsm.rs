use std::borrow::Cow;
#[cfg(feature = "selinux")]
use std::ffi::CString;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use bootc_utils::CommandRunExt;
use camino::{Utf8Path, Utf8PathBuf};
use cap_std::fs::Dir;
use cap_std::fs::{DirBuilder, OpenOptions};
use cap_std::io_lifetimes::AsFilelike;
use cap_std_ext::cap_std;
use cap_std_ext::cap_std::fs::{Metadata, MetadataExt};
use cap_std_ext::dirext::CapStdExtDirExt;
use fn_error_context::context;
use ostree_ext::gio;
use ostree_ext::ostree;
use rustix::fd::AsFd;

/// The mount path for selinux
const SELINUXFS: &str = "/sys/fs/selinux";
/// The SELinux xattr
const SELINUX_XATTR: &[u8] = b"security.selinux\0";
/// The kernel initial SID used for objects without a label.
#[cfg(feature = "selinux")]
const SELINUX_INITIAL_SID_UNLABELED: &str = "unlabeled";
const SELF_CURRENT: &str = "/proc/self/attr/current";

/// Whether SELinux is enabled for the current process.
///
/// libselinux caches this state process-wide, so mounting selinuxfs requires a
/// re-exec before this result can change.
#[cfg(feature = "selinux")]
pub(crate) fn selinux_enabled() -> bool {
    selinux::kernel_support() != selinux::KernelSupport::Unsupported
}

/// Without the `selinux` feature, bootc treats SELinux as disabled.
#[cfg(not(feature = "selinux"))]
pub(crate) fn selinux_enabled() -> bool {
    false
}

/// Whether SELinux is enabled on the host, as observed from PID 1's mount namespace.
///
/// This bypasses libselinux's process-cached state and is only appropriate while
/// bootstrapping the selinuxfs mount before re-exec.
#[cfg(feature = "selinux")]
#[context("Querying host SELinux availability")]
pub(crate) fn host_selinux_enabled() -> Result<bool> {
    Path::new("/proc/1/root/sys/fs/selinux/enforce")
        .try_exists()
        .map_err(Into::into)
}

/// Without the `selinux` feature, bootc treats SELinux as disabled.
#[cfg(not(feature = "selinux"))]
pub(crate) fn host_selinux_enabled() -> Result<bool> {
    Ok(false)
}

/// Get the current process SELinux security context
fn get_current_security_context() -> Result<String> {
    std::fs::read_to_string(SELF_CURRENT).with_context(|| format!("Reading {SELF_CURRENT}"))
}

/// Check if the current process has the capability to write SELinux security
/// contexts unknown to the current policy. In SELinux terms this capability is
/// gated under `mac_admin` (admin control over SELinux state), and in the Fedora
/// policy at least it's part of `install_t`.
#[context("Testing install_t")]
fn test_install_t() -> Result<bool> {
    let tmpf = tempfile::NamedTempFile::new()?;
    // Our implementation here writes a label which is always unknown to the current policy
    // to verify that we have the capability to do so.
    let st = Command::new("chcon")
        .args(["-t", "invalid_bootcinstall_testlabel_t"])
        .arg(tmpf.path())
        .stderr(std::process::Stdio::null())
        .status()?;
    Ok(st.success())
}

/// Ensure that the current process has the capability to write SELinux security
/// contexts unknown to the current policy.
///
/// See [`test_install_t`] above for how we check for that capability.
///
/// In the general case of both upgrade or install, we may e.g. jump major versions
/// or even operating systems, and we need the ability to write arbitrary labels.
/// If the current process doesn't already have `mac_admin/install_t` then we
/// make a new temporary copy of our binary, and give it the same label as /usr/bin/ostree,
/// which in Fedora derivatives at least was already historically labeled with
/// the correct install_t label.
///
/// However, if you maintain a bootc operating system with SELinux, you should from
/// the start ensure that /usr/bin/bootc has the correct capabilities.
#[context("Ensuring selinux install_t type")]
pub(crate) fn selinux_ensure_install(reexec_env: &[(&str, &str)]) -> Result<bool> {
    let guardenv = "_bootc_selinuxfs_mounted";
    let current = get_current_security_context()?;
    tracing::debug!("Current security context is {current}");
    if let Some(p) = std::env::var_os(guardenv) {
        let p = Path::new(&p);
        if p.exists() {
            tracing::debug!("Removing temporary file");
            std::fs::remove_file(p).context("Removing {p:?}")?;
        } else {
            tracing::debug!("Assuming we now have a privileged (e.g. install_t) label");
        }
        return test_install_t();
    }
    if test_install_t()? {
        tracing::debug!("We have install_t");
        return Ok(true);
    }
    tracing::debug!("Lacking install_t capabilities; copying self to temporary file for re-exec");
    // OK now, we always copy our binary to a tempfile, set its security context
    // to match that of /usr/bin/ostree, and then re-exec.  This is really a gross
    // hack; we can't always rely on https://github.com/fedora-selinux/selinux-policy/pull/1500/commits/67eb283c46d35a722636d749e5b339615fe5e7f5
    let mut tmpf = tempfile::NamedTempFile::new()?;
    let srcpath = std::env::current_exe()?;
    let mut src = std::fs::File::open(&srcpath)?;
    let meta = src.metadata()?;
    std::io::copy(&mut src, &mut tmpf).context("Copying self to tempfile for selinux re-exec")?;
    tmpf.as_file_mut()
        .set_permissions(meta.permissions())
        .context("Setting permissions of tempfile")?;
    let container_root = Dir::open_ambient_dir("/", cap_std::ambient_authority())?;
    let policy = ostree::SePolicy::new_at(container_root.as_raw_fd(), gio::Cancellable::NONE)?;
    let label = require_label(&policy, "/usr/bin/ostree".into(), libc::S_IFREG | 0o755)?;
    set_security_selinux(tmpf.as_fd(), label.as_bytes())?;
    let tmpf: Utf8PathBuf = tmpf.keep()?.1.try_into().unwrap();
    tracing::debug!("Created {tmpf:?}");

    let mut cmd = Command::new(&tmpf);
    cmd.env(guardenv, tmpf);
    cmd.env(bootc_utils::reexec::ORIG, srcpath);
    bootc_utils::reexec::prepare_reexec(&mut cmd, reexec_env);
    cmd.log_debug();
    Err(anyhow::Error::msg(cmd.exec()).context("execve"))
}

/// Query whether SELinux is apparently enabled in the target root
pub(crate) fn have_selinux_policy(root: &Dir) -> Result<bool> {
    // TODO use ostree::SePolicy and query policy name
    root.try_exists("etc/selinux/config").map_err(Into::into)
}

/// A type which will reset SELinux back to enforcing mode when dropped.
/// This is a workaround for the deep difficulties in trying to reliably
/// gain the `mac_admin` permission (install_t).
#[must_use]
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct SetEnforceGuard(Option<()>);

impl SetEnforceGuard {
    pub(crate) fn new() -> Self {
        SetEnforceGuard(Some(()))
    }

    #[allow(dead_code)]
    pub(crate) fn consume(mut self) -> Result<()> {
        // SAFETY: The option cannot have been consumed until now
        self.0.take().unwrap();
        // This returns errors
        selinux_set_permissive(false)
    }
}

impl Drop for SetEnforceGuard {
    fn drop(&mut self) {
        // A best-effort attempt to re-enable enforcement on drop (installation failure)
        if let Some(()) = self.0.take() {
            let _ = selinux_set_permissive(false);
        }
    }
}

/// Try to enter the install_t domain, but if we can't do that, then
/// just setenforce 0.
#[context("Ensuring selinux install_t type")]
pub(crate) fn selinux_ensure_install_or_setenforce(
    reexec_env: &[(&str, &str)],
) -> Result<Option<SetEnforceGuard>> {
    // If the process already has install_t, exit early
    // Note that this may re-exec the entire process
    if selinux_ensure_install(reexec_env)? {
        return Ok(None);
    }
    let g = if std::env::var_os("BOOTC_SETENFORCE0_FALLBACK").is_some() {
        tracing::warn!("Failed to enter install_t; temporarily setting permissive mode");
        selinux_set_permissive(true)?;
        Some(SetEnforceGuard::new())
    } else {
        let current = get_current_security_context()?;
        anyhow::bail!(
            "Failed to enter install_t (running as {current}) - use BOOTC_SETENFORCE0_FALLBACK=1 to override"
        );
    };
    Ok(g)
}

/// A thin wrapper for loading a SELinux policy that maps "policy nonexistent" to None.
pub(crate) fn new_sepolicy_at(fd: impl AsFd) -> Result<Option<ostree::SePolicy>> {
    // Loading sets libselinux's process-wide policy root before opening the
    // file contexts below it, so two loads at once could mix up policies.
    static LOADING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let fd = fd.as_fd();
    let cancellable = gio::Cancellable::NONE;
    let sepolicy = {
        let _loading = LOADING.lock().unwrap_or_else(|e| e.into_inner());
        ostree::SePolicy::new_at(fd.as_raw_fd(), cancellable)?
    };
    let r = if sepolicy.csum().is_none() {
        None
    } else {
        Some(sepolicy)
    };
    Ok(r)
}

#[context("Setting SELinux permissive mode")]
#[allow(dead_code)]
pub(crate) fn selinux_set_permissive(permissive: bool) -> Result<()> {
    let enforce_path = &Utf8Path::new(SELINUXFS).join("enforce");
    if !enforce_path.exists() {
        return Ok(());
    }
    let mut f = std::fs::File::options().write(true).open(enforce_path)?;
    f.write_all(if permissive { b"0" } else { b"1" })?;
    tracing::debug!(
        "Set SELinux mode: {}",
        if permissive {
            "permissive"
        } else {
            "enforcing"
        }
    );
    Ok(())
}

/// Check if the ostree-formatted extended attributes include a security.selinux value.
pub(crate) fn xattrs_have_selinux(xattrs: &ostree::glib::Variant) -> bool {
    let n = xattrs.n_children();
    for i in 0..n {
        let child = xattrs.child_value(i);
        let key = child.child_value(0);
        let key = key.data_as_bytes();
        if key == SELINUX_XATTR {
            return true;
        }
    }
    false
}

/// Look up the label for a path in a policy, and error if one is not found.
pub(crate) fn require_label(
    policy: &ostree::SePolicy,
    destname: &Utf8Path,
    mode: u32,
) -> Result<ostree::glib::GString> {
    policy
        .label(destname.as_str(), mode, ostree::gio::Cancellable::NONE)?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No label found in policy '{:?}' for {destname})",
                policy.csum()
            )
        })
}

/// Look up the label for a path in a policy, returning None if no match is found.
pub(crate) fn optional_label(
    policy: &ostree::SePolicy,
    destname: &Utf8Path,
    mode: u32,
) -> Result<Option<ostree::glib::GString>> {
    policy
        .label(destname.as_str(), mode, ostree::gio::Cancellable::NONE)
        .map_err(Into::into)
}

/// A thin wrapper for invoking fsetxattr(security.selinux)
pub(crate) fn set_security_selinux(fd: std::os::fd::BorrowedFd, label: &[u8]) -> Result<()> {
    rustix::fs::fsetxattr(
        fd,
        "security.selinux",
        label,
        rustix::fs::XattrFlags::empty(),
    )
    .context("fsetxattr(security.selinux)")
}

/// The labeling state; "unsupported" is distinct as we need to handle
/// cases like the ESP which don't support labeling.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SELinuxLabelState {
    Unlabeled,
    Unsupported,
    Labeled,
}

/// The type of the kernel's `unlabeled` initial context. Files with it (e.g.
/// created while SELinux was disabled) need relabeling just like files without
/// any label.
#[cfg(feature = "selinux")]
#[derive(Debug)]
struct UnlabeledType(CString);

/// Without the `selinux` feature, bootc never parses SELinux contexts, so this
/// can't be constructed and only files without any label count as unlabeled.
#[cfg(not(feature = "selinux"))]
#[derive(Debug)]
enum UnlabeledType {}

impl UnlabeledType {
    /// Look up the unlabeled type if SELinux is enabled for this process.
    #[cfg(feature = "selinux")]
    fn query() -> Result<Option<Self>> {
        if !selinux_enabled() {
            return Ok(None);
        }
        let context = selinux::SecurityContext::of_initial_kernel_context(
            SELINUX_INITIAL_SID_UNLABELED,
            true,
        )
        .context("Querying the SELinux unlabeled initial context")?;
        context_type(context.as_bytes()).map(|t| Some(Self(t)))
    }

    #[cfg(not(feature = "selinux"))]
    fn query() -> Result<Option<Self>> {
        Ok(None)
    }

    /// Whether a `security.selinux` value has this type.
    #[cfg(feature = "selinux")]
    fn matches(&self, context: &[u8]) -> Result<bool> {
        Ok(context_type(context)?.as_c_str() == self.0.as_c_str())
    }

    #[cfg(not(feature = "selinux"))]
    fn matches(&self, _context: &[u8]) -> Result<bool> {
        match *self {}
    }
}

#[cfg(feature = "selinux")]
fn context_type(context: &[u8]) -> Result<CString> {
    // security.selinux xattrs may include a trailing NUL terminator.
    let context = context.strip_suffix(b"\0").unwrap_or(context);
    let context = CString::new(context).context("SELinux context contains an interior NUL")?;
    context
        .to_str()
        .context("SELinux context is not valid UTF-8")?;
    selinux::OpaqueSecurityContext::from_c_str(&context)
        .context("Parsing SELinux context")?
        .the_type()
        .context("Reading SELinux context type")
}

/// Query the SELinux labeling for a particular path
#[cfg(feature = "selinux")]
pub(crate) fn has_security_selinux(root: &Dir, path: &Utf8Path) -> Result<SELinuxLabelState> {
    let unlabeled_type = UnlabeledType::query()?.context("SELinux is not enabled")?;
    has_security_selinux_inner(root, path, Some(&unlabeled_type))
}

/// Read the `security.selinux` extended attribute of the target path.
/// Symbolic links are not followed for the target.
fn read_security_selinux(root: &Dir, path: &Utf8Path) -> rustix::io::Result<Vec<u8>> {
    // TODO: avoid hardcoding a max size here
    let mut buf = [0u8; 2048];
    let fdpath = format!("/proc/self/fd/{}/{path}", root.as_raw_fd());
    let len = rustix::fs::lgetxattr(fdpath, "security.selinux", &mut buf)?;
    Ok(buf[..len].to_vec())
}

fn has_security_selinux_inner(
    root: &Dir,
    path: &Utf8Path,
    unlabeled_type: Option<&UnlabeledType>,
) -> Result<SELinuxLabelState> {
    match read_security_selinux(root, path) {
        Ok(label) => {
            // Installation can relabel a target while its host has SELinux disabled.
            // In that case, retain the conservative xattr-presence behavior.
            let Some(unlabeled_type) = unlabeled_type else {
                return Ok(SELinuxLabelState::Labeled);
            };
            let unlabeled = unlabeled_type
                .matches(&label)
                .with_context(|| format!("Parsing SELinux context for {path:?}"))?;
            if unlabeled {
                Ok(SELinuxLabelState::Unlabeled)
            } else {
                Ok(SELinuxLabelState::Labeled)
            }
        }
        Err(rustix::io::Errno::OPNOTSUPP) => Ok(SELinuxLabelState::Unsupported),
        Err(rustix::io::Errno::NODATA) => Ok(SELinuxLabelState::Unlabeled),
        Err(e) => Err(e).with_context(|| format!("Failed to look up context for {path:?}")),
    }
}

/// Directly set the `security.selinux` extended attribute on the target
/// path. Symbolic links are not followed for the target.
///
/// Note that this API will work even if SELinux is disabled.
pub(crate) fn set_security_selinux_path(root: &Dir, path: &Utf8Path, label: &[u8]) -> Result<()> {
    let fdpath = format!("/proc/self/fd/{}/", root.as_raw_fd());
    let fdpath = &Path::new(&fdpath).join(path);
    rustix::fs::lsetxattr(
        fdpath,
        "security.selinux",
        label,
        rustix::fs::XattrFlags::empty(),
    )?;
    Ok(())
}

fn ensure_labeled_inner(
    root: &Dir,
    path: &Utf8Path,
    metadata: &Metadata,
    policy: &ostree::SePolicy,
    unlabeled_type: Option<&UnlabeledType>,
) -> Result<SELinuxLabelState> {
    let r = has_security_selinux_inner(root, path, unlabeled_type)?;
    if matches!(r, SELinuxLabelState::Unlabeled) {
        relabel_with(root, metadata, path, None, policy, unlabeled_type)?;
    }
    Ok(r)
}

/// Given the policy, relabel the target file or directory.
/// Optionally, an override for the path can be provided
/// to set the label as if the target has that filename.
///
/// A path that the policy labels `<<none>>` (such as `/var/tmp/.*`) has no
/// label in it: like setfiles and restorecon, this leaves its label alone.
/// If it has none, it gets its directory's, as a file created there would.
pub(crate) fn relabel(
    root: &Dir,
    metadata: &Metadata,
    path: &Utf8Path,
    as_path: Option<&Utf8Path>,
    policy: &ostree::SePolicy,
) -> Result<()> {
    let unlabeled_type = UnlabeledType::query()?;
    relabel_with(
        root,
        metadata,
        path,
        as_path,
        policy,
        unlabeled_type.as_ref(),
    )
}

/// [`relabel`], with the `unlabeled_type` already looked up.
fn relabel_with(
    root: &Dir,
    metadata: &Metadata,
    path: &Utf8Path,
    as_path: Option<&Utf8Path>,
    policy: &ostree::SePolicy,
    unlabeled_type: Option<&UnlabeledType>,
) -> Result<()> {
    assert!(!path.starts_with("/"));
    let as_path = as_path
        .map(Cow::Borrowed)
        .unwrap_or_else(|| Utf8Path::new("/").join(path).into());
    let Some(label) = optional_label(policy, &as_path, metadata.mode())? else {
        if policy.csum().is_none() {
            tracing::debug!("No SELinux policy loaded; not labeling {path}");
            return Ok(());
        }
        return inherit_label(root, path, &as_path, unlabeled_type);
    };
    tracing::trace!("Setting label for {path} to {label}");
    set_security_selinux_path(root, &path, label.as_bytes())
}

/// For [`relabel`]: give `path`, which the policy has no label for (as
/// `as_path`), its parent directory's label if it has none of its own.
fn inherit_label(
    root: &Dir,
    path: &Utf8Path,
    as_path: &Utf8Path,
    unlabeled_type: Option<&UnlabeledType>,
) -> Result<()> {
    let state = |p: &Utf8Path| has_security_selinux_inner(root, p, unlabeled_type);
    if state(path)? != SELinuxLabelState::Unlabeled {
        tracing::debug!("No label for {as_path} in the policy; keeping {path}'s");
        return Ok(());
    }
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    let parent = if parent.as_str().is_empty() {
        Utf8Path::new(".")
    } else {
        parent
    };
    if state(parent)? != SELinuxLabelState::Labeled {
        tracing::debug!("No label for {as_path} in the policy, nor on {parent}");
        return Ok(());
    }
    let label = read_security_selinux(root, parent)
        .with_context(|| format!("Reading the SELinux label of {parent}"))?;
    tracing::debug!("No label for {as_path} in the policy; giving {path} {parent}'s");
    set_security_selinux_path(root, path, &label)
}

fn relabel_recurse_inner(
    root: &Dir,
    path: &mut Utf8PathBuf,
    mut as_path: Option<&mut Utf8PathBuf>,
    policy: &ostree::SePolicy,
    unlabeled_type: Option<&UnlabeledType>,
) -> Result<()> {
    // Relabel this directory
    let self_meta = root.dir_metadata()?;
    relabel_with(
        root,
        &self_meta,
        path,
        as_path.as_ref().map(|p| p.as_path()),
        policy,
        unlabeled_type,
    )?;

    // Relabel all children
    for ent in root.read_dir(&path)? {
        let ent = ent?;
        let metadata = ent.metadata()?;
        let name = ent.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid non-UTF-8 filename: {name:?}"))?;
        // Extend both copies of the path
        path.push(name);
        if let Some(p) = as_path.as_mut() {
            p.push(name);
        }

        if metadata.is_dir() {
            let as_path = as_path.as_deref_mut();
            relabel_recurse_inner(root, path, as_path, policy, unlabeled_type)?;
        } else {
            let as_path = as_path.as_ref().map(|p| p.as_path());
            relabel_with(root, &metadata, &path, as_path, policy, unlabeled_type)?
        }
        // Trim what we added to the path
        let r = path.pop();
        assert!(r);
        if let Some(p) = as_path.as_mut() {
            let r = p.pop();
            assert!(r);
        }
    }

    Ok(())
}

/// Recursively relabel the target directory.
pub(crate) fn relabel_recurse(
    root: &Dir,
    path: impl AsRef<Utf8Path>,
    as_path: Option<&Utf8Path>,
    policy: &ostree::SePolicy,
) -> Result<()> {
    let mut path = path.as_ref().to_owned();
    // This path must be relative, as we access via cap-std
    assert!(!path.starts_with("/"));
    let mut as_path = as_path.map(|v| v.to_owned());
    // But the as_path must be absolute, if provided
    if let Some(as_path) = as_path.as_deref() {
        assert!(as_path.starts_with("/"));
    }
    let unlabeled_type = UnlabeledType::query()?;
    relabel_recurse_inner(
        root,
        &mut path,
        as_path.as_mut(),
        policy,
        unlabeled_type.as_ref(),
    )
}

/// Recursively ensure all files under a directory have SELinux labels.
/// Uses the `walk` API with `noxdev` and `skip_mountpoints` to avoid crossing
/// mount point boundaries
/// (e.g. into sysfs, procfs, etc.).
/// The provided `skip` parameter is a device/inode pair that we will ignore
/// (and not traverse into).
pub(crate) fn ensure_dir_labeled_recurse(
    root: &Dir,
    path: &mut Utf8PathBuf,
    policy: &ostree::SePolicy,
    skip: Option<(libc::dev_t, libc::ino64_t)>,
) -> Result<()> {
    use cap_std_ext::dirext::WalkConfiguration;
    use std::ops::ControlFlow;

    // When SELinux is unavailable to this process, retain the conservative
    // xattr-presence behavior in `has_security_selinux_inner`.
    let unlabeled_type = UnlabeledType::query()?;
    // Juggle the cap-std requirement for relative paths vs the libselinux
    // requirement for absolute paths by special casing the empty string "" as "."
    // just for the initial directory enumeration.
    let path_for_read = if path.as_str().is_empty() {
        Utf8Path::new(".")
    } else {
        &*path
    };

    let mut n = 0u64;

    // Label the starting directory itself; the walk API only visits children.
    let metadata = root.symlink_metadata(path_for_read)?;
    match ensure_labeled_inner(root, path, &metadata, policy, unlabeled_type.as_ref())? {
        SELinuxLabelState::Unlabeled => {
            n += 1;
        }
        SELinuxLabelState::Unsupported => return Ok(()),
        SELinuxLabelState::Labeled => {}
    }
    let config = WalkConfiguration::default()
        .noxdev()
        .skip_mountpoints()
        .path_base(path_for_read.as_std_path());

    root.open_dir(path_for_read)?
        .walk::<_, anyhow::Error>(&config, |component| {
            let metadata = component.entry.metadata()?;

            // Check if this entry should be skipped
            if let Some((skip_dev, skip_ino)) = skip {
                if (metadata.dev(), metadata.ino()) == (skip_dev, skip_ino) {
                    tracing::debug!("Skipping dev={skip_dev} inode={skip_ino}");
                    // For directories, Break skips traversal into the directory
                    // but continues with the next sibling. For non-directories,
                    // Break would skip all remaining siblings, so use Continue
                    // to skip only this entry.
                    if component.file_type.is_dir() {
                        return Ok(ControlFlow::Break(()));
                    } else {
                        return Ok(ControlFlow::Continue(()));
                    }
                }
            }

            let path = Utf8Path::from_path(component.path)
                .ok_or_else(|| anyhow::anyhow!("Invalid non-UTF-8 path: {:?}", component.path))?;

            match ensure_labeled_inner(root, path, &metadata, policy, unlabeled_type.as_ref())? {
                SELinuxLabelState::Unlabeled => {
                    n += 1;
                }
                // We check for Unsupported on the starting directory above,
                // and the walk uses noxdev + skip_mountpoints to stay on
                // the same filesystem, so hitting Unsupported here is
                // unexpected.
                SELinuxLabelState::Unsupported => {
                    anyhow::bail!(
                        "Unexpected SELinuxLabelState::Unsupported during walk at {path}"
                    );
                }
                SELinuxLabelState::Labeled => {}
            }

            Ok(ControlFlow::Continue(()))
        })?;

    if n > 0 {
        tracing::debug!("Relabeled {n} objects in {path}");
    }
    Ok(())
}

/// A wrapper for creating a directory, also optionally setting a SELinux label.
pub(crate) fn ensure_dir_labeled(
    root: &Dir,
    destname: impl AsRef<Utf8Path>,
    as_path: Option<&Utf8Path>,
    mode: rustix::fs::Mode,
    policy: Option<&ostree::SePolicy>,
) -> Result<()> {
    use std::borrow::Cow;

    let destname = destname.as_ref();
    // Special case the empty string
    let local_destname = if destname.as_str().is_empty() {
        ".".into()
    } else {
        destname
    };
    tracing::debug!("Labeling {local_destname}");
    let label = policy
        .map(|policy| {
            let as_path = as_path
                .map(Cow::Borrowed)
                .unwrap_or_else(|| Utf8Path::new("/").join(destname).into());
            require_label(policy, &as_path, libc::S_IFDIR | mode.as_raw_mode())
        })
        .transpose()
        .with_context(|| format!("Labeling {local_destname}"))?;
    tracing::trace!("Label for {local_destname} is {label:?}");

    root.ensure_dir_with(local_destname, &DirBuilder::new())
        .with_context(|| format!("Opening {local_destname}"))?;
    let dirfd = cap_std_ext::cap_primitives::fs::open(
        &root.as_filelike_view(),
        local_destname.as_std_path(),
        OpenOptions::new().read(true),
    )
    .context("opendir")?;
    let dirfd = dirfd.as_fd();
    rustix::fs::fchmod(dirfd, mode).context("fchmod")?;
    if let Some(label) = label {
        set_security_selinux(dirfd, label.as_bytes())?;
    }

    Ok(())
}

/// A wrapper for atomically writing a file, also optionally setting a SELinux label.
/// The label is looked up for `destname` as if `root` were `/`, so pass the
/// directory that stands for the target's root, never a subdirectory of it.
pub(crate) fn atomic_replace_labeled<F>(
    root: &Dir,
    destname: impl AsRef<Utf8Path>,
    mode: rustix::fs::Mode,
    policy: Option<&ostree::SePolicy>,
    f: F,
) -> Result<()>
where
    F: FnOnce(&mut std::io::BufWriter<cap_std_ext::cap_tempfile::TempFile>) -> Result<()>,
{
    let destname = destname.as_ref();
    let label = policy
        .map(|policy| {
            let abs_destname = Utf8Path::new("/").join(destname);
            require_label(policy, &abs_destname, libc::S_IFREG | mode.as_raw_mode())
        })
        .transpose()?;

    root.atomic_replace_with(destname, |w| {
        // Peel through the bufwriter to get the fd
        let fd = w.get_mut();
        let fd = fd.as_file_mut();
        let fd = fd.as_fd();
        // Apply the target mode bits
        rustix::fs::fchmod(fd, mode).context("fchmod")?;
        // If we have a label, apply it
        if let Some(label) = label {
            tracing::debug!("Setting label for {destname} to {label}");
            set_security_selinux(fd, label.as_bytes())?;
        } else {
            tracing::debug!("No label for {destname}");
        }
        // Finally call the underlying writer function
        f(w)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gio::glib::Variant;

    #[test]
    fn test_selinux_xattr() {
        let notfound: &[&[(&[u8], &[u8])]] = &[&[], &[(b"foo", b"bar")]];
        for case in notfound {
            assert!(!xattrs_have_selinux(&Variant::from(case)));
        }
        let found: &[(&[u8], &[u8])] = &[(b"foo", b"bar"), (SELINUX_XATTR, b"foo_t")];
        assert!(xattrs_have_selinux(&Variant::from(found)));
    }

    #[test]
    fn relabel_none() -> Result<()> {
        use testutil::*;
        const ROOT: &str = "system_u:object_r:root_t:s0";
        const VAR: &str = "system_u:object_r:var_t:s0";
        const TMP: &str = "system_u:object_r:tmp_t:s0";
        const OTHER: &str = "system_u:object_r:user_tmp_t:s0";
        let td = cap_std_ext::cap_tempfile::tempdir(cap_std::ambient_authority())?;
        td.create_dir("policy")?;
        let policy = file_contexts_policy(
            &td.open_dir("policy")?,
            &format!("/\t{ROOT}\n/var(/.*)?\t{VAR}\n/var/tmp\t-d\t{TMP}\n/var/tmp/.*\t<<none>>\n"),
        )?;
        td.create_dir_all("var/tmp/dir")?;
        for f in ["labeled", "unlabeled", "dir/nested"] {
            td.write(Utf8Path::new("var/tmp").join(f), "")?;
        }
        if let Some(why) = cannot_label(&td, "var/tmp/labeled", OTHER) {
            eprintln!("skipping relabel_none: {why}");
            return Ok(());
        }
        assert!(is_unlabeled(&td, "var/tmp/labeled")?);
        set_security_selinux_path(&td, "var/tmp/labeled".into(), OTHER.as_bytes())?;
        // Both the full relabel and the one of unlabeled files
        for full in [true, false] {
            for p in [
                "var",
                "var/tmp",
                "var/tmp/unlabeled",
                "var/tmp/dir",
                "var/tmp/dir/nested",
            ] {
                unlabel(&td, p)?;
            }
            if full {
                relabel_recurse(&td, "var", None, &policy)?;
            } else {
                ensure_dir_labeled_recurse(&td, &mut Utf8PathBuf::from("var"), &policy, None)?;
            }
            assert_eq!(label(&td, "var")?, VAR);
            assert_eq!(label(&td, "var/tmp")?, TMP);
            // <<none>>: a label is kept, and a file without one gets its
            // directory's
            assert_eq!(label(&td, "var/tmp/labeled")?, OTHER, "full: {full}");
            for p in ["var/tmp/unlabeled", "var/tmp/dir", "var/tmp/dir/nested"] {
                assert_eq!(label(&td, p)?, TMP, "{p}, full: {full}");
            }
        }
        // Below a directory without a label, it stays without one
        for p in ["var/tmp/dir", "var/tmp/dir/nested"] {
            unlabel(&td, p)?;
        }
        let nested = Utf8Path::new("var/tmp/dir/nested");
        relabel(&td, &td.symlink_metadata(nested)?, nested, None, &policy)?;
        assert!(is_unlabeled(&td, nested.as_str())?);
        Ok(())
    }

    #[test]
    #[cfg(feature = "selinux")]
    fn test_unlabeled_type() {
        // Only meaningful where SELinux is enabled
        let Some(unlabeled_type) = UnlabeledType::query().unwrap() else {
            return;
        };
        assert!(
            unlabeled_type
                .matches(b"system_u:object_r:unlabeled_t:s0\0")
                .unwrap()
        );
        assert!(
            !unlabeled_type
                .matches(b"system_u:object_r:var_t:s0")
                .unwrap()
        );
    }

    #[test]
    #[cfg(feature = "selinux")]
    fn test_context_type() {
        let cases: &[(&[u8], Option<&str>)] = &[
            (b"system_u:object_r:unlabeled_t:s0", Some("unlabeled_t")),
            (b"system_u:object_r:unlabeled_t:s0\0", Some("unlabeled_t")),
            (
                b"system_u:object_r:unlabeled_t:s0:c0.c1023",
                Some("unlabeled_t"),
            ),
            (b"system_u:object_r:var_t:s0", Some("var_t")),
            (b"system_u:object_r", None),
            (b"system_u:object_r:var_t:s0\0\0", None),
            (b"system_u:object_r:var_t\0:s0", None),
            (b"system_u:object_r:unlabeled_t:\xff", None),
        ];

        for (context, expected_type) in cases {
            assert_eq!(
                context_type(context)
                    .ok()
                    .and_then(|context_type| context_type.into_string().ok())
                    .as_deref(),
                *expected_type
            );
        }
    }
}

/// Helpers for tests that label files with a policy of their own.
#[cfg(test)]
pub(crate) mod testutil {
    use super::*;

    const UNLABELED: &str = "system_u:object_r:unlabeled_t:s0";

    /// Write a policy with only `file_contexts` below `root`, enough for
    /// labeling lookups, and load it.
    pub(crate) fn file_contexts_policy(
        root: &Dir,
        file_contexts: &str,
    ) -> Result<ostree::SePolicy> {
        root.create_dir_all("etc/selinux/test/contexts/files")?;
        root.create_dir_all("etc/selinux/test/policy")?;
        root.write(
            "etc/selinux/config",
            "SELINUX=enforcing\nSELINUXTYPE=test\n",
        )?;
        root.write(
            "etc/selinux/test/contexts/files/file_contexts",
            file_contexts,
        )?;
        root.write("etc/selinux/test/policy/policy.33", "")?;
        new_sepolicy_at(root)?.context("Loading the test policy")
    }

    /// The label of `path`.
    pub(crate) fn label(root: &Dir, path: &str) -> Result<String> {
        let label = read_security_selinux(root, path.into())
            .with_context(|| format!("Reading the SELinux label of {path}"))?;
        let label = label.strip_suffix(b"\0").unwrap_or(&label);
        Ok(String::from_utf8(label.to_vec())?)
    }

    /// Make `path` unlabeled as this process sees it: where it sees SELinux,
    /// which doesn't let labels be removed, give it the unlabeled context;
    /// elsewhere remove its label.
    pub(crate) fn unlabel(root: &Dir, path: &str) -> Result<()> {
        if selinux_enabled() {
            return set_security_selinux_path(root, path.into(), UNLABELED.as_bytes());
        }
        let fdpath = format!("/proc/self/fd/{}/{path}", root.as_raw_fd());
        match rustix::fs::lremovexattr(fdpath, "security.selinux") {
            Ok(()) | Err(rustix::io::Errno::NODATA) => Ok(()),
            Err(e) => Err(e).with_context(|| format!("Removing the SELinux label of {path}")),
        }
    }

    /// Whether `path` is unlabeled, as this process sees it.
    pub(crate) fn is_unlabeled(root: &Dir, path: &str) -> Result<bool> {
        let unlabeled_type = UnlabeledType::query()?;
        let state = has_security_selinux_inner(root, path.into(), unlabeled_type.as_ref())?;
        Ok(state == SELinuxLabelState::Unlabeled)
    }

    /// Why this process can't give `path` the `label` and then unlabel it,
    /// if it can't: it isn't allowed to (a confined container), the kernel
    /// doesn't know the label's type, or it hides SELinux from this process
    /// (which then can't remove labels). This only checks the extended
    /// attribute; tests check the classification with [`is_unlabeled`].
    pub(crate) fn cannot_label(root: &Dir, path: &str, label: &str) -> Option<String> {
        let probe = || -> Result<Option<String>> {
            set_security_selinux_path(root, path.into(), label.as_bytes())?;
            unlabel(root, path)?;
            let read = match read_security_selinux(root, path.into()) {
                Ok(l) => Some(l),
                Err(rustix::io::Errno::NODATA) => None,
                Err(e) => return Err(e.into()),
            };
            let read = read.as_deref().map(|l| l.strip_suffix(b"\0").unwrap_or(l));
            let expected = selinux_enabled().then_some(UNLABELED.as_bytes());
            Ok((read != expected).then(|| {
                let read = read.map(String::from_utf8_lossy);
                format!("{path} reads back {read:?} after unlabeling it")
            }))
        };
        match probe() {
            Ok(why) => why,
            Err(e) => Some(format!("can't set and remove SELinux labels here: {e:#}")),
        }
    }
}
