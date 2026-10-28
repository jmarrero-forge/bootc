//! `install to-filesystem --defer-var`: install without seeding the
//! stateroot's /var from the image.

use anyhow::{Context, Result};
use camino::Utf8Path;
use cap_std_ext::cap_std::fs::{Dir, Permissions, PermissionsExt as _};
use cap_std_ext::dirext::CapStdExtDirExt;
use ostree_ext::ostree;

/// Listed by `bootc --version`, so that tools preparing a target for
/// `install to-filesystem` know they can pass `--defer-var`.
pub(crate) const FEATURE: &str = "defer-var";

/// Marks a stateroot var that bootc left without the image's /var: written
/// there before the first deployment, it keeps both backends from seeding
/// it. bootc's composefs deployment checks for it. libostree seeds the
/// stateroot var on every deployment, but only while it is empty
/// (`prepare_deployment_var()`), so on ostree the marker's presence is
/// enough. It stays there afterwards, as a record that /var was deferred.
pub(crate) const MARKER: &str = ".bootc-defer-var";

/// Mark the stateroot var at `var` (relative to `root`, created if needed)
/// as deferred, before the first deployment. With a `policy`, the directory
/// and the marker are labeled as /var and its marker: nothing else labels
/// a stateroot var that isn't seeded on composefs, and on ostree this
/// matches what libostree's relabel of /var then does.
pub(crate) fn mark(root: &Dir, var: &Utf8Path, policy: Option<&ostree::SePolicy>) -> Result<()> {
    root.create_dir_all(var)
        .with_context(|| format!("Creating {var}"))?;
    // Like the image's /var, whatever the umask
    root.set_permissions(var, Permissions::from_mode(0o755))
        .with_context(|| format!("Setting the mode of {var}"))?;
    let dir = root
        .open_dir(var)
        .with_context(|| format!("Opening {var}"))?;
    dir.atomic_write_with_perms(MARKER, b"", Permissions::from_mode(0o644))
        .with_context(|| format!("Writing {var}/{MARKER}"))?;
    if let Some(policy) = policy {
        crate::lsm::relabel_recurse(root, var, Some("/var".into()), policy)
            .with_context(|| format!("SELinux labeling of {var}"))?;
    }
    Ok(())
}

/// Whether the stateroot var at `var` was marked as deferred.
pub(crate) fn is_marked(var: &Utf8Path) -> Result<bool> {
    let marker = var.join(MARKER);
    marker
        .try_exists()
        .with_context(|| format!("Querying {marker}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::cap_std::fs::MetadataExt as _;

    #[test]
    fn mark_stateroot_var() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = Utf8Path::from_path(temp.path()).unwrap();
        let td = Dir::open_ambient_dir(path, cap_std_ext::cap_std::ambient_authority())?;
        let var = Utf8Path::new("state/os/default/var");
        assert!(!is_marked(&path.join(var))?);
        mark(&td, var, None)?;
        assert!(is_marked(&path.join(var))?);
        let meta = td.open_dir(var)?.metadata(MARKER)?;
        assert!(meta.is_file());
        assert_eq!(meta.len(), 0);
        assert_eq!(meta.mode() & 0o7777, 0o644);
        assert_eq!(td.metadata(var)?.mode() & 0o7777, 0o755);
        // Marking again, e.g. after an interrupted installation, is fine,
        // and the mode doesn't depend on how the directory was created
        td.set_permissions(var, Permissions::from_mode(0o700))?;
        mark(&td, var, None)?;
        assert_eq!(td.open_dir(var)?.entries()?.count(), 1);
        assert_eq!(td.metadata(var)?.mode() & 0o7777, 0o755);
        Ok(())
    }
}
