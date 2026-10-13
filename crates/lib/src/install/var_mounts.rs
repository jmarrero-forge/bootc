//! Initialize caller-mounted /var filesystems from the image's /var.

use std::ffi::CString;
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{Context, Result, bail};
use bootc_mount::Filesystem;
use bootc_mount::tempmount::TempMount;
use bootc_utils::CommandRunExt;
use camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::{
    cap_std::{ambient_authority, fs::Dir},
    dirext::CapStdExtDirExt,
};
use ostree_ext::ostree;
use rustix::fs::{Mode, OFlags};
use rustix::mount::{MountFlags, MountPropagationFlags, mount, mount_change};
use rustix::thread::{UnshareFlags, unshare_unsafe};

use super::LOST_AND_FOUND;

/// Listed by `bootc --version`, so that tools preparing a target for
/// `install to-filesystem` know they can pass `--initialize-var-mounts`.
/// Older versions leave /var filesystems empty, or reject them entirely.
pub(crate) const FEATURE: &str = "initialize-var-mounts";

const VAR: &str = "var";

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

/// Fill each empty filesystem among `mounts` (relative to /var, below
/// `root_path`) with its part of the image's /var, one `cp` per filesystem.
/// Hardlinks within one filesystem are kept where the source has them;
/// those spanning filesystems become separate files. Filesystems that
/// already hold data are left alone, but empty filesystems below and above
/// them are still filled.
///
/// Returns the filesystems that were initialized, or left empty because the
/// image has no content for them. These still need labeling and syncing.
pub(crate) fn populate(
    root: &Dir,
    root_path: &Utf8Path,
    mounts: &[Utf8PathBuf],
    source: &ImageVar,
) -> Result<Vec<Utf8PathBuf>> {
    let mut prepared = Vec::new();
    if mounts.is_empty() {
        return Ok(prepared);
    }
    let root_path = root_path
        .canonicalize_utf8()
        .with_context(|| format!("Resolving {root_path}"))?;
    let source_dir = Dir::open_ambient_dir(&source.path, ambient_authority())
        .with_context(|| format!("Opening {}", source.path))?;
    for mount in mounts {
        let target = target_path(mount);
        let nested = children(mount, mounts);
        let target_dir = root
            .open_dir(&target)
            .with_context(|| format!("Opening /{target}"))?;
        if !is_empty_fs(&target_dir, mount, mount, &nested)? {
            println!("Preserving existing contents of /{target}");
            continue;
        }
        if !check_source_path(&source_dir, mount)? {
            println!("No initial content for /{target} in the image");
            prepared.push(mount.clone());
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
        view.copy(
            &source.path.join(mount),
            &root_path.join(&target),
            source.hardlinks,
        )
        .with_context(|| format!("Initializing /{target}"))?;
        prepared.push(mount.clone());
    }
    Ok(prepared)
}

/// SELinux label the filesystems that [`populate`] prepared, by their
/// paths at boot.
pub(crate) fn label(root: &Dir, mounts: &[Utf8PathBuf], policy: &ostree::SePolicy) -> Result<()> {
    for mount in mounts {
        let mut path = target_path(mount);
        // These are fresh filesystems; label their roots unconditionally.
        // Without selinuxfs (e.g. in an osbuild buildroot), an inode without
        // a label still reports the kernel's unlabeled context, which the
        // walk below would take as labeled.
        for p in [path.clone(), path.join(LOST_AND_FOUND)] {
            if let Some(meta) = root.symlink_metadata_optional(&p)? {
                crate::lsm::relabel(root, &meta, &p, None, policy)
                    .with_context(|| format!("SELinux labeling of /{p}"))?;
            }
        }
        crate::lsm::ensure_dir_labeled_recurse(root, &mut path, policy, None)
            .with_context(|| format!("SELinux labeling of /{path}"))?;
    }
    Ok(())
}

/// Flush the filesystems of the given mounts, surfacing writeback errors.
pub(crate) fn sync(root: &Dir, mounts: &[Utf8PathBuf]) -> Result<()> {
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
    use cap_std_ext::cap_std::fs::{MetadataExt, Permissions, PermissionsExt};
    use cap_std_ext::cap_tempfile::TempDir;

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
            populate(&self.dir, &self.path, mounts, &self.image())
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
        let tmpfs = |p: &str| {
            Command::new("mount")
                .args(["-t", "tmpfs", "tmpfs"])
                .arg(path.join(p))
                .run_capture_stderr()
        };
        let result = (|| -> Result<()> {
            assert!(discover(path)?.is_empty());
            let root = Dir::open_ambient_dir(path, ambient_authority())?;
            root.create_dir_all("image/var/opt/app/data")?;
            root.write("image/var/opt/app/seed", "seed")?;
            root.set_permissions("image/var/opt/app/seed", Permissions::from_mode(0o640))?;
            root.set_permissions("image/var/opt/app", Permissions::from_mode(0o750))?;
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
            let mounts = discover(path)?;
            assert_eq!(mounts, paths(&["", "opt/app", "opt/app/data"]));
            assert_eq!(
                populate(&root, path, &mounts, &image)?,
                paths(&["", "opt/app"])
            );
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
                populate(&root, path, &mounts, &image)?,
                paths(&["opt/app/data"])
            );
            assert_eq!(root.read_to_string("var/opt/app/seed")?, "existing state");
            assert_eq!(root.read_to_string("var/opt/app/data/db")?, "image db");
            Ok(())
        })();
        let unmount = bootc_mount::unmount_recursive(path);
        result?;
        unmount
    }
}
