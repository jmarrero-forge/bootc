//! Local layers: changes made on a composefs host by running commands against
//! the deployment's image, kept as one more OCI layer on top of it.
//!
//! `bootc internals local-layer run -- CMD...` changes the system the way a
//! `RUN CMD` line in a Containerfile `FROM <booted image>` would, without a
//! container runtime. CMD runs chrooted in a staging root: a writable overlay
//! (`metacopy=off,redirect_dir=off`) over a fresh mount of the base image's
//! (SELinux-labeled) boot image. It is isolated from the host as
//! [`ChrootCmd::isolate`] describes, but shares its network.
//! The overlay's upper then becomes an OCI layer, and the base's layers plus
//! that one form a derived image in the same composefs repository, sharing
//! the base's objects. It is deployed like any other image, so it boots with
//! fs-verity on every file, the local ones included, and rolls back like any
//! other deployment.
//!
//! The deployment's origin keeps tracking the upstream image, and records the
//! commands and the base image's manifest digest in a `[local-layer]`
//! section. Each run re-runs every recorded command against the base, and
//! `bootc upgrade` does the same against the new base, so a local layer never
//! stacks on a stale one.

use std::ffi::OsStr;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use bootc_utils::{BindMode, ChrootCmd};
use camino::Utf8Path;
use cap_std_ext::cap_std::{ambient_authority, fs::Dir};
use composefs::fsverity::Sha512HashValue;
use composefs::mount::MountOptions;
use composefs_ctl::composefs;
use composefs_ctl::composefs_oci;
use composefs_oci::oci_image::OciImage;
use composefs_oci::overlay_upper::{UpperOptions, import_upper};
use composefs_oci::{DerivedLayer, OciDigest, PullResult};
use fn_error_context::context;
use rustix::mount::{
    FsMountFlags, FsOpenFlags, MountAttrFlags, MoveMountFlags, UnmountFlags, fsconfig_create,
    fsconfig_set_string, fsmount, fsopen, move_mount, unmount,
};

use crate::store::ComposefsRepository;

/// Origin section recording a deployment's local layer.
const ORIGIN_SECTION: &str = "local-layer";
/// The commands, as a JSON array of argument vectors (see [`encode_commands`]).
const ORIGIN_KEY_COMMANDS: &str = "commands";
/// The manifest digest of the image the layer was built on.
const ORIGIN_KEY_BASE: &str = "base-manifest-digest";
/// Config label naming the base image in a derived image.
const LABEL_BASE: &str = "containers.bootc.local-layer.base";
/// Value of `$container` for the commands, which tools such as rpm-ostree
/// and dnf use to tell that they are changing a root that isn't booted.
const CONTAINER_ENV: &str = "bootc-local-layer";
/// Where the base image and the staging root are mounted, in bootc's own
/// mount namespace.
const STAGING_MOUNTS: &str = "/run/bootc/local-layer";
/// Parent of the builds' work directories, which hold the overlay's upper
/// and work directories. This is on the physical root, which an overlay
/// upper needs (not tmpfs, and big enough), and only root can create it.
const WORK_PARENT: &str = "/var/lib/bootc-local-layer";
/// Prefix of the work directories in [`WORK_PARENT`].
const WORK_PREFIX: &str = "build.";
/// See [`BuildLock`]. It is in `/run`, so it doesn't outlive a boot.
const BUILD_LOCK: &str = "/run/bootc/local-layer.lock";
/// Host directory bound at the staging root's `/var/cache`, so package
/// caches survive from one run to the next.
const CACHE_DIR: &str = "/var/cache/bootc-local-layer";
/// Top-level directories that are not part of a local layer: API and runtime
/// mounts, the boot and sysroot mount points, and `/var`, which a
/// deployment only takes from its image on first install.
const EXCLUDED: [&str; 8] = ["boot", "dev", "proc", "run", "sys", "sysroot", "tmp", "var"];

/// Encodes commands as one origin value: JSON, with `;` and `#` escaped,
/// since the origin parser takes either as the start of a comment. Both can
/// only occur inside JSON strings here, where the escapes are valid JSON.
fn encode_commands(commands: &[Vec<String>]) -> Result<String> {
    Ok(serde_json::to_string(commands)?
        .replace(';', "\\u003b")
        .replace('#', "\\u0023"))
}

/// A deployment's local layer, as recorded in its origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalLayer {
    /// Every command, in order, each as its argument vector.
    pub(crate) commands: Vec<Vec<String>>,
    /// The manifest digest of the image the layer was built on.
    pub(crate) base_manifest_digest: String,
}

impl LocalLayer {
    /// Reads the local layer from a deployment's origin, if it has one.
    pub(crate) fn from_origin(origin: &tini::Ini) -> Result<Option<Self>> {
        let Some(commands) = origin.get::<String>(ORIGIN_SECTION, ORIGIN_KEY_COMMANDS) else {
            return Ok(None);
        };
        let commands = serde_json::from_str(&commands)
            .with_context(|| format!("Parsing [{ORIGIN_SECTION}] {ORIGIN_KEY_COMMANDS}"))?;
        let base_manifest_digest = origin
            .get::<String>(ORIGIN_SECTION, ORIGIN_KEY_BASE)
            .with_context(|| format!("[{ORIGIN_SECTION}] has no {ORIGIN_KEY_BASE}"))?;
        Ok(Some(Self {
            commands,
            base_manifest_digest,
        }))
    }

    /// Adds the `[local-layer]` section to an origin.
    pub(crate) fn to_origin(&self, origin: tini::Ini) -> Result<tini::Ini> {
        Ok(origin
            .section(ORIGIN_SECTION)
            .item(ORIGIN_KEY_COMMANDS, encode_commands(&self.commands)?)
            .item(ORIGIN_KEY_BASE, &self.base_manifest_digest))
    }

    /// The digest of the image the layer was built on.
    pub(crate) fn base_digest(&self) -> Result<OciDigest> {
        self.base_manifest_digest.parse().with_context(|| {
            format!(
                "Parsing the base manifest digest {}",
                self.base_manifest_digest
            )
        })
    }

    /// The same commands on another base.
    pub(crate) fn on_base(&self, base_manifest_digest: &str) -> Self {
        Self {
            commands: self.commands.clone(),
            base_manifest_digest: base_manifest_digest.to_owned(),
        }
    }

    /// The commands as one line of text, for the image history.
    fn describe(&self) -> String {
        self.commands
            .iter()
            .map(|argv| argv.join(" "))
            .collect::<Vec<_>>()
            .join(" && ")
    }
}

impl From<&crate::spec::LocalLayerStatus> for LocalLayer {
    fn from(l: &crate::spec::LocalLayerStatus) -> Self {
        Self {
            commands: l.commands.clone(),
            base_manifest_digest: l.base_image_digest.clone(),
        }
    }
}

impl From<&LocalLayer> for crate::spec::LocalLayerStatus {
    fn from(l: &LocalLayer) -> Self {
        Self {
            commands: l.commands.clone(),
            base_image_digest: l.base_manifest_digest.clone(),
        }
    }
}

/// The deployment the next boot has: the staged one if there is one, else
/// the booted one.
pub(crate) fn next_deployment(host: &crate::spec::Host) -> Option<&crate::spec::BootEntry> {
    host.status.staged.as_ref().or(host.status.booted.as_ref())
}

/// The local layer the next boot has (see [`next_deployment`]). A staged
/// deployment without one, such as a `bootc switch`, has dropped it.
pub(crate) fn pending_layer(host: &crate::spec::Host) -> Option<LocalLayer> {
    next_deployment(host)
        .and_then(|e| e.composefs.as_ref())
        .and_then(|c| c.local_layer.as_ref())
        .map(LocalLayer::from)
}

/// Detaches a mount when dropped.
struct MountGuard(PathBuf);

impl Drop for MountGuard {
    fn drop(&mut self) {
        if let Err(e) = unmount(&self.0, UnmountFlags::DETACH) {
            tracing::warn!("Unmounting {}: {e}", self.0.display());
        }
    }
}

/// The host's `/etc/resolv.conf`, bound read-only into the staging root for
/// the commands' network access. Images usually have none, so a placeholder is
/// created to bind over and removed again; it only ever exists in the
/// overlay's upper, so removing it leaves no whiteout.
struct ResolvConf {
    target: PathBuf,
    placeholder: bool,
}

const HOST_RESOLV_CONF: &str = "/etc/resolv.conf";

impl ResolvConf {
    fn bind(root: &Path) -> Result<Option<Self>> {
        if !Path::new(HOST_RESOLV_CONF).exists() {
            return Ok(None);
        }
        let target = root.join("etc/resolv.conf");
        let placeholder = match std::fs::symlink_metadata(&target) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::File::create(&target)
                    .with_context(|| format!("Creating {}", target.display()))?;
                true
            }
            Ok(m) if m.file_type().is_file() => false,
            Ok(_) => {
                // A symlink would be resolved on the host, not in the root.
                println!(
                    "note: the image's /etc/resolv.conf is not a file; not binding the host's"
                );
                return Ok(None);
            }
            Err(e) => return Err(e).with_context(|| format!("Inspecting {}", target.display())),
        };
        let guard = Self {
            target,
            placeholder,
        };
        rustix::mount::mount_bind(HOST_RESOLV_CONF, &guard.target)
            .with_context(|| format!("Binding {HOST_RESOLV_CONF}"))?;
        // Read-only, so that the commands can't change the host's.
        rustix::mount::mount_remount(
            &guard.target,
            rustix::mount::MountFlags::BIND | rustix::mount::MountFlags::RDONLY,
            "",
        )
        .with_context(|| format!("Making the bind of {HOST_RESOLV_CONF} read-only"))?;
        Ok(Some(guard))
    }
}

impl Drop for ResolvConf {
    fn drop(&mut self) {
        if let Err(e) = unmount(&self.target, UnmountFlags::DETACH) {
            tracing::warn!("Unmounting {}: {e}", self.target.display());
        }
        if self.placeholder {
            if let Err(e) = std::fs::remove_file(&self.target) {
                tracing::warn!("Removing {}: {e}", self.target.display());
            }
        }
    }
}

/// Mounts at `target` a writable overlay over `lower` whose upper is
/// self-contained: with metacopy and redirect_dir off, a changed file is
/// copied up whole and a renamed directory is copied, so the upper holds
/// only full files, whiteouts and opaque directories.
#[context("Mounting the staging overlay")]
fn mount_staging_overlay(
    lower: &Path,
    upper: &Path,
    work: &Path,
    target: &Path,
) -> Result<MountGuard> {
    let fs = fsopen("overlay", FsOpenFlags::FSOPEN_CLOEXEC)?;
    fsconfig_set_string(fs.as_fd(), "lowerdir", lower)?;
    fsconfig_set_string(fs.as_fd(), "upperdir", upper)?;
    fsconfig_set_string(fs.as_fd(), "workdir", work)?;
    for (key, value) in [
        ("metacopy", "off"),
        ("redirect_dir", "off"),
        ("index", "off"),
        ("xino", "off"),
    ] {
        fsconfig_set_string(fs.as_fd(), key, value)?;
    }
    fsconfig_create(fs.as_fd())?;
    // Device nodes in the base image are no way out of the root either.
    let mnt = fsmount(
        fs.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::MOUNT_ATTR_NODEV,
    )?;
    move_mount(
        mnt.as_fd(),
        "",
        rustix::fs::CWD,
        target,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    Ok(MountGuard(target.to_owned()))
}

/// Held while local layers are built and deployed, by `local-layer run`,
/// `bootc upgrade` and `bootc switch` from before they read the deployments
/// until they have staged one, so that one doesn't stage over what another
/// just did. Any work directory found while holding it was left by a build
/// that was killed.
pub(crate) struct BuildLock {
    _file: std::fs::File,
}

impl BuildLock {
    /// Takes [`BUILD_LOCK`], waiting for whoever holds it.
    pub(crate) fn acquire() -> Result<Self> {
        let path = Path::new(BUILD_LOCK);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Creating {}", parent.display()))?;
        }
        let file = std::fs::File::create(path).with_context(|| format!("Opening {BUILD_LOCK}"))?;
        use rustix::fs::{FlockOperation, flock};
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(rustix::io::Errno::WOULDBLOCK) => {
                println!("Waiting for another local layer build, upgrade or switch ({BUILD_LOCK})");
                flock(&file, FlockOperation::LockExclusive)
                    .with_context(|| format!("Locking {BUILD_LOCK}"))?;
            }
            Err(e) => return Err(e).with_context(|| format!("Locking {BUILD_LOCK}")),
        }
        Ok(Self { _file: file })
    }
}

/// Creates [`WORK_PARENT`] if needed, and checks that it is a directory only
/// root can write to, since everything in it is removed as stale.
fn work_parent() -> Result<&'static Path> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let path = Path::new(WORK_PARENT);
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("Creating {WORK_PARENT}")),
    }
    let meta =
        std::fs::symlink_metadata(path).with_context(|| format!("Inspecting {WORK_PARENT}"))?;
    anyhow::ensure!(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
        "{WORK_PARENT} is not a directory that only root can write to"
    );
    Ok(path)
}

/// Removes the work directories of builds that were killed, which the
/// [`BuildLock`] the caller holds says they are. A directory that can't be
/// removed is only reported.
fn remove_stale_work_dirs(_lock: &BuildLock, parent: &Path) {
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!("Reading {}: {e}", parent.display());
            return;
        }
    };
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .as_bytes()
            .starts_with(WORK_PREFIX.as_bytes())
        {
            continue;
        }
        let path = entry.path();
        println!("Removing {}, left by an interrupted build", path.display());
        if let Err(e) = std::fs::remove_dir_all(&path) {
            tracing::warn!("Removing {}: {e}", path.display());
        }
    }
}

/// Runs the layer's commands in a staging root over its base image, and
/// imports the result into `repo` as a derived image, tagged as a bootc GC
/// root.
#[context("Building the local layer on {}", layer.base_manifest_digest)]
pub(crate) async fn build_derived(
    repo: &Arc<ComposefsRepository>,
    layer: &LocalLayer,
    lock: &BuildLock,
) -> Result<PullResult<Sha512HashValue>> {
    let base = layer.base_digest()?;
    let image = OciImage::open(repo, &base, None)
        .with_context(|| format!("Opening the base image {base} in the composefs repository"))?;

    let work_parent = work_parent()?;
    remove_stale_work_dirs(lock, work_parent);
    let work = tempfile::Builder::new()
        .prefix(WORK_PREFIX)
        .tempdir_in(work_parent)
        .with_context(|| format!("Creating a work directory in {WORK_PARENT}"))?;
    let upper = work.path().join("upper");
    let overlay_work = work.path().join("work");
    let lower = Path::new(STAGING_MOUNTS).join("base");
    let root = Path::new(STAGING_MOUNTS).join("root");
    for d in [&upper, &overlay_work, &lower, &root] {
        std::fs::create_dir_all(d).with_context(|| format!("Creating {}", d.display()))?;
    }
    std::fs::create_dir_all(CACHE_DIR).with_context(|| format!("Creating {CACHE_DIR}"))?;

    // The boot image, not the plain one: it carries the SELinux labels of
    // the image's own policy, without which the commands (and the scriptlets
    // they run) can't be executed under an enforcing policy. Its empty /boot
    // and /sysroot are not part of a layer anyway.
    image
        .mount_at(repo, true, &lower, &MountOptions::default())
        .context("Mounting the base image")?;
    let lower_mount = MountGuard(lower.clone());
    {
        let _root = mount_staging_overlay(&lower, &upper, &overlay_work, &root)?;
        let _resolv = ResolvConf::bind(&root)?;
        let root_utf8 = Utf8Path::from_path(&root).context("Staging root path is not UTF-8")?;
        for argv in &layer.commands {
            println!("Running: {}", argv.join(" "));
            ChrootCmd::new(root_utf8)
                .set_default_path()
                .setenv("container", CONTAINER_ENV)
                // As PID 1 of its own namespace, the command looks booted
                // rather than chrooted to systemctl, which would then try
                // to reach systemd.
                .setenv("SYSTEMD_OFFLINE", "1")
                .isolate()
                .bind(&CACHE_DIR, &"/var/cache", BindMode::Default)
                .run(argv)
                .with_context(|| format!("Running {argv:?} in the staging root"))?;
        }
    }

    // The base stays mounted so that directories which only hold changes
    // keep the base's metadata (see UpperOptions::lower).
    let excluded: Vec<&OsStr> = EXCLUDED.iter().map(OsStr::new).collect();
    let opts = UpperOptions {
        excluded: &excluded,
        lower: Some(&lower),
        userxattr: false,
    };
    let imported = import_upper(repo, &upper, &opts, work.path()).await?;
    drop(lower_mount);
    if imported
        .upper
        .excluded
        .iter()
        .any(|e| e.as_os_str() == OsStr::new("var"))
    {
        println!("note: changes under /var are not part of the local layer");
    }
    println!(
        "Local layer {}: {} files, {} directories, {} symlinks, {} removals ({} bytes)",
        imported.diff_id,
        imported.upper.files + imported.upper.hardlinks,
        imported.upper.directories,
        imported.upper.symlinks,
        imported.upper.whiteouts + imported.upper.opaque_directories,
        imported.size,
    );

    let created = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let derived = composefs_oci::derive_image(
        repo,
        &base,
        &[DerivedLayer {
            diff_id: imported.diff_id,
            verity: imported.verity,
            size: imported.size,
            created_by: format!("bootc local-layer: {}", layer.describe()),
        }],
        &[(LABEL_BASE, base.as_ref())],
        Some(&created),
        None,
    )?;
    let tag = super::repo::bootc_tag_for_manifest(&derived.manifest_digest.to_string());
    composefs_oci::tag_image(repo, &derived.manifest_digest, &tag)
        .context("Tagging the derived image as a bootc GC root")?;
    Ok(derived)
}

/// `bootc internals local-layer run`: add `command` to the local layer of
/// the next boot's deployment (the staged one, else the booted one), rebuild
/// it on the same base, and stage the result.
#[context("Running a local layer command")]
pub(crate) async fn run(
    storage: &crate::store::Storage,
    booted_cfs: &crate::store::BootedComposefs,
    command: Vec<String>,
    apply: bool,
) -> Result<()> {
    let lock = BuildLock::acquire()?;
    let host = super::status::get_composefs_status(storage, booted_cfs).await?;
    // Build on what the next boot has: a deployment that is staged but not
    // booted yet (a layer run, an upgrade or a switch) is kept.
    let next = next_deployment(&host).context("No booted deployment")?;
    let image = next.image.as_ref().context("The deployment has no image")?;
    let next_cfs = next.require_composefs()?;
    anyhow::ensure!(
        next_cfs.boot_type == super::boot::BootType::Bls,
        "Local layers need a BLS boot entry; a {:?} boot pins the base image's digest",
        next_cfs.boot_type
    );
    if host.status.usr_overlay.is_some() {
        // The layer is built from the image, never from the running /usr.
        println!(
            "note: /usr has an overlay (bootc usr-overlay); changes made there are not part \
             of the local layer, and are discarded on reboot"
        );
    }
    let mut layer = pending_layer(&host).unwrap_or_else(|| LocalLayer {
        commands: Vec::new(),
        base_manifest_digest: image.image_digest.clone(),
    });
    layer.commands.push(command);

    // As for an upgrade: the staged deployment is finalized at shutdown.
    super::service::start_finalize_stated_svc()?;

    let rootfs_dir = Dir::open_ambient_dir("/sysroot", ambient_authority())?;
    let mut repo = super::repo::open_composefs_repo(&rootfs_dir)?;
    if booted_cfs.cmdline.allow_missing_fsverity {
        repo.set_insecure();
    }
    let repo = Arc::new(repo);
    let derived = build_derived(&repo, &layer, &lock).await?;
    let pulled = super::repo::boot_image_for_pulled(
        repo,
        &derived,
        booted_cfs.cmdline.allow_missing_fsverity,
    )?;
    let opts = super::update::DoUpgradeOpts {
        apply,
        ..Default::default()
    };
    super::update::deploy_pulled(
        storage,
        booted_cfs,
        &host,
        &image.image,
        &opts,
        pulled,
        Some(&layer),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_roundtrip() {
        let layer = LocalLayer {
            commands: vec![
                vec!["dnf".into(), "-y".into(), "install".into(), "tmux".into()],
                vec!["sh".into(), "-c".into(), "echo 'a=b; #c' > /etc/x".into()],
            ],
            base_manifest_digest: "sha256:0123".into(),
        };
        let origin = tini::Ini::new().section("origin").item("x", "y");
        let origin = layer.to_origin(origin).unwrap();
        let parsed = tini::Ini::from_string(&origin.to_string()).unwrap();
        assert_eq!(
            LocalLayer::from_origin(&parsed).unwrap(),
            Some(layer.clone())
        );
        assert_eq!(
            layer.describe(),
            "dnf -y install tmux && sh -c echo 'a=b; #c' > /etc/x"
        );
        let plain = tini::Ini::from_string("[origin]\nx=y\n").unwrap();
        assert_eq!(LocalLayer::from_origin(&plain).unwrap(), None);
        assert_eq!(
            layer.on_base("sha256:4567").base_manifest_digest,
            "sha256:4567"
        );
    }

    /// What GC can't read, it must not guess at (see `composefs_gc`).
    #[test]
    fn malformed_origins_are_errors() {
        for origin in [
            "[local-layer]\ncommands=not json\nbase-manifest-digest=sha256:0\n",
            "[local-layer]\ncommands=[]\n",
        ] {
            let ini = tini::Ini::from_string(origin).unwrap();
            assert!(LocalLayer::from_origin(&ini).is_err(), "{origin}");
        }
        let layer = LocalLayer {
            commands: Vec::new(),
            base_manifest_digest: "sha256:not-hex".into(),
        };
        assert!(layer.base_digest().is_err());
    }

    #[test]
    fn pending_layer_follows_the_next_deployment() {
        use crate::spec::{BootEntry, BootEntryComposefs, Host, LocalLayerStatus};
        let entry = |base: Option<&str>| BootEntry {
            image: None,
            cached_update: None,
            incompatible: false,
            pinned: false,
            soft_reboot_capable: false,
            download_only: false,
            store: None,
            ostree: None,
            composefs: Some(BootEntryComposefs {
                verity: String::new(),
                boot_type: super::super::boot::BootType::Bls,
                bootloader: crate::spec::Bootloader::Grub,
                boot_digest: None,
                missing_verity_allowed: false,
                local_layer: base.map(|b| LocalLayerStatus {
                    commands: vec![vec!["true".into()]],
                    base_image_digest: b.into(),
                }),
            }),
        };
        // The bases of the booted and the staged deployment's layers, and
        // the pending layer's.
        let cases = [
            (Some("sha256:a"), None, Some("sha256:a")),
            // Rebuilt by `bootc upgrade --tag`, so on another image.
            (Some("sha256:a"), Some(Some("sha256:b")), Some("sha256:b")),
            // A `bootc switch`, which drops the layer.
            (Some("sha256:a"), Some(None), None),
            (None, Some(Some("sha256:b")), Some("sha256:b")),
            (None, None, None),
        ];
        for (booted, staged, expected) in cases {
            let mut host = Host::default();
            host.status.booted = Some(entry(booted));
            host.status.staged = staged.map(entry);
            assert_eq!(
                pending_layer(&host).map(|l| l.base_manifest_digest),
                expected.map(String::from),
                "booted {booted:?}, staged {staged:?}"
            );
        }
    }
}
