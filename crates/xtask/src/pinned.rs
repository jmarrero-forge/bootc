//! Upgrade tests from pinned bootc releases.
//!
//! The per-PR upgrade test (`just test-upgrade`) starts from whatever bootc
//! the published base image ships that day. These start from an explicit
//! release instead: it is built from its own sources onto the current base
//! image (see `tmt/tests/Dockerfile.pinned-bootc`), installs itself, and the
//! installed system is then upgraded to the bootc under test.
//!
//! How the release installs is the [`Installer`]: `bcvk to-disk` runs the
//! tmt `readonly` plan after the upgrade, as `just test-upgrade` does. A
//! `to-filesystem` install onto a root filesystem bootc didn't make covers the
//! installs behind <https://github.com/bootc-dev/bootc/pull/2629>, whose
//! upgraded boot is expected to fail; a tmt plan can't drive that, so this
//! module runs that VM itself, with the in-VM steps in
//! `tmt/tests/booted/pinned-to-filesystem.nu`.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use fn_error_context::context;
use semver::Version;
use xshell::{Shell, cmd};

use crate::bcvk::BcvkInstallOpts;
use crate::{BootType, Bootloader, Installer, PinnedUpgradeArgs, RunTmtArgs, SealState};

/// Where releases are fetched from
const RELEASE_REPO: &str = "https://github.com/bootc-dev/bootc";
/// `--from` value for the newest release
const LATEST_RELEASE: &str = "latest";
const PINNED_DOCKERFILE: &str = "tmt/tests/Dockerfile.pinned-bootc";
/// Release sources are extracted under this directory
const PINNED_WORKDIR: &str = "target/pinned";
/// The tmt tests directory, which holds the in-VM steps
const TESTS_DIR: &str = "tmt/tests";
/// The in-VM steps of to-filesystem installs, relative to [`TESTS_DIR`]
const TO_FILESYSTEM_STEPS: &str = "booted/pinned-to-filesystem.nu";
/// Where the installed VM mounts [`TESTS_DIR`]
const GUEST_TESTS_DIR: &str = "/run/bootc-tests";
/// Where the `bcvk ephemeral` install VM mounts [`TESTS_DIR`]
const EPHEMERAL_TESTS_DIR: &str = "/run/virtiofs-mnt-tests";
/// Size of the disk for installs that are expected to be refused
const SCRATCH_DISK_SIZE: u64 = 20 << 30;
/// Memory for the `bcvk ephemeral` VM running `bootc install to-filesystem`
const INSTALL_VM_MEMORY: &str = "6G";
/// The published base images' composefs installs need SELinux permissive,
/// as in `just test-upgrade`.
const COMPOSEFS_KARGS: &[&str] = &["enforcing=0"];

/// How long a boot may take before SSH answers
const BOOT_TIMEOUT: Duration = Duration::from_secs(600);
/// How long to wait for the expected boot failure on the console
const FAILURE_TIMEOUT: Duration = Duration::from_secs(600);
const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// The console logs in a VM's log directory, as bcvk names them: the
/// serial console (`--platform-console-log`) and the virtio one (`--log-dir`)
const CONSOLE_LOGS: &[&str] = &["serial.txt", "console.txt"];

/// What the console shows when an install affected by #2629 boots a
/// deployment whose initramfs enforces fs-verity. The clearer message from
/// the follow-up to #2629 isn't asserted yet: once it lands, add its first
/// words here.
const STRICT_VERITY_FAILURE: &[&str] = &[
    "fs-verity is not supported by filesystem",
    "Failed to start bootc-root-setup.service",
];

/// How bootc refuses to install onto a filesystem without fs-verity: 1.15
/// when writing the first object, 1.17 when creating the repository
const REFUSED_INSTALL: &str = "Filesystem does not support fs-verity";

/// A bootc release to install from
#[derive(Debug)]
struct Release {
    tag: String,
    version: Version,
    commit: String,
}

/// Parse a release tag such as `v1.16.0`; pre-releases are not releases
fn release_version(tag: &str) -> Option<Version> {
    let v = Version::parse(tag.strip_prefix('v')?).ok()?;
    v.pre.is_empty().then_some(v)
}

/// Parse `git ls-remote --tags` output into (tag, commit) pairs, using the
/// commit an annotated tag points to.
fn parse_remote_tags(output: &str) -> Vec<(String, String)> {
    let mut tags: Vec<(String, String)> = Vec::new();
    for line in output.lines() {
        let Some((oid, name)) = line.split_once('\t') else {
            continue;
        };
        let Some(name) = name.strip_prefix("refs/tags/") else {
            continue;
        };
        let (name, peeled) = match name.strip_suffix("^{}") {
            Some(name) => (name, true),
            None => (name, false),
        };
        match tags.iter_mut().find(|(t, _)| t == name) {
            Some(existing) if peeled => existing.1 = oid.to_owned(),
            Some(_) => {}
            None => tags.push((name.to_owned(), oid.to_owned())),
        }
    }
    tags
}

/// Pick the tag for `from`: itself, or the newest release for [`LATEST_RELEASE`]
fn select_release(tags: &[(String, String)], from: &str) -> Result<(String, String, Version)> {
    let mut releases = tags
        .iter()
        .filter_map(|(tag, commit)| Some((tag, commit, release_version(tag)?)));
    let found = if from == LATEST_RELEASE {
        releases.max_by(|a, b| a.2.cmp(&b.2))
    } else {
        releases.find(|(tag, _, _)| *tag == from)
    };
    let (tag, commit, version) =
        found.with_context(|| format!("No bootc release tag {from} in {RELEASE_REPO}"))?;
    Ok((tag.clone(), commit.clone(), version))
}

/// Find the release and make its commit available locally
#[context("Resolving bootc release {from}")]
fn resolve_release(sh: &Shell, from: &str) -> Result<Release> {
    let output = cmd!(sh, "git ls-remote --tags {RELEASE_REPO} v*").read()?;
    let (tag, commit, version) = select_release(&parse_remote_tags(&output), from)?;
    let spec = format!("{commit}^{{commit}}");
    if cmd!(sh, "git cat-file -e {spec}")
        .quiet()
        .ignore_stderr()
        .run()
        .is_err()
    {
        let refspec = format!("refs/tags/{tag}");
        cmd!(sh, "git fetch --no-tags --depth=1 {RELEASE_REPO} {refspec}").run()?;
        let fetched_spec = "FETCH_HEAD^{commit}";
        let fetched = cmd!(sh, "git rev-parse {fetched_spec}").read()?;
        anyhow::ensure!(
            fetched.trim() == commit,
            "Fetched {tag} as {fetched}, but the remote listed {commit}"
        );
    }
    println!("bootc release {tag}: {version} at {commit}");
    Ok(Release {
        tag,
        version,
        commit,
    })
}

/// Extract the release's sources, for the `pinned-src` build context
#[context("Extracting {}", release.tag)]
fn extract_release(sh: &Shell, release: &Release) -> Result<Utf8PathBuf> {
    let dir = Utf8Path::new(PINNED_WORKDIR).join(&release.tag);
    if dir.try_exists()? {
        sh.remove_path(&dir)?;
    }
    sh.create_dir(&dir)?;
    let archive = format!("{dir}.tar");
    let commit = &release.commit;
    cmd!(sh, "git archive --format=tar -o {archive} {commit}").run()?;
    cmd!(sh, "tar -C {dir} -xf {archive}").run()?;
    sh.remove_path(&archive)?;
    Ok(dir)
}

/// Build the upgrade source image with the release's bootc, and return its name
#[context("Building an image with bootc {}", release.tag)]
fn build_pinned_image(sh: &Shell, args: &PinnedUpgradeArgs, release: &Release) -> Result<String> {
    let src = extract_release(sh, release)?;
    let image = format!("{}:{}", args.pinned_image, release.tag);
    let pinned_src = format!("pinned-src={src}");
    let commit = &release.commit;
    let epoch = cmd!(sh, "git show -s --format=%ct {commit}").read()?;
    let build_args = [
        format!("base={}", args.base),
        format!("source={}", args.source_image),
        format!("variant={}", args.variant),
        format!("bootloader={}", args.bootloader),
        format!("pkgversion={}", release.version),
        format!("SOURCE_DATE_EPOCH={}", epoch.trim()),
        format!("pinned_ref={}", release.tag),
        format!("pinned_commit={}", release.commit),
    ]
    .map(|a| format!("--build-arg={a}"));
    cmd!(
        sh,
        "podman build -f {PINNED_DOCKERFILE} --build-context {pinned_src} {build_args...} -t {image} ."
    )
    .run()?;
    // Catch a build that didn't produce the release's bootc
    let built = cmd!(sh, "podman run --rm {image} bootc --version").read()?;
    let expected = format!("bootc {}", release.version);
    anyhow::ensure!(
        built.trim() == expected,
        "{image} has {built}, expected {expected}"
    );
    Ok(image)
}

/// Run one pinned-version upgrade test
#[context("Running the upgrade test from bootc {}", args.from)]
pub(crate) fn test_upgrade_pinned(sh: &Shell, args: &PinnedUpgradeArgs) -> Result<()> {
    anyhow::ensure!(
        args.boot_type == BootType::Bls,
        "Only BLS installs are supported so far, not {}",
        args.boot_type
    );
    let release = resolve_release(sh, &args.from)?;
    let pinned = build_pinned_image(sh, args, &release)?;
    match args.installer {
        Installer::ToDisk => run_to_disk(sh, args, &release, &pinned),
        Installer::ToFilesystem => run_to_filesystem(sh, args, &release, &pinned),
    }
}

fn is_composefs(args: &PinnedUpgradeArgs) -> bool {
    args.variant.starts_with("composefs")
}

/// Install with `bcvk to-disk` and run the tmt `readonly` plan, which
/// upgrades first (see `maybe_upgrade` in `bootc_testlib.nu`)
fn run_to_disk(
    sh: &Shell,
    args: &PinnedUpgradeArgs,
    release: &Release,
    pinned: &str,
) -> Result<()> {
    let composefs = is_composefs(args);
    let env = vec![
        format!("BOOTC_variant={}", args.variant),
        format!("BOOTC_test_upgrade_image={}", args.image),
        format!("BOOTC_test_pinned_version={}", release.version),
    ];
    let mut tmt_args = RunTmtArgs {
        image: pinned.to_owned(),
        filters: vec!["readonly".into()],
        context: Vec::new(),
        env,
        upgrade_image: Some(args.image.clone()),
        bridge_image: None,
        skip_bind_storage: false,
        preserve_vm: args.preserve_vm,
        composefs_backend: composefs,
        composefs,
        bootloader: Some(args.bootloader.clone()),
        filesystem: Some(args.filesystem.clone()),
        seal_state: Some(SealState::Unsealed),
        boot_type: args.boot_type.clone(),
        karg: Vec::new(),
        log_dir: args.log_dir.clone(),
    };
    if composefs {
        tmt_args.karg = COMPOSEFS_KARGS.iter().map(|&k| k.to_owned()).collect();
    }
    crate::tmt::run_tmt(sh, &tmt_args)
}

/// What a `to-filesystem` install of a release onto a root filesystem made
/// by the stock mkfs does, per the summary in
/// <https://github.com/bootc-dev/bootc/pull/2629#issuecomment-6695640406>
#[derive(Debug, PartialEq, Eq)]
enum ToFilesystemOutcome {
    /// The install is refused: bootc up to 1.15 fails writing objects
    /// without fs-verity, and 1.17 checks for it first
    Refused,
    /// The install succeeds with a strict command line but no fs-verity,
    /// and boots until the initramfs enforces fs-verity (1.16.x on ext4)
    Affected,
}

fn to_filesystem_outcome(version: &Version, filesystem: &str) -> Result<ToFilesystemOutcome> {
    match filesystem {
        "ext4" if (version.major, version.minor) == (1, 16) => Ok(ToFilesystemOutcome::Affected),
        "ext4" => Ok(ToFilesystemOutcome::Refused),
        other => anyhow::bail!("to-filesystem installs support only ext4 so far, not {other}"),
    }
}

fn run_to_filesystem(
    sh: &Shell,
    args: &PinnedUpgradeArgs,
    release: &Release,
    pinned: &str,
) -> Result<()> {
    anyhow::ensure!(
        is_composefs(args),
        "to-filesystem installs are composefs-only so far"
    );
    let ctx = ToFilesystem::new(sh, args, release, pinned)?;
    match to_filesystem_outcome(&release.version, &args.filesystem)? {
        ToFilesystemOutcome::Refused => ctx.expect_refused(),
        ToFilesystemOutcome::Affected => {
            anyhow::ensure!(
                args.bootloader == Bootloader::Systemd,
                "Recovering affected installs is automated only for systemd-boot so far"
            );
            ctx.recover_after_failure()?;
            ctx.relax_before_upgrade()
        }
    }
}

/// Remove ANSI escape sequences, which the console has inside the messages
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.as_bytes().len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // CSI: ESC [ parameters, ended by a letter
            if chars.next() == Some('[') {
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The patterns of `expected` missing from `console`
fn missing_patterns<'a>(console: &str, expected: &[&'a str]) -> Vec<&'a str> {
    let console = strip_ansi(console);
    expected
        .iter()
        .copied()
        .filter(|p| !console.contains(p))
        .collect()
}

/// The test of one release installed with `to-filesystem`
struct ToFilesystem<'a> {
    sh: &'a Shell,
    args: &'a PinnedUpgradeArgs,
    release: &'a Release,
    pinned: &'a str,
    tests_dir: Utf8PathBuf,
    log_dir: Utf8PathBuf,
}

impl<'a> ToFilesystem<'a> {
    fn new(
        sh: &'a Shell,
        args: &'a PinnedUpgradeArgs,
        release: &'a Release,
        pinned: &'a str,
    ) -> Result<Self> {
        let cwd = Utf8PathBuf::try_from(std::env::current_dir()?)?;
        let base_log_dir = args
            .log_dir
            .clone()
            .or_else(|| {
                std::env::var("TMT_LOG_DIR")
                    .ok()
                    .filter(|d| !d.is_empty())
                    .map(Into::into)
            })
            .unwrap_or_else(|| "/var/tmp/tmt".into());
        Ok(Self {
            sh,
            args,
            release,
            pinned,
            tests_dir: cwd.join(TESTS_DIR),
            log_dir: base_log_dir.join(format!("pinned-to-filesystem-{}", release.tag)),
        })
    }

    fn kargs(&self) -> Vec<String> {
        COMPOSEFS_KARGS.iter().map(|&k| k.to_owned()).collect()
    }

    /// Run `bootc install to-filesystem` onto DISK in a `bcvk ephemeral` VM
    /// of the release's image, returning its combined output
    fn install(&self, disk: &Utf8Path) -> Result<std::process::Output> {
        let sh = self.sh;
        let pinned = self.pinned;
        let disk = format!("{disk}:output");
        let tests = format!("{}:tests", self.tests_dir);
        let steps = format!("{EPHEMERAL_TESTS_DIR}/{TO_FILESYSTEM_STEPS}");
        let fs = &self.args.filesystem;
        let bootloader = self.args.bootloader.to_string();
        let kargs = self.kargs();
        println!("Installing {pinned} with to-filesystem onto {fs}");
        let output = cmd!(
            sh,
            "bcvk ephemeral run-ssh --memory={INSTALL_VM_MEMORY} --bind-storage-ro --mount-disk-file={disk} --ro-bind={tests} {pinned} -- nu {steps} install {pinned} {fs} {bootloader} {kargs...}"
        )
        .ignore_status()
        .output()?;
        print!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        Ok(output)
    }

    /// bootc 1.15 and 1.17 must refuse the install
    #[context("Checking that bootc {} refuses the install", self.release.tag)]
    fn expect_refused(&self) -> Result<()> {
        // Not in the log directory, which CI uploads
        let disk = Utf8Path::new(PINNED_WORKDIR).join(format!("{}-disk.raw", self.release.tag));
        // A sparse file, as large as bcvk's VM disks: what bcvk would create
        // is too small for the install to get as far as fs-verity.
        std::fs::File::create(&disk)
            .and_then(|f| f.set_len(SCRATCH_DISK_SIZE))
            .with_context(|| format!("Creating {disk}"))?;
        let output = self.install(&disk);
        // The disk is only scratch space
        let _ = std::fs::remove_file(&disk);
        let output = output?;
        anyhow::ensure!(
            !output.status.success(),
            "bootc {} installed onto {} without fs-verity",
            self.release.version,
            self.args.filesystem
        );
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        anyhow::ensure!(
            text.contains(REFUSED_INSTALL),
            "The install failed, but not with \"{REFUSED_INSTALL}\""
        );
        println!(
            "bootc {} refused the install, as expected",
            self.release.version
        );
        Ok(())
    }

    /// Create a VM booting a fresh to-filesystem install of the release
    fn create_vm(&self, scenario: &str) -> Result<Vm<'a>> {
        let sh = self.sh;
        let name = format!(
            "bootc-pinned-{}-{scenario}",
            self.release.tag.replace('.', "-")
        );
        let log_dir = self.log_dir.join(scenario);
        // bcvk appends to the console logs; start them afresh
        if log_dir.try_exists()? {
            sh.remove_path(&log_dir)?;
        }
        sh.create_dir(&log_dir)?;
        let console = format!("--log-dir=console={log_dir}");
        let serial = format!("--platform-console-log={log_dir}/{}", CONSOLE_LOGS[0]);
        let tests = format!("--bind-ro={}:{GUEST_TESTS_DIR}", self.tests_dir);
        let install_args = BcvkInstallOpts {
            composefs_backend: true,
            composefs: true,
            bootloader: Some(self.args.bootloader.clone()),
            filesystem: Some(self.args.filesystem.clone()),
            ..Default::default()
        }
        .install_args();
        let pinned = self.pinned;
        // bcvk creates the VM from a to-disk install; its disk is then
        // replaced with the to-filesystem one.
        cmd!(
            sh,
            "bcvk libvirt run --replace --name {name} --detach --firmware=uefi-insecure --label=bootc.test=1 --bind-storage-ro {tests} {console} {serial} {install_args...} {pinned}"
        )
        .run()?;
        let vm = Vm {
            sh,
            name,
            log_dir,
            preserve: self.args.preserve_vm,
            boot_id: None,
        };
        let name = &vm.name;
        cmd!(sh, "bcvk libvirt stop --force {name}").run()?;
        let inspect = cmd!(sh, "bcvk libvirt inspect {name} --format=json")
            .ignore_stderr()
            .read()?;
        let inspect: serde_json::Value = serde_json::from_str(&inspect)?;
        let disk = inspect
            .get("disk_path")
            .and_then(|d| d.as_str())
            .context("bcvk libvirt inspect has no disk_path")?;
        // That disk is an overlay of bcvk's base disk, which the install VM
        // can't open; start from an empty one of the same size instead.
        let info = cmd!(sh, "qemu-img info --output=json {disk}").read()?;
        let info: serde_json::Value = serde_json::from_str(&info)?;
        let size = info
            .get("virtual-size")
            .and_then(|s| s.as_u64())
            .context("qemu-img info has no virtual-size")?
            .to_string();
        cmd!(sh, "qemu-img create -q -f qcow2 {disk} {size}").run()?;
        let output = self.install(Utf8Path::new(disk))?;
        anyhow::ensure!(
            output.status.success(),
            "Installing with to-filesystem failed"
        );
        cmd!(sh, "bcvk libvirt start {name}").run()?;
        Ok(vm)
    }

    /// The documented recovery after the failure: boot the previous entry
    /// (here, made the default before the upgrade), add '?' to the new
    /// entry, which then boots, and the next upgrade keeps the '?'.
    #[context("Recovering bootc {} after the failed boot", self.release.tag)]
    fn recover_after_failure(&self) -> Result<()> {
        let version = self.release.version.to_string();
        let image = &self.args.image;
        let mut vm = self.create_vm("recover")?;
        vm.wait_for_boot()?;
        vm.step(&["pre-upgrade", &version, "--affected"])?;
        let staged = vm.step(&["stage", image])?;
        let staged: serde_json::Value = serde_json::from_str(
            staged
                .lines()
                .last()
                .context("The stage step printed nothing")?,
        )
        .context("Parsing the stage step's output")?;
        let digest = staged
            .get("new_digest")
            .and_then(|d| d.as_str())
            .context("No new_digest")?;
        let mut expected = STRICT_VERITY_FAILURE.to_vec();
        expected.push(digest);
        vm.reboot_expecting_failure(&expected)?;
        vm.reset()?;
        vm.step(&["assert-version", &version])?;
        vm.step(&["relax", "new"])?;
        vm.reboot()?;
        vm.step(&["assert-booted", image, "--relaxed"])?;
        vm.step(&["switch", &self.args.upgrade_image])?;
        vm.reboot()?;
        vm.step(&["assert-booted", &self.args.upgrade_image, "--relaxed"])?;
        println!(
            "bootc {}: recovered after the failed boot",
            self.release.tag
        );
        Ok(())
    }

    /// The documented recovery before upgrading: add '?' to the booted
    /// entry, after which the upgrade boots.
    #[context("Relaxing bootc {} before upgrading", self.release.tag)]
    fn relax_before_upgrade(&self) -> Result<()> {
        let version = self.release.version.to_string();
        let image = &self.args.image;
        let mut vm = self.create_vm("relax-first")?;
        vm.wait_for_boot()?;
        vm.step(&["pre-upgrade", &version, "--affected"])?;
        vm.step(&["relax", "booted"])?;
        vm.reboot()?;
        vm.step(&["pre-upgrade", &version])?;
        vm.step(&["switch", image])?;
        vm.reboot()?;
        vm.step(&["assert-booted", image, "--relaxed"])?;
        println!("bootc {}: upgraded after relaxing first", self.release.tag);
        Ok(())
    }
}

/// A libvirt VM made by bcvk, removed when dropped
struct Vm<'a> {
    sh: &'a Shell,
    name: String,
    log_dir: Utf8PathBuf,
    preserve: bool,
    /// The current boot's ID, once it answered over SSH
    boot_id: Option<String>,
}

impl Vm<'_> {
    /// Run a command over SSH, returning its stdout
    fn ssh(&self, command: &[&str]) -> Result<String> {
        let sh = self.sh;
        let name = &self.name;
        Ok(cmd!(sh, "bcvk libvirt ssh {name} -- {command...}").read()?)
    }

    /// Run an in-VM step of `pinned-to-filesystem.nu`, returning its stdout
    #[context("Running in-VM step {}", step.join(" "))]
    fn step(&self, step: &[&str]) -> Result<String> {
        let script = format!("{GUEST_TESTS_DIR}/{TO_FILESYSTEM_STEPS}");
        let command = [&["nu", script.as_str()], step].concat();
        let output = self.ssh(&command)?;
        println!("{output}");
        Ok(output)
    }

    /// Wait until a boot other than the last one answers over SSH
    #[context("Waiting for {} to boot", self.name)]
    fn wait_for_boot(&mut self) -> Result<()> {
        let start = Instant::now();
        while start.elapsed() < BOOT_TIMEOUT {
            let sh = self.sh;
            let name = &self.name;
            let id = cmd!(
                sh,
                "bcvk libvirt ssh --timeout=5 {name} -- cat /proc/sys/kernel/random/boot_id"
            )
            .quiet()
            .ignore_stderr()
            .read();
            if let Ok(id) = id {
                let id = id.trim().to_owned();
                if !id.is_empty() && self.boot_id.as_ref() != Some(&id) {
                    println!("{} booted ({id})", self.name);
                    self.boot_id = Some(id);
                    return Ok(());
                }
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        anyhow::bail!("No new boot within {BOOT_TIMEOUT:?}; see {}", self.log_dir)
    }

    fn request_reboot(&self) {
        // The connection drops as the VM goes down
        let _ = self.ssh(&["systemctl", "reboot"]);
    }

    fn reboot(&mut self) -> Result<()> {
        self.request_reboot();
        self.wait_for_boot()
    }

    /// Both consoles, each from byte offset `since` on (see
    /// [`Self::console_sizes`]): the serial one has the kernel and the
    /// initramfs, the virtio one what the booted system writes there.
    fn console(&self, since: &[usize]) -> String {
        CONSOLE_LOGS
            .iter()
            .zip(since)
            .filter_map(|(f, &since)| {
                let b = std::fs::read(self.log_dir.join(f)).ok()?;
                Some(String::from_utf8_lossy(b.get(since..)?).into_owned())
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn console_sizes(&self) -> Vec<usize> {
        CONSOLE_LOGS
            .iter()
            .map(|f| std::fs::read(self.log_dir.join(f)).map_or(0, |b| b.len()))
            .collect()
    }

    /// Reboot, and wait for the console to show all of `expected`
    #[context("Waiting for the expected boot failure of {}", self.name)]
    fn reboot_expecting_failure(&mut self, expected: &[&str]) -> Result<()> {
        // Only look at what this boot writes
        let before = self.console_sizes();
        self.request_reboot();
        let start = Instant::now();
        loop {
            let console = self.console(&before);
            let missing = missing_patterns(&console, expected);
            if missing.is_empty() {
                println!("{}: the boot failed as expected", self.name);
                return Ok(());
            }
            if start.elapsed() > FAILURE_TIMEOUT {
                anyhow::bail!(
                    "The console never showed {missing:?} within {FAILURE_TIMEOUT:?}; see {}",
                    self.log_dir
                );
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// Power-cycle the VM, as one would a machine stuck in emergency mode
    fn reset(&mut self) -> Result<()> {
        let sh = self.sh;
        let name = &self.name;
        cmd!(sh, "bcvk libvirt stop --force {name}").run()?;
        cmd!(sh, "bcvk libvirt start {name}").run()?;
        self.wait_for_boot()
    }
}

impl Drop for Vm<'_> {
    fn drop(&mut self) {
        let sh = self.sh;
        let name = &self.name;
        if self.preserve {
            println!("Preserving VM {name}; remove it with: bcvk libvirt rm --stop --force {name}");
            return;
        }
        let _ = cmd!(sh, "bcvk libvirt rm --stop --force {name}")
            .ignore_status()
            .run();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_release() {
        let output = "\
aaa\trefs/tags/v1.15.2
bbb\trefs/tags/v1.16.0
ccc\trefs/tags/v1.16.0^{}
ddd\trefs/tags/v1.17.4
eee\trefs/tags/v1.18.0-rc.1
fff\trefs/tags/v1.9.9
";
        let tags = parse_remote_tags(output);
        // (from, expected tag, expected commit)
        let cases = [
            ("latest", "v1.17.4", "ddd"),
            ("v1.16.0", "v1.16.0", "ccc"),
            ("v1.15.2", "v1.15.2", "aaa"),
        ];
        for (from, tag, commit) in cases {
            let (t, c, _) = select_release(&tags, from).unwrap();
            assert_eq!((t.as_str(), c.as_str()), (tag, commit), "{from}");
        }
        for from in ["v1.18.0-rc.1", "v2.0.0", "main"] {
            assert!(select_release(&tags, from).is_err(), "{from}");
        }
    }

    #[test]
    fn test_to_filesystem_outcome() {
        use ToFilesystemOutcome::*;
        let cases = [
            ("1.15.2", Refused),
            ("1.16.0", Affected),
            ("1.16.14", Affected),
            ("1.17.0", Refused),
            ("1.17.4", Refused),
        ];
        for (version, expected) in cases {
            let version = Version::parse(version).unwrap();
            assert_eq!(
                to_filesystem_outcome(&version, "ext4").unwrap(),
                expected,
                "{version}"
            );
        }
        assert!(to_filesystem_outcome(&Version::new(1, 16, 0), "xfs").is_err());
    }

    #[test]
    fn test_missing_patterns() {
        let console = "[\x1b[0;1;31mFAILED\x1b[0m] Failed to start \x1b[0;1;39mbootc-root-setup.service\x1b[0m - bootc setup root.\n\
            initramfs-setup[641]:     4: FS_IOC_MEASURE_VERITY: fs-verity is not supported by filesystem\n";
        assert!(missing_patterns(console, STRICT_VERITY_FAILURE).is_empty());
        assert_eq!(
            missing_patterns("Reached target basic.target", &STRICT_VERITY_FAILURE[..1]),
            STRICT_VERITY_FAILURE[..1]
        );
    }
}
