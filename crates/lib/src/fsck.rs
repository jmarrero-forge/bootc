//! # Perform consistency checking.
//!
//! This is an internal module, backing the experimental `bootc internals fsck`
//! command.

// Unfortunately needed here to work with linkme
#![allow(unsafe_code)]

use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;

use anyhow::Context as _;
use bootc_utils::collect_until;
use camino::{Utf8Path, Utf8PathBuf};
use cap_std::fs::{Dir, MetadataExt as _};
use cap_std_ext::cap_std;
use cap_std_ext::dirext::CapStdExtDirExt;
use composefs_ctl::composefs;
use fn_error_context::context;
use linkme::distributed_slice;
use ostree_ext::ostree;
use ostree_ext::ostree_prepareroot::Tristate;

use crate::bootc_composefs::fsck as cfsck;
use crate::bootc_composefs::status::composefs_booted;
use crate::store::Storage;

use std::os::fd::AsFd;

/// The kind of problem a check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckFindingCode {
    /// `/usr/etc/resolv.conf` is a zero-sized file.
    ResolvconfZeroSized,
    /// fsverity is enabled for the ostree repository, but not on an object.
    ObjectWithoutFsverity,
    /// A strict composefs boot entry's image has no fs-verity, and the root
    /// filesystem doesn't support it.
    StrictEntryWithoutFsverity,
    /// A strict composefs boot entry's image has no fs-verity, although the
    /// root filesystem supports it.
    ImageWithoutFsverity,
    /// None of a composefs boot entry's images exist.
    ComposefsImageMissing,
    /// The initramfs would refuse a composefs boot entry for another reason.
    UnbootableComposefsEntry,
    /// No composefs boot entry was found, although the system booted from one.
    NoComposefsBootEntries,
    /// The boot entries weren't checked (informational).
    ComposefsBootEntriesNotChecked,
    /// The composefs repository's `meta.json` has no fs-verity under a
    /// strict boot (informational).
    MetaJsonWithoutFsverity,
}

impl std::fmt::Display for CheckFindingCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// A problem a check found in the system.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CheckFinding {
    code: CheckFindingCode,
    /// What the problem is in, e.g. a path or an object.
    subject: String,
    detail: String,
    /// Informational findings are printed, but don't fail the check.
    informational: bool,
}

impl CheckFinding {
    fn new(code: CheckFindingCode, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code,
            subject: subject.into(),
            detail: detail.into(),
            informational: false,
        }
    }

    /// A finding that doesn't fail the check.
    fn info(code: CheckFindingCode, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            informational: true,
            ..Self::new(code, subject, detail)
        }
    }
}

impl std::fmt::Display for CheckFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}: {}", self.code, self.subject, self.detail)
    }
}

/// Like the lints, checks have two levels of errors: the outer `Result` is
/// for unexpected runtime errors, which stop the check; every problem the
/// check finds in the system is collected as a finding, and the check runs
/// to completion.  No findings means the check passed.
pub(crate) type FsckResult = anyhow::Result<Vec<CheckFinding>>;

/// How many findings of one check are printed; the rest are counted.
const MAX_PRINTED_FINDINGS: NonZeroUsize = NonZeroUsize::new(5).unwrap();

pub(crate) type FsckFn = fn(&Storage) -> FsckResult;
pub(crate) type AsyncFsckFn = fn(&Storage) -> Pin<Box<dyn Future<Output = FsckResult> + '_>>;
#[derive(Debug)]
pub(crate) enum FsckFnImpl {
    Sync(FsckFn),
    Async(AsyncFsckFn),
}

impl From<FsckFn> for FsckFnImpl {
    fn from(value: FsckFn) -> Self {
        Self::Sync(value)
    }
}

impl From<AsyncFsckFn> for FsckFnImpl {
    fn from(value: AsyncFsckFn) -> Self {
        Self::Async(value)
    }
}

#[derive(Debug)]
pub(crate) struct FsckCheck {
    name: &'static str,
    ordering: u16,
    f: FsckFnImpl,
}

#[distributed_slice]
pub(crate) static FSCK_CHECKS: [FsckCheck];

impl FsckCheck {
    pub(crate) const fn new(name: &'static str, ordering: u16, f: FsckFnImpl) -> Self {
        FsckCheck { name, ordering, f }
    }
}

#[distributed_slice(FSCK_CHECKS)]
static CHECK_RESOLVCONF: FsckCheck =
    FsckCheck::new("etc-resolvconf", 5, FsckFnImpl::Sync(check_resolvconf));
/// See <https://github.com/bootc-dev/bootc/pull/1096> and <https://github.com/containers/bootc/pull/1167>
/// Basically verify that if /usr/etc/resolv.conf exists, it is not a zero-sized file that was
/// probably injected by buildah and that bootc should have removed.
///
/// Note that this fsck check can fail for systems upgraded from old bootc right now, as
/// we need the *new* bootc to fix it.
///
/// But at the current time fsck is an experimental feature that we should only be running
/// in our CI.
fn check_resolvconf(storage: &Storage) -> FsckResult {
    let ostree = match storage.get_ostree() {
        Ok(o) => o,
        Err(_) => return Ok(Vec::new()), // Not an ostree system (e.g. composefs-only)
    };
    // For now we only check the booted deployment.
    if ostree.booted_deployment().is_none() {
        return Ok(Vec::new());
    }
    let usr = Dir::open_ambient_dir("/usr", cap_std::ambient_authority())?;
    check_resolvconf_in(&usr)
}

/// The subject of the resolv.conf check's finding.
const RESOLVCONF_SUBJECT: &str = "usr/etc/resolv.conf";

/// The resolv.conf check proper, on the `/usr` directory `usr`.
fn check_resolvconf_in(usr: &Dir) -> FsckResult {
    // Read usr/etc/resolv.conf directly.
    let Some(meta) = usr.symlink_metadata_optional("etc/resolv.conf")? else {
        return Ok(Vec::new());
    };
    if meta.is_file() && meta.size() == 0 {
        return Ok(vec![CheckFinding::new(
            CheckFindingCode::ResolvconfZeroSized,
            RESOLVCONF_SUBJECT,
            "zero-sized file",
        )]);
    }
    Ok(Vec::new())
}

#[derive(Debug, Default)]
struct ObjectsVerityState {
    /// Count of objects with fsverity
    enabled: u64,
    /// Count of objects without fsverity
    disabled: u64,
    /// Objects which should have fsverity but do not
    missing: Vec<String>,
}

/// Check the fsverity state of all regular files in this object directory.
#[context("Computing verity state")]
fn verity_state_of_objects(
    d: &Dir,
    prefix: &str,
    expected: bool,
) -> anyhow::Result<ObjectsVerityState> {
    let mut enabled = 0;
    let mut disabled = 0;
    let mut missing = Vec::new();
    for ent in d.entries()? {
        let ent = ent?;
        if !ent.file_type()?.is_file() {
            continue;
        }
        let name = ent.file_name();
        let name = name
            .into_string()
            .map(Utf8PathBuf::from)
            .map_err(|_| anyhow::anyhow!("Invalid UTF-8"))?;
        let Some("file") = name.extension() else {
            continue;
        };
        let f = d.open(&name)?;
        let r: Option<composefs::fsverity::Sha256HashValue> =
            composefs::fsverity::measure_verity_opt(f.as_fd())?;
        drop(f);
        if r.is_some() {
            enabled += 1;
        } else {
            disabled += 1;
            if expected {
                missing.push(format!("{prefix}{name}"));
            }
        }
    }
    let r = ObjectsVerityState {
        enabled,
        disabled,
        missing,
    };
    Ok(r)
}

async fn verity_state_of_all_objects(
    repo: &ostree::Repo,
    expected: bool,
) -> anyhow::Result<ObjectsVerityState> {
    // Limit concurrency here
    const MAX_CONCURRENT: usize = 3;

    let repodir = Dir::reopen_dir(&repo.dfd_borrow())?;

    // It's convenient here to reuse tokio's spawn_blocking as a threadpool basically.
    let mut joinset = tokio::task::JoinSet::new();
    let mut results = Vec::new();

    for ent in repodir.read_dir("objects")? {
        // Block here if the queue is full
        while joinset.len() >= MAX_CONCURRENT {
            results.push(joinset.join_next().await.unwrap()??);
        }
        let ent = ent?;
        if !ent.file_type()?.is_dir() {
            continue;
        }
        let name = ent.file_name();
        let name = name
            .into_string()
            .map(Utf8PathBuf::from)
            .map_err(|_| anyhow::anyhow!("Invalid UTF-8"))?;

        let objdir = ent.open_dir()?;
        joinset.spawn_blocking(move || verity_state_of_objects(&objdir, name.as_str(), expected));
    }

    // Drain the remaining tasks.
    while let Some(output) = joinset.join_next().await {
        results.push(output??);
    }
    // Fold the results.
    let r = results
        .into_iter()
        .fold(ObjectsVerityState::default(), |mut acc, v| {
            acc.enabled += v.enabled;
            acc.disabled += v.disabled;
            acc.missing.extend(v.missing);
            acc
        });
    Ok(r)
}

#[distributed_slice(FSCK_CHECKS)]
static CHECK_FSVERITY: FsckCheck =
    FsckCheck::new("fsverity", 10, FsckFnImpl::Async(check_fsverity));
fn check_fsverity(storage: &Storage) -> Pin<Box<dyn Future<Output = FsckResult> + '_>> {
    Box::pin(check_fsverity_inner(storage))
}

async fn check_fsverity_inner(storage: &Storage) -> FsckResult {
    let ostree = match storage.get_ostree() {
        Ok(o) => o,
        Err(_) => return Ok(Vec::new()), // Not an ostree system (e.g. composefs-only)
    };
    let repo = &ostree.repo();
    let verity_state = ostree_ext::fsverity::is_verity_enabled(repo)?;
    tracing::debug!(
        "verity: expected={:?} found={:?}",
        verity_state.desired,
        verity_state.enabled
    );

    let verity_found_state =
        verity_state_of_all_objects(&ostree.repo(), verity_state.desired == Tristate::Enabled)
            .await?;
    let findings = verity_found_state
        .missing
        .into_iter()
        .map(|obj| {
            CheckFinding::new(
                CheckFindingCode::ObjectWithoutFsverity,
                obj,
                "missing fsverity, which is enabled for the repository",
            )
        })
        .collect();
    Ok(findings)
}

/// Where the host's root is mounted when running from a container, as for
/// `install to-existing-root`.
pub(crate) const HOST_ROOT: &str = "/target";

/// The name of the composefs boot entry check.
const COMPOSEFS_BOOT_POLICY: &str = "composefs-boot-policy";

/// The fix offered for strict BLS entries on a filesystem without fs-verity.
const REPAIR_FLAG: &str = "--repair-allow-missing-verity";

#[distributed_slice(FSCK_CHECKS)]
static CHECK_COMPOSEFS_BOOT_POLICY: FsckCheck = FsckCheck::new(
    COMPOSEFS_BOOT_POLICY,
    20,
    FsckFnImpl::Sync(check_composefs_boot_policy),
);
/// Check that every strict composefs boot entry can boot, i.e. that the
/// image it names has fs-verity. See `bootc_composefs::fsck`.
fn check_composefs_boot_policy(storage: &Storage) -> FsckResult {
    let Some(booted) = composefs_booted()? else {
        return Ok(Vec::new());
    };
    let boot_dirs = cfsck::boot_dirs_from_storage(storage)?;
    if boot_dirs.is_empty() {
        // Android boot images, whose command line isn't parsed here
        return Ok(vec![CheckFinding::info(
            CheckFindingCode::ComposefsBootEntriesNotChecked,
            "boot entries",
            "no ESP or boot directory (aboot), not checked",
        )]);
    }
    let report = cfsck::check_boot_entries(&storage.physical_root, &boot_dirs)?;
    Ok(boot_policy_findings(
        &report,
        !booted.allow_missing_fsverity,
    ))
}

/// Turn a boot entry report into findings. `booted_strict` is whether the
/// booted entry is strict.
fn boot_policy_findings(
    report: &cfsck::BootPolicyReport,
    booted_strict: bool,
) -> Vec<CheckFinding> {
    use cfsck::{EntryKind, Verdict};
    let mut findings = report
        .entries
        .iter()
        .filter_map(|entry| {
            let (code, detail) = match &entry.verdict {
                Verdict::NotComposefs | Verdict::Relaxed | Verdict::Verified => return None,
                Verdict::StrictWithoutFsverity {
                    image,
                    filesystem_supports_fsverity: false,
                } => {
                    let fix = match entry.kind {
                        EntryKind::Bls => format!(
                            "add '?' with `bootc internals fsck {REPAIR_FLAG}`, or reinstall onto a \
                             filesystem with fs-verity to keep enforcement"
                        ),
                        EntryKind::Uki => "the command line is embedded in the UKI, so it can't be \
                             repaired: boot the previous UKI, or reinstall onto a filesystem with \
                             fs-verity"
                            .to_owned(),
                    };
                    (
                        CheckFindingCode::StrictEntryWithoutFsverity,
                        format!(
                            "strict, but image {image} has no fs-verity and the root filesystem \
                             doesn't support it (e.g. ext4 without '-O verity'), so it fails to \
                             boot; {fix}"
                        ),
                    )
                }
                Verdict::StrictWithoutFsverity {
                    image,
                    filesystem_supports_fsverity: true,
                } => (
                    CheckFindingCode::ImageWithoutFsverity,
                    format!(
                        "strict, but image {image} has no fs-verity although the root \
                         filesystem supports it, so it fails to boot"
                    ),
                ),
                Verdict::NoImage(e) => (CheckFindingCode::ComposefsImageMissing, e.clone()),
                Verdict::Unbootable(e) => (CheckFindingCode::UnbootableComposefsEntry, e.clone()),
            };
            Some(CheckFinding::new(code, &entry.path, detail))
        })
        .collect::<Vec<_>>();
    if report.entries.is_empty() {
        let searched = if report.searched.is_empty() {
            "none".to_owned()
        } else {
            report.searched.join(", ")
        };
        findings.push(CheckFinding::new(
            CheckFindingCode::NoComposefsBootEntries,
            "boot entries",
            format!("no composefs boot entry found (searched: {searched})"),
        ));
    }
    if booted_strict && !report.meta_json_has_fsverity {
        findings.push(CheckFinding::info(
            CheckFindingCode::MetaJsonWithoutFsverity,
            "composefs/meta.json",
            "no fs-verity (left by bootc 1.16.x installs; the initramfs doesn't read it)",
        ));
    }
    findings
}

/// Add `?` to the strict BLS entries that can't boot because the root
/// filesystem doesn't support fs-verity, and print what was done.
fn repair_composefs_boot_policy(
    physical_root: &Dir,
    boot_dirs: &[cfsck::BootDir],
    mut output: impl std::io::Write,
) -> anyhow::Result<()> {
    let repaired = cfsck::repair_bls_entries(physical_root, boot_dirs)?;
    if repaired.is_empty() {
        writeln!(output, "{REPAIR_FLAG}: no boot entries to repair")?;
        return Ok(());
    }
    writeln!(
        output,
        "{REPAIR_FLAG}: added '?' to these boot entries, so they boot without fs-verity \
         enforcement, which this root filesystem can't provide:"
    )?;
    for path in repaired {
        writeln!(output, "  {path}")?;
    }
    writeln!(
        output,
        "Reboot before upgrading: upgrades copy the policy of the booted entry.\n\
         To keep fs-verity enforcement instead, reinstall onto a filesystem with fs-verity \
         (e.g. ext4 created with '-O verity')."
    )?;
    Ok(())
}

/// Check, and with `repair` repair, the composefs boot entries of the host
/// whose root is mounted at `target`, from a privileged container. Only the
/// composefs boot entry check runs this way.
pub(crate) fn fsck_composefs_host(
    target: &Utf8Path,
    repair: bool,
    mut output: impl std::io::Write,
) -> anyhow::Result<()> {
    let cmdline = std::fs::read_to_string("/proc/cmdline").context("Reading /proc/cmdline")?;
    let candidates = bootc_initramfs_setup::parse_composefs_candidates(&cmdline)
        .context("Parsing the host's kernel command line")?;
    anyhow::ensure!(
        !candidates.is_empty(),
        "The host is not booted with composefs"
    );
    let booted_strict = !bootc_initramfs_setup::composefs_candidates_policy(&candidates)?;
    let layout = cfsck::HostLayout::open(target, repair)?;
    if repair {
        repair_composefs_boot_policy(&layout.physical_root, &layout.boot_dirs, &mut output)?;
    }
    let r = cfsck::check_boot_entries(&layout.physical_root, &layout.boot_dirs)
        .map(|report| boot_policy_findings(&report, booted_strict));
    if !print_check_result(COMPOSEFS_BOOT_POLICY, &r, &mut output)? {
        anyhow::bail!("Encountered errors")
    }
    Ok(())
}

/// Print the result of the check `name`, returning whether it passed.
fn print_check_result(
    name: &str,
    result: &FsckResult,
    mut output: impl std::io::Write,
) -> std::io::Result<bool> {
    let findings = match result {
        Ok(findings) => findings,
        Err(e) => {
            writeln!(output, "Unexpected runtime error in check {name}: {e:#}")?;
            return Ok(false);
        }
    };
    let (infos, errors): (Vec<_>, Vec<_>) = findings.iter().partition(|f| f.informational);
    for finding in infos {
        writeln!(output, "fsck info: {name}: {finding}")?;
    }
    let Some((shown, rest)) = collect_until(errors.into_iter(), MAX_PRINTED_FINDINGS) else {
        writeln!(output, "ok: {name}")?;
        return Ok(true);
    };
    for finding in shown {
        writeln!(output, "fsck error: {name}: {finding}")?;
    }
    if rest > 0 {
        writeln!(output, "fsck error: {name}: ...and {rest} more")?;
    }
    Ok(false)
}

/// Run all checks. With `repair`, first add `?` to the composefs boot
/// entries that need it (see [`repair_composefs_boot_policy`]).
pub(crate) async fn fsck(
    storage: &Storage,
    repair: bool,
    mut output: impl std::io::Write,
) -> anyhow::Result<()> {
    if repair {
        anyhow::ensure!(
            composefs_booted()?.is_some(),
            "{REPAIR_FLAG} only applies to systems booted with composefs"
        );
        let boot_dirs = cfsck::boot_dirs_from_storage(storage)?;
        repair_composefs_boot_policy(&storage.physical_root, &boot_dirs, &mut output)?;
    }
    let mut checks = FSCK_CHECKS.static_slice().iter().collect::<Vec<_>>();
    checks.sort_by(|a, b| a.ordering.cmp(&b.ordering));

    let mut errors = false;
    for check in checks.iter() {
        let name = check.name;
        let r = match check.f {
            FsckFnImpl::Sync(f) => f(&storage),
            FsckFnImpl::Async(f) => f(&storage).await,
        };
        if !print_check_result(name, &r, &mut output)? {
            errors = true;
        }
    }
    if errors {
        anyhow::bail!("Encountered errors")
    }

    // Run an `ostree fsck` (yes, ostree exposes enough APIs
    // that we could reimplement this in Rust, but eh)
    // TODO: Fix https://github.com/bootc-dev/bootc/issues/1216 so we can
    // do this.
    // let st = Command::new("ostree")
    //     .arg("fsck")
    //     .stdin(std::process::Stdio::inherit())
    //     .status()?;
    // if !st.success() {
    //     anyhow::bail!("ostree fsck failed");
    // }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std_ext::cap_tempfile;

    #[test]
    fn test_check_resolvconf() -> anyhow::Result<()> {
        let zero_sized = || {
            vec![CheckFinding::new(
                CheckFindingCode::ResolvconfZeroSized,
                RESOLVCONF_SUBJECT,
                "zero-sized file",
            )]
        };
        // Sets up etc/resolv.conf (if anything) in a fresh /usr
        type Setup = fn(&Dir) -> std::io::Result<()>;
        let cases: &[(&str, Setup, Vec<CheckFinding>)] = &[
            ("missing", |_| Ok(()), Vec::new()),
            (
                "zero-sized",
                |d| d.write("etc/resolv.conf", ""),
                zero_sized(),
            ),
            (
                "nonempty",
                |d| d.write("etc/resolv.conf", "nameserver 192.0.2.1\n"),
                Vec::new(),
            ),
            (
                "symlink",
                |d| d.symlink("../run/resolv.conf", "etc/resolv.conf"),
                Vec::new(),
            ),
            ("directory", |d| d.create_dir("etc/resolv.conf"), Vec::new()),
        ];
        for (name, setup, expected) in cases {
            let usr = cap_tempfile::tempdir(cap_std::ambient_authority())?;
            usr.create_dir("etc")?;
            setup(&usr)?;
            assert_eq!(&check_resolvconf_in(&usr)?, expected, "case {name}");
        }
        Ok(())
    }

    #[test]
    fn test_print_check_result() {
        let info = || CheckFinding::info(CheckFindingCode::MetaJsonWithoutFsverity, "m", "detail");
        let objects = |n: usize| -> FsckResult {
            Ok((0..n)
                .map(|i| {
                    CheckFinding::new(
                        CheckFindingCode::ObjectWithoutFsverity,
                        format!("{i:02}.file"),
                        "detail",
                    )
                })
                .collect())
        };
        let cases: &[(&str, FsckResult, bool, &str)] = &[
            ("no findings", Ok(Vec::new()), true, "ok: c\n"),
            (
                "one finding",
                objects(1),
                false,
                "fsck error: c: ObjectWithoutFsverity: 00.file: detail\n",
            ),
            (
                "at the limit",
                objects(5),
                false,
                indoc::indoc! {"
                    fsck error: c: ObjectWithoutFsverity: 00.file: detail
                    fsck error: c: ObjectWithoutFsverity: 01.file: detail
                    fsck error: c: ObjectWithoutFsverity: 02.file: detail
                    fsck error: c: ObjectWithoutFsverity: 03.file: detail
                    fsck error: c: ObjectWithoutFsverity: 04.file: detail
                "},
            ),
            (
                "over the limit",
                objects(8),
                false,
                indoc::indoc! {"
                    fsck error: c: ObjectWithoutFsverity: 00.file: detail
                    fsck error: c: ObjectWithoutFsverity: 01.file: detail
                    fsck error: c: ObjectWithoutFsverity: 02.file: detail
                    fsck error: c: ObjectWithoutFsverity: 03.file: detail
                    fsck error: c: ObjectWithoutFsverity: 04.file: detail
                    fsck error: c: ...and 3 more
                "},
            ),
            (
                "runtime error",
                Err(anyhow::anyhow!("inner").context("outer")),
                false,
                "Unexpected runtime error in check c: outer: inner\n",
            ),
            (
                "only informational",
                Ok(vec![info()]),
                true,
                "fsck info: c: MetaJsonWithoutFsverity: m: detail\nok: c\n",
            ),
            (
                "informational and an error",
                objects(1).map(|mut v| {
                    v.insert(0, info());
                    v
                }),
                false,
                indoc::indoc! {"
                    fsck info: c: MetaJsonWithoutFsverity: m: detail
                    fsck error: c: ObjectWithoutFsverity: 00.file: detail
                "},
            ),
        ];
        for (name, result, passed, expected) in cases {
            let mut output = Vec::new();
            let r = print_check_result("c", result, &mut output).unwrap();
            assert_eq!(r, *passed, "case {name}");
            assert_eq!(String::from_utf8(output).unwrap(), *expected, "case {name}");
        }
    }

    #[test]
    fn test_boot_policy_findings() {
        use cfsck::{BootPolicyReport, EntryKind, EntryReport, Verdict};
        let entry = |kind, path: &str, verdict| EntryReport {
            kind,
            path: path.into(),
            verdict,
        };
        let without = |filesystem_supports_fsverity| Verdict::StrictWithoutFsverity {
            image: "aa".into(),
            filesystem_supports_fsverity,
        };
        let report = |meta_json_has_fsverity| BootPolicyReport {
            entries: vec![
                entry(EntryKind::Bls, "ok", Verdict::Verified),
                entry(EntryKind::Bls, "relaxed", Verdict::Relaxed),
                entry(EntryKind::Bls, "bls", without(false)),
                entry(EntryKind::Uki, "uki", without(false)),
                entry(EntryKind::Bls, "missing", without(true)),
                entry(EntryKind::Bls, "noimage", Verdict::NoImage("e".into())),
                entry(EntryKind::Bls, "bad", Verdict::Unbootable("e".into())),
            ],
            searched: vec!["ESP".into()],
            meta_json_has_fsverity,
        };
        let codes = |findings: Vec<CheckFinding>| {
            findings
                .into_iter()
                .map(|f| (f.subject, f.code, f.informational))
                .collect::<Vec<_>>()
        };
        let base = vec![
            (
                "bls".into(),
                CheckFindingCode::StrictEntryWithoutFsverity,
                false,
            ),
            (
                "uki".into(),
                CheckFindingCode::StrictEntryWithoutFsverity,
                false,
            ),
            (
                "missing".into(),
                CheckFindingCode::ImageWithoutFsverity,
                false,
            ),
            (
                "noimage".into(),
                CheckFindingCode::ComposefsImageMissing,
                false,
            ),
            (
                "bad".into(),
                CheckFindingCode::UnbootableComposefsEntry,
                false,
            ),
        ];
        let mut with_meta = base.clone();
        with_meta.push((
            "composefs/meta.json".into(),
            CheckFindingCode::MetaJsonWithoutFsverity,
            true,
        ));
        let cases: [(bool, bool, &Vec<(String, CheckFindingCode, bool)>); 4] = [
            (true, true, &base),
            (true, false, &with_meta),
            // meta.json only matters under a strict boot
            (false, false, &base),
            (false, true, &base),
        ];
        for (booted_strict, meta_json_has_fsverity, expected) in cases {
            assert_eq!(
                &codes(boot_policy_findings(
                    &report(meta_json_has_fsverity),
                    booted_strict
                )),
                expected,
                "booted_strict={booted_strict} meta_json_has_fsverity={meta_json_has_fsverity}"
            );
        }
        // Only BLS entries are offered the repair
        let findings = boot_policy_findings(&report(true), true);
        assert!(findings[0].detail.contains(REPAIR_FLAG));
        assert!(!findings[1].detail.contains(REPAIR_FLAG));

        // A composefs boot with no entries at all is an error
        let empty = BootPolicyReport {
            entries: Vec::new(),
            searched: vec!["ESP".into(), "boot".into()],
            meta_json_has_fsverity: true,
        };
        let findings = boot_policy_findings(&empty, true);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, CheckFindingCode::NoComposefsBootEntries);
        assert!(findings[0].detail.contains("ESP, boot"));
    }
}
