//! Upgrade tests from pinned bootc releases.
//!
//! The per-PR upgrade test (`just test-upgrade`) starts from whatever bootc
//! the published base image ships that day. These start from an explicit
//! release instead: it is built from its own sources onto the current base
//! image (see `tmt/tests/Dockerfile.pinned-bootc`), installs itself, and the
//! installed system is then upgraded to the bootc under test.
//!
//! How the release installs is the [`Installer`]: `bcvk to-disk` runs the
//! tmt `readonly` plan after the upgrade, as `just test-upgrade` does.

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use fn_error_context::context;
use semver::Version;
use xshell::{Shell, cmd};

use crate::{BootType, Installer, PinnedUpgradeArgs, RunTmtArgs, SealState};

/// Where releases are fetched from
const RELEASE_REPO: &str = "https://github.com/bootc-dev/bootc";
/// `--from` value for the newest release
const LATEST_RELEASE: &str = "latest";
const PINNED_DOCKERFILE: &str = "tmt/tests/Dockerfile.pinned-bootc";
/// Release sources are extracted under this directory
const PINNED_WORKDIR: &str = "target/pinned";
/// The published base images' composefs installs need SELinux permissive,
/// as in `just test-upgrade`.
const COMPOSEFS_KARGS: &[&str] = &["enforcing=0"];

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
}
