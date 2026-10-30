//! Build Unified Kernel Images (UKI) using ukify.
//!
//! This module provides functionality to build UKIs by computing the necessary
//! arguments from a container image and invoking the ukify tool. Default V1
//! UKIs also carry the legacy V2 digest for older bootc clients.

use std::ffi::OsString;
use std::process::Command;

use anyhow::{Context, Result};
use bootc_initramfs_setup::KARG_KMODS;
use bootc_utils::CommandRunExt;
use camino::Utf8Path;
use cap_std_ext::cap_std::fs::Dir;
use composefs::fsverity::{FsVerityHashValue, Sha512HashValue};
use composefs_ctl::composefs;
use fn_error_context::context;
use linux_kernel_cmdline::utf8::Cmdline;

use crate::boot_artifact::{prepare_boot_artifact, resolve_erofs_version};
use crate::bootc_composefs::digest::compute_kmods_digest;
use crate::bootc_composefs::kmods::KMODS_PAYLOAD_DIR;
use crate::cli::ErofsVersionArg;

/// Add the [`KARG_KMODS`] pin of the kernel modules image `digest` to
/// `cmdline`, replacing any from kargs.d or `--karg`, like the composefs kargs.
fn pin_kmods(cmdline: String, digest: &Sha512HashValue) -> String {
    let mut cmdline = Cmdline::from(cmdline);
    for param in &Cmdline::from(format!("{KARG_KMODS}={}", digest.to_hex())) {
        cmdline.add_or_modify(&param);
    }
    cmdline.to_string()
}

/// Build a UKI from the given rootfs.
///
/// Finds the kernel, computes the composefs digest, reads kernel arguments from
/// kargs.d, pins the kernel modules image if the rootfs ships one in
/// `/boot/bootc/modules` (see [`crate::bootc_composefs::kmods`]), then invokes
/// ukify with any additional pass-through arguments.
#[context("Building UKI")]
pub(crate) async fn build_ukify(
    rootfs: &Utf8Path,
    extra_kargs: &[String],
    args: &[OsString],
    kernel_dir: Option<&Utf8Path>,
    allow_missing_fsverity: bool,
    erofs_version: Option<ErofsVersionArg>,
    write_dumpfile_to: Option<&Utf8Path>,
) -> Result<()> {
    if !extra_kargs.is_empty() {
        tracing::warn!(
            "The --karg flag is temporary and will be removed as soon as possible \
            (https://github.com/bootc-dev/bootc/issues/1826)"
        );
    }

    if !crate::utils::have_executable("ukify")? {
        anyhow::bail!(
            "ukify executable not found in PATH. Please install systemd-ukify or equivalent."
        );
    }

    let mut inputs = prepare_boot_artifact(
        rootfs,
        kernel_dir,
        extra_kargs,
        allow_missing_fsverity,
        erofs_version,
        write_dumpfile_to,
    )
    .await?;

    // Kernel modules shipped outside the root filesystem get their own digest
    let kmods_digest = compute_kmods_digest(rootfs, resolve_erofs_version(erofs_version)).await?;
    if let Some(digest) = kmods_digest {
        let root = Dir::open_ambient_dir(rootfs, cap_std_ext::cap_std::ambient_authority())
            .with_context(|| format!("Opening rootfs {rootfs}"))?;
        let kver = &inputs.kernel_version;
        let kver_dir = format!("{KMODS_PAYLOAD_DIR}/{kver}");
        if !root
            .try_exists(&kver_dir)
            .context("Checking kernel modules")?
        {
            anyhow::bail!("/{KMODS_PAYLOAD_DIR} has no modules for kernel {kver}");
        }
        tracing::info!("Kernel modules digest: {}", digest.to_hex());
        inputs.cmdline = pin_kmods(std::mem::take(&mut inputs.cmdline), &digest);
    }

    let mut cmd = Command::new("ukify");
    cmd.current_dir(rootfs);
    cmd.arg("build")
        .arg("--linux")
        .arg(&inputs.vmlinuz)
        .arg("--initrd")
        .arg(&inputs.initramfs)
        .arg("--uname")
        .arg(&inputs.kernel_version)
        .arg("--cmdline")
        .arg(&inputs.cmdline)
        .arg("--os-release")
        .arg("@usr/lib/os-release");
    cmd.args(args);

    tracing::debug!("Executing ukify: {:?}", cmd);
    cmd.run_inherited().context("Running ukify")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_kmods() {
        let digest = Sha512HashValue::from_hex("ab".repeat(64)).unwrap();
        let pin = format!("{KARG_KMODS}={}", digest.to_hex());
        let stale = format!("{KARG_KMODS}={}", "cd".repeat(64));
        for (cmdline, expected) in [
            ("rw quiet".to_string(), format!("rw quiet {pin}")),
            (format!("rw {stale} quiet"), format!("rw {pin} quiet")),
            (format!("rw {pin}"), format!("rw {pin}")),
            // Duplicates collapse into one pin
            (
                format!("{stale} rw {stale} quiet {stale}"),
                format!("{pin} rw quiet"),
            ),
            // A bare key, or one without a value
            (format!("rw {KARG_KMODS} quiet"), format!("rw {pin} quiet")),
            (format!("rw {KARG_KMODS}= quiet"), format!("rw {pin} quiet")),
            (format!("rw {KARG_KMODS} {stale}"), format!("rw {pin}")),
        ] {
            let out = pin_kmods(cmdline.clone(), &digest);
            assert_eq!(out, expected, "{cmdline}");
            // What the initramfs reads back
            assert_eq!(
                bootc_initramfs_setup::parse_kmods_digest(&out).unwrap(),
                Some(digest.clone())
            );
        }
    }
}
