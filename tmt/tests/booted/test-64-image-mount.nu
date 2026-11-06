# number: 64
# tmt:
#   summary: Verify booted and staged deployment image mounts
#   duration: 30m
#
# Covers `bootc image mount` and `bootc image unmount`: read-only mounts of
# booted image content, of a staged image after `bootc switch` (no reboot),
# explicit unmount and the CLI's error cases. On ostree the staged image
# disables composefs, so it goes through the plain checkout path while the
# booted deployment uses composefs.

use std assert
use tap.nu

const staged_image = "localhost/bootc-image-mount"
# Image content only the staged image has, in /opt as in bootc#2433.
const marker_dir = "/opt/bootc-image-mount-test"

def mount_image [deployment: string, source: string, target: string] {
    bootc image mount --deployment $deployment --source $source --target $target
}

# Run bootc with arguments that must fail, and return its stderr.
def --wrapped bootc_fails [...args] {
    let result = (do -i { ^bootc ...$args } | complete)
    assert ($result.exit_code != 0) $"bootc ($args | str join ' ') should fail"
    $result.stderr
}

def is_mountpoint [path: string] {
    (do -i { ^findmnt --mountpoint $path } | complete).exit_code == 0
}

def assert_mount_options [target: string] {
    let options = (
        findmnt --mountpoint $target --json
        | from json
        | get filesystems.0.options
        | split row ","
    )
    for option in [ro nosuid nodev nosymfollow] {
        assert ($option in $options) $"($target) should have the ($option) mount option"
    }
    assert (not ("noexec" in $options)) $"($target) should not have noexec"
}

def unmount_image [target: string] {
    bootc image unmount $target
    assert (not (is_mountpoint $target)) $"($target) should no longer be a mountpoint"
}

def test_booted [base: string] {
    let root = ($base | path join "root")
    let usr = ($base | path join "usr")
    mkdir $root $usr

    mount_image booted / $root
    mount_image booted /usr $usr
    assert_mount_options $root
    assert_mount_options $usr
    assert equal (open --raw ($root | path join "usr/lib/os-release")) (open --raw /usr/lib/os-release)
    assert equal (open --raw ($usr | path join "lib/os-release")) (open --raw /usr/lib/os-release)
    assert (not ($root | path join "opt/bootc-image-mount-test" | path exists)) "booted image should not have the staged marker"

    let write_path = ($usr | path join ".bootc-image-mount-write-test")
    let write_result = (do -i { ^touch $write_path } | complete)
    assert ($write_result.exit_code != 0) "writes to mounted image content should fail"
    assert (not ($write_path | path exists)) "failed write should not create a file"

    # The mount is intentionally not noexec.
    let true_result = (do -i { ^($usr | path join "bin/true") } | complete)
    assert equal $true_result.exit_code 0 "mounted /usr/bin/true should be executable"

    # A target that holds content, or already a mount, is refused.
    let err = (bootc_fails image mount --deployment booted --source /usr --target $usr)
    assert ($err | str contains "must be empty") $err
    let tmpfs = ($base | path join "tmpfs")
    mkdir $tmpfs
    mount -t tmpfs tmpfs $tmpfs
    let err = (bootc_fails image mount --deployment booted --source /usr --target $tmpfs)
    assert ($err | str contains "already a mountpoint") $err
    umount $tmpfs

    unmount_image $usr
    unmount_image $root
    let err = (bootc_fails image unmount $usr)
    assert ($err | str contains "is not a mountpoint") $err

    # /mnt is a symlink to var/mnt on bootc systems; the target path may use it.
    let mnt_target = "/mnt/bootc-image-mount-test"
    mkdir $mnt_target
    mount_image booted /usr $mnt_target
    assert ($mnt_target | path join "lib/os-release" | path exists)
    unmount_image $mnt_target
    rm $mnt_target
}

def test_errors [base: string] {
    let target = ($base | path join "errors")
    mkdir $target

    let err = (bootc_fails image mount --deployment booted --source /usr/nonexistent --target $target)
    assert ($err | str contains "No such file") $err
    let err = (bootc_fails image mount --deployment booted --source /usr/lib/os-release --target $target)
    assert ($err | str contains "must both be directories") $err
    let err = (bootc_fails image mount --deployment booted --source usr --target $target)
    assert ($err | str contains "absolute") $err
    let err = (bootc_fails image mount --deployment booted --source /usr --target ($base | path join "missing"))
    assert ($err | str contains "No such file") $err
    let err = (bootc_fails image mount --deployment staged --source /usr --target $target)
    assert ($err | str contains "No staged") $err

    "content" | save ($target | path join "existing")
    let err = (bootc_fails image mount --deployment booted --source /usr --target $target)
    assert ($err | str contains "must be empty") $err
    assert (not (is_mountpoint $target)) "failed mounts should not leave a mount behind"
}

def stage_derived_image [] {
    bootc image copy-to-storage
    # Disable composefs for the staged ostree deployment so that it is a plain
    # checkout; the prepare-root.conf of the deployment decides that.
    let ostree_setup = if (tap is_composefs) {
        ""
    } else {
        "RUN sed -i -e '/^\\[composefs\\]/,/^\\[/ s/^enabled *=.*/enabled = no/' /usr/lib/ostree/prepare-root.conf && grep -q '^enabled = no' /usr/lib/ostree/prepare-root.conf"
    }
    # make_uki_containerfile appends stages that build on `base`.
    let containerfile = $"FROM localhost/bootc as base
RUN mkdir -p ($marker_dir) && echo staged > ($marker_dir)/marker
($ostree_setup)
"
    (tap make_uki_containerfile $containerfile) | save --force Containerfile
    podman build -t $staged_image .
    bootc switch --transport containers-storage $staged_image
    let status = (bootc status --json | from json)
    assert ($status.status.staged? != null) "bootc switch should stage a deployment"
}

def test_staged [] {
    # Mount below /var, which bootc must leave alone otherwise (bootc#2433).
    let base = (^mktemp -d /var/tmp/bootc-image-mount.XXXXXX | str trim)
    let staged_opt = ($base | path join "staged-opt")
    let booted_opt = ($base | path join "booted-opt")
    let staged_usr = ($base | path join "staged-usr")
    mkdir $staged_opt $booted_opt $staged_usr

    mount_image staged $marker_dir $staged_opt
    assert_mount_options $staged_opt
    assert equal (open ($staged_opt | path join "marker") | str trim) "staged"
    # The documented copy-out use case.
    let copy = ($base | path join "copy")
    ^cp -a $"($staged_opt)/." $copy
    assert equal (open ($copy | path join "marker") | str trim) "staged"

    mount_image booted /opt $booted_opt
    assert (not ($booted_opt | path join "bootc-image-mount-test" | path exists)) "booted /opt should not have the staged marker"

    mount_image staged /usr $staged_usr
    assert ($staged_usr | path join "lib/os-release" | path exists)

    if not (tap is_composefs) {
        # The staged checkout's /etc is deployment state, not image content.
        let target = ($base | path join "staged-root")
        mkdir $target
        let err = (bootc_fails image mount --deployment staged --source / --target $target)
        assert ($err | str contains "/etc") $err
        let err = (bootc_fails image mount --deployment staged --source /etc --target $target)
        assert ($err | str contains "/usr/etc") $err
    }

    for target in [$staged_opt $booted_opt $staged_usr] {
        unmount_image $target
    }
    rm -r $base
}

def main [] {
    tap begin "bootc image mount"

    let base = (^mktemp -d /run/bootc-image-mount.XXXXXX | str trim)
    test_booted $base
    test_errors $base
    rm -r $base

    stage_derived_image
    test_staged

    tap ok
}
