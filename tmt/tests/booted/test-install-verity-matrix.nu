# number: 69
# tmt:
#   summary: Test composefs install to-filesystem onto filesystems with and without fs-verity
#   duration: 45m
#   enabled: false
#   adjust:
#     - when: distro == fedora and boot_type == bls and filesystem == ext4 and bootloader == systemd
#       enabled: true
#       because: it doesn't depend on the booted system, so one cell is enough, and Fedora has btrfs
# extra:
#   skip_if_ostree: true
#
# Install the booted image with `bootc install to-filesystem` onto a loop
# disk whose root is formatted in different ways, and check the fs-verity
# policy each install gets. `bcvk` installs every other test system with
# `to-disk`, which formats ext4 with fs-verity, so no other test installs
# onto an ext4 without it, where bootc assumes fs-verity from the filesystem
# type.
#
# TODO: This doesn't depend on the booted host; move it into a dedicated
# install test suite: https://github.com/cgwalters-forge/tracker/issues/249

use std assert
use tap.nu

const IMAGE = "localhost/bootc-install-verity"
const DISK = "/var/tmp/install-verity.img"
const MNT = "/var/mnt/install-verity"

# The lsattr flags of every regular file at or under `path`
def file_flags [path: string] {
    if not ($path | path exists) {
        return []
    }
    ^find $path -type f -exec lsattr "{}" + | lines | each { |l| $l | split row " " | first }
}

# Partition DISK as an ESP and a root made with `mkfs`, install onto it with
# `flags`, and return the result and what the install left on the disk.
def install [bootloader: string, mkfs: list<string>, flags: list<string>] {
    rm -f $DISK
    truncate -s 10G $DISK
    let loop = (losetup --find --show --partscan $DISK | str trim)
    "label: gpt\nsize=512MiB, type=uefi\ntype=linux\n" | sfdisk --quiet $loop
    udevadm settle
    let esp = $"($loop)p1"
    let root = $"($loop)p2"
    mkfs.vfat -F32 $esp
    run-external ($mkfs | first) ...($mkfs | skip 1) $root
    let uuid = (blkid -p -s UUID -o value $root | str trim)
    mkdir $MNT
    mount $root $MNT
    mkdir $"($MNT)/boot/efi"
    mount $esp $"($MNT)/boot/efi"

    let result = (do {
        (podman run --rm --privileged --pid=host
            --security-opt label=type:unconfined_t
            -v /dev:/dev -v $"($MNT):/target"
            $IMAGE
            bootc install to-filesystem --disable-selinux
            --bootloader $bootloader
            $"--karg=root=UUID=($uuid)" $"--root-mount-spec=UUID=($uuid)"
            ...$flags /target)
    } | complete)
    print $result.stdout $result.stderr

    let entries = (glob $"($MNT)/boot/loader/entries/*.conf" | append (glob $"($MNT)/boot/efi/loader/entries/*.conf"))
    let options = ($entries | each { |e| open --raw $e | lines | where { |l| $l | str starts-with "options " } } | flatten)
    let cfs_args = ($options | each { |l| $l | split row " " } | flatten | where { |arg|
        ($arg | str starts-with "composefs=") or ($arg | str starts-with "composefs.digest=")
    })
    let repo = $"($MNT)/composefs"
    let objects = (file_flags $"($repo)/objects")
    let meta = (file_flags $"($repo)/meta.json")
    let state = {
        exit_code: $result.exit_code,
        stderr: $result.stderr,
        entries: ($entries | length),
        relaxed: ($cfs_args | each { |arg| $arg | split row "=" | get 1 | str starts-with "?" } | uniq),
        objects: ($objects | length),
        objects_verity: ($objects | where { |f| $f | str contains "V" } | length),
        meta_verity: ($meta | each { |f| $f | str contains "V" } | get 0?),
    }

    umount -R -l $MNT
    losetup -d $loop
    rm -f $DISK
    print ($state | reject stderr | to nuon)
    $state
}

def assert_refused [state: record, message: string, what: string] {
    assert ($state.exit_code != 0) $"($what): the install must fail"
    assert ($state.stderr | str contains $message) $"($what): expected '($message)' in the error"
    assert equal $state.entries 0 $"($what): no boot entry may be written"
}

def assert_installed [state: record, relaxed: bool, what: string] {
    assert equal $state.exit_code 0 $"($what): the install must succeed"
    assert equal $state.entries 1 $"($what): one boot entry must be written"
    assert equal $state.relaxed [$relaxed] $"($what): composefs arguments must have relaxed=($relaxed)"
    assert ($state.objects > 0) $"($what): the repository must have objects"
}

def main [] {
    tap begin "composefs install to-filesystem fs-verity matrix"

    let st = bootc status --json | from json
    let bootloader = ($st.status.booted.composefs.bootloader | str downcase)

    bootc image copy-to-storage
    let td = mktemp -d
    "FROM localhost/bootc\nRUN rm -rf /usr/lib/bootc/bound-images.d/*\n" | save $"($td)/Containerfile"
    podman build -t $IMAGE $td
    rm -rf $td

    let noverity = ["mkfs.ext4" "-q" "-F" "-O" "^verity"]

    # A strict install needs fs-verity, and ext4 is assumed to have it.
    let state = (install $bootloader $noverity [])
    assert_refused $state "enabling verity on meta.json" "ext4 without verity"

    # The repository is created strict before --allow-missing-verity is
    # applied, so this fails the same way. Whether it should instead succeed
    # with `?` is under discussion: https://github.com/bootc-dev/bootc/issues/2636
    let state = (install $bootloader $noverity ["--allow-missing-verity"])
    assert_refused $state "enabling verity on meta.json" "ext4 without verity, --allow-missing-verity"

    # `?` on a filesystem with fs-verity still gives every object fs-verity
    let state = (install $bootloader ["mkfs.ext4" "-q" "-F" "-O" "verity"] ["--allow-missing-verity"])
    assert_installed $state true "ext4 with verity, --allow-missing-verity"
    assert equal $state.objects_verity $state.objects "every object must have fs-verity"
    assert equal $state.meta_verity false "meta.json must not have fs-verity"

    # The type-based default: xfs has no fs-verity, so `?`
    let state = (install $bootloader ["mkfs.xfs" "-q" "-f"] [])
    assert_installed $state true "xfs"
    assert equal $state.objects_verity 0 "xfs can't have fs-verity"

    let state = (install $bootloader ["mkfs.btrfs" "-q" "-f"] [])
    assert_installed $state false "btrfs"
    assert equal $state.objects_verity $state.objects "every object must have fs-verity"
    # Informational until https://github.com/composefs/composefs-rs/issues/441 is fixed
    print $"# btrfs meta.json fs-verity: ($state.meta_verity)"

    podman rmi $IMAGE
    tap ok
}
