# In-VM steps of the pinned-version upgrade tests that install with `bootc
# install to-filesystem` (`cargo xtask test-upgrade-pinned
# --installer=to-filesystem`). There, booting the upgraded deployment is
# expected to fail, which a tmt plan can't drive, so the xtask runs the VM
# (reboots, resets, console checks) and calls these steps over SSH.
#
# Recovery steps follow
# https://github.com/bootc-dev/bootc/pull/2629#issuecomment-6695640406
use std assert

const DISK = "/dev/disk/by-id/virtio-output"
const ESP_LABEL = "EFI-SYSTEM"
const ESP_MOUNT = "/var/tmp/esp"
# Where `stage` leaves the boot entries it found, for `relax new`
const STATE = "/var/bootc-pinned-to-filesystem.json"
# How many composefs objects to check for fs-verity
const SAMPLE_OBJECTS = 100

def composefs-args [] {
    open /proc/cmdline | str trim | split row " " | where {|a| $a =~ '^composefs(\.digest)?=' }
}

def is-relaxed [arg: string] {
    $arg | split row "=" | get 1 | str starts-with "?"
}

# The directory with loader/: the ESP, which systemd-boot installs keep the
# BLS entries on
def esp [] {
    let found = do -i { ^bootctl --print-esp-path } | complete
    if $found.exit_code == 0 {
        return ($found.stdout | str trim)
    }
    if not ($"($ESP_MOUNT)/loader" | path exists) {
        mkdir $ESP_MOUNT
        ^mount $"/dev/disk/by-partlabel/($ESP_LABEL)" $ESP_MOUNT
    }
    $ESP_MOUNT
}

# The composefs image digests an entry's options line names
def entry-digests [entry: string] {
    open --raw $entry | decode utf-8 | lines
        | where {|l| $l starts-with "options " }
        | each {|l| $l | split row " " }
        | flatten
        | where {|a| $a =~ '^composefs(\.digest)?=' }
        | each {|a| $a | split row "=" | get 1 | str trim --left --char "?" | split row ":" | last }
}

# The file name (which systemd-boot uses as the ID) of the entry in DIR that
# boots the composefs image DIGEST
def entry-for [dir: string, digest: string] {
    let found = ls $dir
        | where name ends-with ".conf"
        | where {|e| $digest in (entry-digests $e.name) }
        | get name
    assert equal ($found | length) 1 $"one entry in ($dir) must boot ($digest), found ($found | to nuon)"
    $found | first | path basename
}

# Partition the `output` disk as `to-disk` does, but make the root
# filesystem with the stock mkfs (for ext4: without `-O verity`), as Anaconda
# or a cloud image would, and install IMAGE onto it with its own `bootc
# install to-filesystem`. Runs as root in a `bcvk ephemeral` VM of IMAGE
# with the host's container storage.
def "main install" [image: string, filesystem: string, bootloader: string, ...kargs: string] {
    assert equal (^uname -m | str trim) "x86_64" "the partition types below are x86_64's"
    # Room for the container storage and the install's temporary files
    ^mount -t tmpfs -o size=20G tmpfs /var/tmp
    mkdir /var/tmp/containers
    rm -rf /var/lib/containers
    ^ln -sr /var/tmp/containers /var/lib/containers
    let ais = "/run/virtiofs-mnt-hoststorage"
    if (do -i { ^mountpoint -q $ais } | complete).exit_code != 0 {
        mkdir $ais
        ^mount -t virtiofs mount_hoststorage $ais -o ro
    }

    [
        "label: gpt"
        "size=1MiB, type=21686148-6449-6E6F-744E-656564454649, name=\"BIOS-BOOT\""
        $"size=2GiB, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name=\"($ESP_LABEL)\""
        "type=4f68bce3-e8cd-4db1-96e7-fbcaf984b709, name=\"root\""
    ] | str join "\n" | ^sfdisk --wipe always $DISK
    ^udevadm settle
    ^mkfs.fat -F 32 -n $ESP_LABEL $"($DISK)-part2"
    let root = $"($DISK)-part3"
    match $filesystem {
        "ext4" => {
            ^mkfs.ext4 -F -L root $root
            let features = ^dumpe2fs -h $root | lines | where {|l| $l starts-with "Filesystem features:" }
            print ($features | first)
            assert (not ($features | first | str contains "verity")) "stock mkfs.ext4 must not enable verity, or this row tests nothing"
        },
        _ => { error make { msg: $"Unsupported filesystem: ($filesystem)" } },
    }

    let target = "/var/tmp/target"
    mkdir $target
    ^mount $root $target
    # bootupd wants the ESP under the target
    if $bootloader == "grub" {
        mkdir $"($target)/boot/efi"
        ^mount $"($DISK)-part2" $"($target)/boot/efi"
    }
    let karg_args = $kargs | each {|k| $"--karg=($k)" }
    # Both podman and bootc in the container find IMAGE in the host's storage
    with-env { STORAGE_OPTS: $"additionalimagestore=($ais)" } {
        (^podman run --rm --privileged --pid=host --net=none
            -v /sys:/sys:ro -v /dev:/dev -v /var/lib/containers:/var/lib/containers -v /var/tmp:/var/tmp
            -v $"($ais):($ais)" -v $"($target):/target:rbind"
            --security-opt label=type:unconfined_t --env STORAGE_OPTS
            $image bootc install to-filesystem --skip-fetch-check
            --composefs-backend $"--bootloader=($bootloader)" ...$karg_args /target)
    }
    ^umount -R $target
    ^sync
}

# Check the system before upgrading: that the release under test runs it,
# and that the pre-upgrade check script's verdict matches.
def "main pre-upgrade" [version: string, --affected] {
    assert equal (^bootc --version | str trim) $"bootc ($version)"
    let args = composefs-args
    assert (($args | length) > 0) "must be booted with composefs"
    let check = do -i { ^sh $"($env.FILE_PWD)/check-strict-verity.sh" } | complete
    print $"Pre-upgrade check: ($check.stdout | str trim)"
    if $affected {
        assert ($args | all {|a| not (is-relaxed $a) }) "an affected install boots with a strict command line"
        let objects = glob /sysroot/composefs/objects/*/* | shuffle | first $SAMPLE_OBJECTS
        let with_verity = ^lsattr ...$objects | lines | where {|l| $l | split row " " | first | str contains "V" }
        print $"($with_verity | length) of ($objects | length) sampled objects have fs-verity"
        assert equal ($with_verity | length) 0 "an affected install stores objects without fs-verity"
        assert equal $check.exit_code 1
        assert ($check.stdout | str starts-with "AFFECTED")
    } else {
        assert equal $check.exit_code 0
        assert ($check.stdout | str starts-with "unaffected")
    }
}

# Switch to IMAGE from the host's container storage
def "main switch" [image: string] {
    ^bootc switch --transport containers-storage $image
}

# Switch to IMAGE, and make only the next boot use the new entry: the
# previous one becomes the default, so that resetting the VM after the
# expected failure boots it, as selecting it in the menu would. The entry
# names are final once staged; finalizing only renames the directory.
def "main stage" [image: string] {
    main switch $image
    let st = ^bootc status --json | from json
    let staged = $"(esp)/loader/entries.staged"
    let state = {
        new_digest: $st.status.staged.composefs.verity,
        new_entry: (entry-for $staged $st.status.staged.composefs.verity),
        old_entry: (entry-for $staged $st.status.booted.composefs.verity),
    }
    ^bootctl set-default $state.old_entry
    ^bootctl set-oneshot $state.new_entry
    $state | to json | save --force $STATE
    # The xtask reads this, to find the new digest in the console log
    print ($state | to json --raw)
}

# Add '?' right after composefs= and composefs.digest= in a boot entry: the
# documented recovery. WHICH is "booted" (before upgrading), or "new" for the
# entry `stage` made (after the failed boot); for that one, also drop the
# default `stage` set, so that the entry boots as bootc ordered it.
def "main relax" [which: string] {
    let dir = $"(esp)/loader/entries"
    let entry = match $which {
        "booted" => (entry-for $dir (^bootc status --json | from json).status.booted.composefs.verity),
        "new" => (open $STATE).new_entry,
        _ => { error make { msg: $"Unknown entry: ($which)" } },
    }
    let path = $"($dir)/($entry)"
    let content = open --raw $path | decode utf-8
    let relaxed = $content | str replace --all --regex '(composefs(?:\.digest)?=)([^?])' '${1}?${2}'
    assert ($relaxed != $content) $"($path) must have a strict composefs argument"
    $relaxed | save --force $"($path).tmp"
    mv --force $"($path).tmp" $path
    print ($relaxed | lines | where {|l| $l starts-with "options" } | first)
    if $which == "new" {
        ^bootctl set-default ""
    }
}

# Check that IMAGE is booted from the host's container storage, with '?'
# on every composefs argument (--relaxed) or on none
def "main assert-booted" [image: string, --relaxed] {
    let booted = (^bootc status --json | from json).status.booted.image.image
    assert equal $booted.transport "containers-storage"
    assert equal $booted.image $image
    let args = composefs-args
    print $"Booted ($image): ($args | str join ' ')"
    assert (($args | length) > 0) "must be booted with composefs"
    assert ($args | all {|a| (is-relaxed $a) == $relaxed }) $"composefs arguments must all be relaxed=($relaxed)"
}

# Check that the release under test runs the system again
def "main assert-version" [version: string] {
    assert equal (^bootc --version | str trim) $"bootc ($version)"
}

def main [] {
    print "Run with a subcommand; see --help"
    exit 1
}
