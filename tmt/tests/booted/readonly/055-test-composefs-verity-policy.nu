use std assert
use tap.nu

# Check that the composefs fs-verity policy on the kernel command line, what
# `bootc status` reports, what the booted configuration should get, and what
# is actually enforced all agree.

tap begin "composefs fs-verity policy invariants"

if not (tap is_composefs) {
    print "# Skipping: not a composefs system"
    tap ok
    exit 0
}

# The policy this configuration should get: `?` (missing fs-verity allowed)
# or strict. bootc gives BLS installs `?` on xfs, which it treats as lacking
# fs-verity; the test images build their UKIs the same way, except that a
# sealed one is always strict.
def expected_missing_verity_allowed [boot_type: string, fstype: string, secure_boot: bool] {
    match $boot_type {
        "bls" => ($fstype == "xfs"),
        "uki" => ((not $secure_boot) and $fstype == "xfs"),
        _ => null,
    }
}

def has_fsverity [path: string] {
    let real = ($path | path expand)
    let attrs = (do { ^lsattr -d $real } | complete)
    assert equal $attrs.exit_code 0 $"lsattr ($real) failed: ($attrs.stderr)"
    $attrs.stdout | split row " " | first | str contains "V"
}

def findmnt_json [mountpoint: string] {
    ^findmnt --json -o SOURCE,FSTYPE,OPTIONS --mountpoint $mountpoint | from json | get filesystems | last
}

def secure_boot_enabled [] {
    let var = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    if not ($var | path exists) {
        return false
    }
    # 4 bytes of attributes, then the value
    (^od -An -tu1 -j4 -N1 $var | str trim) == "1"
}

let st = bootc status --json | from json
let cfs = $st.status.booted.composefs
let boot_type = ($cfs.bootType | str downcase)
let fstype = (findmnt_json /sysroot).fstype
let secure_boot = (secure_boot_enabled)
print $"# boot type ($boot_type), root filesystem ($fstype), Secure Boot ($secure_boot)"

# The command line: every composefs argument carries the same policy.
let cfs_args = (open /proc/cmdline | str trim | split row " " | where { |arg|
    ($arg | str starts-with "composefs=") or ($arg | str starts-with "composefs.digest=")
})
assert (($cfs_args | length) > 0) "no composefs argument on the kernel command line"
let relaxed_args = ($cfs_args | each { |arg| $arg | split row "=" | get 1 | str starts-with "?" } | uniq)
assert equal ($relaxed_args | length) 1 $"composefs arguments disagree on the policy: ($cfs_args)"
let cmdline_relaxed = ($relaxed_args | first)
print $"# composefs arguments: ($cfs_args | str join ' ')"

assert equal $cfs.missingVerityAllowed $cmdline_relaxed "bootc status must report the command line's policy"

let expected = (expected_missing_verity_allowed $boot_type $fstype $secure_boot)
if $expected == null {
    print $"# No expected policy for boot type ($boot_type)"
} else {
    assert equal $cmdline_relaxed $expected $"unexpected fs-verity policy for ($boot_type) on ($fstype)"
}

if not $cmdline_relaxed {
    # Strict: the root is mounted requiring fs-verity, and the image and its
    # objects have it.
    let root = (findmnt_json /)
    if ($root.source | str starts-with "transient:composefs=") {
        # root-transient: `/` is an overlay on top of the composefs mount
        print $"# / is transient \(($root.source)\); not checking its options"
    } else {
        assert equal $root.source $"composefs:($cfs.verity)" "/ must be the booted composefs image"
        assert ($root.options | split row "," | any { |o| $o == "verity=require" }) $"strict composefs root must be mounted with verity=require: ($root.options)"
    }

    let image = $"/sysroot/composefs/images/($cfs.verity)"
    assert (has_fsverity $image) $"booted image ($image) must have fs-verity"

    let objects = (^find /sysroot/composefs/objects -type f | lines | first 64)
    assert (($objects | length) > 0) "composefs repository has no objects"
    let missing = ($objects | where { |o| not (has_fsverity $o) })
    assert equal $missing [] "objects in a strict repository must have fs-verity"
    print $"# fs-verity present on the image and ($objects | length) sampled objects"

    # Installs by current bootc should also leave meta.json with fs-verity.
    # Informational until https://github.com/composefs/composefs-rs/issues/441
    # is fixed. Skipped under test-upgrade, where an older bootc installed.
    let meta = "/sysroot/composefs/meta.json"
    if ($env.BOOTC_test_upgrade_image? | default "") == "" and ($meta | path exists) {
        print $"# meta.json fs-verity: (has_fsverity $meta) \(informational\)"
    }
}

tap ok
