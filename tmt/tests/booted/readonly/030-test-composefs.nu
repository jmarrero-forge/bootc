use std assert
use tap.nu

tap begin "composefs integration smoke test"

def parse_cmdline []  {
    open /proc/cmdline | str trim | split row " "
}

# Whether the bootc that installed this system takes loader.conf from the
# image (1.17.4 and later): the current one, or the one an upgrade test
# started from (see maybe_upgrade in bootc_testlib.nu)
def installed_by_bootc_with_image_loader_conf [] {
    let pre_upgrade = "/var/bootc-pre-upgrade-version"
    if not ($pre_upgrade | path exists) {
        return true
    }
    let v = try { open $pre_upgrade | str trim | split row "." | first 3 | each { into int } } catch { [] }
    if ($v | length) != 3 {
        return true
    }
    ($v.0 > 1) or ($v.0 == 1 and ($v.1 > 17 or ($v.1 == 17 and $v.2 >= 4)))
}

def find_root_eq_in_cmdline [bootloader: string] {
    let cmdline = parse_cmdline
    let has_root_param = ($cmdline | any { |param| $param | str starts-with 'root=' })
    assert (not $has_root_param) $"($bootloader) image should not have root= in kernel cmdline; systemd-gpt-auto-generator should discover the root partition via DPS"
}

# Detect composefs by checking if composefs field is present
let st = bootc status --json | from json
let is_composefs = (tap is_composefs)
let expecting_composefs = ($env.BOOTC_variant? | default "" | find "composefs") != null
if $expecting_composefs {
    assert $is_composefs

    let bootloader = ($st.status.booted.composefs.bootloader | str downcase)

    if $bootloader == "systemd" {
        # When using systemd-boot with DPS (Discoverable Partition Specification),
        # /proc/cmdline should NOT contain a root= parameter because systemd-gpt-auto-generator
        # discovers the root partition automatically
        # Note that there is `bootctl --json=pretty` but it doesn't actually output JSON
        let bootctl_output = (bootctl)

        if ($bootctl_output | str contains 'Product: systemd-boot') {
            # Make sure our "timeout 1" is actually present (see ../../../../contrib/packaging/switch-to-sdboot:41)

            mkdir /var/tmp/efi
            mount /dev/disk/by-partlabel/EFI-SYSTEM /var/tmp/efi

            # loader.conf is written at install time, and bootc before 1.17.4
            # wrote its own; in upgrade tests, an older bootc did the install.
            if (installed_by_bootc_with_image_loader_conf) {
                assert (open /var/tmp/efi/loader/loader.conf | lines | any {|s| $s == "timeout 1" })
            }

            find_root_eq_in_cmdline "systemd-boot"
        }
    }

    # GrubCC also supports BLS and shouldn't need root=
    if $bootloader == "grub-cc" {
        find_root_eq_in_cmdline "grub-cc"
    }
}

if $is_composefs {
    # When already on composefs, we can only test read-only operations
    print "# TODO composefs: skipping pull test - cfs oci pull requires write access to sysroot"
    bootc internals cfs --help

    # Regression test for https://github.com/bootc-dev/bootc/issues/1808 :
    # `bootc internals cfs gc` was deleting live deployment objects.
    # Verify GC dry-run does not prune any OCI image or stream symlinks.
    # A small number of raw object orphans (~4) is expected: pull rewrites
    # the config+manifest splitstreams to add EROFS refs, leaving the
    # originals unreferenced until the next GC run.  Those are harmless.
    # We use --assert-no-op in the dedicated writable GC test plan instead.
    print "# Verifying composefs GC dry-run does not prune OCI structure (issue #1808)"
    let gc_out = (bootc internals composefs-gc --dry-run)
    print $gc_out
    assert (not ($gc_out | str contains "Pruned symlinks")) "GC must not prune any OCI image or stream symlinks on a live system"
} else {
    # When not on composefs, run the full test including initialization
    bootc internals test-composefs
    bootc internals cfs --help

    # We use a separate `/sysroot` as we need rw access to the repo which
    # we can't get from `bootc internals cfs ...`
    mkdir /var/tmp/sysroot/composefs
    bootc internals cfs --insecure --repo /var/tmp/sysroot/composefs init
    bootc internals cfs --insecure --repo /var/tmp/sysroot/composefs oci pull docker://busybox busybox
    test -L /var/tmp/sysroot/composefs/streams/refs/oci/busybox
}

tap ok
