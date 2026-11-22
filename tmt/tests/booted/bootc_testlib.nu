# A simple nushell "library" for bootc test helpers

# This is a workaround for what must be a systemd bug
# that seems to have appeared in C10S
# TODO diagnose and fill in here
export def reboot [] {
    # Allow more delay for bootc to settle
    sleep 120sec

    tmt-reboot
}

# True if we're running in bcvk with `--bind-storage-ro` and
# we can expect to be able to pull container images from the host.
# See xtask.rs
export def have_hostexports [] {
    $env.BCVK_EXPORT? == "1"
}

# Parse the kernel commandline into a list.
# This is not a proper parser, but good enough
# for what we need here.
export def parse_cmdline []  {
    open /proc/cmdline | str trim | split row " "
}

# For the pinned-version upgrade tests (`just test-upgrade-pinned`, which
# sets BOOTC_test_pinned_version): check that the bootc release under test
# made this install, record which build it was, and check the verdict of the
# pre-upgrade check script, which must not flag an install made by to-disk.
def check_pinned_source [booted_version: string] {
    use std assert

    let pinned = $env.BOOTC_test_pinned_version? | default ""
    if $pinned == "" {
        return
    }
    assert equal $booted_version $pinned "the system must run the pinned bootc release"
    let proof = {
        version: $booted_version,
        rpm: (rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' bootc | str trim),
        sha256: (open --raw /usr/bin/bootc | hash sha256),
    }
    $proof | to json | save --force /var/bootc-pinned-proof.json
    print $"Pinned bootc: ($proof | to nuon)"

    let st = bootc status --json | from json
    if $st.status.booted.composefs? != null {
        let check = do -i { bash booted/check-strict-verity.sh } | complete
        print $"Pre-upgrade check: ($check.stdout | str trim)"
        assert equal $check.exit_code 0 "the pre-upgrade check must find a to-disk install unaffected"
    }
}

# If the BOOTC_test_upgrade_image environment variable is set, performs
# an upgrade to that image and reboots on the first boot. On the second
# boot (after the upgrade), verifies we're running the upgraded image
# and returns so the caller can proceed with its tests.
#
# This enables an "upgrade test" flow: boot from a published base image,
# upgrade to the image under test, reboot, then run verification tests.
#
# Note: This uses BOOTC_test_upgrade_image (the image to upgrade *into*),
# which is distinct from BOOTC_upgrade_image (the synthetic upgrade image
# used by existing upgrade tests like test-image-upgrade-reboot).
#
# Returns without doing anything if BOOTC_test_upgrade_image is not set.
export def maybe_upgrade [] {
    use std assert

    let upgrade_image = $env.BOOTC_test_upgrade_image? | default ""
    if $upgrade_image == "" {
        return
    }

    match $env.TMT_REBOOT_COUNT? {
        null | "0" => {
            if not (have_hostexports) {
                error make { msg: "BOOTC_test_upgrade_image is set but host exports (--bind-storage-ro) are not available" }
            }
            # Save the pre-upgrade bootc version so post-upgrade tests
            # can detect known incompatibilities with older versions.
            let pre_ver = (bootc --version | parse "bootc {v}" | get 0.v)
            $pre_ver | save /var/bootc-pre-upgrade-version
            print $"Pre-upgrade bootc version: ($pre_ver)"
            check_pinned_source $pre_ver

            print $"Upgrade image specified: ($upgrade_image)"
            print "Performing upgrade switch..."
            bootc switch --transport containers-storage $upgrade_image
            print "Switch complete, rebooting..."
            tmt-reboot
        },
        "1" => {
            print $"Second boot after upgrade to ($upgrade_image)"
            let st = bootc status --json | from json
            let booted = $st.status.booted.image
            assert equal $booted.image.transport "containers-storage"
            assert equal $booted.image.image $upgrade_image
            print "Upgrade verified, continuing with tests..."
        },
        $o => {
            # For higher reboot counts, just continue - the caller
            # may have its own reboot logic
        },
    }
}
