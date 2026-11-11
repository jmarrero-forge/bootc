use std assert
use tap.nu

tap begin "Run fsck"

# That's it, just ensure we've run a fsck on our basic install.
let out = bootc internals fsck
print $out

if (tap is_composefs) {
    # CI installs are consistent: every strict boot entry's image has
    # fs-verity, so the boot entry check passes.
    assert str contains $out "ok: composefs-boot-policy"
}

tap ok
