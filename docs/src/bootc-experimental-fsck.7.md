# bootc internals fsck

Experimental features are subject to change or removal. Please
do provide feedback on them.

## Using `bootc internals fsck`

This command expects a booted system, and performs consistency checks
in a read-only fashion.

## composefs boot entries

On systems booted with composefs, the `composefs-boot-policy` check reads
the command line of every boot entry the way the initramfs does: the BLS
entries in `loader/entries` and `loader/entries.staged` on the ESP or the
boot partition, and the command lines embedded in bootc's UKIs. An entry
whose `composefs=` or `composefs.digest=` argument is strict (no `?`)
only boots if the image it names has fs-verity, so the check reports such
entries whose image lacks it, and says whether the root filesystem
supports fs-verity at all. bootc 1.16.0 through 1.16.14 created such
entries when installing with `install to-filesystem` or `to-existing-root`
onto ext4 created without `-O verity`.

The check can run from a newer image before upgrading:

```
podman run --rm --privileged --pid=host -v /:/target IMAGE \
    bootc internals fsck
```

Run this way, only the composefs boot entry check runs.
