# NAME

bootc-install-to-filesystem - Install to an externally created
filesystem structure

# SYNOPSIS

**bootc install to-filesystem** \[*OPTIONS...*\] <*ROOT_PATH*>

# DESCRIPTION

Install to an externally created filesystem structure.

In this variant of installation, the root filesystem alongside any
necessary platform partitions (such as the EFI system partition) are
prepared and mounted by an external tool or script. The root filesystem
is currently expected to be empty by default.

With `--defer-var`, the deployment's state directory for `/var`
(`ostree/deploy/STATEROOT/var`, or `state/os/default/var` with composefs) is not
seeded from the image's `/var`, and the installed system starts with an empty
`/var` for the caller to fill, for example on a separate filesystem. Before the
first deployment, bootc writes an empty `.bootc-defer-var` file there, which
keeps both backends from seeding it, then and on later deployments: libostree
seeds the state directory only while it is empty, and bootc's composefs backend
checks for the file. On composefs, that check matters only at installation,
since later deployments never seed `/var`. The file stays, as a record that
`/var` was deferred.
With `--defer-var` alone, the caller must fill `/var`, or the filesystems
mounted there, before the first boot. An empty `/var` is not a supported
first-boot state: on composefs it is already visible in the initramfs, before
the SELinux policy is loaded, and directories created there then (such as
`/var/lib`, for `/var/lib/nfs/rpc_pipefs`) are unlabeled, which can keep a
mount below them from working.
On composefs, the file also tells setup-root that `/var` is the caller's: when
the deployment's `/etc/fstab` has a mount entry for `/var`, it doesn't
bind-mount the state directory over it (see **bootc-setup-root-conf**(5)).
Switching or rolling back to an image whose initramfs predates this hides that
`/var` behind the empty state directory.
`--defer-var` is an error over an existing ostree system or with
`--replace=alongside`. Tools can tell whether a bootc binary supports it by
looking for `defer-var` in the `Features:` list of `bootc --version`.

To use separate filesystems for `/var` or its subdirectories, mount them beneath
*ROOT_PATH* before invoking this command, and pass `--initialize-var-mounts`.
On a fresh installation, bootc then initializes empty mounted trees from the
image's initial `/var` contents, including nested mounts. Without that option,
such filesystems are left alone: the image's initial `/var` contents stay in
the deployment's state directory, where these mounts hide them at boot.
`--initialize-var-mounts` is an error over an existing ostree system or with
`--replace=alongside`.

Empty `lost+found` directories and directories needed to reach nested
mountpoints do not prevent initialization. Within a tree being initialized,
mountpoints must resolve to directories in the image, not symlinks. A mount for
which the image has no content is left empty. Filesystems that bootc
initializes or leaves empty are synced, and SELinux labeled when SELinux is
enabled. Unlike the root
filesystem, they are not remounted read-only. When a tree includes nested
filesystems, regular files are copied independently instead of preserving
hardlinks, which cannot span filesystems. Symbolic links, ownership,
permissions, and extended attributes are preserved.

If a mounted tree or any of its nested mounts already contains data, bootc
preserves that entire tree without merging image contents into it. This does
not change upgrade semantics: subsequent image updates do not update `/var`.
The caller remains responsible for configuring `/etc/fstab` or mount units so
the filesystems are mounted at the same locations on subsequent boots.

Tools can tell whether a bootc binary supports `--initialize-var-mounts` by
looking for `initialize-var-mounts` in the `Features:` list of
`bootc --version`.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**ROOT_PATH**

    Path to the mounted root filesystem

    This argument is required.

**--root-mount-spec**=*ROOT_MOUNT_SPEC*

    Source device specification for the root filesystem.  For example, `UUID=2e9f4241-229b-4202-8429-62d2302382e1`. If not provided, the UUID of the target filesystem will be used. This option is provided as some use cases might prefer to mount by a label instead via e.g. `LABEL=rootfs`

**--boot-mount-spec**=*BOOT_MOUNT_SPEC*

    Mount specification for the /boot filesystem

**--defer-var**

    Do not seed the deployment's state directory with the image's /var

**--initialize-var-mounts**

    Initialize empty filesystems mounted at or below /var in the target from the image's /var, including nested mounts

**--replace**=*REPLACE*

    Initialize the system in-place; at the moment, only one mode for this is implemented. In the future, it may also be supported to set up an explicit "dual boot" system

    Possible values:
    - wipe
    - alongside

**--acknowledge-destructive**

    If the target is the running system's root filesystem, this will skip any warnings

**--skip-finalize**

    The default mode is to "finalize" the target filesystem by invoking `fstrim` and similar operations, and finally mounting it readonly.  This option skips those operations.  It is then the responsibility of the invoking code to perform those operations

**--source-imgref**=*SOURCE_IMGREF*

    Install the system from an explicitly given source

**--target-transport**=*TARGET_TRANSPORT*

    The transport; e.g. oci, oci-archive, containers-storage.  Defaults to `registry`

    Default: registry

**--target-imgref**=*TARGET_IMGREF*

    Specify the image to fetch for subsequent updates

**--enforce-container-sigpolicy**

    This is the inverse of the previous `--target-no-signature-verification` (which is now a no-op).  Enabling this option enforces that `containers-policy.json` (see `man containers-policy.json` for the full search path) includes a default policy which requires signatures

**--run-fetch-check**

    Verify the image can be fetched from the bootc image. Updates may fail when the installation host is authenticated with the registry but the pull secret is not in the bootc image

**--skip-fetch-check**

    Verify the image can be fetched from the bootc image. Updates may fail when the installation host is authenticated with the registry but the pull secret is not in the bootc image

**--disable-selinux**

    Disable SELinux in the target (installed) system

**--karg**=*KARG*

    Add a kernel argument.  This option can be provided multiple times

**--karg-delete**=*KARG_DELETE*

    Remove a kernel argument.  This option can be provided multiple times

**--root-ssh-authorized-keys**=*ROOT_SSH_AUTHORIZED_KEYS*

    The path to an `authorized_keys` that will be injected into the `root` account

**--generic-image**

    Perform configuration changes suitable for a "generic" disk image. At the moment:

**--bound-images**=*BOUND_IMAGES*

    How should logically bound images be retrieved

    Possible values:
    - stored
    - skip
    - pull

    Default: stored

**--stateroot**=*STATEROOT*

    The stateroot name to use. Defaults to `default`

**--bootupd-skip-boot-uuid**

    Don't pass --write-uuid to bootupd during bootloader installation

**--bootloader**=*BOOTLOADER*

    The bootloader to use

    Possible values:
    - grub
    - grub-cc
    - systemd
    - ukiboot
    - none

**--composefs-backend**

    Use the composefs backend instead of ostree. This is the default for images with a UKI, and for images with /usr/lib/composefs/setup-root-conf.toml and no ostree prepare-root.conf

    Default: false

**--allow-missing-verity**

    Make fs-verity validation optional in case the filesystem doesn't support it (composefs backend only)

    Default: false

**--uki-addon**=*SCOPED*

    Experimental. Name of the local/scoped UKI addons to install without the ".addon.efi" suffix. This option can be provided multiple times if multiple addons are to be installed (composefs backend only). On upgrade and switch, scoped addons already installed are carried forward; passing this flag adds further addons on top

**--global-uki-addon**=*GLOBAL*

    Experimental. Name of the global UKI addons to install without the ".addon.efi" suffix. This option can be provided multiple times if multiple addons are to be installed (composefs backend only). On upgrade and switch, global addons already installed are carried forward; passing this flag adds further addons on top

<!-- END GENERATED OPTIONS -->

# VERSION

<!-- VERSION PLACEHOLDER -->

