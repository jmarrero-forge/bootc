# separate kernel images

Experimental features are subject to change or removal. Please
do provide feedback on them.

This is a prototype for
[#2584](https://github.com/bootc-dev/bootc/issues/2584).

## Overview

With the composefs backend and a UKI, the UKI pins the root filesystem by
its composefs digest. Normally the kernel modules are in
`/usr/lib/modules`, so they are part of that digest, and any kernel change
means a new digest (and a new signature, for sealed images).

Instead, a bootable image can carry its kernel modules in
`/boot/bootc/modules`. The root filesystem digest never covers `/boot`, so
it stays the same whatever kernel is added: a root filesystem image can be
built and digested once, and combined with kernels from a separate
kernel-only image, for example one published by a different pipeline.

The modules become a second composefs image with its own digest. `bootc
container ukify` pins it in the UKI cmdline with `bootc.kmods=<digest>`,
next to the root filesystem digest. `bootc install` (and upgrades) create
that image from `/boot/bootc/modules`, labeled as if it were
`/usr/lib/modules`, and refuse an image whose modules and UKI don't agree.
At boot, the initramfs mounts it on `/usr/lib/modules`, verified the same
way as the root filesystem.

## Kernel-only images

A kernel-only image is an OCI image with exactly one
`/usr/lib/modules/<kver>/` directory, containing:

- `vmlinuz`
- the modules, and the `modules.*` files that `depmod` generates
- optionally other files the kernel package ships there (`config`,
  `System.map`, `.vmlinuz.hmac`, ...)

and nothing else: no userspace and no initramfs. For example, from CentOS
Stream RPMs:

```dockerfile
FROM quay.io/centos/centos:stream10 AS build
RUN <<EORUN
set -xeuo pipefail
dnf -y install dnf-plugins-core cpio kmod
dnf download --destdir /rpms kernel-core kernel-modules-core kernel-modules
mkdir /kroot && cd /kroot
for rpm in /rpms/*.rpm; do rpm2cpio "$rpm" | cpio -idm --quiet; done
# These packages use /lib/modules, which is /usr/lib/modules on the host
mkdir -p usr/lib && mv lib/modules usr/lib/ && rm -rf lib && ln -s usr/lib lib
depmod -b /kroot "$(ls usr/lib/modules)"
EORUN

FROM scratch
COPY --from=build /kroot/usr/lib/modules /usr/lib/modules
```

## Building a bootable image

The root filesystem image must have an empty `/usr/lib/modules` (it is the
mount point for the modules image), no kernel in `/boot`, and the tools to
build an initramfs and a UKI (`dracut`, `systemd-ukify`, `bootc`). As for
any sealed image, it should be flattened or rechunked: a derived layer that
changes a directory's metadata can give a different digest at build time
than from the image layers
([composefs-rs#132](https://github.com/containers/composefs-rs/issues/132)).

The initramfs combines the root filesystem's userspace and dracut
configuration with the kernel's modules, so it is built for each pair:

```dockerfile
ARG rootfs
ARG kernel
FROM $kernel AS kernel
FROM $rootfs AS rootfs

# The layer cache doesn't track the content of bind mounts, so what changes
# with the kernel is copied into the stages instead (the staged bind mount
# in the uki stage is covered by the initramfs copied there).
FROM rootfs AS initramfs
COPY --from=kernel /usr/lib/modules /usr/lib/modules
RUN <<EORUN
set -xeuo pipefail
kver=$(ls /usr/lib/modules)
mkdir -p /out/$kver
cp /usr/lib/modules/$kver/vmlinuz /out/$kver/vmlinuz
dracut --no-hostonly --reproducible --kver "$kver" /out/$kver/initramfs.img
EORUN

# The modules go under /boot, which is not part of the rootfs digest
FROM rootfs AS staged
COPY --from=kernel /usr/lib/modules/ /boot/bootc/modules/

# The UKI pins both digests
FROM rootfs AS uki
COPY --from=initramfs /out/ /var/tmp/kernel/
RUN --mount=type=bind,from=staged,target=/run/target <<EORUN
set -xeuo pipefail
kver=$(ls /var/tmp/kernel)
mkdir -p /out
bootc container ukify --rootfs /run/target --kernel-dir /var/tmp/kernel/$kver \
    -- --output /out/$kver.efi
EORUN

FROM staged
COPY --from=uki /out/ /boot/EFI/Linux/
```

Build it with the root filesystem and kernel images as arguments, for
example `podman build --build-arg rootfs=... --build-arg kernel=... .`.
Signing the UKI works as for other sealed images.

`bootc container compute-composefs-digest` gives the same digest for the
root filesystem image and for each image built from it this way.

## Limitations

- A deployment is still identified by the root filesystem digest alone, so
  `bootc upgrade` to an image that changes only the kernel considers it
  already deployed, and `bootc switch` refuses it.
- The modules image is kept by a repository reference that nothing removes
  yet.
- Only UKIs are supported, not Type 1 boot entries, and only the image's
  first UKI is checked against the modules.
- Only the UKI itself may carry `bootc.kmods=`: install, upgrade and
  `bootc uki-addon add` refuse it in a UKI addon (including global addons
  carried over to a new deployment), in the kernel arguments of a Type 1
  (BLS) entry (from kargs.d, `--karg`, or on upgrade the booted entry's own
  options), and in an aboot image.
- `bootc usr-overlay` puts an overlay on `/usr` that doesn't include the
  modules mount, so `/usr/lib/modules` looks empty under it.
- `bootc container lint` warns about the non-empty `/boot`.
- Out-of-tree modules built against the kernel have to be part of the
  kernel image (or of the `/boot/bootc/modules` payload).
- Tools that boot or inspect the container image directly (such as `bcvk`
  ephemeral VMs, which install via the image itself) don't see any modules
  in `/usr/lib/modules`.
