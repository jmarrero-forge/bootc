# Experimental: composefs image sets

With the [composefs backend](bootc-composefs.7.md), a deployment's root
filesystem is normally one EROFS image, and `composefs.digest=` on the kernel
command line pins that image's fs-verity digest. An *image set* splits the
root filesystem into several images instead, while one digest still pins all
of them.

This is an experimental proof of concept, and its format and configuration
may change or be removed.

## Configuration

An image opts in by listing the directories that should become images of
their own in `/usr/lib/bootc/composefs-image-set.conf`, one absolute path per
line (empty lines and lines starting with `#` are ignored):

```
/usr/lib/modules
```

A path may not start with a directory named with two lowercase hexadecimal
digits (`/00` to `/ff`): composefs puts whiteout stubs with those names at the
root of its V0/V1 images, which would hide it.

At install and upgrade time bootc then writes:

- one image for the root filesystem, with an empty directory at each listed
  path;
- one image for each listed directory, holding that directory (and only
  empty copies of its parents);
- an image set manifest naming those images, in that order, with the
  directory each provides.

The deployment is named by the digest of the manifest, and its boot entry
carries `composefs.digest=set1-sha512-12:<digest>`. bootc's initramfs
verifies the manifest against that digest and every image against the
manifest, then mounts all of them as overlayfs lower layers over the
composefs object store, with fs-verity required for all file data. The result
is a single mount at `/` that shows the original tree.

An image that changes only a listed directory, such as a new kernel's
modules, produces the same root filesystem image as before, so the
deployments share it and only the changed part is written.

Each deployment's set has a ref of its own in the composefs repository
(`image-sets/refs/bootc/<digest>`), which keeps the set and its images through
any garbage collection of the repository, and which `bootc` removes with the
deployment. That ref is what keeps the set: being booted or mounted doesn't,
so a repository garbage collection run without it (such as
`bootc internals cfs gc`) deletes the set even while it is booted, and the
next boot fails. bootc's own garbage collection restores the ref of any live
deployment that lacks it. The first set also marks the repository with the `image_sets`
incompatible feature, so that an older composefs-rs, whose garbage collection
would delete what only sets keep alive, refuses to open it.

## Limitations

- Only BLS (Type 1) boot entries are supported; an image with a UKI or an
  Android boot image that asks for an image set is refused.
  `bootc container ukify` doesn't compute image set digests.
- A bootc that doesn't know image sets refuses a `composefs.digest=set1-...`
  argument, so a system has to be upgraded to a bootc with image set support
  before it can stage an image that uses one.
- Once a set has been written, a deployment whose bootc predates image sets
  (such as the rollback deployment when the first set is staged, or a pinned
  one) no longer boots: its initramfs refuses the repository's `image_sets`
  feature. Even without that feature, such a bootc couldn't parse an image
  set deployment's boot entry, so `bootc status`, `upgrade`, `rollback` and
  garbage collection would fail there while the entry exists.
- At most 8 directories can be listed: kernels before 6.15 take every layer
  in one `lowerdir` mount option, which is limited to 255 bytes.
- Images are written in the repository's default EROFS format only.
