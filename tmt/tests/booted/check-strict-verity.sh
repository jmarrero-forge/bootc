#!/bin/sh
# The pre-upgrade check from https://github.com/bootc-dev/bootc/pull/2629#issuecomment-6695640406:
# would an initramfs that enforces fs-verity for strict composefs boots (bootc
# since #2629) fail to boot this system's next deployment? Exits 0 when
# unaffected, 1 when affected and 2 when it can't tell; the pinned-version
# upgrade tests check its verdict on every composefs install they make.
# Run as root (/sysroot/composefs is mode 0700).
args=$(tr ' ' '\n' </proc/cmdline | grep -E '^composefs(\.digest)?=') || { echo "unaffected: not booted with composefs"; exit 0; }
for arg in $args; do
  val=${arg#*=}
  case $val in \?*) echo "unaffected: '?' set, fs-verity is optional"; exit 0;; esac
  img=$(readlink -e /sysroot/composefs/images/${val##*:}) || continue
  if lsattr "$img" 2>/dev/null | cut -d' ' -f1 | grep -q V; then echo "unaffected: strict, and the image has fs-verity"; exit 0; fi
  echo "AFFECTED: strict $arg but $img has no fs-verity ($(findmnt -no FSTYPE /sysroot) root)"; exit 1
done
echo "unknown: no composefs image found for $args"; exit 2
