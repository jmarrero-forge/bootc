# number: 65
# tmt:
#   summary: Test composefs local layers (bootc internals local-layer)
#   duration: 45m
# extra:
#   skip_if_ostree: true
#
# A local layer is a command run against the booted image, whose changes
# are deployed as one more layer on top of it. This test:
# 1. switches to a local base image (so that the test can update it later)
# 2. checks that a failing command stages nothing (and leaves nothing
#    behind, removing what an interrupted run left), that the command can't
#    write the host through /proc, /sys, /dev or a descriptor it inherits,
#    nor reach the caller's terminal, and that a retry after an
#    interrupted stage works; then runs `dnf -y install tmux` as a local
#    layer, and adds a second command before rebooting, which builds on the
#    staged layer
# 3. boots it: tmux is there (and its scriptlet ran), the origin still
#    tracks the base image
# 4. rolls back to the base: no tmux; then rolls forward again
# 5. checks `bootc upgrade` is a no-op while the base is unchanged, then
#    updates the base image and upgrades: the layer is rebuilt on the new
#    base. Then `bootc upgrade --tag` rebuilds it on another tag, and a
#    plain `bootc upgrade` keeps that staged layer.
# 6. boots that: tmux and the new base's files are all there
#
# Local layers need a BLS boot entry (a UKI pins the base's digest), so a
# UKI boot only checks that the command is refused.

use std assert
use tap.nu

bootc status
journalctl --list-boots

let st = bootc status --json | from json
let booted = $st.status.booted
const base_image = "localhost/bootc-local-layer-base"
const upgrade_marker = "/usr/share/local-layer-new-base"
const second_file = "/usr/share/local-layer-second"
const other_tag = "other"
const other_marker = "/usr/share/local-layer-other-tag"
const staged_file = "/run/composefs/staged-deployment"
const work_parent = "/var/lib/bootc-local-layer"
const commands = [["dnf" "-y" "install" "tmux"] ["sh" "-c" "echo two > /usr/share/local-layer-second"]]

# The base differs from the installed image (a switch to the same content is
# refused), and the upgraded base differs again.
def build_base [tag: string, markers: list<string>] {
    let extra = $markers | each { |m| $"RUN touch ($m)\n" } | str join
    $"FROM localhost/bootc\nRUN touch /usr/share/local-layer-base\n($extra)" | podman build -t $"($base_image):($tag)" -f - .
}

def staged-entry [] {
    (bootc status --json | from json).status.staged
}

# Probes what the command can reach; every line it prints with LEAK is a
# way to the host. /proc/1/root is its own root (it is PID 1 of its own
# namespace), and chrooting out of a chroot ends in it too, so the writes
# there are checked on the host. It fails, so that nothing is staged.
const probe = [
    'echo x > /proc/1/root/etc/t65-escaped;'
    r#'python3 -c "import os; os.mkdir('/t65c'); os.chroot('/t65c'); [os.chdir('..') for _ in range(64)]; os.chroot('.'); open('/etc/t65-chroot', 'w')" && echo PROBE:chroot;'#
    '[ "$$" = 1 ] || echo LEAK:pid;'
    'echo 0 > /sys/fs/selinux/enforce && echo LEAK:selinux;'
    r#'awk '$2 == "/sys" && $4 !~ /^ro,/ { print "LEAK:sys" }' /proc/self/mounts;'#
    'echo 1 > /proc/sys/kernel/sysrq && echo LEAK:sysctl;'
    'test -e /dev/kmsg && echo LEAK:dev;'
    'echo t65-kmsg-probe > /dev/kmsg;'
    r#'bnd=$(awk '/^CapBnd/ { print $2 }' /proc/self/status);'#
    '[ $(( 0x$bnd >> 21 & 1 )) = 0 ] || echo LEAK:cap_sys_admin;'
    'exit 1'
]

# Runs a command on a terminal of its own, as its controlling one, with the
# host's /etc open without close-on-exec on fd 7.
const fd_tty_wrapper = r#'
import os, pty, sys
os.dup2(os.open("/etc", os.O_RDONLY | os.O_DIRECTORY), 7, inheritable=True)
sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))
'#
# Probes, under that wrapper, whether the command can use the descriptor or
# the terminal. /dev/tty is what shows it has no controlling terminal; the
# TIOCSTI line is a backstop, since kernels without legacy TIOCSTI refuse it
# anyway. It fails too.
const fd_tty_probe = [
    'echo PROBE:fd-tty;'
    'echo x > /proc/self/fd/7/t65-fd && echo LEAK:fd;'
    '(: < /dev/tty) 2>/dev/null && echo LEAK:tty;'
    r#'python3 -c "import fcntl, termios; fcntl.ioctl(0, termios.TIOCSTI, b' ')" 2>/dev/null && echo LEAK:tiocsti;'#
    'exit 1'
]

# The lines of a command's output that start with LEAK: (a terminal's carry
# a trailing \r).
def leaks [out: string] {
    $out | lines | str trim | where { |l| $l | str starts-with "LEAK:" }
}

def local_layer [] {
    $booted.composefs.localLayer?
}

def first_boot [] {
    tap begin "composefs local layer"
    if ($booted.composefs.bootType | str downcase) != "bls" {
        let r = do { bootc internals local-layer run -- true } | complete
        assert ($r.exit_code != 0) "local-layer must be refused on a UKI boot"
        print $"refused as expected: ($r.stderr)"
        tap ok
        exit 0
    }
    bootc image copy-to-storage
    build_base latest []
    bootc switch --transport containers-storage $base_image
    tmt-reboot
}

def second_boot [] {
    assert equal $booted.image.image.image $base_image
    assert ((local_layer) == null)

    # A failing command stages nothing, and a run removes what a killed one
    # left behind.
    mkdir $"($work_parent)/build.t65-stale/upper"
    let r = do { bootc internals local-layer run -- dnf -y install no-such-package-t65 } | complete
    assert ($r.exit_code != 0) "a failing command must fail the run"
    assert ((staged-entry) == null) "nothing may be staged"
    assert ((ls $work_parent | length) == 0) "no work directory may be left"

    # The command is isolated from the host.
    let r = do { bootc internals local-layer run -- sh -c ($probe | str join ' ') } | complete
    print $r.stdout $r.stderr
    assert ($r.exit_code != 0) "the probe fails"
    # (bootc prints the command line too, so only whole lines count.)
    let found = leaks $r.stdout
    assert ($found | is-empty) $"the command reached the host: ($found)"
    assert (not ("/etc/t65-escaped" | path exists)) "the command wrote the host's /etc through /proc"
    assert ($r.stdout | lines | any { |l| $l == "PROBE:chroot" }) "the chroot probe ran"
    assert (not ("/etc/t65-chroot" | path exists)) "the command chrooted out to the host"
    assert (not (^dmesg | str contains "t65-kmsg-probe")) "the command wrote the host's /dev/kmsg"
    assert ((staged-entry) == null) "nothing may be staged"

    # Nor through a descriptor or the terminal it inherits, which the
    # wrapper does give a command.
    let c = do { python3 -c $fd_tty_wrapper sh -c 'echo x > /proc/self/fd/7/t65-control && rm /etc/t65-control && (: < /dev/tty) && echo CONTROL:ok' } | complete
    assert ($c.stdout | lines | str trim | any { |l| $l == "CONTROL:ok" }) $"the wrapper passes fd 7 and a terminal: ($c.stdout)"
    let r = do { python3 -c $fd_tty_wrapper bootc internals local-layer run -- sh -c ($fd_tty_probe | str join ' ') } | complete
    print $r.stdout $r.stderr
    assert ($r.exit_code != 0) "the probe fails"
    let found = leaks $r.stdout
    assert ($found | is-empty) $"the command reached the host: ($found)"
    assert ($r.stdout | lines | str trim | any { |l| $l == "PROBE:fd-tty" }) "the fd and terminal probe ran"
    assert (not ("/etc/t65-fd" | path exists)) "the command wrote the host's /etc through an inherited descriptor"
    assert ((staged-entry) == null) "nothing may be staged"

    # A retry after an interrupted stage builds the same deployment again,
    # over the state left by the first one. Dropping the staged deployment's
    # record is what an interruption before it is written leaves.
    let same = ["sh" "-c" "echo x > /usr/share/t65-same && touch -d @0 /usr/share/t65-same"]
    bootc internals local-layer run -- ...$same
    let first = (staged-entry).composefs.verity
    rm $staged_file
    bootc internals local-layer run -- ...$same
    assert equal (staged-entry).composefs.verity $first "the same content gives the same deployment"
    rm $staged_file

    bootc internals local-layer run -- dnf -y install tmux
    let staged = staged-entry
    assert equal $staged.image.image.image $base_image "the origin keeps tracking the base"
    assert equal $staged.composefs.localLayer.commands [["dnf" "-y" "install" "tmux"]]
    assert equal $staged.composefs.localLayer.baseImageDigest $booted.image.imageDigest
    assert ($staged.image.imageDigest != $booted.image.imageDigest) "a derived image"
    assert ((which tmux | length) == 0) "nothing changes before the reboot"

    # A second command before the reboot builds on the staged layer.
    bootc internals local-layer run -- sh -c $"echo two > ($second_file)"
    assert equal (staged-entry).composefs.localLayer.commands $commands
    tmt-reboot
}

def third_boot [] {
    assert ((which tmux | length) == 1) "tmux comes from the local layer"
    assert equal (open $second_file | str trim) "two"
    assert equal (local_layer).commands $commands
    assert equal $booted.image.image.image $base_image
    assert equal $booted.composefs.missingVerityAllowed false
    rpm -q tmux
    # Its scriptlet, if it has one, ran in the staging root.
    if (rpm -q --scripts tmux | str contains "postinstall") {
        assert (open /etc/shells | str contains "/usr/bin/tmux") "tmux's %post ran"
    }
    bootc internals fsck
    bootc rollback
    tmt-reboot
}

def fourth_boot [] {
    assert ((which tmux | length) == 0) "rolled back to the base"
    assert ((local_layer) == null)
    bootc rollback
    tmt-reboot
}

def fifth_boot [] {
    assert ((which tmux | length) == 1) "rolled forward to the local layer"
    let out = bootc upgrade | complete
    print $out.stdout
    assert ($out.stdout | str contains "No changes") "an unchanged base is a no-op"
    assert ((staged-entry) == null)

    build_base latest [$upgrade_marker]
    bootc upgrade
    let rebuilt = staged-entry
    assert equal $rebuilt.composefs.localLayer.commands $commands
    assert ($rebuilt.composefs.localLayer.baseImageDigest != (local_layer).baseImageDigest) "rebuilt on the new base"

    # On another tag the layer is rebuilt too, and a plain upgrade then
    # compares with that staged layer's base, keeping it.
    build_base $other_tag [$upgrade_marker $other_marker]
    bootc upgrade --tag $other_tag
    let tagged = staged-entry
    assert ($tagged.image.image.image | str ends-with $":($other_tag)") "the staged deployment tracks the tag"
    assert equal $tagged.composefs.localLayer.commands $commands
    assert ($tagged.composefs.localLayer.baseImageDigest != $rebuilt.composefs.localLayer.baseImageDigest) "rebuilt on the tag"
    let out = bootc upgrade | complete
    print $out.stdout
    assert ($out.stdout | str contains "already staged") "a plain upgrade keeps the staged layer"
    assert equal (staged-entry).composefs $tagged.composefs
    tmt-reboot
}

def sixth_boot [] {
    assert ($upgrade_marker | path exists) "the new base"
    assert ($other_marker | path exists) "the other tag"
    assert ((which tmux | length) == 1) "the local layer, rebuilt"
    assert equal (open $second_file | str trim) "two"
    assert ($booted.image.image.image | str ends-with $":($other_tag)")
    bootc internals fsck
    tap ok
}

def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        "2" => third_boot,
        "3" => fourth_boot,
        "4" => fifth_boot,
        "5" => sixth_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}
