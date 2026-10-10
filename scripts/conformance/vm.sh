#!/bin/ksh
#
# The OpenBSD conformance suite's virtual machine, on vmd(8).
#
# ######################################################################
# #                                                                    #
# #  WARNING: THE CONFORMANCE SUITE DESTROYS THE SYSTEM IT RUNS ON.    #
# #                                                                    #
# #  It takes total control of the machine: it rewrites pf, network   #
# #  interfaces, routes, services, users and groups and files under    #
# #  /etc and /var, and may cut the machine off the network. It must   #
# #  only ever run on a disposable instance of OpenBSD made for it.    #
# #  This script makes and uses such an instance: a vmd guest whose    #
# #  disk is a throwaway copy of a clean install, discarded after      #
# #  every run. Never point the suite at any other machine.            #
# #                                                                    #
# ######################################################################
#
# This script runs on an OpenBSD host with vmd, as a user who can use
# doas(1). It changes nothing on the host but its own directory
# ($OPF_CONFORMANCE_HOME, ~/opf-conformance by default) and the guest it
# starts.
#
#   vm.sh [-r release] [-m memory] setup
#	Download the release's install image, bsd.rd and source, check
#	them with signify(1) against the host's keys, put the sets on a
#	disk of their own, and install a clean guest from it, unattended.
#	Once per release.
#   vm.sh [-r release] [-m memory] [-k] run <dir>
#	Boot a fresh copy of the clean guest, copy <dir>/in into it (the
#	suite's test binary, opf, and the list of source directories it
#	reads), run the suite, and copy its results to <dir>/out. -k keeps
#	the guest's disk and leaves it running, to look around afterwards.
#   vm.sh [-r release] start | stop | ssh [cmd...] | console | status | destroy
#
# The guest has two network interfaces: vio0 on vmd's local network,
# where the host reaches it (100.64.<id>.3; vmd's DHCP gives it the
# address), and vio1, a tap that leads nowhere, for the suite to use as
# a port. The host doesn't forward its traffic, so the guest has no
# internet unless the host does that itself (net.inet.ip.forwarding=1
# and NAT for 100.64.0.0/10); the checks that need the internet then
# report that they didn't run.
#
# A release's key must be on the host to check it: OpenBSD ships the
# next release's key in /etc/signify, so the host can be the release
# being checked or the one before it.

set -u

home=${OPF_CONFORMANCE_HOME:-$HOME/opf-conformance}
mirror=${OPF_MIRROR:-https://cdn.openbsd.org/pub/OpenBSD}
release=$(sysctl -n kern.osrelease)
memory=1G
keep=false
arch=$(machine)

while getopts r:m:k o; do
	case $o in
	r)	release=$OPTARG ;;
	m)	memory=$OPTARG ;;
	k)	keep=true ;;
	*)	sed -n '/^#   vm.sh/,/^#$/p' "$0" >&2; exit 1 ;;
	esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] || { sed -n '/^#   vm.sh/,/^#$/p' "$0" >&2; exit 1; }
cmd=$1; shift

case $release in
[0-9].[0-9]) ;;
*)	echo "release $release isn't of the form 7.9" >&2; exit 1 ;;
esac
rr=$(echo "$release" | tr -d .)
dir=$home/$release
name=opfconform$rr
key=/etc/signify/openbsd-$rr-base.pub

die() { echo "vm.sh: $*" >&2; exit 1; }

# The guest's row in vmctl status: ID PID VCPUS MAXMEM CURMEM TTY OWNER STATE NAME.
row() { doas vmctl status "$name" 2>/dev/null | awk -v n="$name" '$NF == n'; }
running() { row | grep -qw running; }
guest() { id=$(row | awk '{print $1}'); [ -n "$id" ] && echo "100.64.$id.3"; }

ssh_() {
	g=$(guest) || die "$name isn't running"
	ssh -i "$dir/id_ed25519" -o UserKnownHostsFile="$dir/known_hosts" \
	    -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 \
	    -o ServerAliveInterval=15 -o BatchMode=yes \
	    -o ControlMaster=auto -o ControlPath="$dir/ssh-%C" -o ControlPersist=5m \
	    "root@$g" "$@"
}

# Copies the guest's serial console into a file until the guest stops.
# The tty is set raw first: otherwise it echoes what the guest prints
# back to it as typed input.
console_log() {
	t=$(row | awk '{print $6}')
	[ -n "$t" ] || return 0
	doas sh -c 'exec < "$1"; stty raw -echo; exec cat' sh "/dev/$t" >> "$1" 2>/dev/null &
}

wait_stopped() { # timeout in seconds
	i=0
	while running; do
		[ $i -ge "$1" ] && return 1
		sleep 5; i=$((i + 5))
	done
}

wait_ssh() {
	i=0
	until ssh_ true 2>/dev/null; do
		[ $i -ge 600 ] && { echo "the guest didn't answer SSH; its console:" >&2; tail -c 3000 "$dir/console.log" >&2; return 1; }
		sleep 5; i=$((i + 5))
	done
}

fetch() { # file url
	[ -f "$1" ] && return 0
	ftp -o "$1.part" "$2" && mv "$1.part" "$1"
}

answers() {
	cat <<-EOF
	System hostname = $name
	Password for root account = *************
	Public ssh key for root account = $(cat "$dir/id_ed25519.pub")
	Start sshd(8) by default = yes
	Allow root ssh login = prohibit-password
	Do you expect to run the X Window System = no
	Change the default console to com0 = yes
	Which speed should com0 use = 115200
	Setup a user = no
	What timezone are you in = UTC
	Network interfaces to configure = vio0
	IPv4 address for vio0 = autoconf
	IPv6 address for vio0 = none
	Which disk is the root disk = sd0
	Use (W)hole disk MBR, whole disk (G)PT or (E)dit = whole
	Use (A)uto layout, (E)dit auto layout, or create (C)ustom layout = a
	Location of sets = disk
	Is the disk partition already mounted = no
	Which disk contains the install media = sd1
	Which sd1 partition has the install sets = a
	Pathname to the sets = $release/$arch
	Set name(s) = -all bsd bsd.mp bsd.rd base$rr.tgz comp$rr.tgz man$rr.tgz
	Continue without verification = no
	Location of sets = done
	EOF
}

marker() {
	cat <<-EOF
	This machine belongs to OPF's conformance suite.

	THE SUITE DESTROYS THE SYSTEM IT RUNS ON: it rewrites pf, network
	interfaces, routes, services, users and groups and files under /etc
	and /var, and may cut the machine off the network. It runs only
	where this file exists. Never copy this file to another machine.
	EOF
}

vm_setup() {
	[ -f "$key" ] || die "no $key: this host can't check $release (a release ships the next one's key)"
	mkdir -p "$dir/dl/src" "$dir/rd/mnt" || exit 1
	cd "$dir/dl" || exit 1
	for f in SHA256.sig bsd.rd install$rr.iso; do
		fetch "$f" "$mirror/$release/$arch/$f" || die "couldn't download $f"
	done
	signify -C -p "$key" -x SHA256.sig bsd.rd "install$rr.iso" || die "$release's files don't match their signatures"
	cd src || exit 1
	for f in SHA256.sig src.tar.gz sys.tar.gz; do
		fetch "$f" "$mirror/$release/$f" || die "couldn't download $f"
	done
	signify -C -p "$key" -x SHA256.sig src.tar.gz sys.tar.gz || die "$release's source doesn't match its signatures"
	if [ ! -d "$dir/src" ]; then
		mkdir -p "$dir/src.part" &&
		    tar -xzf src.tar.gz -C "$dir/src.part" &&
		    tar -xzf sys.tar.gz -C "$dir/src.part" &&
		    mv "$dir/src.part" "$dir/src" || die "couldn't unpack the source"
	fi

	[ -f "$dir/id_ed25519" ] || ssh-keygen -q -t ed25519 -N '' -C "$name" -f "$dir/id_ed25519" || exit 1

	# bsd.rd with the answers inside it, so the install needs nobody at
	# the console: the installer reads /auto_install.conf from its own
	# ramdisk before anything else.
	cd "$dir/rd" || exit 1
	answers > auto_install.conf
	gzip -dc "$dir/dl/bsd.rd" > bsd.rd 2>/dev/null || cp "$dir/dl/bsd.rd" bsd.rd
	rdsetroot -x bsd.rd ramdisk.fs || die "couldn't take the ramdisk out of bsd.rd"
	vnd=$(doas vnconfig ramdisk.fs) || exit 1
	case $vnd in vnd[0-9]*) ;; *) die "vnconfig said $vnd" ;; esac
	doas mount "/dev/${vnd}a" mnt &&
	    doas cp auto_install.conf mnt/auto_install.conf
	ok=$?
	doas umount mnt 2>/dev/null
	doas vnconfig -u "$vnd"
	[ $ok -eq 0 ] || die "couldn't put the answers in the ramdisk"
	rdsetroot bsd.rd ramdisk.fs || die "couldn't put the ramdisk back"

	running && die "$name is running; stop it first"

	# The sets, on a disk of their own: vmd's CD drive stalls part way
	# through the sets under nested virtualization. SHA256.sig goes with
	# them, so the installer checks each set against the release's key.
	if [ ! -f "$dir/sets.img" ]; then
		vmctl create -s 1G "$dir/sets.raw.img" || exit 1
		mkdir -p "$dir/cd" "$dir/setsmnt"
		cdv=$(doas vnconfig "$dir/dl/install$rr.iso") && sv=$(doas vnconfig "$dir/sets.raw.img") || exit 1
		printf 'a a\n\n\n\nw\nq\n' | doas disklabel -E "$sv" > /dev/null &&
		    doas newfs -q "/dev/r${sv}a" > /dev/null &&
		    doas mount -t cd9660 -r "/dev/${cdv}c" "$dir/cd" &&
		    doas mount "/dev/${sv}a" "$dir/setsmnt" &&
		    doas mkdir -p "$dir/setsmnt/$release/$arch" &&
		    doas cp "$dir/cd/$release/$arch/"bsd* "$dir/cd/$release/$arch/INSTALL.$arch" "$dir/cd/$release/$arch/"base$rr.tgz \
			"$dir/cd/$release/$arch/"comp$rr.tgz "$dir/cd/$release/$arch/"man$rr.tgz \
			"$dir/dl/SHA256.sig" "$dir/setsmnt/$release/$arch/"
		ok=$?
		doas umount "$dir/setsmnt" 2>/dev/null; doas umount "$dir/cd" 2>/dev/null
		doas vnconfig -u "$sv"; doas vnconfig -u "$cdv"
		[ $ok -eq 0 ] || die "couldn't make the sets disk"
		mv "$dir/sets.raw.img" "$dir/sets.img"
	fi
	rm -f "$dir/base.qcow2" "$dir/overlay.qcow2" "$dir/known_hosts"
	vmctl create -s 12G "$dir/base.qcow2" || exit 1
	echo "Installing $release; this takes a while. Console: $dir/console.log"
	: > "$dir/console.log"
	# -B disk: a guest started with a boot device is stopped, not
	# restarted, when it reboots, so the installer's reboot ends it.
	doas vmctl start -m "$memory" -L -i 2 -B disk -b "$dir/rd/bsd.rd" \
	    -d "$dir/base.qcow2" -d "$dir/sets.img" "$name" || exit 1
	console_log "$dir/console.log"
	wait_stopped 2400 || { doas vmctl stop -f "$name"; die "the install didn't finish in 40 minutes; see $dir/console.log"; }
	grep -q "CONGRATULATIONS" "$dir/console.log" || die "the install failed; see $dir/console.log"

	# First boot, then the marker the suite looks for.
	doas vmctl start -m "$memory" -L -i 2 -d "$dir/base.qcow2" "$name" || exit 1
	console_log "$dir/console.log"
	wait_ssh || exit 1
	marker | ssh_ 'cat > /etc/opf-conformance-disposable' || exit 1
	ssh_ 'halt -p' 2>/dev/null
	wait_stopped 300 || doas vmctl stop -f "$name"
	chmod a-w "$dir/base.qcow2"
	echo "$name is installed: $dir/base.qcow2"
}

vm_start() {
	[ -f "$dir/base.qcow2" ] || die "no clean guest for $release: run vm.sh -r $release setup"
	running && return 0
	[ -f "$dir/overlay.qcow2" ] || vmctl create -b "$dir/base.qcow2" "$dir/overlay.qcow2" || exit 1
	doas vmctl start -m "$memory" -L -i 2 -d "$dir/overlay.qcow2" -d "$dir/sets.img" "$name" || exit 1
	console_log "$dir/console.log"
	wait_ssh
}

vm_stop() {
	running || return 0
	ssh_ -O exit 2>/dev/null
	doas vmctl stop -w "$name" 2>/dev/null || doas vmctl stop -fw "$name"
}

# The suite runs detached in the guest, so a dropped SSH connection (it
# changes the guest's network) doesn't stop it; this polls until it's
# done.
vm_run() {
	[ $# -ge 1 ] || die "run needs a directory"
	rdir=$(cd "$1" && pwd) || exit 1
	[ -x "$rdir/in/conformance.test" ] || die "no $rdir/in/conformance.test"
	vm_stop
	rm -f "$dir/overlay.qcow2"
	: > "$dir/console.log"
	vm_start || exit 1
	echo "Copying the suite into $name ($(guest))"
	ssh_ 'rm -rf /root/conformance && mkdir -p /root/conformance/src' || exit 1
	(cd "$rdir/in" && tar -cf - .) | ssh_ 'tar -xpf - -C /root/conformance' || exit 1
	if [ -f "$rdir/in/source-dirs" ]; then
		(cd "$dir/src" && tar -cf - $(grep -v '^#' "$rdir/in/source-dirs")) |
		    ssh_ 'tar -xpf - -C /root/conformance/src' || exit 1
	fi
	ssh_ "cd /root/conformance && nohup env \
	    OPF_CONFORMANCE_DISPOSABLE=I-WILL-LOSE-THIS-SYSTEM \
	    OPF_CONFORMANCE_SRC=/root/conformance/src \
	    OPF_CONFORMANCE_OUT=/root/conformance/out \
	    OPF_CONFORMANCE_OPF=/root/conformance/opf \
	    ksh -c './conformance.test -test.v -test.timeout 60m $(cat args 2>/dev/null) > test.log 2>&1; echo \$? > status' \
	    > /dev/null 2>&1 &" || exit 1
	echo "The suite is running; its output is copied to $rdir/test.log"
	i=0 status=
	while :; do
		sleep 10; i=$((i + 10))
		ssh_ 'cat /root/conformance/test.log' > "$rdir/test.log.part" 2>/dev/null &&
		    mv "$rdir/test.log.part" "$rdir/test.log"
		status=$(ssh_ 'cat /root/conformance/status 2>/dev/null')
		[ -n "$status" ] && break
		[ $i -ge 4200 ] && { echo "no result after 70 minutes" >&2; status=124; break; }
	done
	rm -rf "$rdir/out"
	ssh_ 'cd /root/conformance && tar -cf - out' | tar -xf - -C "$rdir"
	cp "$dir/console.log" "$rdir/console.log"
	if $keep; then
		echo "Left $name running: vm.sh -r $release ssh"
	else
		vm_stop
		rm -f "$dir/overlay.qcow2"
	fi
	echo "The suite exited with status $status"
	return "$status"
}

case $cmd in
setup)	vm_setup ;;
run)	vm_run "$@" ;;
start)	vm_start ;;
stop)	vm_stop ;;
ssh)	ssh_ "$@" ;;
console) t=$(row | awk '{print $6}'); [ -n "$t" ] || die "$name isn't running"; doas vmctl console "$name" ;;
status)	doas vmctl status "$name" ;;
destroy) vm_stop; rm -rf "$dir/overlay.qcow2" "$dir/ssh-"* ;;
*)	die "unknown command $cmd" ;;
esac
