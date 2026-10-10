#!/bin/sh
#
# Runs OPF's OpenBSD conformance suite on a disposable vmd guest.
#
# ######################################################################
# #                                                                    #
# #  WARNING: THE CONFORMANCE SUITE DESTROYS THE SYSTEM IT RUNS ON.    #
# #                                                                    #
# #  It runs only inside the throwaway guest that vm.sh makes on the   #
# #  OpenBSD host given here, never on the host itself. The guest's    #
# #  disk is discarded after every run.                                #
# #                                                                    #
# ######################################################################
#
#   scripts/conformance/run.sh [-r release] [-k] host setup
#	Install the clean guest for a release on host (once per release).
#   scripts/conformance/run.sh [-r release] [-k] host [test flags...]
#	Build the suite for OpenBSD, run it in a fresh copy of the guest,
#	and copy what it captured into
#	internal/conformance/testdata/openbsd-<release>/captures. Test flags
#	go to the test binary, e.g. -test.run 'TestBase|TestSource'.
#	-k leaves the guest running afterwards.
#
# host is an OpenBSD machine with vmd where you can ssh and use doas,
# such as openbsd-dev. The release defaults to the host's own.

set -eu

release= keep=
while getopts r:k o; do
	case $o in
	r) release=$OPTARG ;;
	k) keep=-k ;;
	*) sed -n '/^#   scripts/,/^# host/p' "$0" >&2; exit 1 ;;
	esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] || { sed -n '/^#   scripts/,/^# host/p' "$0" >&2; exit 1; }
host=$1; shift

root=$(cd "$(dirname "$0")/../.." && pwd)
[ -n "$release" ] || release=$(ssh "$host" sysctl -n kern.osrelease)
remote=opf-conformance

ssh "$host" "mkdir -p $remote"
scp -q "$root/scripts/conformance/vm.sh" "$host:$remote/vm.sh"

if [ "${1:-}" = setup ]; then
	exec ssh "$host" "ksh $remote/vm.sh -r $release setup"
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/opf-conformance.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir "$work/in"
echo "Building the suite for OpenBSD"
(cd "$root" &&
	GOOS=openbsd GOARCH=amd64 go test -c -o "$work/in/conformance.test" ./internal/conformance &&
	GOOS=openbsd GOARCH=amd64 go build -o "$work/in/opf" ./cmd/opf)
cp "$root/etc/rc.d/opf" "$work/in/rc.d-opf"
go run "$root/internal/conformance/sourcedirs" > "$work/in/source-dirs"
printf '%s\n' "$*" > "$work/in/args"

run=runs/$(date +%Y%m%d-%H%M%S)
ssh "$host" "mkdir -p $remote/$run"
(cd "$work" && tar -cf - in) | ssh "$host" "tar -xf - -C $remote/$run"
status=0
ssh "$host" "ksh $remote/vm.sh -r $release $keep run $remote/$run" || status=$?

dest=$root/internal/conformance/testdata/openbsd-$release
mkdir -p "$dest"
scp -q "$host:$remote/$run/test.log" "$host:$remote/$run/console.log" "$dest/" 2>/dev/null || :
if ssh "$host" "test -d $remote/$run/out/captures"; then
	rm -rf "$dest/captures"
	ssh "$host" "cd $remote/$run/out && tar -cf - captures" | tar -xf - -C "$dest"
	echo "Captures: $dest/captures (review the diff before committing)"
fi
echo "Log: $dest/test.log"
exit $status
