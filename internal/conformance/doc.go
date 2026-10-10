// Package conformance checks every assumption OPF makes about OpenBSD,
// so that a new release that changes one, however slightly, is caught
// before OPF is released for it.
//
// ######################################################################
// #                                                                    #
// #  WARNING: THE SUITE DESTROYS THE SYSTEM IT RUNS ON.                #
// #                                                                    #
// #  The on-OpenBSD tests take total control of the machine: they      #
// #  rewrite pf, network interfaces, routes, services, users, groups   #
// #  and files under /etc and /var, and may cut the machine off the    #
// #  network. Run them only on a disposable instance of OpenBSD made   #
// #  for them, which scripts/conformance/vm.sh makes and throws away.  #
// #  They refuse to start unless the environment has                  #
// #  OPF_CONFORMANCE_DISPOSABLE=I-WILL-LOSE-THIS-SYSTEM and the        #
// #  machine has /etc/opf-conformance-disposable.                      #
// #                                                                    #
// ######################################################################
//
// It has two halves.
//
// The registry (registry.go and the files beside it) declares every
// command OPF runs, with the arguments it passes, every file and
// directory it relies on, the names and limits it takes from OpenBSD,
// and the parser for each kind of output. The ordinary test suite
// (scan_test.go, on any platform) reads OPF's source and fails when
// OPF runs a command, passes a flag, parses output or writes a file
// the registry doesn't declare, and when a declaration has no check on
// OpenBSD. A new feature that relies on something new about OpenBSD
// can't pass the tests until it's declared here and checked there.
//
// The suite (the files built only for OpenBSD) checks each declaration
// against a real system: that each program is in the base system and
// takes the arguments OPF passes; that each command's output still has
// exactly the fields, keys and line shapes OPF's parsers know, so a new,
// renamed or missing one fails instead of being skipped silently; that
// every file OPF generates passes the daemon's own check; that the
// limits and names OPF hard-codes match the release's headers and
// source; and that what OPF does to the system has the effect it
// expects. It saves every command's output in OPF_CONFORMANCE_OUT, and
// scripts/conformance/run.sh copies it to testdata/openbsd-<release>/,
// where the ordinary suite runs the same checks over it on any machine.
//
// For a new release: scripts/conformance/run.sh -r <release> setup and
// then run; read every failure, fix OPF, and commit the new captures.
// See TODO.md › Testing and verification › Conformance.
package conformance
