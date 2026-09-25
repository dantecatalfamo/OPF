# TODO

Things known to need more work, roughly by priority. Not a roadmap of
new features; see "Planned next" in the README for those.

## Direction change (appliance UI)

Decided: the user never edits config files. One model file
(`/var/opf/config.json`) is the source of truth and every OpenBSD file
is generated from it; the UI is React + Mantine (`ui/`), served by the
Go binary. The staging/commit/confirm/history engine stays, with
generated files as its outputs.

- [ ] Go: config model types matching `ui/src/model/types.ts`, and
      generators for pf.conf, hostname.if, dhcpd.conf, unbound.conf,
      myname and ntpd.conf (`ui/src/model/generate.ts` is the draft).
      Golden-file tests for each generator.
- [ ] Stage the model instead of raw files; Changes becomes a list of
      readable change summaries, with generated-file diffs as detail.
- [ ] JSON API for the UI, replacing the mock store in
      `ui/src/model/store.tsx`; embed `ui/dist` in the binary. Remove the
      htmx templates in `internal/web` once the API exists.
- [ ] Hand-edited generated files: detect and warn before overwriting.
- [ ] First-boot setup wizard (WAN, LAN, admin password).
- [ ] Import an existing hand-written system into the model, or state
      clearly that OPF takes over a fresh install.
- [ ] Live data (interface stats, states, leases, WireGuard peers, pf
      log) from the parsers in `legacy/`.

### pf coverage still missing from the UI

Reachable today only through raw rules or custom pf blocks:

- [ ] Traffic shaping: `queue` definitions (bandwidth, min/max, flows)
      and assigning rules to queues.
- [ ] Anchors, including a managed anchor per service.
- [ ] Multi-WAN: gateway groups (`route-to` pools with failover driven
      by gateway health), and `route-to` on a DHCP gateway, which the
      generator currently resolves to the live address.
- [ ] `binat-to` (1:1 NAT), `af-to` (NAT64), `divert-to`.
- [ ] CARP and pfsync for high availability.
- [ ] Parse pasted pf rules back into guided form where possible.
- [ ] A packet tester: "what happens to tcp 192.168.20.5 → 192.168.1.20:445?"
      evaluated against the ruleset.
- [ ] IPv6: interfaces, NAT and rules are IPv4-first today.

## Verify on real OpenBSD

Everything below has only run on macOS, where pledge and unveil are
skipped and the web process isn't dropped to another user.

- [ ] Run as root in `-dry` mode with scratch `-root`/`-state` to
      exercise pledge, unveil and the privilege drop.
- [ ] Parent pledge: confirm `stdio rpath wpath cpath fattr chown proc
      exec id` covers fork, setuid in the child before exec, socketpair,
      atomic writes with chown, and running every check/apply command.
- [ ] Web process pledge `stdio rpath inet`: check nothing in net/http
      or the Go runtime needs more (a violation kills the process).
- [ ] Unveil paths exist on a stock install; `/usr/local/*` and
      `/var/unbound/etc` may be missing.
- [ ] `os.Executable` returns the right path when started from rc.d.
- [ ] rc.d script: `pexp` matches both processes; `rcctl stop` leaves
      nothing behind and reverts an unconfirmed commit.
- [ ] Each validator works on a file outside its usual location:
      `unbound-checkconf` (chroot-relative includes), `pfctl -nf`
      (relative `include`/`table ... file`), `dhcpd -n -c`,
      `httpd -n -f`, `ntpd -n -f`, `sshd -t -f` (host keys, `Include`).
- [ ] Real commits, with and without confirmation, on a VM that can be
      locked out safely.

## Security

- [ ] **No authentication.** It has to be enforced in the parent, not
      the web process: a compromised web process can currently call
      Stage and Commit directly. Likely `auth_userokay(3)` (cgo) plus
      sessions checked at the RPC boundary.
- [ ] TLS.
- [ ] Anyone who can commit can get root: rc.conf.local is sourced by
      rc(8), and sshd_config/httpd.conf are powerful. That comes with
      the product, but it's why auth and audit logging matter.
- [ ] Limit request and RPC message sizes (staged contents are
      unbounded; gob decoding in the root process should be capped).
- [ ] Record who made each commit in history once there are users.

## Staging and commit

- [ ] While a commit waits for confirmation the editor shows the live
      file and Stage fails with an error. The UI should show the pending
      state and disable editing instead.
- [ ] If OPF is killed with SIGKILL (or crashes) during the confirm
      window, the staged pf rules stay loaded until reboot or the next
      start. `Recover` only runs at startup.
- [ ] `hostname.if(5)`: file names aren't known in advance (need globs
      in the registry), and `sh /etc/netstart <if>` can't load from
      another path. Confirmation will have to install, then restore a
      backup on timeout, so the "reboot also reverts" guarantee is lost.
      Needs a design. Interfaces must be applied before pf.
- [ ] rc.conf.local is only checked with `sh -n`; nothing is applied.
      Service enable/disable/flags should be staged through it and
      reconciled with rcctl on commit.
- [ ] Decide whether a service that fails to reload or restart should
      revert the whole commit (it does now).
- [ ] Deleting a managed file isn't supported.
- [ ] One admin assumed: two browsers staging the same file overwrite
      each other silently. Consider tracking the base hash in the form.
- [ ] History is never pruned.
- [ ] Newly created parent directories get 0755; check what each managed
      path expects.

## Code

- [ ] Port monitoring parsers from `legacy/server` (pf states, rules,
      info, interfaces, `ifconfig wg`, `rcctl`) with golden tests on
      captured output; they index fields by position and crash on
      unexpected input. Delete `legacy/` afterwards.
- [ ] `privsep.Client.Pending` drops RPC errors; the banner shows nothing
      if the parent is unreachable.
- [ ] `golang.org/x/sys` is pinned to v0.44.0 to keep Go 1.25; revisit
      when OpenBSD packages Go 1.26.
- [ ] CI running `make test`, plus GOOS=openbsd vet/build.
