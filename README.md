# OPF

A web UI that turns OpenBSD into a firewall appliance while leaving the
system as it is. The configuration files in `/etc` are the only state:
OPF edits them, validates them with the base system's own tools, and
activates them with `pfctl`, `rcctl` and friends. Anything done over SSH
by hand shows up in the UI and the other way around.

## How changes work

1. **Stage.** Edits are saved under `/var/opf/candidate/`, mirroring
   their real paths. Nothing live changes.
2. **Review.** The Changes page shows a diff of each staged file against
   the live one.
3. **Commit.** Every staged file is checked with its daemon's own
   validator (`pfctl -nf`, `dhcpd -n`, `unbound-checkconf`, `sshd -t`,
   ...). If any check fails nothing is touched. Otherwise the old and
   new versions are saved to `/var/opf/history/<id>/` and the files are
   applied in order.
4. **Confirm.** Files that could cut off your access (currently
   `pf.conf`) are loaded from the staged copy *without* being written
   to `/etc`. Unless the commit is confirmed within the timeout (60s by
   default) the live file is loaded again. Since `/etc/pf.conf` is only
   written after confirmation, a reboot also reverts it.

If any apply step fails the whole commit is reverted and the changes
stay staged so they can be fixed. If a live file changes on disk after
it was staged, committing is refused rather than silently overwriting
the hand edit. Rolling back is staging an old version from the History
page and committing it like any other change.

The managed files and how to check and apply each one are listed in
`internal/config/registry.go`.

## Development

Requires Go 1.25+.

```sh
make test
make dev        # http://127.0.0.1:8080, using a scratch copy of dev/seed
make dev-reset  # throw away the scratch copy
```

`make dev` runs with `-dry`, which logs commands such as `pfctl` and
`rcctl` instead of running them, and `-root`, which prefixes every
managed path so nothing outside `dev/run` is touched.

## Status

Early rewrite. **There is no authentication yet**, so OPF listens on
localhost only; reach it with `ssh -L 8080:127.0.0.1:8080`. It must
currently run as root.

Planned next:

- Privilege separation: an unprivileged web process talking to a small
  root helper, with `pledge(2)`/`unveil(2)`
- Login against system accounts (`auth_userokay(3)`) and TLS
- `hostname.if(5)` files, applied with `sh /etc/netstart <if>`
- Service management (`rcctl`), with enable/disable staged through
  `rc.conf.local`
- Monitoring pages (pf states and rules, interfaces, WireGuard) ported
  from `legacy/`

`legacy/` holds the original React + Go dashboard for reference while
its parsers are ported.
