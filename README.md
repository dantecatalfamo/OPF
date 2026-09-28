# OPF

A web UI that turns OpenBSD into a firewall appliance while leaving the
system as it is. The configuration files in `/etc` are the only state:
OPF edits them, validates them with the base system's own tools, and
activates them with `pfctl`, `rcctl` and friends. Anything done over SSH
by hand shows up in the UI and the other way around.

## Web interface

The appliance UI lives in `ui/` (React, Mantine, TypeScript). For now
it runs on sample data from `ui/src/model/`:

```sh
make mock              # UI on http://localhost:5173 with a mock backend
cd ui && npm run build:preview  # single-file build in ui/dist-preview/
```

`make mock` runs `opf -mock` and the Vite dev server together. The mock
backend is the real Go generators, pf parser and staging engine,
started from the sample model in `ui/src/model/sample-model.json`.
It keeps its files in a scratch directory (printed at startup), logs
the commands it would run instead of running them, has no
authentication, and only listens on loopback. Vite proxies `/api` to
it on 127.0.0.1:18080; the staged changes are also visible at
http://127.0.0.1:18080/changes.

The sample model is shared by the UI and the Go tests, which check it
decodes into the Go model without losing anything, so a field added on
one side only fails the build.

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

## Processes

OPF runs as two processes, like the OpenBSD base daemons:

- The **parent** stays root. It owns the staging area and history, runs
  every check and apply command, and holds the confirmation timers. It
  never parses HTTP. On OpenBSD it pledges `stdio rpath wpath cpath
  fattr chown proc exec id` and unveils only the directories of the
  managed files, its state directory and the command directories.
- The **web process** is the same binary re-executed as `_opf`. It
  serves HTTP on a socket the parent opened, can't see the filesystem
  at all (`unveil`) and pledges `stdio rpath inet`. It reaches the
  parent through a fixed set of calls over a socketpair
  (`internal/privsep`), and names files rather than passing paths or
  commands, so it can't choose what is run or written.

Timers live in the parent, so an unconfirmed commit is reverted even if
the web process crashes; the parent restarts it. Stopping OPF reverts
an unconfirmed commit too.

## Installing

```sh
useradd -s /sbin/nologin -d /var/empty -L daemon -c "OPF web" _opf
install -m 555 opf /usr/local/sbin/opf
install -m 555 etc/rc.d/opf /etc/rc.d/opf
rcctl enable opf
rcctl start opf
```

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
localhost only; reach it with `ssh -L 8080:127.0.0.1:8080`.

Planned next:

- Login against system accounts (`auth_userokay(3)`) and TLS
- `hostname.if(5)` files, applied with `sh /etc/netstart <if>`
- Service management (`rcctl`), with enable/disable staged through
  `rc.conf.local`
- Monitoring pages (pf states and rules, interfaces, WireGuard) ported
  from `legacy/`

`legacy/` holds the original React + Go dashboard for reference while
its parsers are ported.
