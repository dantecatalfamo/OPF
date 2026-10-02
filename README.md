# OPF

A web UI that turns OpenBSD into a firewall appliance while leaving the
system as it is. One model file, `/var/opf/config.json`, describes the
configuration; OPF generates every OpenBSD file from it (`pf.conf`,
`hostname.if`, `dhcpd.conf`, `unbound.conf`, …), validates them with the
base system's own tools, and activates them with `pfctl`, `rcctl` and
friends. Files edited by hand over SSH are noticed, and never
overwritten without asking.

## Web interface

The appliance UI lives in `ui/` (React, Mantine, TypeScript) and talks
to the JSON API described in [docs/api.md](docs/api.md). The dashboard
and diagnostics pages still show sample data from `ui/src/model/live.ts`.

```sh
make mock              # UI on http://localhost:5173 with a mock backend
cd ui && npm run build:preview  # single-file build in ui/dist-preview/,
                                # with an in-browser stand-in for the API
```

`make mock` runs `opf -mock` and the Vite dev server together. The mock
backend is the real Go generators, pf parser and staging engine,
started from the sample model in `ui/src/model/sample-model.json`.
It keeps its files in a scratch directory (printed at startup), logs
the commands it would run instead of running them, has no
authentication, and only listens on loopback. Every file it stages,
installs, restores or removes is logged with the path it would have on
the real system and where it actually went:

```
file: stage    /etc/hostname.vlan30 -> <scratch>/state/candidate/etc/hostname.vlan30 (new file)
file: install  /etc/hostname.vlan30 -> <scratch>/root/etc/hostname.vlan30 (commit …, new file, mode 0640)
file: restore  /var/unbound/etc/unbound.conf -> <scratch>/root/var/unbound/etc/unbound.conf (reverting commit …)
```

The operations on the system's files are `stage`, `unstage`,
`install`, `restore` and `remove`. OPF's own bookkeeping is logged too:
`check` (temporary copy for a validator), `index` (the staging index),
`snapshot` (a commit's restore point and contents), `record` (a
commit's history entry and status) and `clear` (staged copies a commit
has used), so `grep -v` can hide it.

Vite proxies `/api` to the mock on 127.0.0.1:18080, so staging,
committing, confirming, reverting and restoring all go through the real
engine. The confirm window is 60 s; `opf -mock -confirm-timeout 15s`
shortens it.

The sample model is shared by the UI and the Go tests, which check it
decodes into the Go model without losing anything, so a field added on
one side only fails the build.

## How changes work

1. **Stage.** The UI sends the edited model. The root process
   validates every field, generates every file, and saves the model and
   the files that changed under `/var/opf/candidate/`, mirroring their
   real paths. Nothing live changes.
2. **Review.** The review dialog shows the changes in words and a diff
   of each file, and says whether confirmation will be needed.
3. **Commit.** Every staged file is checked with its daemon's own
   validator (`pfctl -nf`, `dhcpd -n`, `unbound-checkconf`, `sshd -t`,
   ...). If any check fails nothing is touched. Otherwise the old and
   new versions are saved to `/var/opf/history/<id>/` and the files are
   applied in order.
4. **Confirm.** A commit that changes a file that could cut off your
   access (`pf.conf`, or an interface's `hostname.if`) waits for
   confirmation, and unless it's confirmed within the timeout (60s by
   default) everything it changed is put back. `pf.conf` is loaded from
   the staged copy *without* being written to `/etc`, so a reboot also
   reverts it. `netstart` only reads `/etc`, so `hostname.if` files are
   installed straight away; after a reboot during the wait OPF reverts
   them when it starts.

The model is committed together with the files generated from it, so
they can't disagree. If any apply step fails, the whole commit is
reverted and the changes stay staged so they can be fixed. A file that
was edited by hand is only replaced when the user says so, and if a
live file changes after it was staged, committing is refused. Undoing a
commit from Change history loads the model from before it as pending
edits, to review and commit like any other change.

The managed files and how to check and apply each one are listed in
`internal/config/registry.go`.

## DHCP names in DNS

With "Add other DHCP devices by name" on, the root process watches
`/var/db/dhcpd.leases` and gives each client the name it asked for, as
`name.<domain>`, through `unbound-control local_data` (the generated
`unbound.conf` then has a control socket only root can use). These
records live in unbound at runtime and aren't part of the configuration
or its history; they're re-added within 15 s whenever unbound reloads.
A client picks its own name, so it's only registered if it's a single
valid label, isn't used by the configuration (the router, reservations,
host overrides, `wpad`, `isatap`, `localhost`), isn't asked for by
another client too, and the address is in a DHCP range. See
`internal/leases`.

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
  (`internal/privsep`) that take a model or a commit id, never paths
  or commands. The parent validates the model and generates the files
  itself, so the web process can't choose what is run or written.

Timers live in the parent, so an unconfirmed commit is reverted even if
the web process crashes; the parent restarts it. Stopping OPF reverts
an unconfirmed commit too.

## Installing

`make build` (or `make openbsd` to cross-compile) builds the UI and
embeds it in the binary, so the one file is the whole application.
Plain `go build` leaves the UI out and serves only the API.

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
make dev        # API on http://127.0.0.1:8080, using a scratch copy of dev/seed
make dev-reset  # throw away the scratch copy
```

`make dev` runs the real two-process server with `-dry`, which logs
commands such as `pfctl` and `rcctl` instead of running them, and
`-root`, which prefixes every managed path so nothing outside `dev/run`
is touched. It's built without the UI (serving only the API) and
starts without a model; `make mock` is the way to work on the UI.

## Status

Early rewrite. **There is no authentication yet**, so OPF listens on
localhost only; reach it with `ssh -L 8080:127.0.0.1:8080`.

Planned next:

- Login against system accounts (`auth_userokay(3)`) and TLS
- Importing an existing system's configuration into the model
- Service management (`rcctl`), with enable/disable staged through
  `rc.conf.local`
- Monitoring pages (pf states and rules, interfaces, WireGuard) ported
  from `legacy/`

`legacy/` holds the original React + Go dashboard for reference while
its parsers are ported.
