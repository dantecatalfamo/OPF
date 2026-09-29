# TODO

Known work on OPF, by area. The principles and how we work come first,
then where things stand and what's next, then open work area by area,
then how it's tested and verified. Finished work is listed at the end.
Each item appears once; other sections point to it.

## Principles

**Correctness and security are the top priorities.** OPF manages a
firewall—mistakes can lock out administrators, expose networks, or
break connectivity. Every feature must be:

1. **Correct first.** Parsers must handle all valid input and fail
   gracefully on unexpected input, never crash or produce wrong output.
   Generators must produce valid config files for every valid model.
   Golden-file tests and property-based tests where practical.

2. **Secure by design.** Privilege separation, input validation, no
   shell injection, no path traversal. The web process cannot choose
   what commands run or what paths are written. Auth and audit logging
   before any production use.

3. **Single-binary deployment.** The entire application—Go backend,
   React UI, static assets—must be embedded in one executable. No
   external files, no runtime dependencies beyond base OpenBSD. Copy
   the binary, run it. This simplifies installation, updates, and
   reduces attack surface. Use `go:embed` for the built `ui/dist`.

4. **Drop-in adoption.** It must be possible to install OPF on an
   existing, already-configured OpenBSD system and have it work
   immediately. This means:
   - Import existing configs (`pf.conf`, `dhcpd.conf`, `hostname.if`,
     etc.) into the OPF model on first run or via an import command.
   - Parsers for config files (the reverse of generators) that handle
     real-world hand-written configs, not just OPF-generated ones.
   - Preserve existing behavior exactly—importing must not change how
     the system operates until the admin makes an explicit change.
   - Handle configs that use features OPF doesn't yet support: warn
     the admin, preserve the raw config, don't silently drop rules.
   - First-run wizard that detects existing configs and offers import.

5. **Validated against OpenBSD.** Every parser, generator, and system
   integration must be validated against the latest OpenBSD documentation
   and source code. This means:
   - Parsers must handle output formats documented in the relevant man
     pages (`pfctl(8)`, `ifconfig(8)`, `rcctl(8)`, etc.) and tested
     against actual command output from current OpenBSD.
   - Generators must produce config files that conform to the file format
     man pages (`pf.conf(5)`, `hostname.if(5)`, `dhcpd.conf(5)`, etc.)
     and pass validation by the target daemon.
   - When OpenBSD releases a new version, review the relevant man pages
     and source (cvsweb.openbsd.org) for changes. Update parsers and
     generators, add new test fixtures, and document version-specific
     behavior.
   - Link to authoritative sources in code comments where format details
     are non-obvious.

## How we work

The goal is a polished, OPNsense-style appliance: the user should never
need to write a config file or know how OpenBSD works, yet keeps pf's
full power (raw pf rules, custom pf blocks, the full rule grammar and
interface modifiers). OPF runs as root on a firewall, so a bug can lock
the admin out, open a network, or hand an attacker root.

What follows is the approach behind the code: how it's organized, the
rules it holds to, and how changes are made and tested. See README.md
for the overview and docs/api.md for the API.

### Priorities

The principles above come before features and before backwards
compatibility.

- If a change is only safe with a guard, build the guard in the same
  change. Don't leave it as a note.
- When a feature only looks like it does something (a setting nothing
  enforces, a label the firewall ignores), either make it real or say
  plainly what it does.
- Don't keep old formats or APIs working for their own sake: no
  deployments exist yet. But never let a renamed field change its
  meaning silently. Pick a new name, so an old model fails to load
  loudly.

### Architecture

- **One model is the source of truth**: `/var/opf/config.json`,
  `pf.Model` in `internal/pf/model.go`, `Model` in
  `ui/src/model/types.ts`. Every OpenBSD file is generated from it.
  Nothing is edited in place.
- **Commit engine** (`internal/config`):
  - Stage → check with each daemon's own validator → commit → confirm
    within a deadline, or auto-revert → history.
  - The model is a managed file, so it's staged and committed
    atomically with the files generated from it.
  - `pf.conf` loads from the staged copy and is only installed on
    confirm.
  - The registry (`registry.go`) lists every managed file with its
    check and apply commands.
- **Two processes** (`internal/privsep`):
  - The root parent (`internal/appliance.Manager`) owns the model and
    the engine.
  - The web child runs as `_opf` under pledge/unveil. It speaks a
    fixed RPC that takes models and commit ids, never paths or
    commands.
  - The parent validates everything it's given.
- **The UI is embedded in the binary** (package `ui`, tag `embedui`,
  set by `make build`) and served by the web process alongside the API.
- **JSON API** (`internal/web`, documented in `docs/api.md`). Keep
  `docs/api.md` in step with every endpoint change.
  - Requests: strict decoding, JSON only, 4 MiB cap, cross-origin
    writes refused.
  - Errors are `appliance.Error` codes mapped to HTTP statuses.
    Internal errors reach clients only as "internal error".
- **pf package**: model, generators for every file, a tokenizer and
  parser (pf text back to guided rules), and `Validate`.
- **Runtime helpers** in the parent, such as `internal/leases`, which
  puts DHCP client names into unbound. They go through `run.Runner` so
  `-dry` and the mock can log them instead.

### Rules we hold to

**Input and validation**
- Everything from the web process, and anything a device on the
  network chooses (DHCP hostnames, the leases file), is hostile.
- Validate every model field in the parent (`pf.Validate`) before
  generating anything, and again on commit. Raw pf rules are the only
  free text, and even they must be a single line.
- Take limits from OpenBSD's source and cite them: label 63 bytes,
  table names 31, `IFNAMSIZ` 16. Interface ids can't be pf keywords
  (`keywords_gen.go`, generated from `parse.y`).
- Quote for the reader of the file: `quote()` escapes only `"` because
  that's all pf's lexer understands. Watch for line continuations
  (pf joins a line ending in `\`, even in comments) and shell reads
  (`netstart`).
- Show device-chosen text sanitized (non-printable characters and bidi
  overrides become U+FFFD, lengths capped) and never as markup.
- Build hostile test strings (bidi overrides, control characters) from
  escapes, never as literal characters in source.

**The parser never guesses.** If the guided form can't hold a rule
exactly, it stays raw with its original source text. Unknown options,
user labels, and anything else the form can't represent keep the rule
raw. `FuzzParseRuleRoundTrip` checks that parse → generate → parse
gives back the same rule.

**pf labels are ids, not descriptions.** Generated rules are labelled
`opf:<kind>:<id>` (rule, forward, nat, auto-nat, builtin,
split-tunnel). Descriptions are `#` comments above the rules. IDs that
end up in labels are at most 32 characters of `[A-Za-z0-9_-]`. Tables
OPF makes use reserved names (`opf_*`, `private`, `bogons`).

**One generator, in Go.** `ui/src/model/generate.ts` duplicates the Go
generators for the offline preview build and is to be deleted (see the
roadmap). Until then, keep it in step with every Go generator change.
- `ui/src/model/sample-model.json` is shared by the UI, the mock and
  the Go tests, which decode it strictly and validate it. Keep it
  valid.
- `ui/src/lib/localApi.ts` is the preview build's in-browser stand-in
  for the API and follows the server's rules.

**UI copy.** Say what a setting does in plain language: no OpenBSD
jargon, and no assumption that OPF runs in an office. Show consequences
before they happen: the review dialog gives changes in words, per-file
diffs, whether confirmation is needed, and the server's objections.

### Working on it

- **Go 1.25.** Run `make test` (vet plus `go test -race ./...`) and
  `GOOS=openbsd go vet ./...` before calling anything done. Fuzz
  parsers after changing them:
  `go test -run '^$' -fuzz <Target> -fuzztime 60s ./internal/<pkg>`.
- **UI**:
  - `cd ui && npx tsc`, `npm run build`, and `npm run build:preview`
    (the single-file offline build).
  - When a check is piped through `grep -v`, don't chain `&&` after it:
    `grep -v` exits 1 when there's nothing left to print.
- **`make mock`** runs `opf -mock` (the real engine on the sample
  model, in a scratch directory, commands logged, loopback only) on
  127.0.0.1:18080, plus Vite on 5173.
  - **The user runs this themselves.** Never kill processes on those
    ports, or anything else you didn't start.
  - For your own tests, run
    `opf -mock -listen 127.0.0.1:18081` and
    `OPF_API=http://127.0.0.1:18081 npx vite --port 5174 --strictPort`.
    Record the PIDs you start and stop exactly those. Never use broad
    `pkill`.
- **Test UI changes in a real browser.** `puppeteer-core` driving the
  installed Chrome, headless, with scripts kept in the scratchpad.
  Click through the actual flow (edit → review → apply → confirm) and
  check the files the mock wrote, not just that the page renders.
- **Nothing has run on real OpenBSD yet.** Things that need checking
  there go in "Verify on real OpenBSD" below. Ask before using the
  `openbsd-dev` SSH host.

### Git

- Commit in logical, self-contained commits that each build. Commit
  locally only; the user pushes. Don't rewrite pushed history.
- Commit messages:
  - A short imperative subject.
  - A body in plain prose explaining what was wrong or missing, what
    changed and why, including security reasoning and trade-offs.
  - No bullet dumps, no attribution trailers.
- When something is found but not fixed, add it to this file under
  the one section it belongs to, with enough detail to act on, and
  point to it from anywhere else it matters. When it's finished, move
  it to "Done" at the end with a line on what was done.

## Where things stand (2026-09-29)

- **Working and tested in Go:** the model is the source of truth and
  lives in the parent (`internal/appliance`). The web process sends a
  model over RPC; the parent validates it (`pf.Validate`), generates
  every file, and stages, commits, confirms and reverts the model and
  its files as one unit, with history. There's a JSON API
  (`internal/web`, `docs/api.md`) and privilege separation with
  pledge/unveil.
- **UI:** every page exists. Review, apply, confirm, revert, history and
  undo go through the API (`make mock` runs it against the real engine).
  Leases, lease names, the ARP table and the routing table are live; the
  rest of the dashboard and diagnostics still show sample data from
  `ui/src/model/live.ts`.
- **Missing:** authentication, importing an existing system.
- **Never run on OpenBSD.**

## Roadmap

In order. Each step's details are in the section it points to.

1. **One generator.** Delete `ui/src/model/generate.ts`; the UI gets
   generated files and the annotated ruleset from the API, and the
   offline preview build gets them from a stand-in. Keep the sample
   model as the shared fixture for Go tests and the mock.
2. **Authentication and TLS**, enforced in the parent (Security).
3. **Run on OpenBSD** (Verify on real OpenBSD). The `openbsd-dev` host
   in the SSH config is a candidate; ask before using it.
4. **Import** (Parser and import), then the first-run wizard.
5. **Live data** (Live data and monitoring).

## Commit engine and staging

- [ ] Deleting an interface leaves things that mention it without
      referring to it: a WAN rule that opened a deleted tunnel's port,
      and alias entries with its network. List them in the delete
      dialog too, and offer to remove them.
- [ ] Removing a physical port's `hostname.if` only takes the port down
      (it can't be destroyed); its addresses stay until a reboot.
      Nothing in the UI removes physical ports yet.
- [ ] **Confirm and auto-revert for `hostname.if` changes.** They're
      applied directly with `sh /etc/netstart <devs>`, which can't load a
      staged copy, so they get no confirmation: moving the LAN's address
      (onto a bridge, say) can lock the admin out with nothing to undo
      it. Install, then restore the old files and re-run netstart on
      timeout. That gives up pf.conf's "a reboot reverts it" guarantee,
      so decide what happens on a reboot during the window. Interfaces
      must still be applied before pf.
- [ ] If OPF is killed with SIGKILL (or crashes) during the confirm
      window, the staged pf rules stay loaded until reboot or the next
      start; `Recover` only runs at startup.
- [ ] Decide whether a service that fails to reload or restart should
      revert the whole commit (it does now).
- [ ] A second browser's staging replaces the first's staged model
      (there's one candidate). Fine for one admin; revisit with users.
- [ ] When the UI loads a model someone else staged, it lists the
      changes by section only ("Changed firewall settings"); the edit
      descriptions aren't stored with the staged model.
- [ ] History is never pruned.
- [ ] Newly created parent directories get 0755; check what each managed
      path expects.
- [ ] `mygate` is only read at boot, not applied on commit, and the
      generator skips it when the default gateway is DHCP (dhcpleased
      handles that case); check both behave as intended.
- [ ] No guard against two OPF instances running at once (file
      locking).
- [ ] Graceful shutdown: check that SIGTERM waits for pending operations
      and reverts an unconfirmed commit, and document it.
- [ ] Backup and restore: download `config.json`, and restore it (as a
      staged change, reviewed like any other) for disaster recovery or
      migration. The History page's backup buttons are placeholders.

## Models and generators

- [ ] **NAT exceptions skip outbound rules.** An outbound NAT rule with
      no translation ("don't translate this host") is written as
      `pass out quick` ahead of everything, so evaluation stops before a
      `nat-to` can apply, and also before any outbound user rule. pf has
      no `no nat` any more, so fixing it means keeping those addresses
      out of the NAT rules instead (a table of exceptions the automatic
      and manual `nat-to` rules exclude), then dropping the quick pass.
- [ ] pf features only reachable through raw rules or custom pf blocks:
      traffic shaping (`queue` definitions and assigning rules to them);
      anchors, including a managed anchor per service; `binat-to` (1:1
      NAT), `af-to` (NAT64) and `divert-to`.
- [ ] Multi-WAN: gateway groups (`route-to` pools with failover driven
      by gateway health; relayd or ifstated could drive it), and
      `route-to` on a DHCP gateway, which the generator resolves to the
      address it has at generation time.
- [ ] A packet tester: "what happens to tcp 192.168.20.5 →
      192.168.1.20:445?", evaluated against the ruleset.
- [ ] Anti-lockout ports (443, 22) are hard-coded; derive them from the
      web UI and sshd settings.
- [ ] NAT reflection is added on every inside interface; limit it to the
      ones that need it.
- [ ] Check whether reloading pf empties `persist` tables such as
      `<bruteforce>`; if so, save and restore their contents.
- [ ] URL-type alias tables need a refresh mechanism (scheduled or on
      demand) to re-fetch and reload the table files.
- [ ] **IPv6.** Interfaces, NAT and rules are IPv4-first:
      `automaticNat()` only emits `inet` rules, unbound's access-control
      list only has IPv4 networks, lease names are IPv4 only (DHCP and
      DNS), and `ui/src/lib/ip.ts` needs `isIPv6()`, IPv6 CIDR checks and
      IPv6 `network()`/`netmask()`.
- [ ] Golden tests for the generators other than pf.conf (Testing).

## Parser and import

Principle 4: install OPF on a configured system and change nothing
until the admin does.

- [ ] **Import:** parse existing `pf.conf` (`ParsePfConf`),
      `hostname.if`, `dhcpd.conf`, `unbound.conf` and so on into the
      model. Handle hand-written configs with comments, includes, macros
      and features OPF doesn't model, which stay raw. Tests in Testing.
- [ ] Build the model's interfaces first: rules naming devices
      (`on em0`) only become guided rules when the device is in the
      model; otherwise they stay raw.
- [ ] Reject invalid UTF-8 with a clear error. `encoding/json` replaces
      it with U+FFFD, so even raw rules would change when `config.json`
      is saved.
- [ ] Rules with their own label stay raw (the guided form's label is
      its id). Offer to turn those labels into descriptions.
- [ ] First-run wizard: detect existing configs and offer to import them;
      set up WAN, LAN and the admin password.
- [ ] Still raw: bare names or `name:0` that aren't model interfaces (pf
      treats them as interfaces only if one exists at load time, else as
      hostnames).
- [ ] Raw rules only have a label if their text has one, so their
      counters can't be matched to the model. Offer to add OPF's label
      when a raw rule has none.

## Interfaces

Today there are physical ports, VLANs and WireGuard tunnels, each one
`hostname.<dev>` file applied with `sh /etc/netstart <devs>`. Virtual
interfaces need, first:

- [ ] Confirm and auto-revert for interface changes (Commit engine).
- [ ] **Apply order by dependency.** netstart brings up the devices it's
      given in order, and OPF passes them in path order, so
      `hostname.bridge0` comes before its member `hostname.em1` (VLANs
      only work because em1 sorts before vlan20). Order parents and
      members before the interfaces built on them, and the reverse on
      removal.
- [ ] **An interface kind in the model** (physical, vlan, wireguard,
      bridge, aggr, carp, gre, pppoe, …) with per-kind settings,
      replacing the vlan and wireguard special cases. Validation:
      members exist, have no address, belong to one bridge or aggregate,
      no loops, valid device names (veb0, aggr0, carp1), and the pf
      macro names the interface that carries the address.

Types, roughly in order of usefulness:

- [ ] `veb` + `vport` bridges (bridging LAN ports). The address and pf
      filtering are on the vport, so the LAN macro follows it. The older
      `bridge(4)` is similar.
- [ ] `aggr` link aggregation: `trunkport` lines, members only `up`.
- [ ] `pppoe` WANs: credentials need secret storage (Security), and the
      default route goes through the PPPoE link instead of `mygate`.
- [ ] `carp` failover with `pfsync`: a shared password (secret storage),
      only useful with a second box. ifstated and sasyncd (Services)
      work alongside it.
- [ ] `gre`, `etherip`, `vxlan` tunnels: endpoints, and pf and routing
      like WireGuard.
- [ ] Niche: `tpmr`, `svlan`, `tap`.
- [ ] Live status for each type (members, link state, carp state) on the
      interface pages.

## WireGuard

- [ ] Editing a peer: only adding and removing exist.
- [ ] pf and routing per tunnel: site-to-site tunnels (routed networks,
      usually no NAT) and remote-access ones (clients NATed out) need
      different defaults for automatic NAT and generated rules. Today
      every tunnel's network gets automatic NAT.
- [ ] Private keys: `hostname.wgN` gets a placeholder `wgkey` today; one
      key per tunnel needs generating and storing (Security).
- [ ] Peer status per tunnel (Live data).

## DHCP and DNS

- [ ] **Naming a device yourself.** A device whose name is taken, or
      can't be made valid, gets no DNS name. Let the admin name a lease
      from the leases table, used instead of what the device asked for:
      trusted input, so nothing is guessed. Keyed by MAC like
      reservations, so it shares their weaknesses (MACs can be spoofed,
      and phones rotate private MACs per network or over time, which
      loses the name). Could be "Reserve and name" (a reservation, which
      also fixes the address) or a name-only mapping.
- [ ] **Decide what the hostname rewrite drops.** It drops non-ASCII
      letters and dots ("válid" → `vlid`, `files.evil.example` →
      `filesevilexample`), which can produce names nobody chose. The
      checks still run after the rewrite, so reserved and clashing names
      are refused either way. Refusing names with non-ASCII letters or
      dots, rather than rewriting them, is the alternative.
- [ ] `rewriteInvalidLeaseNames` is meant to be on by default, but a
      model that leaves it out has it off. Import and the first-run
      wizard must set it.
- [ ] Reserving an address from the leases table picks the lease's
      address, which is inside the dynamic range, so dhcpd can hand it to
      another device too. Offer a free address outside the range.
- [ ] No PTR records for leases or reservations: reverse lookups of DHCP
      clients fail.
- [ ] A commit reverted by the confirm timeout doesn't kick the lease
      watcher, so names are missing for up to 15 s after unbound
      reloads.
- [ ] `resolv.conf` isn't managed: OPF's own DNS client configuration
      (OpenBSD uses `resolv.conf.tail` with resolvd).

## Services

OpenBSD's own daemons, controlled with rcctl. Every service must be
fully configurable through OPF, so nobody has to SSH in and edit files:
a page for the common options, a way to reach every other option, raw
config lines as an escape hatch (the way raw pf rules are), a preview of
exactly what will be written, and validation with the daemon's own
checker (`httpd -n`, `smtpd -n`, `bgpd -n`, `ospfd -n`). Each daemon's
model gets structured fields where practical plus a field for extra
lines, all through the commit engine.

- [ ] **OPF owns all of `rc.conf.local`.** It's generated whole, so an
      existing system's lines (`pkg_scripts`, other daemons' flags) are
      flagged as changed outside OPF and replaced if the user agrees.
      Import should carry them into the model, and the Services page
      will need the file to hold every service it manages
      (`config.RcServices` and the generator grow together).
- [ ] **A Services page** listing every base daemon, grouped by
      category, with name, description, enabled and running, quick
      actions (start, stop, restart, enable, disable) and links to the
      services that have their own pages (dhcpd, unbound, pf already
      do). Needs `rcctl ls all`, `rcctl ls on`/`started`, `rcctl get`,
      and start/stop/enable/disable endpoints.
- [ ] A detail view per service: status, uptime, resource use, recent
      log entries, its rc.d settings (`rcctl get`: flags, user, rtable,
      timeout) and its configuration.
- [ ] Dependencies between services (dhcpd needs its interfaces up):
      warn when disabling something another service needs.
- [ ] Boot order: show and set rc.d(8) order where it matters.

Daemons, by how much an appliance needs them:

- [ ] **Core** (status and start/stop; most systems run them): sshd
      (sessions; listen addresses, port, root login), ntpd (sync status,
      offset, peers; servers, listen address, sensors), pflogd (log
      size; file, snaplen, interface), syslogd (remote destinations),
      cron (next jobs; later, managing jobs), dhcpleased and slaacd
      (leases and addresses obtained; managed per interface).
- [ ] **Worth their own pages:** httpd (captive portal, serving
      blocklists; virtual hosts, TLS, roots), rad (IPv6 router
      advertisements; prefixes, DNS, MTU), relayd (health checks, load
      balancing, relays; could drive multi-WAN), smtpd (alert emails;
      relay host, auth, aliases), snmpd (monitoring integration;
      communities, traps).
- [ ] **Advanced networking:** ospfd and ospf6d, bgpd (complex; may
      need raw config), iked (IKEv2 IPsec beside WireGuard), npppd
      (L2TP VPN server; PPPoE WANs are an interface type), ifstated
      (WAN failover, with carp), eigrpd, ripd.
- [ ] **Rarely needed** (show if enabled): nsd (authoritative DNS),
      tftpd and tftpproxy (PXE, firmware; TFTP through NAT), radiusd
      (802.1X, VPN auth), ldapd, ftpd and ftpproxy, isakmpd (legacy IKEv1;
      prefer iked), sasyncd (IPsec failover with carp), ldpd (MPLS),
      dvmrpd and mrouted (multicast), hostapd (Wi-Fi access point), lpd.

## Live data and monitoring

What the legacy server (`legacy/server/`) collected and the new UI
doesn't show yet. Each needs a parser for the command's output, an API
endpoint, sample data for other platforms, and the page. Write new
parsers rather than porting the legacy ones, which index fields by
position and crash on unexpected input: handle every valid output,
return errors on malformed input instead of panicking, and have
golden-file tests from several OpenBSD versions and fuzzing (Testing).
Delete `legacy/` once they're done.

Pattern (from the ARP and routing tables): parsers in
`internal/appliance/` beside `parseARPOutput` and `parseRoutingOutput`,
a `runtime.GOOS` check returning `sample*()` data elsewhere, commands
through the Manager's Runner, types in `ui/src/lib/api.ts` and sample
data in `ui/src/model/live.ts`. Consider batching related endpoints
(`/api/system/stats` for CPU, memory and load), polling at sensible
rates (5 s for stats, 30 s for logs), and later a WebSocket for pflog
and traffic.

System:

- [ ] CPU (`sysctl kern.cp_time`) → `GET /api/system/cpu`: dashboard
      meter (hard-coded 18% today) and history.
- [ ] Load average (`sysctl vm.loadavg`) → `GET /api/system/loadavg`:
      1, 5 and 15 minutes on the dashboard.
- [ ] Memory (vmstat, `sysctl hw.physmem`) → `GET /api/system/memory`:
      dashboard meter with active, free, wired and cached.
- [ ] Swap (`swapctl -l`) → `GET /api/system/swap`, when configured.
- [ ] Disks (`df -P`) → `GET /api/system/disks`: meter per mount, and a
      storage page; disk I/O (vmstat) → `GET /api/system/diskio`.
- [ ] Uptime (`sysctl kern.boottime`) → `GET /api/system/uptime`, on the
      dashboard and System › General.
- [ ] Hardware (`sysctl hw`, `sysctl hw.sensors`) →
      `GET /api/system/hardware` and `/sensors`: CPU model, RAM,
      temperatures, fans, voltages.
- [ ] Processes (`ps aux`) → `GET /api/system/processes`: a Diagnostics
      page with sorting and filtering.

Firewall:

- [ ] States (`pfctl -vv -s states`) → `GET /api/pf/states`: the
      Connections page (sample data today).
- [ ] Killing states (`pfctl -k`) → `POST /api/pf/kill`: by state id from
      the Connections page, by address or interface in bulk, and all of
      a rule's states with `-k label -k opf:rule:<id>`.
- [ ] Per-rule counters (`pfctl -s labels`, or `pfctl -vv -s rules`) →
      `GET /api/pf/labels`: evaluations, packets and bytes on the Rules
      page, matched to model rules by their labels.
- [ ] Per-rule history: counters polled and stored so they can be
      graphed over time.
- [ ] Per-client traffic: pf only keeps bytes per live connection (lost
      when it closes) and per interface. Options: periodic state polling
      aggregated by address, rule labels with accounting, or pflow(4)
      export to a collector.
- [ ] pf info (`pfctl -v -s info`) → `GET /api/pf/info`: the firewall
      dashboard tile (state table size, match rate, drops); interface
      stats (`pfctl -vv -s Interface`) and memory limits
      (`pfctl -s memory`).
- [ ] The firewall log (`tcpdump -n -e -ttt -r /var/log/pflog`) →
      `GET /api/logs/firewall`, with each entry's rule number mapped to
      the model rule through `pfctl -vvsr`'s labels (sample data today).

Network, VPN and logs:

- [ ] Interfaces (`netstat -in`, `ifconfig -a`) →
      `GET /api/network/interfaces`: packets, errors, collisions, link
      state, media, addresses and flags.
- [ ] Traffic rates (deltas of `netstat -i`): the dashboard chart
      (simulated today) and per-interface sparklines.
- [ ] WireGuard peer status (`ifconfig wgN` or `wg show`) →
      `GET /api/wireguard/status`: handshake and bytes per peer, keyed by
      tunnel and peer.
- [ ] System logs → `GET /api/logs/{dmesg,messages,daemon,authlog}`: a
      Diagnostics › System logs page with a tab each.
- [ ] Diagnostics tools: ping, traceroute, DNS lookup.

## UI

- [ ] Responsive design: usable from phones to large monitors, since
      admins may need to check status or make an urgent change from a
      phone. Test at phone (375px), tablet (768px), laptop (1024px) and
      desktop (1440px+) widths; tables scroll or become cards; forms
      stack; touch targets at least 44px; apply, confirm and revert work
      on a phone; the dashboard stays useful. The navigation already
      collapses to a menu.
- [ ] Placeholders that need real actions: change password, syspatch,
      backup download and restore (Commit engine).
- [ ] Split the 1.6 MB bundle by page.

## Security

- [ ] **Authentication**, enforced in the parent, not the web process: a
      compromised web process can call Stage and Commit today. Likely
      `auth_userokay(3)` (cgo) with sessions checked at the RPC
      boundary, and a sign-in page.
- [ ] TLS.
- [ ] Anyone who can commit can get root: rc.conf.local is sourced by
      rc(8), and sshd_config and httpd.conf are powerful. That comes with
      the product, but it's why authentication and audit logging matter.
- [ ] Record who made each commit once there are users.
- [ ] **Secret storage** for WireGuard private keys (one per tunnel),
      PPPoE credentials and CARP passwords: kept out of the model and
      its history, readable only by root, and generated where possible.

## Testing and verification

Regressions in a firewall can silently break network security, so
tests are part of every feature, not an extra.

Parsers of command output:

- [ ] Golden-file tests against real output from several OpenBSD
      versions (7.4 onwards), with edge cases: empty output, one entry,
      the largest realistic size, Unicode in hostnames and descriptions,
      IPv6, unusual but valid formats.
- [ ] Error paths (truncated output, garbage, partial lines, binary
      data) return errors, never panic; fuzz every parser.
- [ ] Every bug's input becomes a permanent test case before the fix.

Generators and import:

- [ ] Golden-file tests for every generator (hostname.if, dhcpd.conf,
      unbound.conf, ntpd.conf, myname, mygate, rc.conf.local; pf.conf
      has some).
- [ ] Generated files pass the real validator (`pfctl -nf`, `dhcpd -n`,
      …), including for random valid models (fuzzing the model →
      generator path), and boundary cases: empty sections, the most
      rules, interfaces and aliases, special characters, every protocol
      and endpoint combination.
- [ ] Import against anonymized real configs: import then export must
      behave the same (comments and whitespace may differ); unsupported
      features (anchors, queues) come back as raw blocks; every syntax
      variation (macros, includes, continuations, comments, blank lines,
      mixed indentation); clear errors
      for malformed input; random valid configs through import, export
      and `pfctl -nf`.

Engine, processes and API:

- [ ] The whole commit flow end to end: stage → check → apply → confirm,
      and → timeout → revert, with failures injected (check fails, apply
      fails, a service won't restart, disk full, permission denied) and
      the rollback checked.
- [ ] Races: several stages, commits racing, confirm during revert; no
      corruption or deadlocks. History: correct diffs, restoring stages
      exactly the old content, history survives a restart. Hand-edits
      between staging and commit block the commit and are kept.
- [ ] RPC: every method's success and error paths, errors crossing the
      process boundary, malicious input (unknown methods, malformed
      requests; oversized messages are covered) that can't crash or
      escalate the parent, random bytes on
      the socketpair, and the lifecycle (child crash → restart, parent
      shutdown → child exits, unconfirmed commits revert).
- [ ] HTTP: every route with valid and invalid input, missing
      authentication once there is some, cross-origin requests, oversized
      and malformed bodies, path traversal in URL parameters, and every
      error path checked for leaked internals.

UI:

- [ ] There are no UI tests. Component tests for every form (valid
      input, clear errors, edge cases); the critical flows end to end
      (add a rule → commit → confirm, edit an interface → see the
      generated file, revert from history); optionally visual regression
      tests of key pages.

CI:

- [ ] On every change, blocking on failure: `make test` (vet and
      `go test -race`), fuzzing for a minimum time per target (30 s),
      `GOOS=openbsd` vet and build, the UI's typecheck and builds, and
      coverage that doesn't drop without a reason.

OpenBSD versions:

- [ ] Fixtures from each supported release (7.4 onwards). For each new
      release: capture fresh output from every parsed command, review
      the man pages and source for changed formats (cvsweb), update
      parsers and generators, add the fixtures, and document
      version-specific behavior. Parsers degrade gracefully on older
      versions (missing fields are empty, not crashes). Record the
      supported versions in the README.

Live on-OpenBSD suite:

- [ ] A harness on an OpenBSD VM that collects real output (`pfctl -s
      states`, `-s rules -v`, `-s info`, `-s Anchors -v`, `ifconfig -a`,
      `netstat -rn`, `rcctl ls all` and `get`, `dhcpleasectl show`,
      `wg show`, `unbound-control stats`), feeds it through every parser,
      checks deterministic values, and keeps it as new fixtures. It
      should include busy state tables, many interfaces, complex
      rulesets and IPv6-heavy setups, validate generated configs with
      `pfctl -nf -` against the system's, run at least on each release
      (ideally on every change), and document how the VM differs from a
      real deployment.

### Verify on real OpenBSD

Everything so far has only run on macOS, where pledge and unveil are
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
- [ ] DHCP names in DNS (`internal/leases`): the lease file format
      matches what OpenBSD's dhcpd writes (`db.c`: time format, `UTC`,
      `client-hostname`); `unbound-control -c … list_local_data` output
      and `local_data` replies are as parsed; the control socket at
      `/var/run/unbound.sock` works with unbound's chroot; the parent can
      read `/var/db/dhcpd.leases` under unveil, including after dhcpd
      replaces the file.
- [ ] Check how dhcpd writes a `client-hostname` containing `"`. If
      `db_printable` lets it through unescaped, a client can forge extra
      lease statements in the file. Records limits the damage (dynamic
      range only, reserved names, clashing names dropped), but the
      parser can't tell forged statements from real ones.
- [ ] rc.conf.local: rc.d reads the quoted `dhcpd_flags="em1 vlan20"`
      and empty `unbound_flags=""` as `rcctl set`/`enable` would write
      them; `rcctl check`, `start`, `restart` and `stop` behave as the
      reconcile expects; a newly enabled dhcpd starts with the new
      dhcpd.conf.
- [ ] Split-tunnel enforcement: pfctl accepts `$iface:network` entries
      in a `const` table (used for DHCP-addressed inside networks in
      `<opf_local>`), and the block rule stops a split-tunnel device
      that sets `AllowedIPs = 0.0.0.0/0` from reaching the internet.
- [ ] The ARP and routing table parsers against real `arp -an` and
      `netstat -rnf inet`/`inet6` output.

## Development tooling

`make mock` and running your own mock are described in How we work.

- [ ] Recorded responses: capture real OpenBSD command output
      (`opf -record dir`) and replay it in the mock.
- [ ] Simulated validator results: run the Go pf parser on staged
      pf.conf so `pfctl -nf`-style errors can be exercised; today every
      check passes in the mock.
- [ ] Storybook or similar for developing components in isolation.
- [ ] `golang.org/x/sys` is pinned to v0.44.0 to keep Go 1.25; revisit
      when OpenBSD packages Go 1.26.
- [ ] Delete the stale Dependabot branches on origin; they target the
      old `ui/`.

## Done

Finished work, kept here for now. Git history has the details.

Parser and generators:

- [x] Outbound rules never matched: the built-in `pass out quick inet`
      ended evaluation before every user rule. It's a non-quick
      `pass out` now, with a test that nothing ahead of the user's rules
      ends outbound evaluation except NAT exceptions.
- [x] Parser hangs: fuzzing found infinite loops in the tokenizer (bytes
      treated as runes) and the interface, protocol and port list loops.
      The inputs are regression seeds in `internal/pf/testdata/fuzz` and
      `parser_termination_test.go`.
- [x] The parser dropped what it didn't understand. Anything the form
      can't hold now keeps the rule raw (unknown or repeated options,
      `log (…)` other than `(all)`, bare macros and hostnames, groups and
      devices not in the model, host lists and ranges, unmodelled state
      options, and more). The tokenizer's keywords are case-sensitive and
      its string escapes follow pf's parse.y; the generator quotes the
      same way. `FuzzParseRuleRoundTrip` checks the round trip.
- [x] Raw rules keep their source text instead of being rebuilt from
      tokens; continuations are removed before tokenizing, as pf's lexer
      does. `FuzzRawRuleText` checks it.
- [x] Interface references: one `iface` endpoint (a model interface or
      group, with `:network`, `:broadcast`, `:peer`, `:0`, and
      parentheses when it should follow address changes), following
      pfctl's parse.y and `host_if()`. `self` takes the same modifiers.
- [x] Built-in rules (anti-lockout, port forwards, NAT reflection,
      automatic NAT) use `iface` endpoints, and include DHCP-addressed
      inside networks.
- [x] Model validation: `pf.Validate` checks every field in the parent
      before generation and again on commit, with limits from pf's source
      and interface ids that aren't pf keywords. It found two bugs in the
      sample model.
- [x] pf labels are `opf:<kind>:<id>` and descriptions are comments, so
      descriptions are free text and counters map back to the model.
- [x] The rule drawer converts a pasted pf rule to the guided form when
      the form can hold it.

Commit engine and API:

- [x] Removing generated files: a file the new model no longer generates
      is staged for removal (with the same modified-outside protection),
      committed by removing it and running its Remove command (`ifconfig
      <dev> destroy`, or `down` for a physical port), and restored and
      re-applied on revert. VLANs and tunnels can be deleted from the UI,
      which lists what uses them (rules, DHCP, NAT, forwards, gateways,
      routes, routed rules, and pf text to edit) before removing or
      changing it.
- [x] `rc.conf.local` is generated from the model (dhcpd with the devices
      that have a DHCP scope, so never the WAN; unbound when DNS is on)
      and applied last, after every service's configuration, by a
      reconcile that starts, restarts or stops dhcpd and unbound to
      match; also after a revert removes the file. Turning on DHCP or
      DNS now enables and starts the daemon.
- [x] The binary serves the UI: `make build` embeds `ui/dist` (package
      `ui`, tag `embedui`), served with a strict Content-Security-Policy,
      no framing, no referrer, and long caching only for hashed assets.
      Without the tag, `/` says the UI wasn't built.
- [x] RPC messages from the web process are capped at 8 MiB each,
      checked from gob's length prefix before the decoder allocates
      anything; an oversized message drops the connection (the child is
      restarted). Fuzzed (`FuzzLimitReader`).
- [x] `hostname.*` pattern entries in the registry (device names only),
      applied first with `sh /etc/netstart <dev>`, mode 0640; `myname`
      and `mygate` are managed files too.
- [x] The model lives in the parent, as a managed file (0600) staged and
      committed with everything generated from it, so applying is atomic.
- [x] A JSON API (`docs/api.md`) replaced the htmx pages; the UI stages
      the model and the review dialog shows change summaries with each
      file's diff.
- [x] Confirm and revert go to the server, which reverts on its own at
      the deadline; the UI polls `/api/status` to notice.
- [x] Request bodies are capped at 4 MiB, JSON only, strictly decoded;
      cross-origin writes are refused; internal errors reach clients
      only as "internal error".
- [x] While a commit waits for confirmation, staging is refused
      (`commit_pending`) and the UI blocks edits and undo.
- [x] Two browsers: staging needs the live version the edits started
      from and committing the staged version, so neither silently undoes
      the other (`conflict`).
- [x] Hand-edited generated files: staging refuses with
      `modified_outside` until the user chooses to replace them.
- [x] The RPC client's old `Pending` call, which dropped errors, is gone;
      status comes from `Status`.

WireGuard, DHCP and DNS:

- [x] Each VPN interface carries its own tunnel (port, public key,
      peers); several tunnels, with a tab each and "Add tunnel".
- [x] Validation across tunnels: unique ports and keys, peer ids unique
      everywhere and peer keys within a tunnel, peer addresses inside
      their tunnel, `wgaip` networks not overlapping each other or local
      networks, and no two interfaces on overlapping networks.
- [x] "Only your networks" is enforced in pf, not just told to the
      device.
- [x] DHCP clients' names in DNS, with registered and refused names on
      the DNS page (`GET /api/dns/leases`).
- [x] The DHCP page's leases table reads the leases file
      (`GET /api/dhcp/leases`) and says which name each device got.
- [x] Invalid hostnames are rewritten into valid labels ("Fix names that
      aren't valid", on in the sample model; off refuses them), and the
      DNS page shows the name each came from.

Live data and tooling:

- [x] The ARP table and routing table have real backends
      (`GET /api/network/arp`, `/api/network/routes`) and pages, and set
      the pattern for the rest of live data.
- [x] `make mock` runs the real engine with Vite proxying to it; commit,
      confirm and revert work through the API, and `-confirm-timeout`
      makes the timeout testable. The UI loads the model from the backend
      (`GET /api/config`); the preview build uses an in-browser stand-in.
