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

**One generator, in Go.** The UI never generates config itself. It
asks the API (`/api/pf/ruleset`, `/api/pf/derived`, `/api/pf/render`,
through the hooks in `ui/src/lib/generated.ts`). The offline preview
build runs the same Go code compiled to WebAssembly (`cmd/opfwasm`,
about 5 MB, 1.4 MB gzipped, inlined only into the preview). Something
new a page needs from the generators goes in `pf.Derive` or a new
endpoint, and in `cmd/opfwasm` too.
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

- **Go 1.25.** Run `make test` (vet plus `go test -race ./...`),
  `GOOS=openbsd go vet ./...` and `GOOS=js GOARCH=wasm go vet
  ./cmd/opfwasm` before calling anything done. Fuzz
  parsers after changing them:
  `go test -run '^$' -fuzz <Target> -fuzztime 60s ./internal/<pkg>`.
- **UI**:
  - `cd ui && npx tsc`, `npm run build`, and `npm run build:preview`
    (the single-file offline build; it builds the wasm first).
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
  Leases, the ARP and routing tables, the system, interfaces, gateways,
  VPN devices, updates, and pf's state table, counters and log are
  live. `ui/src/model/live.ts` only feeds the offline preview.
- **Missing:** authentication, importing an existing system.
- **Never run on OpenBSD.**

## Roadmap

In order. Each step's details are in the section it points to.

1. **Authentication and TLS**, enforced in the parent (Security › User
   accounts).
2. **Run on OpenBSD** (Verify on real OpenBSD). The `openbsd-dev` host
   in the SSH config is a candidate; ask before using it.
3. **Import** (Parser and import), then the first-run wizard.
4. **Live data** (Live data and monitoring).

## Commit engine and staging

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

- [ ] A NAT exception retags its traffic `opf_nonat`, and a packet has
      one tag, so an earlier rule's tag on the same traffic is replaced:
      an outbound rule testing it (`pass out tagged WEB`) won't match
      that traffic. If that matters, exceptions could be expressed
      without tags (excluding their addresses from each nat-to rule
      through tables with negated entries).
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
- [ ] `rc.conf.local`: nothing to import but OPF's own lines, since the
      rest of the file is kept as it is. Import must derive DHCP and DNS
      from their config files and check `dhcpd_flags` and
      `unbound_flags` agree (dhcpd enabled on exactly the devices with
      a scope, unbound on when DNS is), and ask the admin when they
      don't rather than change what's running.
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

- [ ] The Services page will manage more daemons through
      `rc.conf.local`: `config.RcServices`, `pf.RcNames` and `RcVars`
      grow together (a test holds them to the same list).
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

Pattern (from the system and interface status):
- Parsers in `internal/sysinfo`, pure functions of a command's output,
  tested against output captured on real OpenBSD
  (`testdata/openbsd-<release>/`, golden JSON, `go test -update`) and
  fuzzed. Output the capture host can't produce goes in
  `testdata/handwritten/` and is listed under Verify on real OpenBSD.
- The Manager runs the commands through its Runner (`status.go`),
  leaves out what failed with a sentence in `errors`, and works out
  rates from its last two readings (`rate`).
- The mock answers the same commands with simulated output in the
  captured formats (`cmd/opf/mocksys.go`), so the mock exercises the
  parsers; the offline preview's `localApi` returns
  `ui/src/model/live.ts` samples in the API's shapes.
- Pages read it through `useLive` (`ui/src/lib/live.ts`), one shared
  poller per endpoint, paused while the tab is hidden.
- The ARP and routing tables still use the older pattern (parsers in
  `internal/appliance`, samples on other platforms); move them over.
- Later a WebSocket for pflog and traffic.

System:

- [ ] Disks: a storage page with a meter per mount (the dashboard only
      sums them), and disk I/O (`iostat`).
- [ ] Sensors: show every sensor on System › General, not just a
      temperature on the dashboard, with WARNING and CRITICAL
      highlighted.
- [ ] Processes (`ps aux`) → `GET /api/system/processes`: a Diagnostics
      page with sorting and filtering.

Firewall:

- [ ] Killing states in bulk: by address or interface, and all of a
      rule's states (`pfctl -k label -k opf:rule:<id>`), from the rule's
      menu. One at a time from Connections is done.
- [ ] Record each state killed in the event log (who, when, which
      connection) once there's one.
- [ ] The firewall log: follow pflog0 live (`tcpdump -l -i pflog0`,
      over a WebSocket) instead of rereading the file, and read the
      rotated `pflog.0.gz` for older entries.
- [ ] A log entry's rule is only known for entries after the last
      commit (pf numbers rules, and a reload renumbers them). Keep the
      number-to-label map of each loaded ruleset with its commit, so
      older entries can be matched too.
- [ ] pf's per-interface statistics (`pfctl -vv -s Interfaces`), memory
      limits as a meter beside the state table, and the counters in
      `pfctl -s info` (state-mismatch, memory, congestion) on a pf page.
- [ ] The Rules page shows counters for form rules and the built-in
      rows; show them for port forwards and outbound NAT too, and for
      raw rules (which only have a label if their text has one).

Network, VPN and logs:

- [ ] Interfaces OPF doesn't configure (a spare port, one added by
      hand) are in `/api/network/interfaces` but no page shows them;
      list them on Interfaces with an offer to set them up.
- [ ] Gateway health is a ping per request, cached 10 s. A real monitor
      (dpinger-like, in the collector) would keep loss and latency over
      time and could drive gateway-group failover (Models and
      generators › Multi-WAN).
- [ ] System logs → `GET /api/logs/{dmesg,messages,daemon,authlog}`: a
      Diagnostics › System logs page with a tab each.

Diagnostics tools (everything in the base system that helps someone
work out what's wrong, each with a form rather than a command line):

- [ ] **How they run.** Only through the parent, as a fixed argv built
      from validated fields (never a shell, never free-form flags), with
      a time limit, an output cap, one run at a time per tool, and the
      output streamed to the page. Addresses and names are checked like
      the model's; interfaces come from a list. Tools that change
      something (killing states, flushing a cache, waking a device) are
      actions that say what they'll do, and later need the operator
      role (Security › User accounts). Record each run in the event log.
- [ ] Every tool page offers the next useful step: a ping that fails
      offers a traceroute, a DNS answer offers a ping, a lookup of an
      address offers "which rule allows this" (the packet tester).

Reachability:

- [ ] Ping (`ping`, `ping6`): count, size, interval, source address or
      interface, don't-fragment (`-D -s`) to find the path MTU. Show
      loss and round-trip min/avg/max as they arrive.
- [ ] Traceroute (`traceroute`, `traceroute6`): UDP, ICMP (`-P icmp`)
      or TCP to a port, source interface, AS numbers (`-A`), each hop
      with its name and times.
- [ ] Port test (`nc -z -v`, `nc -u`): does a TCP or UDP port answer,
      from a chosen source address, with a time limit.
- [ ] Fetch a URL (`ftp -o - -M`, headers only or the first bytes):
      proves DNS, routing, NAT and TLS together.
- [ ] TLS check (`openssl s_client -connect -servername`): the
      certificate chain, expiry, protocol and cipher of a server.
- [ ] Throughput (`tcpbench`): between the firewall and a device on the
      network running `tcpbench -s` (or the reverse), for testing a link
      without the firewall's own traffic in the way.
- [ ] Wake-on-LAN (`arp -W`): wake a device by MAC address on an
      interface, with the DHCP reservations and ARP table as a picker.

DNS:

- [ ] Lookup (`dig`, `host`): any record type, against unbound or a
      chosen server, with `+trace` and DNSSEC (`+dnssec`) output, so
      "is it the resolver or upstream?" can be answered.
- [ ] unbound (`unbound-control`): statistics (`stats_noreset`), what
      it would answer (`lookup`), the cache for a name (`dump_cache`
      filtered), local data (`list_local_data`, the lease names), and
      flushing a name or zone (`flush`, `flush_zone`, `flush_bogus`).
      Needs `remote-control` on a local socket in unbound.conf.
- [ ] `unbound-checkconf` output on the DNS page when unbound refuses
      its configuration.

Packets:

- [ ] Packet capture (`tcpdump`): interface, a filter built from fields
      (host, network, port, protocol) or typed, a packet and time limit,
      live decoded output, and a pcap download for Wireshark. The file
      lives in a private directory, is capped in size and deleted after
      a while.
- [ ] Live pflog (`tcpdump -n -e -ttt -i pflog0`): blocked and logged
      traffic as it happens, each line mapped to its rule.
- The packet tester is under Models and generators; it belongs on
  this page too.

pf:

- [ ] Everything `pfctl -s` shows, on one page with a tab each: rules
      with counters (`-vv -s rules`), states, info, tables and their
      entries (`-t name -T show`), labels, memory and timeouts as pf
      has them, interfaces (`-vv -s Interfaces`), source-tracking nodes
      (`-s Sources`) and OS fingerprints (`-s osfp`).
- [ ] Test an address against a table (`pfctl -t name -T test addr`):
      "is 1.2.3.4 in my blocklist?".
- [ ] Clear things: kill states (above), source nodes (`-K`), a table's
      entries (dynamic tables only) and counters (`-z`).
- [ ] The loaded ruleset against OPF's (`pfctl -s rules` vs the
      generated pf.conf), to spot something loaded by hand.

Network state:

- [ ] Which route a destination takes (`route -n get addr`): interface,
      gateway, source address. Offered from the routing table and the
      packet tester.
- [ ] Routing changes as they happen (`route -n monitor`), for flapping
      links and DHCP renewals.
- [ ] Neighbours: ARP (done) and IPv6 (`ndp -an`).
- [ ] Protocol statistics (`netstat -s`, per protocol with `-p`):
      retransmissions, checksum errors, drops; mbufs (`netstat -m`).
- [ ] Listening and connected sockets (`netstat -an`, `fstat -n`):
      which process has a port open on the firewall itself.
- [ ] Interfaces in full (`ifconfig -A`): media, capabilities,
      groups, MTU, and wireless scans (`ifconfig if scan`) where there's
      a wireless card.
- [ ] DHCP client and SLAAC state (`dhcpleasectl -l`, `slaacctl`): the
      WAN's lease, its server and when it renews; router
      advertisements received.
- [ ] Neighbour discovery on the wire (`lldp`, if the release has it in
      base: check) to show which switch port each interface is plugged
      into.

Time, system and health:

- [ ] Time (`ntpctl -s all`): OpenNTPD's peers, offsets, whether the
      clock is synced, sensors; TLS constraints status. A wrong clock
      breaks TLS and DNSSEC, so show it prominently when unsynced.
- [ ] Processes (above), `top -b` for a snapshot, `vmstat` and `iostat`
      for where time goes, `pstat -s` for swap.
- [ ] Sensors (`sysctl hw.sensors`, `sensorsd`): temperatures, fans,
      voltages, disk and RAID health.
- [ ] Disks: `df`, RAID status (`bioctl`), SMART on ATA disks
      (`atactl`), and which disks the system sees (`sysctl hw.disknames`).
- [ ] Kernel messages (`dmesg`, and `dmesg -s` for the console buffer)
      and the system logs (above).
- [ ] Who's logged in and recent logins (`w`, `last`), and failed
      sshd logins from authlog.
- [ ] The nightly reports (`daily(8)`, `security(8)`, in root's mail):
      setuid changes, disk use, failed services, shown on the dashboard
      rather than left unread in a mailbox.
- [ ] Services that should be running and aren't (`rcctl ls failed`).
- [ ] Updates: `syspatch -c` (patches available), whether a newer
      release is on the mirror (what `sysupgrade` would fetch),
      `fw_update -n` (firmware), `pkg_add -u -n` (package updates).
      Applying them is a separate, confirmed action.

When the matching daemon is enabled (Services):

- [ ] Routing daemons' status: `ospfctl`, `ospf6ctl`, `bgpctl`,
      `ripctl`, `eigrpctl`, `ldpctl` (`show neighbor`, `show rib`,
      `show interfaces`).
- [ ] IPsec: `ipsecctl -s all`, `ikectl show sa`.
- [ ] carp and pfsync: each carp interface's state (master, backup),
      demotion counters (`ifconfig -g carp`), `netstat -s -p pfsync`.
- [ ] relayd (`relayctl show summary`), smtpd (`smtpctl show queue`),
      httpd (`httpd -n`), snmpd (`snmp` walk of the firewall itself),
      npppd (`npppctl session all`), dhcrelay and rad status.
- [ ] Certificates: expiry of every certificate OPF knows of
      (`openssl x509 -enddate`), and `acme-client` renewal results.

History over time (the pages above show the current values; these keep
them, so they can be graphed and compared):

- [ ] **A collector** in the parent that samples on a fixed interval
      (10 s, say) and keeps each series in a bounded store: recent
      samples at full resolution, older ones averaged down (1 min for a
      day, 1 h for a month, and so on, like RRD), with a fixed cap on
      disk under the state directory so it can never fill the disk.
      Counters are stored as rates (deltas per second), and a counter
      that goes backwards (a pf reload, a reboot) starts over rather
      than giving a negative spike. It survives restarts, and the API
      gives a series over a time range at the resolution asked for.
- [ ] What to collect:
      - **Interface traffic**: bytes, packets, errors and drops in and
        out per interface (`netstat -in`, queue drops from
        `netstat -id`): the dashboard chart (simulated today) and
        per-interface graphs. Also pf's own view per interface and
        group (`pfctl -vvsI`: passed and blocked, in and out).
      - **pf as a whole** (`pfctl -si`, `pfctl -sm`): state table size
        against its limit, state inserts and removals, searches,
        matches, drops by reason (memory, fragment, state mismatch…),
        syncookies active, and every memory pool's use against its
        limit (states, source nodes, fragments, table entries), so the
        UI can warn before one fills.
      - **New connections per second** by protocol, and how old states
        are.
      - **Per rule** (`pfctl -s labels`, by OPF's labels): evaluations,
        packets, bytes and states per model rule, on the Rules page and
        a rule's own graph. That includes OPF's own blocking rules by
        label: the default block, antispoof, split-tunnel limits, WAN
        protection.
      - **Tables**: how many addresses `<bruteforce>` and other
        overload tables hold over time (attacks as they happen), and
        hits per blocklist alias for tables with `counters`
        (`pfctl -t … -T show -v`).
      - **NAT**: source ports in use on each WAN address against what's
        available; they can run out on a busy network.
      - **Queues**, once traffic shaping exists: bandwidth and drops per
        queue (`pfctl -vsq`).
      - **Per host**: states and traffic per inside address. pf only
        keeps bytes per live connection (lost when it closes) and per
        interface, so: periodic state polling aggregated by address,
        rule labels with accounting, or pflow(4) export to a collector.
        Top talkers over time, and a host's own history.
      - **From the firewall log** (pflog): top blocked sources, targeted
        ports and blocks per interface over time (scans, noisy
        devices), and outbound traffic blocked per inside host (a
        device trying to reach what it shouldn't).
      - **Network stack** (`netstat -s`, `netstat -m`): TCP
        retransmits and resets, IP and ICMP errors, mbuf and cluster
        use; routing table size and changes (dynamic routing).
      - **WireGuard**: bytes per peer, handshake age (a site link that's
        silently down), and endpoint changes (a device roaming).
      - **The WAN and gateways**: latency, jitter and loss to each
        gateway and to a public address, DNS lookup latency, and the
        WAN address changing. The "is it my ISP?" graphs.
      - **DNS** (`unbound-control stats`): queries by type and by
        response code (a rising NXDOMAIN rate often means malware or a
        misconfiguration), cache hit rate, recursion time, DNSSEC
        validation failures. Top domains and queries per client too,
        but only opt-in (see privacy below).
      - **DHCP**: leases given, renewed and released, how full each
        pool is, and pools running out.
      - **Time** (`ntpctl -s all`): clock offset and usable peers.
      - **Services**: each managed daemon up or down, and restarts
        (`rcctl check`).
      - **Logins**: failed and successful SSH logins (authlog), and
        OPF's own once it has authentication.
      - **OPF itself**: commits, confirms, automatic reverts, failed
        validator checks, how long commits take, API errors and
        latency.
      - **System**: CPU, load, memory, swap, disk use and I/O,
        interrupts per device (`vmstat -i`), sensors (temperatures,
        fans, voltages from `sysctl hw.sensors`), uptime and reboots.
- [ ] **An event log** beside the series, for things that happen rather
      than values that vary: a device seen for the first time (a new
      MAC in the ARP table or DHCP, both an inventory and a security
      signal), links going up or down and media changes, CARP state
      changes, the WAN address changing, WireGuard endpoints moving,
      daemons stopping, logins, commits and reverts. Graphs mark them
      ("the WAN went down here"), and they can be filtered and searched.
      Bounded like the series.
- [ ] **Privacy**: per-host traffic, DNS names, new-device tracking and
      logins are personal data. Each gets a retention limit, shorter
      than the rest, and the most sensitive (DNS queries per client and
      top domains) are off unless the admin turns them on, saying what
      is kept and for how long. Deleting a device's history should be
      possible.
- [ ] Graphs in the UI: time range picker, per-interface, per-rule and
      per-host views, and the dashboard's charts from real data.

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

### User accounts (sketch)

A first design, to argue with before building. Today anyone who can
reach the port can do anything, and a compromised web process could
call Stage and Commit directly, so accounts have to be enforced in the
parent, and the web process must never be the one deciding who
someone is.

**Who can log in** (decided 2026-09-29: system accounts). OpenBSD's own
accounts, not a second user database:
the admin already has one, SSH and the UI share it, passwords are
bcrypt and handled by the base system, and bsd_auth brings its other
login styles (YubiKey, RADIUS) for free. Membership of a group decides
the role:

- `_opfadmin`: everything.
- `_opfoperator`: can see everything and confirm, revert or restore a
  commit, but can't stage new changes (someone watching over an
  appliance at night).
- `_opfview`: read-only.

Anyone else, including root and members of wheel, can't log in unless
they're in one of these. A user in several gets the most powerful.
Open question: whether `_opfoperator` is worth having from the start,
or later with finer per-section permissions.

**Checking a password** happens in the parent, which is root: either
`auth_userokay(3)` through cgo (cross-compiling then needs an OpenBSD
sysroot), or running bsd_auth's `login_<style>` helper directly with
the password on its back channel, which keeps the build pure Go. Try
the helper first, on OpenBSD. The parent then needs `/etc/group` and
`/usr/libexec/auth` unveiled.

**Sessions** live in the parent. Logging in is an RPC with the name and
password; on success the parent makes a random 256-bit token and keeps
it in memory with the user, role, and when it was last used. Every
other RPC carries the token, and the parent checks it and the role
before doing anything, so a compromised web process can't mint a
session or raise one's role; it could at worst reuse the tokens of
people logging in while it's compromised. Sessions end after 30
minutes idle or 12 hours in all, on logout, when the parent restarts,
and when the user leaves the group or their password changes. Users
can see their sessions and end them; admins, anyone's.

**In the browser** the token is a cookie: `__Host-` prefixed, `Secure`,
`HttpOnly`, `SameSite=Strict`, alongside the cross-origin protection
that's already there. The UI shows a sign-in page and nothing else
until there's a session. The web process only passes the cookie on; it
doesn't keep or check sessions itself.

**TLS is required** once there are passwords: the parent generates a
self-signed certificate on first run (the UI shows its fingerprint to
compare, and it can be replaced), with HSTS. Plain HTTP only on
loopback, for `ssh -L`. Later: ACME, where the box has a public name.

**Brute force.** Failed logins back off per user and per source
address (one second doubling to a few minutes), in the parent. The
error never says whether the user exists, and every attempt goes to
authlog and the event log (History over time).

**Sensitive actions ask again.** Changing who can log in, disabling the
firewall, skipping filtering on an interface, and restoring a backup
ask for the password again, good for five minutes.

**Audit.** Every commit records who made it and every confirm or revert
who did that; history and the event log show them. Commits made by the
confirm timeout are recorded as OPF's own.

**Managing accounts from the UI** (admins only): add a user (useradd
with a login class and the right group), set a password, change a
role, lock or remove someone. These happen straight away, not through
staging and confirm: accounts aren't part of the network configuration
and don't belong in its history. They're guarded instead: the last
admin can't be removed or demoted, and nobody can take away their own
admin role. The first-run wizard creates the first admin. Forgotten
passwords are reset from the console or SSH as root, which is the
recovery path and should be documented.

**API tokens** for scripts and monitoring: made by an admin with a role
(often read-only) and an expiry, shown once, stored only as a hash in a
root-only file in the parent's state directory, and sent as
`Authorization: Bearer`. They're checked the same way as sessions, and
listed and revoked like them.

**Two-factor**: TOTP first, its secret per user in the same root-only
file, asked for after the password; WebAuthn (passkeys, hardware keys)
later. bsd_auth's YubiKey style already works through system logins.

**Development.** The mock keeps working without accounts, loopback
only, with a banner saying so; `-dry` on OpenBSD can use real accounts.

- [ ] Build the above, starting with system accounts in `_opfadmin`,
      sessions checked in the parent, the cookie, TLS and the sign-in
      page; then roles, re-authentication, the account pages, API
      tokens and two-factor.
- [ ] Check the bsd_auth helper protocol and pledge/unveil needs on
      OpenBSD before choosing it over cgo.
- [ ] Anyone who can commit can get root: rc.conf.local is sourced by
      rc(8), and sshd_config and httpd.conf are powerful. That comes with
      the product, but it's why authentication and audit logging matter.
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
- [ ] Status parsers against output they've only seen written by hand
      (`internal/sysinfo/testdata/handwritten/`): `ifconfig` for wg
      peers (as root), vlan, carp and point-to-point interfaces; pfctl
      on a configured firewall (`-v -s info` with a loginterface, `-vv
      -s states` with NAT, port forwards and IPv6, `-vv -s rules` with
      labels); and pflog lines from rules (TCP, UDP with a decoded
      payload, anchors, truncated packets). The formats themselves are
      checked against a 7.9 capture with pf's default ruleset, which has
      none of these. Capture them and move them to
      `testdata/openbsd-<release>/`.
- [ ] `pfctl -k id -k <id>/<creatorid>` takes the creator id in hex, as
      `-vv -s states` prints it.
- [ ] Status parsers on other hardware: `hw.sensors` from real sensors
      (temperatures, fans, volts, drives), `df` with more filesystems,
      `swapctl` with two devices, and a release other than 7.9.
- [ ] `ping -6` for an IPv6 gateway, and `kern.boottime` read in the
      parent's time zone matching the system's.
- [ ] `syspatch -c` output when patches are available (names one per
      line is assumed), and its error when the mirror can't be reached.
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
- [ ] NAT exceptions: a tag set by an outbound `match` rule is seen by
      later rules in the same evaluation (`! tagged opf_nonat` on the
      nat-to rules), so excepted traffic leaves untranslated and still
      reaches the outbound user rules.
- [ ] pf options: pfctl accepts every generated `set` line (a braced
      `set limit`/`set timeout` list, `set skip on { lo $iot }` with a
      group or device, `set hostid`, quoted `set fingerprints`), scrub's
      `min-ttl` and `reassemble tcp`, and `antispoof log quick for $lan
      inet label …`.
- [ ] Split-tunnel enforcement: pfctl accepts `$iface:network` entries
      in a `const` table (used for DHCP-addressed inside networks in
      `<opf_local>`), and the block rule stops a split-tunnel device
      that sets `AllowedIPs = 0.0.0.0/0` from reaching the internet.
- [ ] The ARP and routing table parsers against real `arp -an` and
      `netstat -rnf inet`/`inet6` output.

## Development tooling

`make mock` and running your own mock are described in How we work.

- [ ] Recorded responses: capture real OpenBSD command output
      (`opf -record dir`) and replay it in the mock. The status commands
      are simulated in their captured formats already
      (`cmd/opf/mocksys.go`); this would cover the rest.
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

Live data:

- [x] pf's own state: the dashboard's firewall tile (states, packets
      blocked a minute on the statistics interface) and recently
      blocked, Connections from the state table with closing a
      connection for real, counters on the Rules page by label, and the
      firewall log with each entry's rule when it's known.
- [x] The dashboard, Interfaces, Routing's gateways, WireGuard's devices
      and System › General's updates show the running system instead of
      sample data: CPU, load, memory, swap, disks, uptime, hardware and a
      temperature (`/api/system`); every interface's state, counters,
      traffic and WireGuard peers (`/api/network/interfaces`); gateway
      pings (`/api/network/gateways`); OpenNTPD's sync state; and
      `syspatch -c` in the background (`/api/system/updates`). The fake
      "Install patches" progress bar is gone; installing is under
      Diagnostics tools › Updates.

Parser and generators:

- [x] One generator: the TypeScript copy (`ui/src/model/generate.ts`)
      is gone. Pages get the ruleset, previews and derived data
      (automatic NAT, local networks, rule text, which interfaces are
      dynamic) from the API, and the offline preview runs the Go
      generators as WebAssembly. A half-finished model that makes a
      generator panic is a 422, not a crash.
- [x] Every pf.conf(5) option: `set limit` (all of them), `set timeout`
      (each key), adaptive syncookies' thresholds, `set state-defaults`,
      `set reassemble`, `set ruleset-optimization`, `set debug`,
      `set hostid`, `set fingerprints`, the statistics interface and
      unfiltered interfaces (never the WAN or `egress`), scrub's
      `min-ttl` and `reassemble tcp`, and antispoof per interface (fixed
      addresses only). Unset means pf's default and writes nothing.
      Option lines in the ruleset name their setting. Scrub with no
      options no longer writes an invalid `scrub ()`.
- [x] NAT exceptions no longer skip outbound rules: instead of
      `pass out quick`, an exception tags its traffic (`opf_nonat`,
      reserved) and the nat-to rules on that interface skip tagged
      traffic.
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

- [x] `rc.conf.local` is shared, not owned: OPF sets only `dhcpd_flags`
      and `unbound_flags`, in a marked block at the end, and keeps every
      other line (`pkg_scripts`, other daemons' flags, comments) where it
      is, so `rcctl enable` for a package and an existing system's setup
      survive. Only a hand change to OPF's own lines counts as a change
      outside OPF, and the reconcile reads those lines instead of
      sourcing the file.
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

- [x] Deleting a tunnel also deletes the WAN rule that opened its port,
      and deleting an interface removes its network from aliases (or
      flags an alias that would be left empty, or holds addresses in it).
- [x] Editing a WireGuard device (name, address, routing, networks,
      endpoint, keepalive), with its router gateway and routes kept in
      step, and the device's new settings shown when it needs them.
      Removing a router removes its routes too.
- [x] Reservations can't be inside their scope's dynamic range or on the
      interface's address; reserving from a lease suggests a free
      address outside the range.
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
