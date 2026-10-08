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

6. **Networking first, then the whole base system.** OPF starts as a
   firewall and router, but the aim is almost everything OpenBSD's base
   system does, so the same binary can run different jobs on different
   machines: a firewall on one, a mail server (smtpd), a web server
   (httpd, relayd, acme-client), authoritative DNS (nsd), a VM host
   (vmd), a file server on another. That means, from now on:
   - Nothing may assume the machine is a firewall. A model with one
     interface, no WAN and pf close to its defaults must be valid and
     make sense on every page; the firewall is one job among several.
   - Each area follows the same pattern (a model section, a generator,
     the daemon's own check, status read with its tools, a page), so
     adding one is mechanical rather than a redesign.
   - The navigation and dashboard are built from what the machine does,
     not a fixed list: a mail server doesn't lead with an Internet
     tile.
   - Each instance manages its own machine. Managing several from one
     place is a separate, later piece (Roadmap).

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
  - `npm run check:tools` after changing the Tools page's result
    summaries: they're run against real OpenBSD output
    (`internal/diag/testdata/openbsd-7.9-tools.txt`). After changing
    how `internal/diag` builds a command, run `TestRealTools` on
    OpenBSD (`GOOS=openbsd go test -c ./internal/diag`, then
    `OPF_REAL_TOOLS=1 ./diag.test -test.run TestRealTools`).
  - When a check is piped through `grep -v`, don't chain `&&` after it:
    `grep -v` exits 1 when there's nothing left to print.
- **On OpenBSD**, `opf -dry -checks` runs the real validators but
  logs every command that changes the system; see Verify on real
  OpenBSD for how it's run on `openbsd-dev`.
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

## Where things stand (2026-09-30)

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
  VPN devices, updates, pf's state table, counters and log, and DNS
  stats are live, with a month of history for traffic, the system, pf,
  DNS and gateways. `ui/src/model/live.ts` only feeds the offline
  preview.
- **Missing:** importing an existing system. Accounts and sessions are
  built and tried on OpenBSD (Security › User accounts).
- **On OpenBSD:** installed from the README on a stock 7.9 VM, it
  makes real commits: confirm, revert, the automatic revert, and lock-
  outs through pf and through an interface's address all come back by
  themselves (Verify on real OpenBSD).

## Roadmap

In order. Each step's details are in the section it points to.

1. **Authentication and TLS**, enforced in the parent (Security › User
   accounts).
2. **Run on OpenBSD** (Verify on real OpenBSD). Dry runs with the real
   validators work on 7.9 (`openbsd-dev`, user `opfdev`; ask before
   using it); next are real commits on a VM that can be locked out
   safely. That VM exists: `opfvm`, a clean 7.9 install under vmd on
   `openbsd-dev` (`~opfdev/opf-test/vm`). It runs on an overlay over a
   read-only base image, so `vm.sh reset` undoes everything in about 3
   minutes. Use `vm.sh ssh` (root by key, 100.64.1.3). `vm.sh type`
   and `vm.sh log` reach its serial console, which still works when a
   commit cuts the network; root's password is in `root-password`
   there.
3. **Import** (Parser and import), then the first-run wizard.
4. **Live data** (Live data and monitoring): the pages read the real
   system now; what's left is history over time and the rest of the
   diagnostics.
5. **Beyond networking** (Principles › 6): jobs chosen at first run
   and changed later, which decide what the navigation and dashboard
   lead with; then the base system's other daemons as full areas
   (Services), and storage, accounts and scheduled jobs. Later still,
   a view of several OPF instances from one place.

## Commit engine and staging

- [ ] Removing a physical port's `hostname.if` only takes the port down
      (it can't be destroyed); its addresses stay until a reboot.
      Nothing in the UI removes physical ports yet.
- [ ] Decide whether a service that fails to reload or restart should
      revert the whole commit (it does now).
- [ ] A second browser's staging replaces the first's staged model
      (there's one candidate). Fine for one admin; revisit with users.
- [ ] When the UI loads a model someone else staged, it lists the
      changes by section only ("Changed firewall settings"); the edit
      descriptions aren't stored with the staged model.
- [ ] History is never pruned. System › Storage shows it growing
      (48 commits, 880 KB on the VM after a week of testing).
- [ ] Newly created parent directories get 0755; check what each managed
      path expects.
- [ ] Graceful shutdown: SIGTERM reverts an unconfirmed commit (seen on
      the VM: `reboot` during the wait reverted it, its log saying OPF
      stopped). Still to check that it waits for an operation already
      under way (a commit applying) rather than cutting it off.
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
- [ ] **authpf** (authpf(8)): network access that opens when someone
      logs in over SSH and closes when they log out, for contractors,
      guests or anything that should need a person present. authpf is
      the user's login shell; on login it loads rules for their address
      (`$user_ip`) into the anchor `authpf/<user>(<pid>)` and adds it to
      the `<authpf_users>` table, and on logout removes both.
  - Generated: `anchor "authpf/*"` in pf.conf at a point the page shows
    (before the interface rules, so an authenticated user's rules are
    reached), `/etc/authpf/authpf.conf`, `authpf.rules` (for everyone)
    and `users/<name>/authpf.rules` (for one), `authpf.allow`,
    `banned/<name>` (with the message the user sees) and
    `authpf.message`. The rules are ordinary OPF rules written with
    `$user_ip` as the source, from the same form, and checked by
    `pfctl -n` with the anchor loaded (`pfctl -a authpf/test -n -f`).
  - Simpler still, for rules that only need to know "is this address
    logged in": `<authpf_users>` in any rule's source, offered as an
    endpoint ("any authenticated user").
  - Accounts: authpf users are system accounts with `/usr/sbin/authpf`
    as their shell, created and removed by OPF, apart from the admin
    accounts (Security › User accounts) and never able to reach OPF's
    interface. Their SSH keys are managed on the page; sshd needs
    `AllowTcpForwarding no` and a `Match` for them, and
    `ClientAliveInterval` so a dropped connection ends the session.
  - Live: who's logged in, from where and since when (the anchors
    under `authpf/*` and the table), their rules' counters and states
    (`pfctl -a 'authpf/…' -s rules`), and a way to end a session
    (kill that authpf process, which removes its rules). Logins and
    logouts go in the event log.
  - The firewall log, rule counters and the packet tester don't follow
    anchors yet; they need to for authpf rules to show up in them.
- [ ] A packet tester: "what happens to tcp 192.168.20.5 →
      192.168.1.20:445?", evaluated against the ruleset. A wrong
      "allowed" is worse than no answer, so it has to follow pf
      exactly (quick and last match, floating before interface rules,
      in and out passes, NAT, tags such as `opf_nonat`, tables and
      aliases, dynamic interface addresses, the default block) and say
      "can't tell" whenever a raw rule, custom pf, a URL table, an OS
      fingerprint or probability could decide it. Build it on the
      generated ruleset rather than the model, so it tests what pf
      loads, and test it against pf itself on OpenBSD (`pfctl -nvf`
      plus real packets) before trusting it.
- [ ] Anti-lockout ports (443, 22) are hard-coded; derive them from the
      web UI and sshd settings.
- [ ] NAT reflection is added on every inside interface; limit it to the
      ones that need it.
- [ ] Check whether reloading pf empties `persist` tables such as
      `<bruteforce>`; if so, save and restore their contents.
- [ ] Run downloads as a dedicated `_opffetch` user created at install,
      rather than the web process's user, so the fetcher can't signal
      the web process or the other way round.
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
  - [ ] A URL alias's list must download before the first commit that
        uses it, so on a box that isn't online yet (the commit setting up
        the WAN is the one that would bring it online) the commit is
        refused. Found taking over a fresh VM with the sample model's
        `blocklist`. The wizard should leave URL aliases for after the
        first commit, or a list that has never downloaded could load as
        empty with a warning (fail open for a block list, closed for a
        pass list: choose per use).
- [ ] Still raw: bare names or `name:0` that aren't model interfaces (pf
      treats them as interfaces only if one exists at load time, else as
      hostnames).
- [ ] Raw rules only have a label if their text has one, so their
      counters can't be matched to the model. Offer to add OPF's label
      when a raw rule has none.

## Interfaces

- [x] **OPF behind another router** (only a VPN server reached through
      a port forward, one LAN and no WAN). A LAN or optional interface
      can share its address (`masquerade`): traffic from OPF's other
      networks leaving through it is NATed to it, so the router needs no
      route back to the VPN. A tunnel has a public address
      (`publicEndpoint`, host or host:port) for devices' configurations,
      instead of the WAN's. Checked: the configuration of such a server
      (testdata/lan-only-vpn.json) validates, and its pf.conf and
      unbound.conf parse on 7.9. What else assumed a WAN, now not:
      - A new tunnel's "let devices in" rule goes on the WAN, or behind
        a router on the interface towards it (`upstream`); How traffic
        flows finds a rule on any interface, says where NAT takes it,
        and asks for the public address when there's no WAN.
      - The dashboard's Internet tile and traffic graph use that
        interface, and say so.
      - A port forward can arrive on any interface but a tunnel.
      - DHCP warns when its network has a router on it, which probably
        hands out addresses already.
      - Already fine: the default gateway on a LAN (/etc/mygate), the
        office network counting as local for split-tunnel devices,
        anti-lockout on the LAN, unbound on the LAN and the tunnel.
  - [x] Tried on the VM (`opfvm` with one interface, the vmd host as
        its router, sharing on, a tunnel; the host a VPN device in a
        routing domain of its own): the commit from a WAN/LAN layout,
        confirmed over the new LAN; the device's handshake, DNS over the
        tunnel (names and reverse names), and the router reached through
        OPF with its address shared; the gateway monitored online; the
        device's last-seen; and the interface moved to DHCP from the
        router and back. That found and fixed: no IP forwarding at all,
        the default gateway only set at boot, turning DHCP off failing
        the commit, and DHCP left running on an interface given a fixed
        address. Not tried: a port forward on a real router (the vmd
        host would have to forward), so the device reached OPF directly.
  - [ ] The first-run wizard should offer this layout: one port, its
        address, the router as gateway, sharing on, a tunnel.
  - [ ] Devices' names only reach DNS from OPF's own DHCP server; behind
        a router that hands out addresses, LAN devices have none. DNS
        blocking only covers devices that ask OPF, so the router's DHCP
        has to name it as the resolver. Say both on the DNS page in this
        layout.
  - [x] LAN devices starting connections to VPN devices: a tunnel can
        be reachable from LAN or optional interfaces (WireGuard, Done),
        and the WireGuard page says which route the router needs.
  - [ ] Not tried: a port forward on a real router in front of OPF. On
        the VM the devices reached OPF directly; making the vmd host the
        router means turning on its IP forwarding and adding a pf rdr-to
        rule there (temporarily, and only with the user's say-so).
  - [ ] No dynamic DNS: behind a home connection the public address
        changes, and a tunnel's `publicEndpoint` should be a name that
        follows it. OPF can't keep one up to date; for now it's the
        router's DDNS or another service. A DDNS client (a job OPF
        runs, with its provider's secret in secret storage) would close
        it.
  - [ ] VPN devices reaching the internet but not the LAN OPF sits on
        takes a block rule above "to anywhere", by hand; "Only this
        VPN" (WireGuard) keeps a device off both. Offer "not the network
        OPF sits on" as its own choice for a tunnel in this layout.
  - [ ] Nothing protects the LAN-facing interface the way a WAN is
        (blocking private and bogon sources makes no sense there); its
        rules are the admin's. If OPF sits on an untrusted network,
        that should be a WAN instead, with the router as its gateway.
  - [ ] Two DHCP servers on one network is only a warning on the page,
        not checked when committing.

Today there are physical ports, VLANs and WireGuard tunnels, each one
`hostname.<dev>` file applied with `sh /etc/netstart <devs>`. Virtual
interfaces need, first:

- [x] Confirm and auto-revert for interface changes (Commit engine).
- [x] **Apply order by dependency.** `hostname.*` files apply in
      netstart's order (physical, aggr/trunk, vlan/svlan, carp, pppoe,
      then tunnels and bridges), not path order, so a VLAN's parent is
      up before it. Not done: a bridge before its members isn't wrong
      for netstart, but removals aren't yet ordered in reverse.
- [x] **VLANs:** the parent is checked when staging (a port, not
      itself, not a disabled interface); a parent no interface uses gets
      a bare `hostname.<port>` ("Carries VLAN 35", `up`) so the VLAN
      works; Add VLAN offers spare ports; the WAN can be tagged (a VLAN
      ID on its edit page, for ISPs that need one).
  - [ ] The tag is tied to the device name (`vlan35` is tag 35): two
        parents can't both carry VLAN 35.
  - [ ] MTU isn't checked against the parent's.
  - [x] Tried on the VM: the WAN tagged as VLAN 35 on vio0 (802.1Q
        VID 35 on the wire, vio0 up bare), through a reboot, an
        unconfirmed commit's revert, and back to untagged DHCP.
- [x] **A fixed WAN address got no default route.** The edit page's
      Gateway went to `ipv4.gateway`, which nothing reads; mygate comes
      from Routing's default gateway, still "dhcp". The page now edits
      that gateway (renaming WAN_DHCP to WAN_GW), and staging refuses a
      DHCP default gateway on an interface with a fixed address.
  - [x] `ipv4.gateway` is gone from the model: an older config.json
        or stage request with one has it moved to Routing (pf.Upgrade,
        when a model is read or staged), and validation refuses it.
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

- [ ] Not tried live end to end: site-to-site, a router peer with
      networks behind it, through OPF as the hub. On the VM a LAN
      device's packets reached the site router's tunnel from their real
      address, but the test site (the host, in a routing domain, its
      network on vether4) never answered for its network, even to OPF,
      while its tunnel address did. Likely the host itself: with IP
      forwarding off, OpenBSD only accepts packets for an address on the
      interface they arrive on (the way-out test met the same, a packet
      for wg6's address arriving on the tap). Try with forwarding on in
      that routing domain, a real router, or a second VM.
- [ ] A site-to-site router's configuration lists "your networks",
      which include its own networks behind it; wg-quick (and routers
      that route by AllowedIPs) would then send its own LAN into the
      tunnel. Leave its own networks out. Check against a real router
      first.
- [ ] Ways out, not tried: a real provider (Mullvad, Proton and the
      like) and its resolvers answering (the stand-in's never did; the
      lookups were only seen arriving). Keep a test that a provider's
      configuration with an IPv6 address and DNS parses as expected.
- [ ] Ways out falling back to the WAN while the tunnel is down (built,
      then taken out: the traffic still went to the dead tunnel, since
      nothing switched the route). It needs gateway monitoring that
      replaces the table's route, and a page that says so loudly.
- [ ] Ways out for some devices rather than whole networks (a table of
      addresses, or a DHCP reservation's device), and a way out per
      destination (only some sites through the provider).
- [ ] Ways out and IPv6: OPF forwards no IPv6 today, so none leaks; once
      it does, IPv6 from the networks leaving must go through the tunnel
      or nowhere.
- [ ] IPv6 inside tunnels: devices get IPv4 only (see IPv6, Models and
      generators). A VPN-only device's IPv6 is all blocked.
- [ ] pf and routing per tunnel: site-to-site tunnels (routed networks,
      usually no NAT) and remote-access ones (clients NATed out) need
      different defaults for automatic NAT and generated rules. Today
      every tunnel's network gets automatic NAT.
- [x] Real WireGuard keys. A tunnel's pair is made by the parent
      (X25519) when it's created; the private key is kept root-only in
      /var/opf/wireguard, named for the public key, and `hostname.wgN`
      reads it as it comes up (`!ifconfig $if wgkey "$(cat …)"`), so
      it's never in the model, a generated file, a diff or history.
      Staging refuses a new tunnel key the firewall didn't make, and
      unused key files go once a commit is final. A device's pair is
      made by the browser (WebCrypto X25519), so its private key never
      reaches the firewall; a browser without it gets one from the
      firewall, which keeps nothing. Tried live on openbsd-dev (7.9): a
      tunnel and device made in the UI, `hostname.wgN` brought up by
      netstart, a stand-in device in another routing domain from the
      device configuration; both key pairs matched, the handshake
      completed, and pings crossed the tunnel. Before this the keys were
      random strings and no tunnel could have worked.
  - [x] New keys: a tunnel's (made on the firewall; then each device's
        configuration with the tunnel's new public key, keeping its own
        keys) and a device's (made in the browser; its whole new
        configuration, once). Revert-safe: a new tunnel key is a new
        file, and the old one stays until the commit is final.
  - [x] Preshared keys: added when making a device, or later (made on
        the firewall, or one you have), replaced, removed. Each is a
        file of its own named by an id in the model, never the key, so
        a revert finds the old one; `hostname.wgN` reads it with
        `!ifconfig $if wgpeer <key> wgpsk "$(cat …)"`, and it's in the
        device's configuration once.
  - [x] When a device was last seen, and where from, kept across the
        interface reloading (which forgets its handshakes) with the
        event log, and shown on the tunnel's devices.
  - Tried live on openbsd-dev: a tunnel made a new key and a device
    given new keys and a preshared key in the UI; netstart brought up
    the generated `hostname.wgN`, its public key the one the device was
    told; with the preshared key 12 of 12 pings crossed, with a wrong
    one none did. A handshake can take a retry (five seconds) to
    complete: a test should wait for it.
  - [ ] The key is on ifconfig's command line for an instant as the
        interface comes up, as with any wgkey; ifconfig can't read it
        from a file.
  - [ ] The sample model's tunnels have made-up public keys with no
        private key behind them, so in the mock only new tunnels work.

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
- [x] Which networks the resolver answers on (`dns.interfaces`, "Answer
      on" in its settings): every inside interface with a fixed address
      by default, never a WAN or a way out (which it used to listen on);
      one left out gets no listening address and no access, so its
      queries are refused whatever the firewall allows. A DHCP scope that
      hands out OPF as the resolver on a network it doesn't answer on is
      refused, and VPN devices' configurations name OPF's DNS only when
      it answers on their tunnel.
- [x] The resolver didn't know the firewall's own name when the firewall
      asked (from 127.0.0.1, `opfvm.home.arpa` was NXDOMAIN): its
      records were only in the networks' views. Loopback has a view of
      its own now, with the firewall's address on every network it
      answers. Tried on the VM.
  - [x] The firewall's own programs didn't find it either: resolv.conf
        sends them to the WAN's DHCP DNS (resolvd), which says no such
        name for home.arpa. OPF now adds the name, with the firewall's
        address on each inside network, to /etc/hosts (each line marked
        "# set by OPF", every other line kept, merged like sysctl.conf),
        which "lookup file bind" reads first, even with unbound down.
        Tried on the VM: getent and ping find it.
- [x] A change to where unbound listens (DNS resolver › Answer on)
      restarts it. Tried on the VM: a reload kept the sockets it had,
      never binding an address added (the VPN's devices got no answers)
      and holding one taken away (access-control refused it, so only
      the socket was left). unbound.conf's RestartIf now restarts it
      when its `interface:` lines change; other changes still reload.
- [ ] The resolver can't answer on a DHCP-addressed inside interface
      (the LAN-only layout with its LAN by DHCP from the router): unbound
      needs the address to listen on and the network to allow, and 7.9's
      unbound (1.24.2) has no `access-control-interface` to allow it by
      name. Write the lease's network when the address arrives (a
      commit-free regeneration of unbound.conf, or `unbound-control
      set_option`), or wait for an unbound that has it.
- [x] Reverse names (PTR): one per address, a reverse name record's
      first, then the firewall's on each inside network, host names and
      reserved devices'; a DHCP lease's name becomes its address's
      reverse name at runtime when the address has none of those.
      Checked on 7.9: `unbound-control local_data` for a PTR answers
      inside unbound's default private reverse zones, and
      `local_data_remove` takes it away.
- [x] **Local DNS records**: the DNS page's "Local names" card lists
      host names beside the other records, which are `dns.records`:
      aliases, mail servers (MX), text (TXT), services (SRV), reverse
      names (PTR) and certificate authorities (CAA), each checked for
      its type and written as single-quoted unbound `local-data`
      (`local-data-ptr` for reverse names). Per domain, `dns.zones` says
      how names without a record answer, shown at the head of each
      domain's names: "don't exist" (static, the system domain's
      default) or "are looked up on the internet" (transparent). A host name with an IPv6 address is now AAAA; it
      was written as an A record, which unbound refuses. Checked with a
      scratch unbound on openbsd-dev (7.9, 1.26.1):
  - A CNAME in local-data is answered alone, in a static or a
    transparent zone, with or without recursion: unbound doesn't
    follow it, even to its own names, and many clients' resolvers
    don't either. A redirect zone at the name does follow it, but
    through the internet, so a target of ours comes back "no such
    name". So an alias to a host name or reserved device is written
    as that name's addresses; to anything else as a CNAME in a
    redirect zone (names under the alias answer the same, so nothing
    else may be under it). An alias to a lease's name can't work
    either way and is refused.
  - Quotes, backslashes and non-ASCII are refused in TXT and CAA;
    `#` and `;` inside a quoted TXT are fine; text over 255 bytes is
    split into several strings.
  - Leases can't take a record's name.
  - A record with no zone above it gets one from unbound, transparent
    at the record's own name, which behaves as "looked up on the
    internet", so that choice is only written as a zone where it's an
    exception inside a "don't exist" domain. A top-level domain (com,
    org; not internal, lan, home and the like) can't be made "don't
    exist", which would hide every name under it.
  - Not done: NS records. In local-data they only answer NS
    questions; they don't delegate, which is what anyone adding one
    wants (that's a `stub-zone`). Nor an authoritative server: no
    DNSSEC signing, dynamic updates or zone transfers; for a public
    domain served from here, that's nsd (Services).
- [x] The firewall's own name (`gw.office.arpa`) answers with the
      firewall's address on the network asking: a view per inside
      network (`access-control-view`, `view-first: yes`, so everything
      else falls through). Checked on 7.9; `interface-view`, by the
      address asked, didn't apply there, with or without the port. It's
      listed in Local names. The firewall asking itself (127.0.0.1)
      still gets "no such name".
- [x] A commit reverted by the confirm timeout now reports the change
      too, so the lease watcher puts names back straight away. (Found on
      the way: Commit returned the pending entry itself, which the
      timeout's revert then changed under its reader; it returns a copy
      now.)
- [x] The firewall's own DNS servers (`system.dns`, System › General):
      the WAN's (OpenBSD's default), its own resolver first with
      fallbacks, or servers given. resolvd keeps resolv.conf; OPF sends
      it a proposal on lo0 (`route nameserver lo0 ...`), which resolvd
      puts ahead of the WAN's lease's and keeps them after it. Seen on
      7.9: a proposal on the WAN's interface replaces its lease's, and
      withdrawing it leaves none until the lease renews, so OPF never
      sends one there; resolvd forgets a proposal when it restarts and
      none survives a boot, so OPF puts it back whenever resolv.conf
      lacks it (every collector tick and after every change). The page
      shows the servers asked now, and warns when there are none (a WAN
      with a fixed address learns none). Tried on the VM: each mode, a
      resolvd restart, a reboot, and back.
  - [ ] It isn't a file, so a commit's review shows no diff for it and
        a revert puts it back only through the model (a tick later).
  - [x] "Only these": the WAN's servers are kept out too. OPF writes
        /etc/dhcpleased.conf with `ignore dns` for each interface on
        DHCP (checked with dhcpleased -n, then a SIGHUP), and removes it
        to undo; dhcpleased withdraws the lease's servers on the HUP and
        proposes them again at once when the file goes (seen on 7.9).
        Tried on the VM with these servers and with its own resolver.
  - [ ] A WAN on IPv6 autoconfiguration can still bring servers from
        router advertisements (slaacd, which has no such option); the
        page says so. Not tried: the VM's WAN has no IPv6.

DNS blocklists (ad and tracker blocking in the resolver; unbound 1.26.1
in 7.9 has RPZ, response policy zones, through its respip module):

- The downloader is built (Done): OPF downloads every list, whatever
  its format, and writes the zones. Still to do:
- [ ] Let unbound download RPZ-format lists itself (`rpz:` with `url:`),
      in its chroot as `_unbound`, so OPF never touches their data.
      Check first that unbound's HTTPS download works in the chroot (it
      needs a CA bundle, `tls-cert-bundle`); the status then comes from
      `unbound-control list_auth_zones`.
- [x] A list removed from the configuration loses its downloads (a
      blocklist's names and zones, a URL alias's table) once that's
      final: after its commit is confirmed, or applied without needing
      it, and on each refresher pass. Not while a commit is pending, and
      a list that's only turned off, or is in the staged configuration,
      keeps them.
- [ ] Allow a name from the blocked-queries log ("this broke
      something"). Your own blocked and allowed names are built (Done).
  - Regex entries, which Pi-hole has, aren't possible with OpenBSD's
    unbound: RPZ and local zones match exact names and wildcards only,
    and it's built without the Python module (`--without-pythonmodule`)
    that could match anything else. Say so on the page rather than
    offer them.
- [ ] Per network: apply lists only to some interfaces (the IoT VLAN
      but not the LAN, say) with unbound's views
      (`access-control-view`).
- Stats (queries blocked, top blocked names, which list blocked a name)
  are under Live data and monitoring › DNS, now and over time.
- [ ] Keeping devices on the resolver: an optional pf rule sending plain
      DNS (port 53) from inside networks to the firewall, and blocking
      DNS over TLS (853) outbound. DNS over HTTPS looks like any web
      traffic and can't be stopped this way; the page says so.
- [ ] Turning a list off changes unbound.conf and reloads every list
      (the review says how long DNS pauses). It could instead keep the
      zone loaded with `rpz-action-override: disabled` and use
      `rpz_disable`, at the cost of its memory; decide whether that's
      worth it.
- [ ] Memory and reload estimates (`ui/src/lib/dnsCost.ts`) come from
      one measurement (1,400 bytes and 24 µs a name). Measure a few more
      lists and a machine with less memory, and warn from unbound's own
      size once it's running rather than only from the estimate.

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
- [ ] **Nothing assumes a firewall** (Principles › 6): check each page
      and generator with a model that has one interface and no WAN, and
      fix what assumes otherwise (the dashboard's Internet tile, the
      anti-lockout rule on the LAN, NAT and the WAN rules, the default
      navigation).
- [ ] **Jobs** for an instance (firewall and router, web server, mail,
      DNS, VM host, file server...), chosen in the first-run wizard and
      changeable later. They order the navigation and dashboard and
      suggest what to set up, and never turn a feature off: any page
      stays reachable.
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
- [ ] **vmd** (virtual machines, with vmm(4) and vmctl), off unless
      asked for, for a few small services kept apart from the host. A
      deliberate trade-off: a vmm bug or a compromised guest sits on the
      box that guards the network (vmm has had security fixes), so the
      page says so before it's turned on.
  - Check the hardware first (VT-x with EPT, or AMD-V with RVI, in
    dmesg's vmm lines); many small firewall boxes have neither.
  - Guests are OpenBSD or Linux with a serial console only, one vCPU
    each, no device passthrough; say so rather than let someone find
    out.
  - Each guest gets a network of its own behind the firewall's rules,
    never the LAN's: vmd's local interfaces (a /31 each, NATed), or
    `tap` interfaces on a `veb` bridge (Interfaces › veb), with the pf
    rules and addresses generated like any other network's.
  - Managed: `vm.conf` (disks, memory, networks, boot image or ISO),
    disk images (`vmctl create`), start and stop, the console in the
    page (`vmctl console`, over a WebSocket through the parent), and
    each guest's status and resource use (`vmctl status`).

## Live data and monitoring

- [ ] The firewall log lags by up to a minute: pflogd writes
      /var/log/pflog every 60 s by default (`-d 60`), and the page reads
      the file. Read `pflog0` live from the parent (tcpdump on the
      interface), or give pflogd a shorter delay through rc.conf.local.
      Seen on the VM.

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
- [ ] Reverse DNS for the addresses on Connections (and the firewall
      log, a device's connections): a button or toggle that looks up
      each address's PTR name through the firewall's own resolver and
      shows it beside the address. Asked for, not by default: a lookup
      for every address on a busy table is a lot of queries, and they
      go out to the address's owner. Cache the answers for a while,
      in the web child's memory only.
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

DNS:

- [ ] DNS stats over time (the collector): queries, cache hits and
      blocks per minute, and blocks by list.
- Which device asked for a blocked name, and top names overall: under
  Per-device activity below.
- [ ] Blocked names older than the current daemon log (newsyslog
      rotates it at 300 KB, which on a busy network is an hour or less):
      with DNS activity on they come from its counts, as far back as
      it keeps; without it, read the rotated copies too.

Network, VPN and logs:

- [x] Interfaces OPF doesn't configure (a spare port, one set up by
      hand) are listed on Interfaces, "Not set up by OPF", with their
      link, MAC and addresses; a port can be set up there (name, role,
      address, starting from the one it has), with a warning when it
      has addresses set outside OPF. Loopback, enc, pflog and pfsync
      aren't listed.
- [ ] Setting up the other kinds found (a VLAN, bridge, carp or tunnel
      configured by hand) as they are, which is import (Parser and
      import).
- [ ] Gateway health is a ping per request, cached 10 s. A real monitor
      (dpinger-like, in the collector) would keep loss and latency over
      time and could drive gateway-group failover (Models and
      generators › Multi-WAN).
- [x] System logs (System › System logs, `GET /api/logs/system/{log}`):
      messages, daemon, authlog, maillog and dmesg, the last 5,000
      lines read as root, filtered by text and program on the firewall,
      cleaned, newest first (the kernel's in its order), with follow.
      Read correctly on openbsd-dev.
- [ ] The rotated copies (`messages.0.gz` ...) for further back, and a
      download of a whole log.
- [ ] Logins (authlog) are personal data: once there are accounts, only
      admins read them (Security › User accounts).

Diagnostics tools (everything in the base system that helps someone
work out what's wrong, each with a form rather than a command line):

- How they run is built (`internal/diag`, Monitoring › Tools): the
  parent builds a fixed argv from checked fields, with `--` before the
  host, a time limit, at most four at once, output capped and cleaned
  and fetched by the page as it arrives. New tools go in
  `diag.Tools`, with a streamed simulation in `cmd/opf/mockdiag.go`
  and `ui/src/lib/localTools.ts`.
- [ ] Tools that change something (flushing a cache, waking a device)
      say what they'll do before they do it, and later need the
      operator role (Security › User accounts).
- [ ] Record each run in the event log once there's one.
- [ ] A source address or interface for ping, traceroute and the port
      test (`-I`, `-s`), chosen from the interfaces, so a test can
      leave from the LAN side.
- [ ] More links in: ping or trace from a DHCP lease, an ARP entry, a
      connection or a log entry.

Reachability:

- [ ] Traceroute to a TCP port (`-P 6 -p <port>`), which gets through
      where UDP and ICMP are dropped.
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

- [x] Resolver tools, the DNS page's Tools tab: where unbound would
      ask for a name (`lookup`), what it has cached for it and under it
      (`dump_cache`, filtered on the firewall), its local zones and data,
      and forgetting a name, a zone, failed DNSSEC answers or "no such
      name" answers (`flush`, `flush_zone`, `flush_bogus`,
      `flush_negative`), each after saying what it does. Forgetting runs
      as an action, so `-dry` logs it; a name is checked as a DNS name
      so it can't be read as an option. The cache view is tested
      against 7.9's own `dump_cache` (records without their signatures,
      and each kept answer as one line).
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

Storage:

- [x] System › Storage: everything that fills up as the firewall
      runs, what it holds now and the most it can, with a bar each:
      pf's state table, tables and table entries against its hard
      limits; OPF's graphs (memory and saved), event log, DNS activity
      and its unread log, change history and downloaded lists; the
      logs OPF reads with their old copies against newsyslog's sizes;
      OPF's memory and the disk its state is on. Tried on the VM, under
      the sandbox. The graphs by what they record (the firewall's,
      DNS's, the system's, then each capped kind), and each row says
      where its limit is set, linking to the card (#id; the layout
      scrolls to it), or why there's no setting.
  - [x] Tried on the VM: the graphs' rows with the VM's own sizes, and
        every "Set under" link lands on its page and on its card.
- [ ] Warn somewhere people look (the dashboard, an event) when one is
      near its limit, pf's state table above all.
- [ ] pf's source nodes and fragments: their limits are there, their
      counts aren't read yet.

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

- The collector is built (`internal/metrics`, `internal/appliance/
  collect.go`): every 10 s, rings of an hour at 10 s, a day at 1 min, a
  week at 10 min and a month at 1 h, at most 256 series (about 110 KB
  each), saved to `metrics.bin` in the state directory every 5 minutes
  and when OPF stops, in a format whose every count is checked on
  reading (gob looped for ever on a damaged file). It keeps interface
  traffic, CPU, memory, load, pf states and blocks, DNS queries, blocks
  and cache hits, gateway latency and loss, WireGuard peers' traffic
  and handshake age, packets per labelled rule, DHCP leases in use per
  network and the clock's offset (the slower ones every 30 s).
  `GET /api/metrics`, Monitoring › Graphs, the dashboard's traffic
  chart, and a graph where each number is shown (the DNS page,
  Routing's gateways, an interface, a DHCP network, a rule, a VPN
  device), with peaks dashed for traffic and latency. It ran on 7.9
  (`-dry`): every series, the file under unveil, about 1% of a CPU.
  Loopback, enc and pflog aren't kept.
- Each kind of thing has its own cap (interfaces, gateways, VPN
  devices, DHCP networks, rules, and the fixed system series), set on
  System › General (`system.graphs`) with what each costs in memory at
  most; rules keep only 10-minute and hourly rings. A group at its cap
  says so in the log once, on System › General, and in a rule's tooltip.
- [ ] Say where else a group is full: an interface card, a VPN device
      or a DHCP network without a graph should say why, as a rule does.
- [ ] What else to collect (what's above is collected):
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
      - **Per host**: traffic per inside address and top talkers, under
        Per-device activity below.
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
        validation failures, and queries blocked, in total and by
        blocklist (is a list worth its memory?). Top domains, top
        blocked names and queries per client are under Per-device
        activity below.
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
- The event log is built (`internal/appliance/events.go`,
  `eventwatch.go`, Monitoring › Events): links going down and up, a
  DHCP address changing, gateways stopping and answering again, a
  device seen for the first time (by MAC, named from its lease), a VPN
  device connecting from a new address, dhcpd, unbound and ntpd
  stopping, list downloads failing and recovering, new security patches,
  OPF starting, and every commit (from history). The newest 5,000, none
  older than 90 days, in the state directory; OPF's first look takes
  what's there as known. Graphs mark the events about what they show.
- Webhooks send events as signed JSON (System › Notifications;
  `internal/webhook`, `internal/appliance/webhooks.go`). Which webhooks
  and which events are in the model; each URL and key are secrets in
  the state directory's `secrets.json` (root only), never in an API
  answer, the history or its diffs, set at once and shown after only as
  scheme and host. The sender is OPF's binary as the unprivileged user,
  pledged to stdio, rpath, inet and dns and unveiled to the CA bundle and
  resolver files, handed the delivery on stdin; redirects aren't
  followed. Retries at 10 s, 1 min, 5 min, 30 min and 2 h, then dropped.
- Slack, Discord and ntfy are formats of a webhook (`webhookformat.go`):
  messages made harmless for each (no Slack or Discord mention from a
  name a device chose, no header from a line break), ntfy with a title
  and a high priority for problems. Checked against a local receiver;
  not yet against the services themselves.
- [ ] More formats: Microsoft Teams, Pushover, Gotify, and email
      (smtpd).
- [ ] WireGuard private keys (Security › Secret storage) could live in
      the same write-only store as webhook secrets.
- [ ] More events: CARP state changes, media changes (a link falling to
      100 Mbit/s), a pool running out of leases, a login once there are
      accounts, a disk filling, a sensor too hot.
- [ ] Say on the event log's page what devices a MAC address was seen
      as since, from the leases and the ARP table (an inventory).
- [ ] **Privacy**: per-host traffic, DNS names, new-device tracking and
      logins are personal data. Each gets a retention limit, shorter
      than the rest, and the most sensitive (DNS queries per client and
      top domains) are off unless the admin turns them on, saying what
      is kept and for how long. Deleting a device's history should be
      possible.
- [ ] Graphs for rules and hosts, once those are collected, and a
      custom time range beside the hour, day, week and month.

Per-device activity (what each machine on the network does: its DNS
names and its traffic, and the top names overall). Everything here is
under Privacy above: off until the admin turns it on, kept for a short,
set time.

DNS activity is built (`dns.activity`: `internal/activity`,
`internal/appliance/dnsactivity.go`, DNS resolver › Activity, and its
setting under Settings), and tried on 7.9 with the real unbound:

- [x] **Collecting it.** 7.9's unbound is built without dnstap (no
      `--enable-dnstap` in `unbound -V`; with `dnstap-enable: yes` it
      stops at startup, "dnstap enabled in config but not built with
      dnstap support", though `unbound-checkconf` passes that config).
      So while it's on, unbound logs to its own file
      (`/var/unbound/db/opf-dns.log`, `use-syslog: no`, `log-replies`,
      `log-tag-queryreply`), which the collector reads every tick and
      empties past 4 MB once it's read to the end. unbound appends, so
      truncating leaves no hole; a reload reopens the file. OPF makes
      the file 0600 (unbound makes it world-readable, in a directory
      anyone can list) and passes unbound's other lines on to its own
      log, so they still reach the daemon log.
  - [x] unbound never goes back to syslog on a reload, only reopens its
        file: turning activity off left it writing every query to the
        deleted file. Changing where it logs restarts it now
        (`RestartIf` in the registry), on commits and reverts.
  - [ ] Whether `log-replies` is cheap enough on an APU-class box with a
        busy network; the 4 MB truncation has been tried with a test
        file, not under real load. On the VM (one vCPU, under 110
        answers a second on loopback, so the VM is the limit) it made
        no difference beyond the noise, OPF's reader using under 1% of
        the CPU, and every answer was logged (unbound's own query count
        against the lines). A load generator must send raw packets: Go's
        resolver answers some names itself and merges identical
        lookups in flight.
  - [ ] The other lines unbound logs go to OPF's log at most 50 a tick;
        say so when some were dropped.
- [x] **Who a device is.** A MAC address from the DHCP leases or the ARP
      table, a VPN device by its peer's address, the firewall itself
      for loopback, or else the address. An address not known yet is
      looked up again (at most every 10 s), so a device that has only
      just asked isn't filed under its address. Named from DHCP
      reservations, then the lease's name in DNS or the one it asked
      for. Found the ARP table's parser didn't read OpenBSD's table
      format (it expected other BSDs' `? (addr) at` lines), so
      Devices › ARP table was empty on a real firewall; fixed.
- [x] **What's kept.** By hour: queries, blocked, allowed, NXDOMAIN (not
      counting blocks), SERVFAIL and cached, for the network and each
      device, and blocks by list. By day: the names looked up, blocked
      and not found most, Space-Saving top lists (200 for the network,
      25 a device), at most 128 devices a day by default (the rest
      pooled as "other"; `maxDevices`, up to 4,096, each about 5.6 KB a
      day at most; traffic's default is 512, at about 140 bytes a device
      an hour), at most 31 days.
  - [ ] Try the device caps on the VM: a low cap (2, say) with more
        devices than that, for DNS activity and traffic, to see the
        rest pooled as other devices; only tests and the mock have. The
        VM's LAN has one client, so this needs more addresses on the
        host's side of the LAN (aliases on its tap), which is a change
        to the host to ask for first. In `dns-activity.json` in the state
      directory, with the place in unbound's file so a restart doesn't
      count lines twice. DNSBlocked reads from it while it's on.
- [x] **The pages.** Activity: counts, an hourly chart, the names looked
      up, blocked and not found most, and devices, each with its own
      view and "Forget this device". Each of the network's names opens
      when it was asked for (by hour) and the devices that asked most:
      every name in a day's lists keeps 24 hourly counts and its ten
      top devices (Space-Saving), counted from when it entered the
      list. That's at most about 300 KB a day; a worst-case day is
      about 1 MB saved and a worst-case month about 32 MB, under the
      64 MB Load reads (`TestStoreWorstDaySize`).
  - [x] Each kind's retention is its own setting: the counts and top
        names (`days`), each device's (`deviceDays`) and the names' when
        and who (`detailDays`), the last two at most the first. The
        setting shows what the choice costs at most (from the measured
        worst case: 65 KB a day for the network, 307 KB for the when and
        who, 5.7 KB a device; memory about what's saved,
        `TestStoreWorstDayMemory`) with this network's devices, what's
        kept as last saved, and warns when that's much of the RAM, /var
        is short of room, or the CPU looks low-power (a GX-, Atom,
        Celeron, J/N-series or ARM chip, or two CPUs or fewer).
  - [ ] Keep the when and who only for the names the page can show (the
        top 50), which would quarter it. The setting says what keeping it
      means; turning it off, or devices off, deletes what was kept;
      "Delete what's kept" deletes it now.
- [x] **API and roles.** `GET /api/dns/activity`, `/device`, `DELETE`,
      admin only (the overall top names too), never in webhooks.
- [x] A device's page (Devices, and one device's page):
      who it is (its DHCP lease and reservation, ARP entries, the
      network it's on, its VPN tunnel and its state now, when it was
      first seen), its traffic and DNS activity where kept (admins),
      its connections now, its events and its firewall log, together.
      Linked from the Traffic and DNS activity device views, the DHCP
      leases and the ARP table. Tried on the VM: a LAN device by ARP,
      VPN devices with their tunnel's state.
  - [x] A VPN device's graph through its tunnel; the firewall rules and
        port forwards that name a device (by its address or its
        reservation's, a network it's in, or an alias holding either,
        those naming it exactly first); and where its name came from
        (its reservation, its lease's name in DNS, what it calls itself
        when DNS has no name for it, the VPN device's), the list marking
        a device's own name.
  - [x] Tried on the VM: the rules card (the port forward to the LAN
        device), a VPN device's tunnel graph and handshake, and the
        links from WireGuard, Events, ARP and the DNS activity drawer.
        Found and fixed there: ARP linked the firewall's own addresses
        and the WAN's neighbours, which aren't devices; a MAC OPF
        doesn't count as a device (the WAN's gateway, which an event
        links) said "None now" though ARP had it; and the firewall log
        card broke addresses across lines.
  - [ ] Still to see on the VM: a name's source, and DHCP's links,
        which need a device with a lease (the VM's LAN client has a
        fixed address).
- [ ] "Never block" from the Activity tab's blocked names, as Blocking's
      list has.
- [ ] A rising NXDOMAIN rate on one device as an event (often malware);
      the Activity tab only marks a device most of whose lookups fail.
- [ ] Top names by hour for "today": the top lists are by day, so
      "today" is since midnight, not the last 24 hours.

Traffic per device is built (`firewall.traffic`: `internal/activity/
traffic.go`, `internal/appliance/traffic.go`, Devices › Traffic,
its setting on Firewall › Settings), and tried on 7.9:

- [x] **Collecting it.** pf's table counters (`table <opf_hosts>
      persist counters`) with, on each inside interface, `match in on
      $if from <opf_hosts>`, `match out on $if to <opf_hosts>` and a
      catch-all `match in on $if from ! <opf_hosts>` for addresses not
      in the table yet; match rules, so they change nothing else.
      Tried on the VM before building on it: pf updates the counters
      for every packet of a connection (4 MB up showed 4,348,092
      bytes), both ways (In is what the host sent, Out what it got),
      outgoing through NAT and incoming through a port forward,
      between two inside networks each host once, a static host with
      no lease too; counters survive ruleset reloads, and a table
      declared empty keeps what was added at runtime. Every collector
      tick OPF reads the counters into the hour by device (the same
      devices as DNS activity: devices.go), adds the devices on the
      inside networks the leases, ARP and VPN show, and takes out
      those not seen for an hour after reading their last counts.
      Tried after building: 3 MB up, 2 MB down and 1 MB in through a
      forward counted to within headers; a restart counts nothing
      twice (the counters as last read are saved); turned off, the
      rules, the table and what was kept go.
- [x] pflow, checked against these claims on the VM: only states of
      rules marked pflow (or state-defaults) are exported, each when
      pf removes it, about 90 s after a TCP connection closes
      (tcp.closed), never while it's open; one record per direction
      with the inside address before NAT and a template carrying the
      translation. bpf on pflow0 fails on 7.9 ("Device not
      configured"), despite pflow(4); the export can be captured on
      lo0. Not used: the table counters are complete and current.
- [ ] Traffic per destination (country, port, the names DNS activity
      saw), top talkers as an event when one moves far more than its
      usual, and per-device retention apart from the network's.
- [x] The firewall's own traffic as a row: what it starts itself (its
      lookups for devices, updates, downloads, time), from `match out
      from (self)`'s counters, before the NAT rules so a device's
      connection leaving with the WAN's address isn't the firewall's;
      apart from the devices' total. Tried on the VM: its own 2 MB
      download on its row, a device's 1 MB out through NAT and 1 MB in
      through a forward not.
  - [ ] Its counters start again when a commit reloads the rules: up
        to a collector tick (10 s) of it is lost then. A table with
        counters, as the devices', would keep it.
  - [ ] Connections to it from the internet (SSH from the WAN, a VPN
        device's tunnel) aren't on its row: pf sees a port forward's
        connection as one to the WAN's address at that point. A VPN
        device's traffic is on its own row anyway.
- [ ] IPv6, once OPF forwards it.

- [ ] **Storage.** Not the graphs' rings: they're capped at 256 series,
      and a series per device or name would fill them. Hourly buckets
      per device in their own file in the state directory, with a cap
      on devices and on its size shown on System › General (as the
      graphs' caps are), the oldest buckets dropped first. Retention
      set per kind (DNS shorter than traffic by default).
- [ ] **Forgetting.** Delete one device's history from its page, and
      everything at once; turning a kind off deletes what it kept,
      after saying so.
- [ ] **API and roles.** `GET /api/activity/...` for devices, names and
      talkers. DNS names per device are the most personal data OPF
      holds: admin only, or a role of its own, and never in webhooks.

## UI

- [ ] **The DNS page's layout** is out of line with the other service
      pages. DHCP and WireGuard use tabs only for separate things (an
      interface, a tunnel), and within one: the graph across the page,
      then Settings (5/12) beside the list the admin adds to (7/12),
      then the list that grows on its own across the page. DNS has
      Overview, Local names and Settings as tabs of one resolver,
      Settings among them. Match the others: Resolver, Blocking, Tools;
      in Resolver the numbers and graph, Settings beside Local names
      (descriptions under each name, and each domain's choice under
      it, to fit 7/12), then Devices' names. Tried and dropped on the
      way: everything on one tab with Local domains as a card beside
      the settings (heights never matched), and settings in a rail on
      the left (long, and Local names cramped).

- Page order, for pages that show a service's state and its settings
  (DNS, DHCP, WireGuard, Routing): what's happening now (its numbers and
  graph) first, then its settings, then the lists that grow on their own
  (connected devices, leases, blocked names). A growing list above the
  settings would push them down as devices connect, and an admin would
  have to hunt for them. Lists only the admin adds to (reservations,
  host names, blocklists) can sit beside the settings.
- The sidebar is grouped by what a page is about, not by whether it
  shows state or settings: Devices (all devices, their traffic, ARP),
  Network, Firewall (with its connections and log), Services,
  Monitoring (graphs, events, tools), System (with its logs, files and
  storage). Diagnostics held eleven pages and grew with every feature.
  The old /diagnostics/... addresses redirect.
- [ ] A command palette (Ctrl/Cmd-K) for getting around: every page
      by its name and section, and things by name (an interface, a
      tunnel, a VPN device, a device, an alias, a rule), opening the
      page that has them. Mantine has Spotlight for it.
- [x] A device page's DNS card shows one of its top-name lists at a
      time (Looked up, Blocked, Not found, each tab with how many), as
      a table: the name, a bar for its share of the first, and the
      count close by; blocked names say which list blocked them, and
      an empty list says what that means ("Nothing blocked."). The
      three side-by-side columns ran together.
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

- Responses are gzipped (`internal/web/gzip.go`). None carries a secret
  today; one that ever does (a private key to download, a CSRF token in
  a body) must call `noCompression`, or its compressed size can leak it
  next to text an attacker influences (BREACH). Sessions go in cookies,
  which aren't compressed.

### User accounts

Built (2026-09-30), as sketched below: system accounts in `_opfadmin`,
`_opfoperator` and `_opfview`, checked in the parent with the
account's login style (`internal/auth`); sessions in the parent, every
RPC carrying its token and checked against a role per method
(`internal/privsep/auth.go`, a test makes sure no method is left out);
the `__Host-opf` cookie; backoff per name and address, failures
padded to a second; the session ending idle (only active use counts),
at 12 hours, and when the account changes; TLS with a self-signed
certificate unless on loopback; the sign-in page; commits' authors
and who confirmed or reverted, from the session; sign-ins in the event
log (kind `login`, so webhooks can send them). See docs/api.md.

Still to do:

- [x] Signed in on openbsd-dev (7.9), under pledge and unveil, over
      the self-signed certificate (its served fingerprint matched the
      logged one), with a temporary account in `_opfadmin`, since
      removed: a wrong password refused after 1.1 s, the right one an
      admin session, signing out ending it, and taking the account out
      of the group ending its session within the minute.
- [ ] No HSTS: with a self-signed certificate it would stop anyone
      clicking through the browser's warning, and so lock them out.
      Send it once the certificate is one they put there (or ACME).
- [x] Sign-ins and account changes go to authlog too, through
      logger(1) on stdin (the parent's pledge has no "unix" for
      /dev/log, and Go can't make OpenBSD's sendsyslog(2) call); -dry
      only logs it.
- [ ] The certificate is made for `localhost, 127.0.0.1` even when
      OPF listens on every address (`-listen 0.0.0.0:443` on the VM), so
      a browser at the LAN address warns about the name as well as the
      issuer. Add the host name and the model's interface addresses,
      and make a new one when they change.
- [ ] OPF listening on one address (`-listen 192.168.1.1:443`) that a
      commit moves stays bound to the old one, so the page at the new
      address (which the review dialog points to) doesn't answer, and
      the change undoes itself. Listen on every address and let pf
      decide, or rebind when the model's addresses change.
- [ ] A line sent through logger(1) can time out (`logger: context
      deadline exceeded`, seen on the VM while it was busy after a boot)
      and is then lost; an audit line shouldn't be. Retry it, or queue
      it to retry.
- [ ] Under rc.d, OPF's log lines carry a second timestamp after
      syslog's (`opf[25302]: opf: 2026/10/05 15:10:18 …`): drop Go's
      date and time when the output goes to logger.
- [x] Roles in the UI: a banner says what your role can do, edits are
      refused before they're made, Apply is disabled, and Users is only
      in the menu for admins.
  - [ ] Still shown to every role: each page's own buttons (Add,
        Save, Run). They say no when used; hide or disable them.
- [x] Sessions: an admin sees everyone's on Users, and ends them;
      everyone sees and ends their own on General.
- [x] **User and role management** (System › Users), built as below,
      with re-authentication (five minutes, signing in counting) for
      every change, and your own password on General.
  - [x] Tried on openbsd-dev (7.9) with throwaway accounts, since
        removed: `groupadd -g`, `useradd -p` (hash from `encrypt` on
        stdin), `usermod -S`, `-p`, `-Z` and `-U`, `userdel -r`, and
        `logger` into authlog; passwords checked by the real
        `login_passwd`, a locked account refused, the guards held, and
        signing in and the accounts API worked under pledge and unveil.
        It found three things, fixed: an account left with the id of a
        deleted group became an admin when `_opfadmin` was given that
        id, so only being listed in a group counts now, and OPF's
        groups take an id from 999 down that nothing uses; `userdel -r`
        leaves the account's own group, which removing now deletes too;
        and `-Z` appends "-" to the shell rather than prefixing it.
        Accounts with no password (only stars, like a key-only one) say
        so, and nobody (32767) isn't offered a role.
  - [ ] Under -dry an account change is only logged, but OPF still
        notes the account as one it made (accounts.json).
  - [ ] `useradd -p` and `usermod -p` take the hash as an argument,
        which any local user can see in ps for an instant. Writing
        master.passwd through `pwd_mkdb -p` (as vipw does) would keep
        it off the command line.
  - The plan it followed:
  - OPF's groups don't exist until someone makes them. Create
    `_opfadmin`, `_opfoperator` and `_opfview` at install (or first
    start), and say on the sign-in page, until someone's in one, how to
    add the first admin from the console (`usermod -G _opfadmin name`).
  - List who can sign in: each member of the three groups with their
    role, whether the account is locked or expired, its login class
    and style, and when they last signed in (from the event log).
  - Add an account: name, full name, role, password (twice), and
    whether it can also log in over SSH (a shell) or only here
    (`/sbin/nologin`). Through `useradd` with the password hashed by
    `encrypt(1)` on stdin, so only the hash is ever on a command line.
  - Give an existing system account a role, or take it away, without
    touching anything else about it: OPF only changes membership of
    its own groups, never wheel or other groups.
  - Set someone's password (an admin), or your own (everyone, asking
    for the current one); lock and unlock (`usermod -Z`/`-U`); remove
    an account OPF created. Removing an account it didn't create only
    takes away its role.
  - Guards: the last admin can't be removed, locked or demoted, nobody
    can take away their own admin role, and root and the system's own
    accounts (uid below 1000, `_`-prefixed daemons) can't be given a
    role.
  - Applied straight away, not staged: accounts aren't the network
    configuration and don't belong in its history or its revert. Each
    change goes in the event log (kind `login`, or its own) with who
    made it, and asks for the admin's password again (re-auth below).
  - Ending sessions follows: a role taken away or a password changed
    ends that person's sessions at once, not at the next minute's
    check.
  - Each operation an RPC method of its own, admin-only in
    `methodRoles`, with the arguments checked in the parent (names by
    the same pattern as `auth.BSDAuth`, roles from the fixed three):
    the web process can't name a file, a group or a command.
  - Open: whether to keep three fixed roles, or later per-area
    permissions (DNS only, firewall read-only); and the first-run
    wizard making the first admin.
- [ ] Re-authentication for the other sensitive actions (disabling the
      firewall, restoring a backup), API tokens and two-factor, as
      below.

The design: Today anyone who can
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

- [x] The bsd_auth helper rather than cgo: `login_<style> -s response` with
      "\0password\0" on descriptor 3, answering "authorize" or
      "reject" there; checked on 7.9. The parent unveils
      /usr/libexec/auth to run it, and reads master.passwd (the login
      class), group and login.conf. An unknown user is refused in 0.02 s
      against bcrypt's 0.07 s, hence the padding to a second.
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

OPF has run as root on OpenBSD 7.9 (`openbsd-dev`, as `opfdev`, who
has passwordless doas) with `-dry -checks`, a scratch `-root` and
`-state`, and the web process as `opfdev` (downloads run as it too):
pledge, unveil and the
privilege drop hold; status, pf, the tools, commits, confirm, revert
and the automatic revert all work; and the real `pfctl -n`, `dhcpd -n`,
`unbound-checkconf` and `ntpd -n` judged the generated files. How:
`GOOS=openbsd go build -tags embedui`, copy it with a seed root (the
mock's), start it with doas and nohup, and tunnel 127.0.0.1:18090.
Stop it by the PID it wrote; never pkill.

- [x] Test pf.conf with the real `pfctl -n` on a model whose interfaces
      exist on the test host: done on the VM (vio0 and vio1), where it
      found that a static `$lan` failed the check before the commit gave
      vio1 its address (now always in parentheses).
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
- [ ] unbound's lines in `/var/log/daemon`, as syslogd writes them.
      The DNS page's "Blocked most" (`DNSBlocked`, `sysinfo.ParseRPZLog`)
      and System logs › Daemons read them, expecting
      `Sep 29 10:00:00 host unbound: [pid:tid] info: rpz: applied
      [opf:list:<id>] <entry>. rpz-local-data <client>@<port> <name>. A IN`.
      The message is as unbound 1.26.1 wrote it on 7.9 (captured from its
      own logfile, to keep the host's syslog untouched); the prefix before
      it (`unbound: [pid:tid] info:`) is only what unbound's log.c and
      syslogd should write, never seen. If it differs, no blocked name is
      ever counted, silently. To check, on a host where it's fine to
      write to the system log: run unbound with `use-syslog: yes` and
      OPF's rpz sections (or let OPF run the real resolver with a
      blocklist), look up a listed name, then read the line in System
      logs › Daemons and see "Blocked most" count it. Keep a captured
      line as a fixture in `testdata/openbsd-7.9/`.
- [x] The webhook sender on OpenBSD 7.9 (`-dry` on openbsd-dev): under
      its pledge and unveil it resolved names and made a verified TLS
      connection (example.com), refused unknown hosts, closed ports and
      forbidden headers, with no violations in dmesg; started by the
      parent as the unprivileged user (seen in ps, with no URL on its
      command line), it delivered a signed test, an ntfy one, and a
      commit through the queue, all valid; secrets.json was root's,
      mode 0600, and the secret was in no other file or the log.
- [ ] `pfctl -k id -k <id>/<creatorid>` takes the creator id in hex, as
      `-vv -s states` prints it.
- [ ] Status parsers on other hardware: `hw.sensors` from real sensors
      (temperatures, fans, volts, drives), `df` with more filesystems,
      `swapctl` with two devices, and a release other than 7.9.
- [ ] `ping6` for an IPv6 gateway (openbsd-dev has no IPv6 route), and
      `kern.boottime` read in the parent's time zone matching the
      system's.
- [ ] `syspatch -c`'s error when the mirror can't be reached (its
      output with patches available is in
      `internal/sysinfo/testdata/openbsd-other/`).
- [ ] Parent pledge and unveil on paths not yet exercised: removals,
      and reading `/var/log/pflog` when pflogd rotates it (applying for
      real and `hostname.if` changes worked on the VM; not yet under
      ktrace).
      Run under `ktrace -i` and look for `PLDG` in `kdump`: a violation
      kills the process with SIGABRT and nothing in OPF's log.
- [x] Unveil paths exist on a stock install, and `os.Executable` is
      right when started from rc.d: installed by the README's steps on
      a fresh 7.9, it started and served.
- [ ] rc.d script: `rcctl stop` reverts an unconfirmed commit (seen at
      a reboot); still to check that `pexp` matches both processes and
      nothing is left behind.
- [ ] Each validator works on a file outside its usual location:
      `pfctl -n -f`, `dhcpd -n -c`, `unbound-checkconf` and
      `ntpd -n -f` do (checked on 7.9); still to check `httpd -n -f`,
      `sshd -t -f` (host keys, `Include`), and `sh -n` on hostname.if.
- [x] Real commits on a VM that can be locked out safely (`opfvm`, see
      the Roadmap): installed from the README on stock 7.9, the first
      commit took over the stock files (with `overwrite`) and brought up
      the LAN; signed in over it and confirmed. Every file, pf's rules,
      dhcpd, unbound (names and reverse names from the LAN) and
      rc.conf.local (OPF's own lines kept) matched. Revert and the
      automatic revert put pf, the files and the model back and staged
      the change again; while waiting, `/etc/pf.conf` kept the old
      rules. Closing WAN SSH came back by itself; moving the LAN's
      address came back by itself after the fix, also across a reboot
      (reverted as OPF stopped) and a power-off (reverted by `Recover`
      at boot). Killing the web process changed nothing; killing the
      parent left the commit loaded until a watchdog was added (Done).
      Found and fixed: a crash before the first commit, the static
      `$lan` above, interface changes with no confirmation, reverts
      leaving created interfaces up, and "Reverted by user" for a stop.
      The VM's clock runs at half speed (only i8254), so its 60 s take
      two minutes.
- [x] The VM as a router, with a device on its LAN (the host's LAN tap
      in routing domain 2, and a small DHCP client): a lease with the
      router, resolver and domain; its name in DNS forward and back
      (about 7 s after the lease); a blocked name answered 0.0.0.0; NAT
      out; a rule blocking one port, with its counter and its line in
      the firewall log; a port forward from outside and reflected from
      the LAN. Found and fixed: no IP forwarding, and blocking a first
      name failing the commit (unbound-checkconf and the staged zone).
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

With `-root`, pf.conf still names `/var/opf/tables/<name>`, so
`-checks` reads the real path, not the scratch copy; and `-dry` logs
`unbound-anchor`, so with `-checks` and DNSSEC on, unbound-checkconf
still refuses on a host without a root.key.

Found and fixed by running on 7.9 (kept here as what to look for):
the web user was looked up after unveil hid /etc/passwd; the parent
took the listener's file, and built the RPC connection with
`net.FileConn`, after pledging without "inet" (both call getsockopt);
the child was started with `Dir: "/"`, which unveil hides; gob dropped
every zero across the RPC, so exit status 0, 0 bps and a handshake 0
seconds ago arrived as "unknown"; and `-dry` still closed connections
for real; a URL alias's list was never downloaded, so pfctl refused
the ruleset; and unbound-checkconf refused until unbound-anchor had
run.

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

WireGuard:

- [x] Ways out through a VPN provider (a tunnel with `exit`): paste
      the provider's WireGuard configuration, and the networks picked
      reach everything beyond your networks through it, appearing at
      its address, while OPF's own traffic keeps the main table and the
      WAN. Their traffic goes to a routing table of its own (200 plus
      the device's number) whose only route is into the tunnel, chosen
      by pf match rules ahead of the user's, which still decide what
      may pass; NAT to the tunnel's address and an MSS clamp to fit
      WireGuard's MTU; the provider's private key imported and kept
      root-only like OPF's own; the provider's resolvers, when given,
      reached through the tunnel by OPF's resolver, so devices keep
      using OPF's names and blocking. The kill switch is the routing
      itself (the table has no other way out), with pf blocking the
      other ways out as well. Tried on the VM against a stand-in
      provider on the host: a LAN device's connection arrived from the
      tunnel's address while OPF's own left by the WAN from its own;
      the resolver's lookups reached the provider through the tunnel;
      with the provider gone, or the tunnel interface down, nothing of
      the LAN's left by the WAN, and it came back by itself; removing
      the way out took the interface, its table's route, the rules and
      the forwarding with it.
- [x] A tunnel reachable from other networks ("Reachable from": LAN or
      optional interfaces): their connections to the tunnel's devices
      go in from OPF's address on the tunnel, so a device that only
      routes and accepts the tunnel's addresses (WireGuard drops any
      other source) can answer. Any tunnel, whatever the outbound NAT
      mode; the sites behind its routers keep being routed with real
      addresses (on the VM a LAN device's packets reached a site
      router from their own address). The rules of the network reaching
      in decide what may, and the tunnel's devices still can't start
      anything towards it. The WireGuard page names the route a router
      in front of OPF needs. Tried on the VM: a device configured to
      accept only the tunnel got nothing from a LAN device without it,
      and its connection, from 10.8.0.1, with it; told to send
      everything into the tunnel, it still couldn't reach the LAN.
- [x] Devices kept to their VPN ("Only this VPN", a device's route
      choice beside "Your networks", "All traffic" and site-to-site):
      such a device reaches the tunnel's network, and of OPF only DNS
      there, whatever rules or its own configuration say; blocks on its
      address before every user rule, and its configuration routes only
      the tunnel. Per device, so one tunnel can mix them; the sites
      behind the tunnel's routers aren't part of it. (First built per
      tunnel, with the sites included; changed before it was pushed.)
      Tried on the VM with two devices on one tunnel, both configured to
      send everything into it: the VPN-only one reached the other
      device and OPF's resolver, and not OPF's web interface, a LAN
      device, the site, or the router; the "your networks" one reached
      the LAN and the web interface as before.

Commit engine:

- [x] What goes away is taken down before anything is brought up, when
      committing and when reverting: a fixed gateway given up for DHCP
      is deleted before the interface asks for a lease, whose route goes
      through the same router. An interface given a fixed address after
      DHCP (or SLAAC) has autoconf turned off first, and dhcpleased
      given time to let go: netstart left the flag on, and when it went
      dhcpleased deleted the address and default route, even ones also
      set by hand. Tried both ways on the VM.
- [x] The default gateway takes effect on commit: netstart only ever
      adds it (`route add` does nothing when a default route exists),
      so changing it waited for a reboot. `mygate` now sets the route
      itself (change, else add), after the interfaces, and waits for
      confirmation; removing it deletes the route through that gateway
      only (dhcpleased's have the same priority). A revert puts every
      file back first and then applies them in the commit's order, so
      the old gateway is reachable again before it's set. A fixed
      default gateway while an interface uses DHCP is refused: netstart
      ignores mygate then.
- [x] A commit's watchdog: the parent holds an flock(2) lock on its
      state directory for as long as it runs, and a commit that waits
      for confirmation starts `opf -watchdog <id>` (root, its own
      session, the parent's sandbox plus "flock"). Just after the
      deadline it takes the lock if it can, which means the parent is
      gone, and reverts what's left as `Recover` would. Tried on the VM:
      with the parent killed by SIGKILL, WAN SSH came back 15 s after
      the deadline without OPF running. The lock also makes a second
      OPF wait two minutes (a watchdog may be reverting) and then
      refuse.
- [x] Interface changes wait for confirmation: `hostname.if` files are
      installed at once (netstart only reads /etc), and unless the
      commit is confirmed they're put back and netstart runs again; a
      file the commit created is removed and its interface destroyed.
      After a reboot during the wait, OPF reverts them as it starts.
      Tried on the VM by moving the LAN's address.
- [x] Outside changes are judged against the copy OPF last wrote (the
      newest commit's, or the old one it put back after a revert or a
      failure), so an OPF upgrade that changes a generator's output
      doesn't make every file look hand-edited. Files no commit has
      touched yet are still judged against what the applied model
      generates.

Configuration files:

- [x] System › Configuration files: every file the configuration
      manages, grouped by what it's for, as it is on the firewall (with
      line numbers and a copy button), with the staged change to it and,
      for one changed by hand, a diff from what OPF last wrote, the same
      check staging uses. Read only through the parent, and only the
      files it lists. Each service links to its own (DHCP, DNS, General,
      each interface and tunnel); pf.conf points to Firewall › Ruleset.

Live data:

- [x] Checked on 7.9 with Hagezi Pro and OISD small (574,720 names):
      `stats_noreset` and `ps` captured (`testdata/openbsd-7.9/`); the
      action names are `rpz-local-data`, `rpz-passthru` and so on, in
      the stats and the log alike (the handwritten guesses were wrong);
      782 MB and 13.6 s to start, and `unbound-control status` doesn't
      answer until every zone is loaded, which is what OPF times.
      Reloading one list's zone stopped every answer for 14 s with one
      thread; with two, queries kept being answered, so unbound.conf
      has `num-threads: 2` whenever a blocklist is on.
- [x] DNS stats on the DNS page and the dashboard, from `unbound-control
      stats_noreset` (extended-statistics, over the control socket,
      which is now on whenever the resolver is): queries a second, cache
      hits, typical lookup time, blocked a second, answers by response
      code, DNSSEC failures and unbound's memory. The names blocked most
      and by which list, from unbound's rpz-log lines (zone names are
      ids, `opf:own` and `opf:list:<id>`, so renaming a list no longer
      changes unbound.conf), with "Never block" and "Stop blocking";
      names that aren't DNS names are counted but not offered, and which
      device asked isn't kept.
- [x] Blocklist costs: each list's estimated memory, a warning when the
      enabled lists would take over a quarter (or half) of the RAM with
      lighter lists suggested, and, when a change reloads the resolver
      whole, a notice in the review with how long DNS will pause,
      scaled from the last full reload, which OPF times after each
      commit by asking unbound until it answers.
- [x] A commit or revert tells each service once, after its last
      changed file (unbound was reloaded once per changed file before),
      and a file with a cheaper reload uses it when it changed alone:
      your own blocked and allowed names reload just their zone
      (`unbound-control auth_zone_reload opf-own.`), so editing them
      doesn't reload every blocklist.
- [x] DNS blocklists: hosts files, name lists, the domain rules of
      adblock lists (EasyList's rules for whole names, with the rest
      counted and explained) and RPZ zones, downloaded by OPF at commit
      when missing, then on a schedule and on demand, and loaded into
      unbound as response policy zones, one per list; a refresh reloads
      just its zone. Your own blocked and allowed names (exact or
      `*.name`) come first, so an allowed name wins. Blocked names answer
      0.0.0.0 and :: (checked on 7.9: unbound can't do that as an
      override, so each answer has its own zone file) or NXDOMAIN. The
      parser is tested on the first 300 lines of Steven Black's hosts,
      the AdGuard DNS filter, Hagezi's domains, wildcard and RPZ lists,
      OISD's RPZ and EasyList.
- [x] Downloaded lists (pf URL aliases and DNS blocklists) are
      downloaded again every so many hours (24 by default); a failure
      keeps the list and retries an hour later, and the pages say when
      the next download is and what went wrong.
- [x] URL aliases' lists: a commit downloads a list that isn't there
      yet (refusing the commit, with ftp's reason, if it can't) and uses
      one that is; Aliases shows when each was downloaded and how many
      entries it has, and downloads one again on demand, loading it into
      pf. ftp runs as the unprivileged user, and only the lines that are
      addresses are kept. A commit with DNSSEC on runs unbound-anchor
      first when there's no root.key. Checked on 7.9.
- [x] Monitoring › Tools: ping (with don't-fragment sizes for the
      path MTU), traceroute (UDP or ICMP, AS numbers), DNS lookups (any
      type, another server, +trace, DNSSEC, reverse) and port tests,
      run by the parent from checked fields, output streamed to the
      page, each result explained in words with the next useful step.
      Gateways can be pinged from Routing. Checked on OpenBSD 7.9:
      every command runs, and the summaries read its real output
      (which is how ping6 and traceroute6 were found to be needed for
      IPv6, instead of -6).
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
