# TODO

Things known to need more work, roughly by priority. Not a roadmap of
new features; see "Planned next" in the README for those.

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
- **UI**: React + Mantine in `ui/`, served by the Go binary.
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

**Go and TypeScript mirror each other.** `ui/src/model/generate.ts`
mirrors the Go generators for the offline preview build. Change both
together.
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
  the right section, with enough detail to act on. Mark finished items
  `[x]` with a line on what was done.


## Where things stand (2026-09-29)

- **Working and tested in Go:** the model lives in the root parent
  (`internal/appliance`), which validates it, generates every file, and
  stages, commits, confirms and reverts the model and its files as one
  unit, with history. JSON API and privilege separation with
  pledge/unveil.
- **UI:** every page exists. Review, apply, confirm, revert, history and
  undo go through the API (`make mock` runs it against the real engine).
- **Live data:** only the ARP and routing tables are real. The dashboard
  and diagnostics still show sample data from `ui/src/model/live.ts`.
- **Missing:** authentication, serving the UI from the binary, import
  from an existing system, removing generated files.
- **Never run on OpenBSD.**

## Next up

In order. Each step has details in its section below.

1. **Outbound rules never match** (Firewall rules).
2. **Removing generated files** (Commit engine).
3. **One generator.** Delete `ui/src/model/generate.ts`; the UI gets
   generated files and the annotated ruleset from the API. Keep the
   sample model as a shared JSON fixture for Go golden tests and for
   the UI's mock mode.
4. **Authentication and TLS**, enforced in the parent (Security).
5. **Run on OpenBSD** (Verify on real OpenBSD).
6. **Import** (Import).
7. **Live data** (Live data).

## Commit engine

The engine itself: stage → check → commit → confirm or auto-revert →
history (`internal/config`).

- [x] **Apply is atomic.** The model is a managed file (0600) staged
      with everything generated from it; a failure part-way discards
      the lot.
- [x] **Confirm is server-side.** Keep and revert go to the server,
      which also reverts on its own at the deadline; the UI polls
      `/api/status` to notice.
- [x] **Pattern entries.** `hostname.*` resolves to `hostname.em0` etc.
      (device names only), applied first with `sh /etc/netstart <dev>`,
      mode 0640. `/api/model/apply` used to fail for any model with
      interfaces.
- [x] Hand-edited generated files: staging refuses with
      `modified_outside` until the user chooses to replace them.
- [x] While a commit waits for confirmation, staging is refused with
      `commit_pending` and the UI blocks edits and undo.
- [x] Two browsers: staging requires the live version the edits started
      from and committing requires the staged version, so neither undoes
      the other's work silently (`conflict`).
- [ ] **Removing generated files.** Staging a model that no longer
      generates a file (a deleted VLAN's `hostname.vlan30`, a deleted
      WireGuard tunnel's `hostname.wgN`) is refused as `unsupported`.
      The engine needs deletion, with restore on revert; removed
      interfaces also need `ifconfig <dev> destroy`. Blocks deleting
      interfaces, VLANs and tunnels in the UI.
- [ ] **Apply order by dependency.** Today it's registry order (model,
      interfaces, pf, services), and within `hostname.*` path order:
      netstart brings devices up in the order given, so
      `hostname.bridge0` comes before its member `hostname.em1` (VLANs
      only work because em1 sorts before vlan20). Order parents and
      members before the interfaces built on them, the reverse on
      removal, and interfaces before pf.
- [ ] **Confirm and auto-revert for interface changes.** `hostname.if`
      files are applied directly with no confirmation, because
      `sh /etc/netstart <if>` can't load from another path. Moving the
      LAN's address onto a bridge is the easiest way to lock yourself
      out. Install, then restore the old files and re-run netstart on
      timeout; that gives up pf.conf's "a reboot reverts it" guarantee,
      so decide how to handle a reboot during the window. Needs a
      design.
- [ ] **rc.conf.local** isn't generated, and is only checked with
      `sh -n`; nothing is applied. Enabling DHCP, DNS or WireGuard must
      set `dhcpd_flags` (with the interface list), `unbound_flags` and
      so on; service enable/disable/flags should be staged through it
      and reconciled with rcctl on commit.
- [ ] `myname` and `mygate` are generated but not in the registry: give
      them managed file entries, or generate them outside the commit
      flow. `mygate` is skipped when the default gateway is DHCP;
      dhcpleased handles that differently.
- [ ] `resolv.conf` isn't handled; DNS client config isn't generated or
      managed (OpenBSD uses `/etc/resolv.conf.tail` with resolvd).
- [ ] If OPF is killed with SIGKILL (or crashes) during the confirm
      window, the staged pf rules stay loaded until reboot or the next
      start. `Recover` only runs at startup.
- [ ] Graceful shutdown: verify and document that SIGTERM waits for
      pending operations and reverts unconfirmed commits.
- [ ] File locking: no guard against two OPF instances running at once.
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
- [ ] Backup/restore: no way to export/import `config.json` for disaster
      recovery or migration (the System page's backup buttons are
      placeholders).

## Security

- [x] **Model validation.** `pf.Validate` checks every field in the
      parent before anything is generated, and again on commit (see
      Rules we hold to). It found two bugs in the sample model. It also
      had to reject quoted strings containing a newline, and a
      backslash before a space, tab or quote, which pf's lexer eats.
- [x] Requests: 4 MiB limit, JSON only, strict decoding. Cross-origin
      state-changing requests are refused
      (`http.CrossOriginProtection`); internal errors reach clients only
      as "internal error".
- [ ] **No authentication.** It has to be enforced in the parent, not
      the web process: a compromised web process can currently call
      Stage and Commit directly. Likely `auth_userokay(3)` (cgo) plus
      sessions checked at the RPC boundary. The UI needs a sign-in page
      and a working "change password".
- [ ] TLS.
- [ ] Record who made each commit in history once there are users.
- [ ] Anyone who can commit can get root: rc.conf.local is sourced by
      rc(8), and sshd_config/httpd.conf are powerful. That comes with
      the product, but it's why auth and audit logging matter.
- [ ] Cap RPC message sizes: gob decoding in the root process is
      unbounded (HTTP bodies are capped, but a compromised web process
      could send more).
- [ ] `privsep.Client.Pending` drops RPC errors; the banner shows nothing
      if the parent is unreachable.
- [ ] Secret storage, needed for WireGuard private keys (one per tunnel;
      today a placeholder in the `hostname.if` generator, and keys
      aren't generated), PPPoE credentials and CARP passwords.

## Import

Principle 4: install on a configured system and keep its behaviour.

- [ ] `ParsePfConf` for whole files (the rule parser exists), plus
      importers for `hostname.if`, `dhcpd.conf` and `unbound.conf`.
      Must handle hand-written configs: comments, includes, macros,
      multi-line rules, and features OPF doesn't model (anchors, queues,
      …), which stay raw blocks and re-export unchanged.
- [ ] Build the model's interfaces first: rules naming devices
      (`on em0`) only become guided rules when the device is in the
      model, otherwise they stay raw.
- [ ] Reject invalid UTF-8 with a clear error. `encoding/json` replaces
      it with U+FFFD, so even raw rules would change when `config.json`
      is saved.
- [ ] Rules with their own label stay raw (the guided form's label is
      its id). Offer to turn those labels into descriptions.
- [ ] First-boot setup wizard (WAN, LAN, admin password) that detects
      existing configs and offers import.

## Verify on real OpenBSD

Everything below has only run on macOS, where pledge and unveil are
skipped and the web process isn't dropped to another user. The
`openbsd-dev` SSH host is a candidate; ask before using it.

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
- [ ] Check whether reloading pf empties `persist` tables such as
      `<bruteforce>`; if so, save and restore their contents.
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
- [ ] Split-tunnel enforcement: pfctl accepts `$iface:network` entries
      in a `const` table (used for DHCP-addressed inside networks in
      `<opf_local>`), and the block rule stops a split-tunnel device
      that sets `AllowedIPs = 0.0.0.0/0` from reaching the internet.

## Firewall rules

### Generator and parser

- [x] **Parser hangs.** Fuzzing found infinite loops in the tokenizer
      (bytes treated as runes, so identifiers rewound past their start)
      and in the interface, protocol and port list loops. The inputs are
      regression seeds in `internal/pf/testdata/fuzz` and
      `parser_termination_test.go`. All three targets run 90 s clean.
- [x] **The parser dropped what it didn't understand.** Anything
      `tryParseFormRule` doesn't model keeps the rule raw: unknown or
      repeated options, unreadable arguments, `log (…)` other than
      `(all)`, bare macros and hostnames, `:0`/`:broadcast`/`:peer`,
      `! any`, interface groups and devices not in the model, host lists
      and ranges, unmodelled state options, empty `{ }` lists, and ports,
      flags or ICMP types on a protocol the generator won't write them
      for. `route-to`/`reply-to` map to a model gateway by address, or
      keep the rule raw. Keywords are case-sensitive and string escapes
      follow pf's parse.y; the generator quotes strings the same way
      (Go's `%q` escapes reached pf as literal text), always writes
      aliases as `<table>`, and no longer turns `netbios-ssn` into
      `netbios:ssn`.
- [x] **Raw rules were rebuilt from tokens.** Tokens carry byte offsets
      and raw text is the source slice (`parseAsRaw` used to produce
      `$lan : network`). Continuations are removed before tokenizing, as
      pf's lexer does, even mid-word. `FuzzRawRuleText` checks raw text
      always comes from the input.
- [x] **Interface references.** One `iface` endpoint replaces `net` and
      `ifaddr`: a model interface or a group (`egress`), with
      `:network`/`:broadcast`/`:peer`, `:0`, and parentheses when it
      should follow address changes (automatic: yes for DHCP/SLAAC and
      groups). Combinations follow pfctl's `parse.y` and `host_if()`.
      The `on` clause takes groups too, which make a rule floating.
      `self` takes the same modifiers (in the kernel `(self)` is the
      "all" group, `pf_if.c`); left automatic, it's parenthesized when
      any interface uses DHCP or SLAAC.
- [x] Built-in rules (anti-lockout, port forwards, NAT reflection,
      automatic outbound NAT) use `iface` endpoints like user rules, and
      include every enabled inside network with IPv4, DHCP-addressed
      ones too. `nat-to` targets stay in parentheses always.
- [x] Pasted pf rules are parsed back into guided form where possible
      (`POST /api/pf/parse`).
- [ ] **Outbound rules never match.** Both generators emit
      `pass out quick inet` before user rules (`internal/pf/generate.go`,
      `ui/src/model/generate.ts`, the `self-out` builtin), so outbound
      rules such as the sample's floating `match out … set prio 6` are
      never reached. Use a non-quick `pass out`.
- [ ] Still raw: bare names or `name:0` that aren't model interfaces
      (pf treats them as interfaces only if one exists at load time,
      else as hostnames).
- [ ] Anti-lockout ports (443, 22) are hard-coded; derive them from the
      web UI and sshd settings.
- [ ] NAT reflection is added on every inside interface; limit it to the
      ones that need it.
- [ ] URL-type alias tables need a refresh mechanism (scheduled or on
      demand) to re-fetch and reload the table files.

### pf labels

Generated rules are labelled `opf:<kind>:<id>` (see Rules we hold to),
so counters and states map back to model objects.

- [ ] Raw rules only have a label if their text has one. Offer to add
      OPF's when a raw rule has none.
- [ ] Map pflog entries (rule numbers) to model rules through
      `pfctl -vvsr`'s labels.
- Live counters and killing a rule's states: see Live data.

### pf features missing from the UI

Reachable today only through raw rules or custom pf blocks:

- [ ] Traffic shaping: `queue` definitions (bandwidth, min/max, flows)
      and assigning rules to queues.
- [ ] Anchors, including a managed anchor per service.
- [ ] Multi-WAN: gateway groups (`route-to` pools with failover driven
      by gateway health, perhaps via relayd or ifstated), and `route-to`
      on a DHCP gateway, which the generator currently resolves to the
      live address.
- [ ] `binat-to` (1:1 NAT), `af-to` (NAT64), `divert-to`.
- [ ] pfsync, alongside CARP (Interfaces).
- [ ] A packet tester: "what happens to tcp 192.168.20.5 → 192.168.1.20:445?"
      evaluated against the ruleset.

## Interfaces

Today there are physical ports, VLANs and WireGuard tunnels, each one
`hostname.<dev>` file applied with `sh /etc/netstart <devs>`. Virtual
interfaces also depend on removing files, apply order and interface
confirmation (Commit engine).

- [ ] **Model**: an interface kind (physical, vlan, wireguard, bridge,
      aggr, carp, gre, pppoe, …) with per-kind settings, replacing the
      vlan/wireguard special cases. Validation: members exist, have no
      address, belong to one bridge or aggregate, no loops, valid
      device names (veb0, aggr0, carp1), and the pf macro names the
      interface that carries the address.

Types, roughly in order of usefulness:

- [ ] `veb` + `vport` bridges (bridging LAN ports). The address and pf
      filtering are on the vport, so the LAN macro follows it. The
      older `bridge(4)` is similar.
- [ ] `aggr` link aggregation: `trunkport` lines, members only `up`.
- [ ] `pppoe` WANs: credentials need secret storage, and the default
      route goes through the PPPoE link instead of mygate.
- [ ] `carp` failover: a shared password (secret storage), only useful
      with a second box, and wants pfsync alongside.
- [ ] `gre`, `etherip`, `vxlan` tunnels: endpoints, and pf and routing
      like WireGuard.
- [ ] Niche: `tpmr`, `svlan`, `tap`.
- [ ] Live status for each type (members, link state, carp state) in the
      interface pages.

## WireGuard

- [x] **Every VPN interface got the same tunnel.** Each VPN interface
      now carries its own `wireguard` settings (port, public key,
      peers); its address and whether it's up are the interface's.
- [x] Multiple tunnels, with a tab per tunnel and "Add tunnel" on the
      WireGuard page (picks a free wgN, port and /24, and can add the
      WAN rule for the port).
- [x] Validation across tunnels: unique listen ports and keys, peer ids
      unique everywhere and peer keys within a tunnel, peer addresses
      inside their tunnel's network, peer addresses and networks
      (`wgaip`) not overlapping each other or local networks, and no two
      interfaces on overlapping networks.
- [ ] Removing a tunnel waits on removing generated files; until then a
      tunnel can only be turned off.
- [ ] Editing a peer: only adding and removing exist.
- [ ] pf and routing per tunnel: site-to-site tunnels (routed networks,
      usually no NAT) and remote-access ones (clients NATed out) need
      different defaults for automatic NAT and generated rules. Today
      every tunnel's network gets automatic NAT.
- Private keys: see secret storage (Security). Peer status: see Live
  data.

## DHCP and DNS

- [x] Show registered and refused names in the UI: `GET /api/dns/leases`
      and "DHCP devices by name" on the DNS page.
- [x] The DHCP page's leases table reads the leases file
      (`GET /api/dhcp/leases`) and says which name each device got.
- [ ] No PTR records for leases (or reservations): reverse lookups of
      DHCP clients fail.
- [ ] A commit reverted by the confirm timeout doesn't kick the watcher,
      so names are missing for up to 15 s after unbound reloads.
- [ ] **Naming a device yourself.** A device asking for an invalid name
      ("Priya's iPad") or a taken one gets no DNS name. Options, best
      first:
      - A name the admin gives a lease from the leases table, used
        instead of the one the device asked for. Trusted input, so no
        guessing; keyed by MAC like reservations, so it has the same
        weaknesses (MACs can be spoofed, and phones rotate private MACs
        per network or over time, which loses the name). Could be
        "Reserve and name" (the existing reservation, which also fixes
        the address) or a name-only mapping.
      - Optionally, a conservative automatic rewrite: lower-case, drop
        apostrophes, turn spaces and underscores into hyphens, collapse
        repeats, and refuse anything left that isn't ASCII
        ("Priya's iPad" → "priyas-ipad"). It must run before every
        existing check, so a rewritten name can't reach a reserved one
        ("WPAD " → "wpad" is still refused) and two devices rewriting to
        the same name still get neither. Show both ("priyas-ipad, from
        “Priya's iPad”") so it's never surprising. Off by default.
      - Not: punycode for non-ASCII names (unreadable), or guessing a
        name from the MAC vendor.
- [ ] Reserving an address from the leases table picks the lease's
      address, which is inside the dynamic range. dhcpd can then hand it
      to another device too; offer a free address outside the range.

## IPv6

Interfaces, NAT and rules are IPv4-first today.

- [ ] `ui/src/lib/ip.ts` is IPv4-only: needs `isIPv6()`, v6 CIDR
      validation, and `network()`/`netmask()` equivalents.
- [ ] `automaticNat()` only emits `inet` rules; `unboundConf()` only adds
      IPv4 access-control entries.
- [ ] DHCP names in DNS are IPv4 only; no names for SLAAC or DHCPv6
      clients.
- [ ] Router advertisements (rad, under Services).

## Services

Every OpenBSD base daemon an appliance needs should be fully
configurable through OPF, so nobody has to SSH in and edit files. For
each daemon:

- A model with every option as structured fields where practical, plus
  a `raw`/`extra` field for arbitrary lines appended to the generated
  file (like raw pf rules).
- A basic UI for common options and an advanced one for the rest.
- A preview of the generated file, like the Ruleset page's pf.conf.
- The generated file goes through the commit engine, checked with the
  daemon's own validator (`httpd -n`, `smtpd -n`, `bgpd -n`,
  `ospfd -n`, …).
- Enabling and flags go through rc.conf.local (Commit engine).

### Services page

- [ ] List every base daemon, grouped by category (Core, Network,
      Security, …): name, description, enabled, running, and start,
      stop, restart, enable, disable. Link to the config page for
      services that have one. Backend: see Live data > Services.
- [ ] Detail view: status, uptime, resource usage, recent log entries,
      rc.d flags/user/rtable/timeout, and configuration where
      applicable.
- [ ] Dependency awareness: some services depend on others (dhcpd needs
      interfaces up); warn when disabling a dependency.
- [ ] Show and configure rc.d(8) order where relevant.

### Already configurable

The Services page should show their status and link to their pages:

- [x] **pf**: Firewall pages.
- [x] **dhcpd**: Services > DHCP server.
- [x] **unbound**: Services > DNS resolver.
- [x] **ntpd**: `ntpd.conf` is generated; show sync status, offset and
      peers too.

`httpd.conf` and `sshd_config` are managed files in the registry but
have no model or UI yet.

### Core (most users need)

- [ ] **sshd**: remote administration. Show running status and session
      count. Config: listen addresses, port, root login.
- [ ] **pflogd**: firewall logging to `/var/log/pflog`, needed for
      diagnostics. Show status and log size. Config: log file, snaplen,
      interface.
- [ ] **syslogd**: show status. Config: remote syslog destinations.
- [ ] **cron**: needed for blocklist updates, backups and maintenance.
      Show status and next jobs; later, a UI for managing jobs.
- [ ] **dhcpleased** and **slaacd**: DHCP and SLAAC clients for WANs,
      managed per interface. Show status and the leases/addresses
      obtained.

### Tier 2 (worth a config UI)

- [ ] **httpd**: captive portal, hosting blocklists, file serving.
      Virtual hosts, TLS, document roots. Services > Web server.
- [ ] **rad**: IPv6 router advertisements (prefixes, DNS, MTU per
      interface). In interface config or Services > IPv6 RA.
- [ ] **relayd**: multi-WAN health checks, reverse proxy, redirects;
      could replace custom gateway monitoring. Tables, protocols,
      relays, redirections.
- [ ] **smtpd**: send alert emails. Relay host, authentication, aliases.
      System > Notifications or Services > Mail relay.
- [ ] **snmpd**: monitoring integration. Communities, trap receivers,
      system info.

### Tier 3 (advanced networking)

- [ ] **ospfd** / **ospf6d**: OSPFv2/v3 dynamic routing (areas,
      interfaces, neighbours, redistribution).
- [ ] **bgpd**: multi-homing, transit, policy (AS, neighbours, filters,
      communities). Complex; may need the raw config option.
- [ ] **eigrpd**, **ripd**: EIGRP (mixed Cisco environments) and RIP
      (legacy). All routing daemons go under Network > Dynamic
      Routing.
- [ ] **iked**: IKEv2 IPsec, site-to-site and mobile clients (policies,
      flows, auth, proposals). Services > IPsec VPN, beside WireGuard.
- [ ] **npppd**: PPPoE and L2TP (interfaces, auth, IP pools). PPPoE in
      interface config, L2TP under Services.
- [ ] **ifstated**: WAN failover and link monitoring with carp and
      route changes. Network > Failover, or part of multi-WAN.

### Tier 4 (niche; show if enabled)

- [ ] **nsd** (authoritative DNS zones), **tftpd** (PXE, firmware) and
      **tftpproxy**, **ftpd** and **ftpproxy** (FTP through NAT).
- [ ] **radiusd** (802.1X, VPN auth), **ldapd** (directory).
- [ ] **isakmpd** (IKEv1, legacy peers only; prefer iked), **sasyncd**
      (IPsec SA sync between carp hosts).
- [ ] **ldpd** (MPLS), **dvmrpd** and **mrouted** (multicast routing).
- [ ] **hostapd** (Wi-Fi AP where hardware allows), **lpd** (printing).

## Live data

The dashboard and diagnostics read sample data from
`ui/src/model/live.ts`. Each feature needs a Go parser behind an API
endpoint with mock data on non-OpenBSD, and a UI page with TypeScript
types.

**Rewrite the parsers from scratch**, using `legacy/server` only as a
reference: the legacy parsers index fields by position and crash on
unexpected input. New parsers handle all valid output, return errors
on anything else (never panic), and get golden-file and fuzz tests
(Testing). Delete `legacy/` once they're done.

Conventions:

- Parsers go in `internal/appliance/` beside `parseARPOutput` and
  `parseRoutingOutput`, with a `runtime.GOOS` check returning mock data
  from `sample*()` functions like `sampleARPTable()`.
- Types in `ui/src/lib/api.ts`; mock data in `ui/src/model/live.ts`.
- Consider batching related endpoints (`/api/system/stats` for CPU,
  memory and load).
- Rate-limited polling (say 5 s for stats, 30 s for logs); WebSocket
  for pflog and traffic later.

### System

- [ ] CPU (`sysctl kern.cp_time`): dashboard meter (hard-coded 18% now)
      and history. `GET /api/system/cpu`.
- [ ] Load average (`sysctl vm.loadavg`): 1/5/15 min on the dashboard.
- [ ] Memory (`vmstat`, `sysctl hw.physmem`): meter with
      active/free/wired/cached.
- [ ] Swap (`swapctl -l`), when configured.
- [ ] Disks (`df -P`) per mount, and I/O rates from `vmstat`.
- [ ] Uptime (`sysctl kern.boottime`): dashboard and System > General.
- [ ] Sensors (`sysctl hw.sensors`): temperature, fans, voltage.
- [ ] Hardware (`sysctl hw`): CPU model, RAM, disks on System > General.
- [ ] Processes (`ps aux`): Diagnostics > Processes with sorting and
      filtering.

### pf

- [ ] States (`pfctl -vv -s states`): Connections page, with kill by id
      (`pfctl -k id -k <id>`) and by source, destination or interface.
      `GET /api/pf/states`, `POST /api/pf/kill`.
- [ ] Per-rule counters (`pfctl -s labels`, `pfctl -vv -s rules`):
      evaluations, packets and bytes on the Rules page, and kill a
      rule's states with `pfctl -k label -k opf:rule:<id>`.
- [ ] Per-rule history: poll and store counters to graph them.
- [ ] Info (`pfctl -v -s info`): firewall tile with state table size,
      match rate, drops.
- [ ] Interfaces (`pfctl -vv -s Interface`): per-interface packets and
      bytes.
- [ ] Memory limits (`pfctl -s memory`).
- [ ] Firewall log (`tcpdump -n -e -ttt -r /var/log/pflog`): the
      Firewall log page, mapped to rules through labels.
- [ ] Per-client traffic and graphs: pf only tracks bytes per live
      connection (lost when closed) and per interface. Options: poll
      states and aggregate by IP, accounting rules with labels, or
      pflow(4) export to a collector.

### Network

- [ ] Interface counters (`netstat -i -n`): rx/tx packets, errors,
      collisions; rates from deltas for the dashboard traffic chart
      (simulated now) and per-interface sparklines.
- [ ] Interface status (`ifconfig -a`): link state, media, addresses,
      flags.
- [ ] WireGuard peers (`ifconfig wgN` or `wg show`): handshake time and
      rx/tx per peer. Output comes per interface; key it by tunnel and
      peer.
- [ ] DHCP leases and unbound stats (`unbound-control stats`).

### Services

- [ ] `rcctl ls all`, `rcctl ls on`, `rcctl ls started`: list with
      enabled and running state. `GET /api/services`.
- [ ] `rcctl get <service>`: flags, user, rtable, timeout.
      `GET /api/services/:name`.
- [ ] `rcctl start|stop|enable|disable`:
      `POST /api/services/:name/<action>`. Enabling should go through
      rc.conf.local and a commit rather than bypass it.

### Logs

- [ ] `dmesg`, `/var/log/messages`, `/var/log/daemon`,
      `/var/log/authlog` (tail): Diagnostics > System logs, a tab each.

### Tools

- [ ] Ping, traceroute and DNS lookup under Diagnostics.

## UI

- [ ] Embed `ui/dist` in the binary (principle 3).
- [ ] Deleting VLANs and interfaces (waits on removing generated
      files).
- [ ] Real actions behind placeholders: change password, syspatch,
      backup download/restore.
- [ ] Split the 1.6 MB bundle by page.
- [ ] Responsive design, from desktop monitors down to phones, since
      admins may need to act from a phone:
      - Test at 375, 768, 1024 and 1440+ px.
      - Tables scroll horizontally or collapse to cards.
      - Navigation collapses to a menu (already does).
      - Forms stack on narrow screens; touch targets at least 44 px.
      - Apply, confirm and revert work on mobile, and the dashboard is
        still useful.
- [ ] Storybook or similar for developing components in isolation.

## Testing

Tests are a blocking requirement for every feature: a regression here
can silently break network security. When a bug is found, add the
failing input as a permanent test case before fixing it.

- [ ] **Parsers** (command output): golden files from real output
      across supported versions; edge cases (empty, single entry,
      largest realistic, Unicode names, IPv6, unusual but valid
      formats); errors on truncated, garbage, partial or binary input,
      never panics; fuzzing.
- [ ] **Generators**: golden files for every generated file (only the
      pf parser has them today); validate output with the real tool
      (`pfctl -nf`, `dhcpd -n`, …); boundaries (empty sections, many
      rules/interfaces/aliases, special characters, every protocol and
      endpoint combination); fuzz random valid models through the
      daemon's checker.
- [ ] **Importers**: anonymized real-world configs; import → export is
      behaviourally identical; unsupported features survive as raw;
      syntax variations (macros, includes, continuations, comments);
      clear errors on malformed input; fuzz random valid configs
      through `pfctl -nf`.
- [ ] **Commit engine**: stage → check → apply → confirm, and → timeout
      → revert; failure injection (check, apply or restart fails, disk
      full, permission denied) with correct rollback; races (concurrent
      stages and commits, confirm during revert); history diffs,
      rollback content and survival across restart; drift between stage
      and commit blocks the commit and keeps the hand-edit.
- [ ] **Privilege separation**: success and error paths of every RPC
      method, sentinel errors across the boundary; oversized messages,
      path traversal, unknown methods; child crash → restart, parent
      shutdown → child exits, unconfirmed commits revert; random bytes
      on the socketpair crash neither process.
- [ ] **API**: every route with valid and invalid input, missing auth
      (once added), cross-origin writes, oversized and malformed bodies,
      path traversal in URLs; errors never leak internal details.
- [ ] **UI**: none exist. Form tests (valid accepted, invalid rejected
      clearly, empty and max length); workflow tests (add rule → commit
      → confirm, edit interface → see generated file, revert from
      history); optionally visual regression.
- [ ] **CI**: `make test` (vet, `go test -race`), GOOS=openbsd vet and
      build, UI type-check and builds, fuzzing for a fixed time per
      target (say 30 s), on every PR and blocking merge; track coverage.

### On OpenBSD

- [ ] A harness on an OpenBSD VM that captures `pfctl -s states`,
      `pfctl -s rules -v`, `pfctl -s info`, `pfctl -s Anchors -v`,
      `ifconfig -a`, `netstat -rn`, `rcctl ls all`/`rcctl get`,
      `dhcpleasectl show`, `wg show` and `unbound-control stats`, runs
      each through its parser (no errors, known values match), and
      keeps the output as fixtures. Include busy state tables, many
      interfaces, complex rulesets and IPv6.
- [ ] Validate generated files there (`pfctl -nf -` and so on) and
      compare them with the system's.
- [ ] Run it in CI on every release, ideally every PR, and note how the
      VM differs from production (services not running, minimal config).
- [ ] Support 7.4 and later; state the minimum and maximum in the
      README. For each release: capture fresh output, review man page
      and source changes (cvsweb.openbsd.org), update parsers and
      generators, add fixtures, document version differences. Missing
      fields on older versions become empty values, not errors.

## Development

`make mock` is described under Working on it. The mock is one process
with the real generators, parser and engine, started from
`ui/src/model/sample-model.json`; its "live" files are what the sample
generates.

- [x] Commit, confirm and revert through the API; a short
      `-confirm-timeout` makes the timeout testable.
- [x] The UI loads the model from `GET /api/config`; the preview build
      uses `ui/src/lib/localApi.ts`.
- [ ] Live data endpoints fed from fixtures, so the mock stops relying
      on `live.ts`.
- [ ] Recorded mode: capture real command output (`opf -record dir`)
      and replay it in the mock.
- [ ] Simulated validators: run the Go pf parser on staged pf.conf so
      `pfctl -nf`-style errors can be exercised; today every check
      passes.

## Housekeeping

- [ ] `golang.org/x/sys` is pinned to v0.44.0 to keep Go 1.25; revisit
      when OpenBSD packages Go 1.26.
- [ ] Delete the stale Dependabot branches on origin; they target the
      old `ui/`.
