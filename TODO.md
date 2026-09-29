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

## Where things stand (2026-09-28)

- **Go, working and tested:** the model is the source of truth and lives
  in the parent (`internal/appliance`). The web process sends a model
  over RPC; the parent validates it (`pf.Validate`), generates every
  file, and stages the model and the files as one unit, committed,
  confirmed and reverted together, with auto-revert and history. There's
  a JSON API (`internal/web`, `docs/api.md`) and privilege separation
  with pledge/unveil.
- **UI:** every page exists. Review, apply, confirm, revert, history and
  undo go through the API (`make mock` runs it against the real engine).
  The dashboard and diagnostics still show sample live data.
- **Live data:** ARP table and routing table have real backend
  implementations with `runtime.GOOS` checks for mock data on non-OpenBSD.
  All other live data (system metrics, pf states, services, logs) still
  uses frontend-only mock data. See "Live monitoring data" section below
  for the full list of features to implement.
- **Missing:** authentication, serving the UI from the binary, import
  from an existing system, removing generated files.
- **Never run on OpenBSD.**

## Next up

In order. Each step has details further down.

1. **Fix the remaining bugs found in review** (next section): outbound
   rules never matching.
2. ~~Move the model into the parent.~~ Done: `internal/appliance`.
3. **Removing generated files.** Staging a model that no longer
   generates a file (a deleted VLAN's `hostname.vlan30`) is refused as
   `unsupported`; the commit engine needs deletion, with restore on
   revert. Apply order is registry order: model, interfaces, pf,
   services.
4. **One generator.** Delete `ui/src/model/generate.ts`; the UI gets
   generated files and the annotated ruleset from the API. Keep the
   sample model as a shared JSON fixture for Go golden tests and for
   the UI's mock mode.
5. **Authentication and TLS**, enforced in the parent (see Security).
6. **Run on OpenBSD** (see Verify on real OpenBSD). The `openbsd-dev`
   host in the SSH config is a candidate; ask before using it.
7. **Import** (principle 4): `ParsePfConf` plus importers for
   `hostname.if`, `dhcpd.conf` and `unbound.conf`, then the first-run
   wizard.
8. **Live data:** new parsers for pfctl, ifconfig, leases, WireGuard and
   pflog behind the API.

## Bugs found in review (2026-09-28)

- [x] **Parser hangs.** Fuzzing found infinite loops in the tokenizer
      (bytes treated as runes, so identifiers rewound past their start)
      and in the interface, protocol and port list loops. Fixed; the
      inputs are regression seeds in `internal/pf/testdata/fuzz` and in
      `parser_termination_test.go`. All three targets now run 90 s clean.
- [x] **The parser dropped what it didn't understand.** Anything
      `tryParseFormRule` doesn't model now keeps the rule raw: unknown or
      repeated options, unreadable arguments, `log (…)` other than
      `(all)`, bare macros and hostnames, `:0`/`:broadcast`/`:peer`,
      `! any`, interface groups and devices not in the model, host lists
      and ranges, unmodelled state options, empty `{ }` lists, and ports,
      flags or ICMP types on a protocol the generator won't write them
      for. `route-to`/`reply-to` map to a model gateway by address, or
      keep the rule raw. The tokenizer's keywords are case-sensitive and
      its string escapes follow pf's parse.y; the generator quotes
      strings the same way (Go's `%q` escapes reached pf as literal
      text), always writes aliases as `<table>`, and no longer turns
      `netbios-ssn` into `netbios:ssn`. `FuzzParseRuleRoundTrip`
      checks parse → generate → parse gives the same rule.
- [x] **Interface references.** One `iface` endpoint replaces `net` and
      `ifaddr`: a model interface or a group (`egress`), with
      `:network`/`:broadcast`/`:peer`, `:0`, and parentheses when it
      should follow address changes (automatic: yes for DHCP/SLAAC and
      groups). Combinations follow pfctl's `parse.y` and `host_if()`.
      The `on` clause takes groups too, which make a rule floating. The
      old generator always wrote `$if:network` unparenthesized, which
      goes stale on a DHCP interface until pf reloads.
- [x] `self` takes the same modifiers (`self:network`, `(self)`; in
      the kernel `(self)` is the "all" group, `pf_if.c`). Left
      automatic, it's in parentheses when any interface is addressed by
      DHCP or SLAAC.
- [x] Built-in rules (anti-lockout, port forwards, NAT reflection,
      automatic outbound NAT) use `iface` endpoints like user rules.
      Reflection and automatic NAT used to skip DHCP-addressed inside
      networks entirely; now they include every enabled inside network
      with IPv4. `nat-to` targets stay in parentheses always.
- [ ] Still raw: bare names or `name:0` that aren't model interfaces
      (pf treats them as interfaces only if one exists at load time,
      else as hostnames).
- [ ] Importing (principle 4) must build the model's interfaces first:
      rules naming devices (`on em0`) only become guided rules when the
      device is in the model, otherwise they stay raw.
- [ ] Reject invalid UTF-8 on import with a clear error. `encoding/json`
      replaces it with U+FFFD, so even raw rules would change when
      `config.json` is saved.
- [x] **No model validation.** `pf.Validate` now checks every field in
      the parent before anything is generated, and on commit again.
      Limits come from pf's source (label 63 bytes, table names 31,
      `IFNAMSIZ`), interface ids can't be pf keywords
      (`keywords_gen.go`, from parse.y), and ids that go into labels
      are checked against pf's label rules.
      It found two bugs in the sample model. Was: nothing checks the model before
      generating. Alias names, interface ids and devices, hostnames,
      domains, reservation names and addresses are written into pf.conf,
      hostname.if, dhcpd.conf and unbound.conf unchecked, so a crafted
      value can inject configuration. Validate every field in the parent
      (characters, length, references to other objects); raw pf rules
      are the only intended exception. Quoted strings in pf.conf can't
      contain a newline, and pf's lexer eats a backslash before a space,
      tab or quote, so those values must be rejected. The generator also
      silently drops a port spec naming an unknown `alias:`.
- [ ] **Outbound rules never match.** Both generators emit
      `pass out quick inet` before user rules (`internal/pf/generate.go:602`,
      `ui/src/model/generate.ts:265`), so outbound rules such as the
      sample's floating `match out … set prio 6` are never reached. Use a
      non-quick `pass out`.
- [x] **`/api/model/apply` failed for any model with interfaces.** The
      registry now has pattern entries: `hostname.*` resolves to
      `hostname.em0` etc. (device names only), applied first with
      `sh /etc/netstart <dev>`, mode 0640.
- [x] **Apply isn't atomic.** The model is a managed file (0600)
      staged with everything generated from it; a failure part-way
      discards the lot.
- [x] **The model lives in the web process.** It's in the parent now.
- [x] **The mock UI couldn't apply.** `make mock` runs `opf -mock` with
      Vite proxying `/api` to it; the preview build uses the TypeScript
      generator offline.
- [x] **Raw rules were rebuilt from tokens.** `parseAsRaw` joined
      tokens with spaces (`$lan : network`, invalid pf) and re-quoted
      strings with Go's `%q`. Tokens now carry byte offsets and raw text
      is the source slice. Continuations are removed before tokenizing,
      as pf's lexer does, even mid-word. `FuzzRawRuleText` checks raw
      text always comes from the input.
- [x] **Confirm is client-side only.** Keep and revert go to the
      server, which also reverts on its own at the deadline; the UI polls
      `/api/status` to notice.
- [x] **Unbounded request bodies.** 4 MiB limit, JSON only, strict
      decoding.

## Testing

Every component must have extensive test coverage. Regressions in a
firewall appliance can silently break network security. Tests are not
optional—they are a blocking requirement for every feature.

### Parsers (monitoring data from system commands)

- [ ] Golden-file tests for every parser against real output captured
      from multiple OpenBSD versions (7.4, 7.5, 7.6, 7.7, 7.8+).
- [ ] Edge-case fixtures: empty output, single entry, maximum realistic
      size, Unicode in hostnames/descriptions, IPv6 addresses, unusual
      but valid formats.
- [ ] Error-path tests: truncated output, garbage input, partial lines,
      binary data. Parsers must return errors, never panic.
- [ ] Fuzz testing with `go test -fuzz` for every parser. Run fuzzing
      in CI for a minimum duration on each PR.
- [ ] Regression tests: when a bug is found, add the failing input as
      a permanent test case before fixing.

### Generators (model → config files)

- [ ] Golden-file tests for every generator (pf.conf, hostname.if,
      dhcpd.conf, unbound.conf, ntpd.conf, myname, mygate, rc.conf.local).
- [ ] Round-trip property tests where applicable: generate config,
      validate with the real tool (`pfctl -nf`, `dhcpd -n`, etc.),
      confirm no errors.
- [ ] Boundary tests: empty model sections, maximum number of rules/
      interfaces/aliases, special characters in names/descriptions,
      every protocol and endpoint type combination.
- [ ] Fuzz the model→generator path: random valid models must produce
      valid config files (validated by the daemon's own checker).
- [ ] Regression tests for every generator bug found in production.

### Config importers (existing config files → model)

- [ ] Golden-file tests against real-world hand-written configs
      collected from production systems (anonymized).
- [ ] Round-trip tests: import config → export config → diff must be
      semantically equivalent (comments/whitespace may differ, but
      behavior must be identical).
- [ ] Preserve unsupported features: configs using pf features OPF
      doesn't model (anchors, queues, etc.) must import as raw blocks
      and re-export correctly.
- [ ] Handle all valid syntax variations: macros, includes, multi-line
      rules, comments, blank lines, mixed indentation.
- [ ] Error handling: malformed configs should produce clear errors
      pointing to the problem, not crash or silently drop rules.
- [ ] Fuzz with valid configs: generate random valid pf.conf (etc.)
      files, import, export, validate with `pfctl -nf`.

### Config engine (staging, commit, confirm, history, revert)

- [ ] Integration tests for the full commit workflow: stage → check →
      apply → confirm, and stage → check → apply → timeout → revert.
- [ ] Failure injection: check fails, apply fails, service restart
      fails, disk full, permission denied. Verify correct rollback.
- [ ] Concurrent access tests: multiple stages, commits racing, confirm
      during revert. Verify no corruption or deadlocks.
- [ ] History integrity: commits produce correct diffs, rollback stages
      the exact previous content, history survives restart.
- [ ] File drift detection: hand-edits between stage and commit must
      block the commit and preserve the hand-edit.

### Privilege separation (parent/child RPC)

- [ ] Every RPC method must have explicit tests for success and error
      paths, including sentinel errors crossing the process boundary.
- [ ] Invalid/malicious RPC inputs: oversized messages, path traversal
      attempts in file names, unknown method calls. Child must not be
      able to escalate or crash parent.
- [ ] Process lifecycle: child crash → parent restarts it, parent
      shutdown → child terminates cleanly, unconfirmed commits revert.
- [ ] Fuzz the RPC protocol: random bytes over the socketpair must not
      crash either process.

### Web server and API

- [ ] HTTP endpoint tests for every route: valid requests, invalid
      parameters, missing auth (once added), CSRF protection.
- [ ] Input validation: oversized bodies, malformed JSON, path traversal
      in URL parameters.
- [ ] Error responses: every error code path must be tested and must
      not leak internal details.

### Frontend (React UI)

- [ ] Component tests for every form: valid input accepted, invalid
      input rejected with clear errors, edge cases (empty, max length).
- [ ] Integration tests for critical workflows: add rule → commit →
      confirm, edit interface → see generated config, revert from
      history.
- [ ] Visual regression tests for key pages (optional but recommended).

### CI requirements

- [ ] All tests run on every PR, blocking merge on failure.
- [ ] `go test -race` to catch data races.
- [ ] `go test -fuzz` with minimum duration (e.g., 30s per fuzz target).
- [ ] Cross-compile and vet for GOOS=openbsd on every PR.
- [ ] Coverage tracking: no decrease in coverage without justification.

### OpenBSD version compatibility

- [ ] Maintain test fixtures captured from each supported OpenBSD version
      (currently 7.4+). Each new OpenBSD release requires:
      1. Capture fresh output from all parsed commands (`pfctl -s states`,
         `pfctl -s rules`, `ifconfig`, `rcctl ls all`, etc.)
      2. Review man page changes for parsed commands and config files
         (compare with previous version via `cvsweb.openbsd.org`)
      3. Update parsers/generators if formats changed
      4. Add new fixtures to the test suite
      5. Document any version-specific behavior
- [ ] Track minimum and maximum supported OpenBSD versions in README.
- [ ] Parsers must degrade gracefully on older versions—missing fields
      should result in zero/empty values, not crashes.

### Live on-OpenBSD test suite

Extensive testing that runs directly on OpenBSD to validate parsers against
real system output. This ensures compatibility with the current OpenBSD
version and catches any format changes that static fixtures might miss.

- [ ] Test harness that runs on OpenBSD and collects live data from:
      - `pfctl -s states` (connection states)
      - `pfctl -s rules -v` (rules with counters)
      - `pfctl -s info` (pf statistics)
      - `pfctl -s Anchors -v` (anchor contents)
      - `ifconfig -a` (interface configuration)
      - `netstat -rn` (routing table)
      - `rcctl ls all` / `rcctl get <service>` (service status)
      - `dhcpleasectl show` (DHCP leases if server is running)
      - `wg show` (WireGuard status if configured)
      - `unbound-control stats` (DNS resolver stats if running)
- [ ] Feed live output through each parser, verify no panics or errors
      on valid data.
- [ ] Compare parsed structures against expected values where deterministic
      (e.g., interface names, IP addresses that can be verified).
- [ ] Store captured output as new test fixtures for regression testing.
- [ ] Run as part of a CI job on an OpenBSD VM (at minimum on each new
      OpenBSD release, ideally on every PR).
- [ ] Include edge cases triggered by real usage: busy state tables,
      many interfaces, complex pf rulesets, IPv6-heavy configurations.
- [ ] Test config generators by: generating config from current model,
      validating with `pfctl -nf -`, comparing against actual system config.
- [ ] Document any differences between test VM and production systems
      (services not running, minimal config, etc.) that affect coverage.

## Direction change (appliance UI)

Decided: the user never edits config files. One model file
(`/var/opf/config.json`) is the source of truth and every OpenBSD file
is generated from it; the UI is React + Mantine (`ui/`), served by the
Go binary. The staging/commit/confirm/history engine stays, with
generated files as its outputs.

- [x] Go: config model types matching `ui/src/model/types.ts`, and
      generators for pf.conf, hostname.if, dhcpd.conf, unbound.conf,
      myname and ntpd.conf (`internal/pf`). Golden files cover the pf
      parser; the other generators still need golden tests, and
      rc.conf.local isn't generated at all.
- [x] Stage the model instead of raw files; the review dialog lists
      readable change summaries, with generated-file diffs as detail.
- [x] JSON API for the UI (`docs/api.md`); the htmx pages are gone.
- [ ] Embed `ui/dist` in the binary.
- [x] Hand-edited generated files: staging refuses with
      `modified_outside` until the user chooses to replace them.
- [ ] First-boot setup wizard (WAN, LAN, admin password).
- [ ] **Config import parsers** (see principle 4): parse existing
      `pf.conf`, `hostname.if`, `dhcpd.conf`, `unbound.conf`, etc. into
      the OPF model. Must handle hand-written configs with comments,
      includes, macros, and features OPF doesn't fully support (preserve
      as raw blocks). Golden-file tests against real-world configs.
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
- [ ] rc.conf.local generation: enabling DHCP, DNS or WireGuard must set
      `dhcpd_flags` (with the interface list), `unbound_flags` and so on,
      applied with rcctl.
- [ ] Anti-lockout ports (443, 22) are hard-coded; derive them from the
      web UI and sshd settings.
- [ ] NAT reflection is added on every inside interface; limit it to the
      ones that need it.
- [ ] Check whether reloading pf empties `persist` tables such as
      `<bruteforce>`; if so, save and restore their contents.
- [ ] Per-client traffic stats and graphs: pf only tracks bytes per
      active connection (lost when closed) and per-interface aggregates.
      Options: periodic state polling with aggregation by IP, pf rule
      labels with accounting, or pflow(4) NetFlow export to a collector.

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
- [ ] DHCP names in DNS (`internal/leases`): the lease file format
      matches what OpenBSD's dhcpd writes (`db.c`: time format, `UTC`,
      `client-hostname`); `unbound-control -c … list_local_data` output
      and `local_data` replies are as parsed; the control socket at
      `/var/run/unbound.sock` works with unbound's chroot; the parent can
      read `/var/db/dhcpd.leases` under unveil, including after dhcpd
      replaces the file.
- [ ] Split-tunnel enforcement: pfctl accepts `$iface:network` entries
      in a `const` table (used for DHCP-addressed inside networks in
      `<opf_local>`), and the block rule stops a split-tunnel device
      that sets `AllowedIPs = 0.0.0.0/0` from reaching the internet.
- [ ] Check how dhcpd writes a `client-hostname` containing `"`. If
      `db_printable` lets it through unescaped, a client can forge extra
      lease statements in the file. Records limits the damage (dynamic
      range only, reserved names, clashing names dropped), but the
      parser can't tell forged statements from real ones.

## Security

- [ ] **No authentication.** It has to be enforced in the parent, not
      the web process: a compromised web process can currently call
      Stage and Commit directly. Likely `auth_userokay(3)` (cgo) plus
      sessions checked at the RPC boundary.
- [ ] TLS.
- [ ] Anyone who can commit can get root: rc.conf.local is sourced by
      rc(8), and sshd_config/httpd.conf are powerful. That comes with
      the product, but it's why auth and audit logging matter.
- [ ] Cap RPC message sizes: gob decoding in the root process is
      unbounded (HTTP bodies are capped at 4 MiB, but a compromised web
      process could send more).
- [x] Cross-origin state-changing requests are refused
      (`http.CrossOriginProtection`); internal errors reach clients only
      as "internal error".
- [ ] Record who made each commit in history once there are users.

## Live monitoring data

The legacy server (`legacy/server/`) collected extensive runtime data
that the new UI doesn't yet surface. Each feature needs:
1. **Go backend**: Parser for command output, API endpoint, mock data for non-OpenBSD
2. **Frontend**: UI page or component, TypeScript types, mock data in `live.ts`

### System metrics

- [ ] **CPU usage** (`sysctl kern.cp_time`)
      - Backend: Parser, `GET /api/system/cpu`, mock data
      - Frontend: Dashboard meter (currently hardcoded 18%), history graph
- [ ] **Load average** (`sysctl vm.loadavg`)
      - Backend: Parser, `GET /api/system/loadavg`, mock data
      - Frontend: Dashboard display, 1/5/15 minute values
- [ ] **Memory details** (vmstat, `sysctl hw.physmem`)
      - Backend: Parser, `GET /api/system/memory`, mock data
      - Frontend: Dashboard meter with breakdown (active/free/wired/cached)
- [ ] **Swap usage** (`swapctl -l`)
      - Backend: Parser, `GET /api/system/swap`, mock data
      - Frontend: Dashboard meter when swap is configured
- [ ] **Disk usage** (`df -P`)
      - Backend: Parser, `GET /api/system/disks`, mock data
      - Frontend: Dashboard meter per mount, storage page
- [ ] **Disk I/O** (vmstat disk transfers)
      - Backend: Parser, `GET /api/system/diskio`, mock data
      - Frontend: Per-disk read/write rates
- [ ] **Boot time / uptime** (`sysctl kern.boottime`)
      - Backend: Parser, `GET /api/system/uptime`, mock data
      - Frontend: Dashboard (currently mock), System General page
- [ ] **Hardware sensors** (`sysctl hw.sensors`)
      - Backend: Parser, `GET /api/system/sensors`, mock data
      - Frontend: Temperature, fan speed, voltage readings
- [ ] **Hardware info** (`sysctl hw`)
      - Backend: Parser, `GET /api/system/hardware`, mock data
      - Frontend: System General page (CPU model, RAM, disks)
- [ ] **Process list** (`ps aux`)
      - Backend: Parser, `GET /api/system/processes`, mock data
      - Frontend: New Diagnostics > Processes page with sorting/filtering

### pf firewall diagnostics

- [ ] **pf states** (`pfctl -vv -s states`)
      - Backend: Parser, `GET /api/pf/states`, mock data
      - Frontend: Connections page (currently mock only), kill state action
- [ ] **pf rule statistics** (`pfctl -vv -s rules`)
      - Backend: Parser, `GET /api/pf/rules`, mock data
      - Frontend: Rules page per-rule counters (evaluations, packets, bytes)
- [ ] **pf info/counters** (`pfctl -v -s info`)
      - Backend: Parser, `GET /api/pf/info`, mock data
      - Frontend: Firewall dashboard tile (state table size, match rate, drops)
- [ ] **pf interface stats** (`pfctl -vv -s Interface`)
      - Backend: Parser, `GET /api/pf/interfaces`, mock data
      - Frontend: Per-interface packet/byte counters, cleared/referenced stats
- [ ] **pf memory** (`pfctl -s memory`)
      - Backend: Parser, `GET /api/pf/memory`, mock data
      - Frontend: Firewall Settings or System page (state table limits)
- [ ] **Kill state by ID** (`pfctl -k id -k <id>`)
      - Backend: `POST /api/pf/kill`, action endpoint
      - Frontend: Kill button in Connections page per-connection
- [ ] **Kill states by criteria** (`pfctl -k <src> -k <dst>`)
      - Backend: `POST /api/pf/kill`, action endpoint with filters
      - Frontend: Bulk kill by IP/interface in Connections page

### Network interfaces

- [ ] **Interface statistics** (`netstat -i -n`)
      - Backend: Parser, `GET /api/network/interfaces`, mock data
      - Frontend: Interfaces page (rx/tx packets, errors, collisions)
- [ ] **Interface status** (`ifconfig -a`)
      - Backend: Parser, included in interfaces endpoint, mock data
      - Frontend: Link state, media type, addresses, flags

### WireGuard

- [ ] **Peer status** (`ifconfig wgN` or `wg show`)
      - Backend: Parser, `GET /api/wireguard/status`, mock data
      - Frontend: WireGuard page peer list (handshake time, rx/tx bytes)
      - Note: Parser must handle per-tunnel output

### Services management

- [ ] **Service list** (`rcctl ls all`)
      - Backend: Parser, `GET /api/services`, mock data
      - Frontend: New Services page listing all services
- [ ] **Service status** (`rcctl ls on`, `rcctl ls started`)
      - Backend: Combined in services endpoint, mock data
      - Frontend: Enabled/running status per service
- [ ] **Service details** (`rcctl get <service>`)
      - Backend: Parser, `GET /api/services/:name`, mock data
      - Frontend: Service detail view (flags, user, rtable, timeout)
- [ ] **Start/stop service** (`rcctl start/stop <service>`)
      - Backend: `POST /api/services/:name/start`, `POST /api/services/:name/stop`
      - Frontend: Start/Stop buttons in Services page
- [ ] **Enable/disable service** (`rcctl enable/disable <service>`)
      - Backend: `POST /api/services/:name/enable`, `POST /api/services/:name/disable`
      - Frontend: Enable/Disable toggle in Services page

### System logs

- [ ] **dmesg** (`dmesg`)
      - Backend: Parser (or raw), `GET /api/logs/dmesg`, mock data
      - Frontend: New Diagnostics > System Logs page, dmesg tab
- [ ] **/var/log/messages**
      - Backend: File reader with tail, `GET /api/logs/messages`, mock data
      - Frontend: System Logs page, messages tab
- [ ] **/var/log/daemon**
      - Backend: File reader with tail, `GET /api/logs/daemon`, mock data
      - Frontend: System Logs page, daemon tab
- [ ] **/var/log/authlog**
      - Backend: File reader with tail, `GET /api/logs/authlog`, mock data
      - Frontend: System Logs page, auth tab (login attempts, sudo)
- [ ] **Firewall log** (`tcpdump -n -e -ttt -r /var/log/pflog`)
      - Backend: Parser, `GET /api/logs/firewall`, mock data
      - Frontend: Diagnostics > Firewall log (currently mock only)

### Traffic and bandwidth

- [ ] **Interface traffic rates** (periodic `netstat -i` delta)
      - Backend: Rate calculation from counter deltas, mock data
      - Frontend: Dashboard traffic chart (currently simulated), per-interface sparklines
- [ ] **Per-rule traffic** (`pfctl -s labels`)
      - Backend: Parser, `GET /api/pf/labels`, mock data
      - Frontend: Rules page with bytes/packets per rule

### Implementation notes

- All parsers go in `internal/appliance/` alongside existing `parseARPOutput`
  and `parseRoutingOutput`
- Each parser needs `runtime.GOOS` check to return mock data on non-OpenBSD
- Mock data functions follow `sampleARPTable()` / `sampleRoutingTable()` pattern
- Frontend types go in `ui/src/lib/api.ts` (API types) and `ui/src/model/live.ts` (mock)
- Consider batching related endpoints (e.g., `/api/system/stats` combining CPU/memory/load)
- Rate-limited polling in frontend (e.g., 5s for stats, 30s for logs)
- WebSocket option for real-time updates (pflog, traffic) - future consideration

## OpenBSD base system daemons

Services from OpenBSD base that should be surfaced in the UI for a
network appliance. Organized by priority. All are controlled via rcctl.

### Design principle: full configuration through OPF

Every service should be fully configurable through OPF, not just basic
options. Users should never need to SSH in and edit config files manually.

- [ ] **Basic config UI** for common options (ports, addresses, toggles)
- [ ] **Advanced config UI** for all daemon options, even obscure ones
- [ ] **Raw config option** as escape hatch for anything the UI doesn't
      cover, similar to raw pf rules - include arbitrary config lines
      that get appended to the generated config file
- [ ] **Config file preview** showing exactly what will be written,
      like the pf.conf preview in the Ruleset page
- [ ] **Validation** using each daemon's own checker where available
      (e.g., `httpd -n`, `smtpd -n`, `bgpd -n`, `ospfd -n`)

The goal is an appliance where the UI is the complete interface. A user
who only knows the UI should have access to every feature. Advanced
users get the same power as editing files directly, with the safety of
validation and atomic commits.

For each daemon, the model should include:
- All configuration options as structured fields where practical
- A `raw` or `extra` field for arbitrary config lines
- Generated config goes through the commit engine like other files

### Core services (most users need)

These should show status on the Services page and allow start/stop:

- [ ] **sshd** - Remote SSH access
      - Critical for administration
      - Show: running status, connected sessions count
      - Config: listen addresses, port, permit root login
- [ ] **ntpd** - Time synchronization
      - Critical for logs, certificates, DNSSEC
      - Show: sync status, offset, peers
      - Config: servers/pools, listen address, sensor
- [ ] **pflogd** - Firewall logging to /var/log/pflog
      - Critical for diagnostics
      - Show: running status, log file size
      - Config: log file, snaplen, interface
- [ ] **syslogd** - System logging
      - Important for all logs
      - Show: running status
      - Config: remote syslog destinations
- [ ] **cron** - Scheduled tasks
      - Important for blocklist updates, backups, maintenance
      - Show: running status, next scheduled jobs
      - Future: UI for managing cron jobs
- [ ] **dhcpleased** - DHCP client for interfaces
      - Essential for DHCP-configured WANs
      - Show: running status, leases obtained
      - Note: Automatically managed per-interface
- [ ] **slaacd** - IPv6 SLAAC client
      - Essential for IPv6 autoconfiguration
      - Show: running status, addresses obtained
      - Note: Automatically managed per-interface

### Already configurable in OPF

These have dedicated UI pages; the Services page should show their
status and link to their config pages:

- [x] **dhcpd** - DHCP server (Services > DHCP server)
- [x] **unbound** - DNS resolver (Services > DNS resolver)
- [x] **pf** - Packet filter (Firewall pages)

### Useful additions (Tier 2)

These warrant configuration UI beyond just start/stop:

- [ ] **httpd** - Web server
      - Use case: Captive portal, hosting blocklists, simple file serving
      - Config: virtual hosts, TLS, document roots
      - UI: Services > Web server page
- [ ] **rad** - IPv6 router advertisement daemon
      - Use case: IPv6 networks, announcing prefixes/DNS to clients
      - Config: interfaces, prefixes, DNS servers, MTU
      - UI: Part of interface config or Services > IPv6 RA
- [ ] **relayd** - Load balancer, relay, health checks
      - Use case: Multi-WAN health monitoring, reverse proxy, redirects
      - Config: tables, protocols, relays, redirections
      - UI: Services > Load Balancer or Network > Gateways health
      - Note: Can replace custom gateway monitoring
- [ ] **smtpd** - OpenSMTPD mail relay
      - Use case: Send alert/notification emails from the appliance
      - Config: relay host, authentication, local aliases
      - UI: System > Notifications or Services > Mail relay
- [ ] **snmpd** - SNMP monitoring agent
      - Use case: Integration with monitoring systems (Nagios, Zabbix, etc.)
      - Config: community strings, trap receivers, system info
      - UI: Services > SNMP

### Advanced networking (Tier 3)

For advanced users; show in Services page but config may be complex:

- [ ] **ospfd** - OSPFv2 dynamic routing
      - Use case: Multi-router networks, automatic route failover
      - Config: areas, interfaces, neighbors, redistribution
      - UI: Network > Dynamic Routing > OSPF
- [ ] **ospf6d** - OSPFv3 for IPv6
      - Use case: IPv6 dynamic routing
      - Config: areas, interfaces, redistribution
      - UI: Network > Dynamic Routing > OSPFv3
- [ ] **bgpd** - BGP routing
      - Use case: Multi-homing, transit, route servers, advanced policy
      - Config: AS number, neighbors, filters, communities
      - UI: Network > Dynamic Routing > BGP
      - Note: Complex; may need raw config option
- [ ] **iked** - IKEv2 IPsec VPN
      - Use case: Site-to-site IPsec, mobile IKEv2 clients
      - Config: policies, flows, authentication, proposals
      - UI: Services > IPsec VPN (alongside WireGuard)
- [ ] **npppd** - PPP daemon (PPPoE, L2TP)
      - Use case: DSL/PPPoE WANs, L2TP VPN server
      - Config: interfaces, authentication, IP pools
      - UI: Interface config for PPPoE; Services > L2TP for VPN
- [ ] **ifstated** - Interface state daemon
      - Use case: Automatic WAN failover, link monitoring
      - Config: state definitions, interface triggers, actions
      - UI: Network > Failover or integrated with multi-WAN
      - Note: Works with carp, route changes
- [ ] **eigrpd** - EIGRP routing
      - Use case: Mixed Cisco environments
      - Config: AS number, interfaces, redistribution
      - UI: Network > Dynamic Routing > EIGRP
- [ ] **ripd** - RIP routing (legacy)
      - Use case: Simple/legacy dynamic routing
      - Config: interfaces, redistribution
      - UI: Network > Dynamic Routing > RIP

### Niche services (Tier 4)

Available but rarely needed; show in Services if enabled:

- [ ] **nsd** - Authoritative DNS server
      - Use case: Hosting DNS zones (not just resolving)
      - Config: zones, primaries/secondaries
      - UI: Services > Authoritative DNS
- [ ] **tftpd** - TFTP server
      - Use case: PXE boot, firmware upgrades for network devices
      - Config: root directory, chroot
      - UI: Services > TFTP
- [ ] **tftpproxy** - TFTP proxy for pf
      - Use case: TFTP through NAT
      - Config: listen address
- [ ] **radiusd** - RADIUS server
      - Use case: Network authentication (802.1X, VPN auth)
      - Config: clients, users, authentication backends
      - UI: Services > RADIUS
- [ ] **ldapd** - LDAP directory server
      - Use case: Centralized authentication, directory services
      - Config: schemas, ACLs, backends
      - UI: Services > LDAP
- [ ] **ftpd** - FTP server
      - Use case: File transfers (legacy)
      - Config: chroot, anonymous access
      - UI: Services > FTP
- [ ] **ftpproxy** - FTP proxy for pf
      - Use case: FTP through NAT (active mode)
      - Config: listen address
- [ ] **isakmpd** - IKEv1 IPsec (legacy)
      - Use case: Legacy IPsec peers that don't support IKEv2
      - Note: Prefer iked for new deployments
- [ ] **sasyncd** - IPsec SA synchronization
      - Use case: IPsec failover between carp hosts
      - Config: peer, interface, carp group
- [ ] **ldpd** - MPLS LDP
      - Use case: MPLS networks
      - Config: interfaces, neighbors
- [ ] **dvmrpd** - Multicast routing (DVMRP)
      - Use case: Multicast across routers
      - Config: interfaces, groups
- [ ] **mrouted** - Multicast routing (legacy)
      - Use case: Legacy multicast
- [ ] **hostapd** - Wireless access point
      - Use case: WiFi AP (if hardware supports it)
      - Config: SSID, authentication, channel
      - UI: Services > Wireless AP
- [ ] **lpd** - Line printer daemon
      - Use case: Print server (very legacy)

### Services page implementation

- [ ] Services page showing all base system daemons
      - Group by category (Core, Network, Security, etc.)
      - Show: name, description, enabled, running, actions
      - Quick actions: start, stop, restart, enable, disable
      - Link to config page for services with dedicated UI
- [ ] Service detail view
      - Status, uptime, resource usage
      - Recent log entries for that service
      - Configuration (where applicable)
- [ ] Dependency awareness
      - Some services depend on others (e.g., dhcpd needs interfaces up)
      - Show warnings when disabling a dependency
- [ ] Boot order
      - Show/configure rc.d(8) order where relevant

## pf labels

Generated rules are labelled `opf:<kind>:<id>` (rule, forward, nat,
auto-nat, builtin) and descriptions are `#` comments above them, so
descriptions are free text and counters map back to model objects.

- [ ] Show live counters per rule from `pfctl -s labels`, and kill a
      rule's states with `pfctl -k label -k opf:rule:<id>`.
- [ ] Map pflog entries (rule numbers) to model rules through
      `pfctl -vvsr`'s labels.
- [ ] Raw rules only have a label if their text has one. Offer to add
      OPF's when a raw rule has none.
- [ ] Importing: rules with their own label stay raw (the guided form's
      label is its id). Offer to turn those labels into descriptions.

## Virtual interfaces (bridges, aggregation, tunnels)

Creating virtual interfaces from the Interfaces page. Today there are
physical ports, VLANs and WireGuard tunnels, each one hostname.<dev>
file applied with `sh /etc/netstart <devs>`.

Groundwork, needed by every type:

- [ ] **Removing interfaces**: delete hostname.<dev> and run
      `ifconfig <dev> destroy`. The commit engine refuses file removals
      today (same gap as deleting a tunnel).
- [ ] **Apply order by dependency.** netstart brings up the devices it's
      given in order, and OPF passes them in path order, so
      hostname.bridge0 comes before its member hostname.em1 (VLANs only
      work because em1 sorts before vlan20). Order parents and members
      before the interfaces built on them, and the reverse on removal.
- [ ] **Confirm and auto-revert for interface changes.** Moving the
      LAN's address onto a bridge is the easiest way to lock yourself
      out, and hostname.if files are applied directly with no
      confirmation (netstart can't load a staged copy). Install, then
      restore the old files and re-run netstart on timeout; that gives
      up pf.conf's "a reboot reverts it" guarantee, so decide how to
      handle a reboot during the window.
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
- [ ] Removing a tunnel: deleting its interface would remove
      `hostname.wgN`, and removing generated files isn't supported yet
      (see Next up). Until then a tunnel can only be turned off.
- [ ] Editing a peer: only adding and removing exist.
- [ ] pf and routing per tunnel: site-to-site tunnels (routed networks,
      usually no NAT) and remote-access ones (clients NATed out) need
      different defaults for automatic NAT and generated rules. Today
      every tunnel's network gets automatic NAT.
- [ ] Peer status (`wg show`, sample data in `live.ts`) comes per
      interface; the parser must key it by tunnel and peer.
- [ ] Key storage (see Code) has to hold one private key per tunnel.

## DHCP names in DNS

- [ ] No PTR records for leases (or reservations): reverse lookups of
      DHCP clients fail.
- [ ] A commit reverted by the confirm timeout doesn't kick the watcher,
      so names are missing for up to 15 s after unbound reloads.
- [ ] IPv4 only; no names for SLAAC or DHCPv6 clients.
- [x] Show registered and refused names in the UI: `GET /api/dns/leases`
      and "DHCP devices by name" on the DNS page.
- [x] The DHCP page's leases table reads the leases file
      (`GET /api/dhcp/leases`) and says which name each device got.
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

## Staging and commit

- [x] While a commit waits for confirmation, staging is refused with
      `commit_pending` and the UI blocks edits and undo.
- [ ] If OPF is killed with SIGKILL (or crashes) during the confirm
      window, the staged pf rules stay loaded until reboot or the next
      start. `Recover` only runs at startup.
- [ ] `hostname.if(5)`: pattern entries handle the names;
      `sh /etc/netstart <if>` can't load from another path. Confirmation will have to install, then restore a
      backup on timeout, so the "reboot also reverts" guarantee is lost.
      Needs a design. Interfaces must be applied before pf.
- [ ] rc.conf.local is only checked with `sh -n`; nothing is applied.
      Service enable/disable/flags should be staged through it and
      reconciled with rcctl on commit.
- [ ] Decide whether a service that fails to reload or restart should
      revert the whole commit (it does now).
- [ ] Deleting a managed file isn't supported (Next up, step 3).
- [x] Two browsers: staging requires the live version the edits started
      from and committing requires the staged version, so neither undoes
      the other's work silently (`conflict`).
- [ ] A second browser's staging replaces the first's staged model
      (there's one candidate). Fine for one admin; revisit with users.
- [ ] When the UI loads a model someone else staged, it lists the
      changes by section only ("Changed firewall settings"); the edit
      descriptions aren't stored with the staged model.
- [ ] History is never pruned.
- [ ] Newly created parent directories get 0755; check what each managed
      path expects.

## Development and cross-platform testing

OPF targets OpenBSD exclusively, but development and testing should be
possible on any platform. This requires mocking the OpenBSD-specific
backends so the UI, API, and business logic can be tested without a
real OpenBSD system.

### Mock backend for non-OpenBSD platforms

`make mock` (`scripts/mock.sh`) runs `opf -mock` on 127.0.0.1:18080 and
the Vite dev server, which proxies `/api` to it. The mock is one
process with the real generators, pf parser and staging engine,
started from `ui/src/model/sample-model.json` (shared with the UI and
checked against the Go model by `internal/pf/sample_model_test.go`). It
keeps files in a scratch directory whose "live" files are what the
sample model generates, logs commands instead of running them, and
refuses non-loopback addresses.

- [x] Commit, confirm and revert through the API; a short
      `-confirm-timeout` makes the timeout testable.
- [x] Pattern established for live data: `runtime.GOOS` check in each
      method, `sample*()` functions return mock data on non-OpenBSD.
      See ARP table and routing table implementations in `manager.go`.
- [ ] Live data endpoints fed from fixtures (states, rules with
      counters, interfaces, leases, WireGuard peers, pflog), so the
      dashboard and diagnostics stop reading `ui/src/model/live.ts`.
      See "Live monitoring data" section for the full feature list.
- [ ] Recorded response mode: capture real OpenBSD command output
      (`opf -record dir`) and replay it in the mock.
- [ ] Simulated validator results: run the Go pf parser on staged
      pf.conf so `pfctl -nf`-style errors can be exercised; today every
      check passes.
- [x] Load the model from the backend on startup (`GET /api/config`)
      instead of the UI's bundled copy. The preview build uses an
      in-browser stand-in (`ui/src/lib/localApi.ts`).

### Frontend development workflow

- [x] `npm run dev` proxies `/api/*` to the Go backend; `make mock`
      starts one.
- [ ] Storybook or similar for developing components in isolation.

## Code

- [ ] **Rewrite monitoring parsers** from scratch, using `legacy/server`
      only as a reference. The legacy parsers index fields by position
      and crash on unexpected input—they are not safe to port directly.
      New parsers must:
      - Handle all valid output from each command (`pfctl -s states`,
        `pfctl -s rules`, `pfctl -s info`, `ifconfig`, `rcctl`, etc.)
      - Return errors on malformed input, never panic or produce garbage
      - Have golden-file tests against real captured output from multiple
        OpenBSD versions
      - Be fuzz-tested where practical
      Delete `legacy/` only after the new parsers are complete and tested.
- [ ] Per-rule stats over time: the UI shows live counters but there's
      no historical data or graphing. Needs periodic polling and storage
      to graph evaluations/packets/bytes per rule.
- [ ] `privsep.Client.Pending` drops RPC errors; the banner shows nothing
      if the parent is unreachable.
- [ ] `golang.org/x/sys` is pinned to v0.44.0 to keep Go 1.25; revisit
      when OpenBSD packages Go 1.26.
- [ ] CI running `make test`, plus GOOS=openbsd vet/build.
- [ ] `myname` and `mygate` are generated but not in the registry—need
      managed file entries or generate them outside the commit flow.
- [ ] URL-type alias tables need a refresh mechanism (cron-like, or on
      demand) to re-fetch and reload the table files.
- [ ] WireGuard private key storage: currently a placeholder in the
      hostname.if generator; needs secure storage and key generation.
- [ ] `resolv.conf` not handled; DNS client config isn't generated or
      managed (OpenBSD uses /etc/resolv.conf.tail with resolvd).
- [ ] `lib/ip.ts` is IPv4-only—needs `isIPv6()`, v6 CIDR validation, and
      `network()`/`netmask()` equivalents for IPv6.
- [ ] Generators are IPv4-first: `automaticNat()` only emits `inet` rules,
      `unboundConf()` only adds IPv4 access-control entries.
- [ ] DHCP gateway handling in `mygate`: generator skips it when the
      default gateway is DHCP; dhclient handles this differently.
- [ ] Frontend tests: no UI test coverage exists.
- [ ] UI gaps: deleting VLANs and interfaces (and their `hostname.*`
      files); a Services page (rcctl status, start/stop); sign-in page;
      real actions behind placeholders (change password, syspatch,
      backup download/restore); diagnostics tools (ping, traceroute, DNS
      lookup, `pfctl -k`); showing that editing is blocked while a
      commit waits for confirmation; a version on the staged model so
      two admins can't silently overwrite each other; splitting the
      1.6 MB bundle by page.
- [ ] Delete the stale Dependabot branches on origin; they target the
      old `ui/`.
- [ ] File locking: no guard against two OPF instances running at once.
- [ ] Graceful shutdown: document/verify that SIGTERM waits for pending
      operations and reverts unconfirmed commits.
- [ ] Backup/restore: no way to export/import the config.json model for
      disaster recovery or migration.
