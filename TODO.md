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

## Where things stand (2026-09-28)

- **Go, working and tested:** staging, check, commit with confirm and
  auto-revert, history, recovery at startup, privilege separation with
  pledge/unveil (`internal/config`, `internal/privsep`). It stages raw
  files, not the model.
- **Go, new:** `internal/pf` has the model, generators for every file,
  a pf tokenizer and parser (text back to guided rules), golden files
  and fuzz targets. `internal/web/model.go` has a model API
  (`/api/model`, `/preview`, `/apply`) plus parse/generate endpoints.
- **Not connected yet:** `cmd/opf` passes an empty model path, so the
  model API returns 500 in the real binary. The model lives in the web
  process instead of the parent. The UI's confirm/revert is still
  simulated in the browser.
- **UI:** every page exists. It runs on sample data, except Apply, which
  now calls the backend (see bugs below).
- **Never run on OpenBSD.**

## Next up

In order. Each step has details further down.

1. **Fix the bugs found in review** (next section), starting with model
   validation, a correctness and security problem under the principles
   above.
2. **Move the model into the parent.** The web process sends a model
   over RPC; the parent validates it, generates every file, stages them
   as one unit, and owns `config.json` (atomic write, 0600). Commit,
   confirm and revert go through the same RPC, so the UI's countdown is
   the backend's.
3. **Make generated outputs first-class in the commit engine.** The file
   registry becomes the set of generated files, including ones that come
   and go (`hostname.vlan30`), with deletion. Apply order: interfaces,
   routes, pf, services. Check the whole set before touching anything.
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
- [ ] Importing (principle 4) must build the model's interfaces first:
      rules naming devices (`on em0`) only become guided rules when the
      device is in the model, otherwise they stay raw.
- [ ] Reject invalid UTF-8 on import with a clear error. `encoding/json`
      replaces it with U+FFFD, so even raw rules would change when
      `config.json` is saved.
- [ ] **No model validation.** Nothing checks the model before
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
- [ ] **`/api/model/apply` fails for any model with interfaces.** It
      stages `hostname.<dev>`, which isn't in the config registry, so the
      check returns "unknown file".
- [ ] **Apply isn't atomic.** Files are checked and staged one at a time;
      a failure part-way leaves some staged and the model unsaved.
- [ ] **The model lives in the web process.** `ModelManager` writes
      `config.json` from the unprivileged side, non-atomically, mode
      0644. Belongs in the parent (Next up, step 2).
- [ ] **The mock UI can't apply.** The store requires
      `/api/model/apply`, so apply fails under `npm run dev` and in the
      shared preview. Needs a mock mode (see Mock backend).
- [ ] **Confirm is client-side only.** Keep and revert don't reach the
      backend; the backend never loads anything today.
- [ ] **Unbounded request bodies** on every `/api/*` endpoint
      (`io.ReadAll`); use `http.MaxBytesReader`.

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
- [ ] Stage the model instead of raw files; Changes becomes a list of
      readable change summaries, with generated-file diffs as detail.
- [ ] JSON API for the UI, replacing the mock store in
      `ui/src/model/store.tsx`; embed `ui/dist` in the binary. Remove the
      htmx templates in `internal/web` once the API exists. Started:
      model, preview, apply and parse/generate endpoints exist but aren't
      connected (see Where things stand).
- [ ] Hand-edited generated files: detect and warn before overwriting.
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

## Development and cross-platform testing

OPF targets OpenBSD exclusively, but development and testing should be
possible on any platform. This requires mocking the OpenBSD-specific
backends so the UI, API, and business logic can be tested without a
real OpenBSD system.

### Mock backend for non-OpenBSD platforms

- [ ] `--mock` flag that enables a mock backend instead of real system
      commands. Useful for UI development on macOS/Linux and CI testing.
- [ ] Mock `config.Manager` implementation that:
      - Returns pre-defined sample data for all queries
      - Accepts stages/commits without running real validators
      - Simulates the confirm/revert workflow with timers
      - Logs what commands *would* have run for debugging
- [ ] Mock data fixtures:
      - Sample pf states, rules, and info from a realistic firewall
      - Sample interface configs (WAN with DHCP, LAN with static IP, VLANs)
      - Sample DHCP leases and DNS stats
      - Sample WireGuard peer status
- [ ] Recorded response mode: capture real OpenBSD command output to files,
      replay in mock mode. Allows testing against real data without OpenBSD.
      - `opf --record /path/to/fixtures` captures live data
      - `opf --mock --fixtures /path/to/fixtures` replays it
- [ ] Mock validator responses: simulate `pfctl -nf` validation results,
      including realistic error messages for invalid configs.
- [ ] Time simulation for confirm/revert testing: allow fast-forwarding
      the confirmation timeout in mock mode.
- [ ] API-only mock mode: `opf --mock --api-only` starts just the JSON API
      without serving the UI, for frontend development with `npm run dev`.
- [ ] Document mock mode limitations: what differs from real OpenBSD
      behavior (no actual network changes, no real file writes, etc.).

### Frontend development workflow

- [ ] `npm run dev` in `ui/` should work standalone with API calls proxied
      to a mock backend or a real OPF instance.
- [ ] Vite proxy config to forward `/api/*` to the Go backend.
- [ ] Hot reload for UI development without rebuilding the Go binary.
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
