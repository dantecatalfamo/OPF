# OPF API

The web UI's only way to change the system. It's served by the
unprivileged web process (`internal/web`) and backed by the root
process (`internal/appliance`, over `internal/privsep`), which validates
everything it's given.

Every request but signing in needs a session (see Signing in). The
mock server (`opf -mock`) has no accounts unless it's started with
`-mock-login name:password`.

## Conventions

- Every body is JSON. Requests with a body must send
  `Content-Type: application/json` (otherwise 415). Bodies are limited
  to 4 MiB (413). Unknown fields and trailing data are rejected (400).
- Cross-site requests that change state are refused
  (`http.CrossOriginProtection`, 403).
- Responses are `Cache-Control: no-store`. Configuration responses carry
  their version as an `ETag`.
- A **version** is a hash of a model's canonical JSON. `"none"` is the
  version of a configuration that doesn't exist yet.

### Errors

```json
{"error": {"code": "invalid", "message": "…", "details": [{"path": "firewall.aliases[2].name", "message": "…"}]}}
```

| code | status | meaning |
|---|---|---|
| `invalid` | 400/422 | malformed request (400), or the model fails validation (422); `details` name each field |
| `check_failed` | 422 | a validator (`pfctl -n`, `dhcpd -n`, …) rejected a generated file; `details[].output` is its output |
| `unsupported` | 422 | something OPF can't do yet |
| `not_found` | 404 | no such commit or resource |
| `nothing_staged` | 404 (409 on commit) | there's no staged model |
| `conflict` | 409 | a version didn't match: someone else changed the configuration |
| `commit_pending` | 409 | a commit is waiting for confirmation; nothing else can change until it's kept or reverted |
| `not_pending` | 409 | the commit isn't the one waiting (perhaps it just timed out) |
| `modified_outside` | 409 | files were edited outside OPF; `details[].path` lists them |
| `unauthorized` | 401 | not signed in, the session ended, or the name or password is wrong |
| `forbidden` | 403 | signed in, but the role doesn't allow it |
| `rate_limited` | 429 | too many failed sign-ins from this name or address; the message says when to try again |
| `reauth_required` | 403 | give your password again first (`POST /api/session/reauth`), then repeat the request |
| `internal` | 500 | logged on the server; the message says only "internal error" |

## Signing in

Accounts are OpenBSD's own, checked by the privileged process with the
account's login style (bsd_auth's `login_<style>`, from login.conf's
`auth-opf` or `auth`). A user's groups give their role:

| group | role | may |
|---|---|---|
| `_opfadmin` | `admin` | everything |
| `_opfoperator` | `operator` | look; confirm or revert a commit; run tools; refresh lists; kill states; forget cached DNS answers; test webhooks |
| `_opfview` | `view` | look |

Anyone in none of them can't sign in, root included.

- `GET /api/session`: `{"accounts", "session", "tls"}`. `accounts` is
  false on a server without them; `session` (`{"id", "user", "role",
  "source", "created", "lastUsed"}`) is there when signed in; `tls` is
  the SHA-256 of the certificate served, which OPF also logs at start,
  to compare before trusting it.
- `POST /api/session` with `{"user", "password"}`: signs in, answering
  as `GET` does, with the session in a cookie, `__Host-opf`: `Secure`,
  `HttpOnly`, `SameSite=Strict`, for the path `/`. The token is never
  in a body. A wrong name, a wrong password and an account in none of
  the groups all answer the same `unauthorized`, after at least a
  second. After a failure, the name and the address each wait a second
  before the next try, doubling up to five minutes (`rate_limited`).
- `DELETE /api/session`: signs out (204) and clears the cookie.
- `GET /api/sessions`: `{"sessions"}`, your own; an admin's,
  everyone's.
- `DELETE /api/sessions/{id}`: ends one of yours; an admin, anyone's.

- `POST /api/session/reauth` with `{"password"}`: gives your password
  again (204). Changes to accounts need it within the last five
  minutes, counting signing in; otherwise they answer
  `reauth_required`.
- `PUT /api/session/password` with `{"current", "new"}`: changes your
  own password (anyone; at least 12 characters). Your other sessions
  end.

### Accounts

Admins only. The accounts are the system's: OPF changes only
membership of its three groups (never wheel or any other), makes and
removes the accounts it created itself, and sets passwords and locks.
These happen at once, not through staging; each needs the password
given within five minutes, and goes to OPF's log, the event log
(`login`) and authlog. Root, accounts under uid 1000 and `_`-prefixed
ones can't be given a role; nobody can take away their own admin role,
lock or remove themselves; and the last admin can't be demoted, locked
or removed (`conflict`).

- `GET /api/users`: `{"users", "candidates"}`, each `{"name",
  "fullName", "role", "locked", "expired", "class", "shell",
  "created"}`: who can sign in, and the accounts that could be given a
  role. `shell` is whether it can also log in over SSH or at the
  console; `created`, whether OPF made it.
- `POST /api/users` with `{"name", "fullName", "role", "password",
  "shell"}`: makes an account (201). The password goes to encrypt(1)
  on stdin; only the hash is passed to useradd.
- `PUT /api/users/{name}/role` with `{"role"}` (`admin`, `operator`,
  `view`, or `""` for none): their sessions take the new role on their
  next request.
- `PUT /api/users/{name}/password` with `{"password"}`: their sessions
  end.
- `PUT /api/users/{name}/lock` with `{"locked"}`: locking ends their
  sessions.
- `DELETE /api/users/{name}`: removes an account OPF made; for one it
  didn't, takes away its role and says so in `{"note"}`.

A session ends after 30 minutes unused or 12 hours in all, when OPF
restarts, and when its account changes: a new password, leaving the
groups, or expiring (checked each minute). Only requests marked
`X-OPF-Active: 1` count as using it; the UI marks those made within a
minute of someone touching the page, so a page left open, polling,
still signs out. A commit records its author from the session, and its
log who confirmed or reverted it.

Plain HTTP is only served on a loopback address (for `ssh -L`); on any
other, `opf` serves HTTPS with a self-signed certificate it makes on
first start (`<state>/tls`), or one put there in its place.

## Making a change

```
GET  /api/config                 → {version: L, model}
PUT  /api/config/staged          {base: L, model}            → staged, with each file's diff
POST /api/commits                {staged: S, message, changes} → 201, the commit
POST /api/commits/{id}/confirm   (only if its status is "pending")
```

1. **Read** the live model and its version.
2. **Stage** the edited model. The server validates it, generates every
   file, and returns the diffs to review. `base` must be the live version
   the edits started from, or it's a `conflict`. Staging replaces
   anything staged before. If a file the model generates was edited by
   hand, staging fails with `modified_outside`. List those paths in
   `overwrite` to replace them with OPF's versions.
3. **Commit** by the staged version, so what's committed is exactly what
   was reviewed. `message` and `changes` describe the commit for
   history. Every file is checked by its own validator first; if one
   fails nothing is touched (`check_failed`).
4. If the commit changed a file that could cut off access (`pf.conf`,
   a `hostname.if` or `mygate`), its status is `pending` with a
   `deadline`. Confirm before then, or the server reverts it by
   itself. Other commits are `applied` straight away.

If applying fails part-way, everything is put back, the commit is
recorded with status `failed` (still 201, with its log), and the model
stays staged so it can be fixed. The same happens on revert: the
reverted model is staged again.

## Resources

### `GET /api/status`

Small enough to poll.

```json
{"live": "6265311081b0c6acc983", "staged": "9e304c6944d77c8d8571", "pending": {…commit…}}
```

`staged` and `pending` are omitted when there's none.

### `GET /api/config`

`{version, model}`: the live model.

### `GET /api/config/staged`

```json
{
  "version": "9e304c6944d77c8d8571",
  "base": "6265311081b0c6acc983",
  "model": {…},
  "changes": [
    {"path": "/var/opf/config.json", "status": "modified", "diff": "…", "model": true},
    {"path": "/etc/pf.conf", "status": "modified", "diff": "…", "needsConfirm": true}
  ]
}
```

`status` is `added`, `modified` or `removed` (a file the model no longer
generates, such as a deleted VLAN's `hostname.if`), and `diff` is a
unified diff. `404
nothing_staged` when there's nothing staged.

### `PUT /api/config/staged`

```json
{"base": "6265311081b0c6acc983", "model": {…}, "overwrite": ["/etc/pf.conf"]}
```

Returns `{"version", "base", "changes"}`: the staged resource without
its model, which the client just sent (`GET /api/config/staged` has
it). `overwrite` is optional. Refused with `commit_pending` while a
commit waits for confirmation.

### `DELETE /api/config/staged`

Discards it. 204.

### `GET /api/commits`

History, newest first.

```json
[{
  "id": "20260928-161602.024",
  "time": "2026-09-28T16:16:02.024Z",
  "status": "pending",
  "deadline": "2026-09-28T16:17:02.024Z",
  "message": "Disabled rule “Allow DNS from IoT devices” (IoT)",
  "changes": [{"area": "firewall", "summary": "Disabled rule “Allow DNS from IoT devices” (IoT)"}],
  "files": [{"path": "/var/opf/config.json", "model": true}, {"path": "/etc/pf.conf", "needsConfirm": true}]
}]
```

`status` is one of `applying`, `pending`, `applied`, `confirmed`,
`reverted` or `failed`. `deadline` is only there while pending.
`files[].created` and `files[].removed` mark files the commit created or
removed.

### `POST /api/commits`

```json
{"staged": "9e304c6944d77c8d8571", "message": "…", "changes": [{"area": "firewall", "summary": "…"}]}
```

`message` is at most 500 bytes. There are at most 500 `changes`, each
with an `area` of up to 32 bytes and a `summary` of up to 300. None may
contain control characters. Answers 201 with a `Location` header and
the commit.

### `GET /api/commits/{id}`

The commit plus `diffs` (`[{path, diff}]`) and `log`, the commands run
and their output.

### `POST /api/commits/{id}/confirm`, `POST /api/commits/{id}/revert`

Keep the pending commit, or undo it now. No body. `not_pending` if it
isn't the one waiting, which includes one that has just timed out.

### `GET /api/commits/{id}/config/{before|after}`

`{version, model}`: the model as it was before or after the commit.
This changes nothing. To restore it, stage it with `PUT
/api/config/staged` and commit it, so it's validated and reviewed like
any other change.

### `GET /api/dhcp/leases`

dhcpd's current leases, read from its leases file, by address.

```json
{
  "leases": [{
    "ip": "192.168.20.142", "mac": "02:00:00:00:00:04", "hostname": "Priya's iPad", "iface": "iot",
    "starts": "2026-09-28T16:17:40Z", "ends": "2026-09-28T18:17:40Z",
    "dnsRefused": "not a valid host name"
  }],
  "error": "dhcpd’s leases file couldn’t be read"
}
```

`iface` is the interface whose DHCP range holds the address. `ends` is
absent for a lease that doesn't end. `dnsName` is the name the lease
has in DNS, and `dnsRefused` why it didn't get the one it asked for
(both from the lease watcher's last pass; absent while names from
leases are off). Hostnames are sanitized as below, and the list holds at
most 5000 leases, with `truncated` set when there were more. Leases for
reserved (fixed) addresses aren't in the file, so they aren't listed.

### `GET /api/dns/leases`

What the DHCP lease watcher last did: the names dynamic leases have in
DNS, and the leases that weren't given the name they asked for.

```json
{
  "enabled": true,
  "checked": "2026-09-28T17:12:32-04:00",
  "registered": [
    {"name": "priya-mbp.office.arpa", "ip": "192.168.1.112"},
    {"name": "priyas-ipad.office.arpa", "ip": "192.168.20.142", "from": "Priya's iPad"}
  ],
  "refused": [{"ip": "192.168.1.150", "hostname": "wpad", "reason": "the name is taken by the configuration"}],
  "error": "unbound isn’t answering on its control socket"
}
```

`enabled` is false while "Add other DHCP devices by name" is off.
`from` is the hostname a device sent when its name was rewritten into a
valid one (the model's `dns.rewriteInvalidLeaseNames`); with rewriting
off, such devices are refused as "not a valid host name".
`checked` is absent before the first pass. The watcher looks every 15 s
and right after a commit. `error` describes a failed pass; the lists
are then from the last pass that got that far, and OPF's log has the
details. Hostnames are chosen by the devices: characters that aren't
printable (including bidi overrides) become U+FFFD and they're cut to
64 characters. Each list holds at most 1000 entries, in name or address
order, with `truncated` set when there were more.

### The running system

These read the system with OpenBSD's own tools (sysctl, vmstat, df,
ifconfig, netstat, ping, ntpctl, syspatch) and change nothing. A
command that fails leaves its part out and adds a sentence to `errors`
(or `error`), so the rest still shows; the status is 200 either way.
Rates are over the few seconds since the previous request: the first
request after a quiet minute takes a second longer, to measure one.

- `GET /api/system`: `hostname`, `release`, `version`, `machine`,
  `cpuModel`, `vendor`, `product`, `cpus`, `bootedAt`, `load` (1, 5,
  15 minutes), `cpu` (percent `user`, `nice`, `system`, `spin`,
  `interrupt`, `idle`), `memory` and `swap` (bytes; in use is total
  minus free), `disks` (local filesystems, bytes), `sensors` (as
  `sysctl hw.sensors` reports them, with `number` and `unit` when the
  value is a number), `time` (OpenNTPD's state; absent when ntpd
  isn't running) and `dns`, the servers the firewall's own lookups go
  to, from /etc/resolv.conf: `servers` in order (`{"address", "from",
  "unused"}`: `from` is the interface resolvd learned it on, `lo0`
  being OPF's own (`system.dns`); `unused` past the three the C library
  reads) and `lookup`.
- `GET /api/devices`: every device OPF knows of, `{"devices",
  "errors"}`, from DHCP leases and reservations, the ARP table (inside
  networks only) and VPN tunnels: `{"key", "kind", "name", "nameFrom",
  "mac",
  "addresses", "networks", "lease", "reservation", "arp", "vpn",
  "firstSeen"}`. `key` is what DNS activity and traffic are kept under
  (`mac:…`, `vpn:<peer id>`, `ip:…`, `firewall`); `kind` is `device`
  or `vpn`; `nameFrom` is where the name came from: `reservation`,
  `dns` (its lease's name in DNS), `asked` (what the device calls
  itself, with no name in DNS) or `vpn`.
- `GET /api/devices/device?key=…`: one device, with its VPN tunnel's
  state now (`endpoint`, `handshakeAgo`, `rxBytes`, `txBytes`) for a
  VPN device. `ip:<address>` is the device that has the address now,
  when OPF knows one (a device first, else a VPN device). A key DNS
  activity or traffic counted but nothing else knows (`ip:…`, a MAC not seen now, `firewall`) is a device too, with
  `kind` `address` or `firewall`; anything else is `not_found`.
- `GET /api/traffic?days=N` (admin): what each device sent and
  received over the last `N` days (`firewall.traffic`). Only `enabled`
  and `days` while it isn't counted. Otherwise `maxDevices` (devices
  kept apart a day: `firewall.traffic.maxDevices`, 512 unset), `since`,
  `total` and
  `hours` (`{"sent", "received", "sentPackets", "receivedPackets"}`,
  bytes, by the device: sent is what it sent), `unknown` (bytes from
  addresses not in pf's table yet), `devices` (those that moved most
  first, `{"key", ...bytes}`; the firewall among them as `firewall`),
  `firewall` (what it started itself: its lookups, updates, downloads;
  not in `total`), `deviceInfo` by key as for DNS activity, and
  `savedBytes`.
- `GET /api/traffic/device?device=key&days=N` (admin): one device's
  `total` and `hours`, with its `kind`, `name` and `mac`.
- `DELETE /api/traffic[?device=key]` (admin): deletes one device's
  traffic, or all of it.
- `GET /api/diagnostics/storage`: everything that fills up as the
  firewall runs: `items`, each `{"id", "group", "name", "desc", "unit",
  "where", "current", "max", "unbounded", "note", "off", "link",
  "settings", "fixed"}`: `settings` are where its limit or what fills
  it is set (`{"label", "to"}`, a UI path with the card as `#id`),
  `fixed` why there's nowhere. `group` is `opf` (its own records: the
  saved graphs, the event log, DNS activity, the change history,
  downloaded lists), `graphs` (the graphs in memory by what they
  record: the firewall's states and blocks, DNS, the system, each a
  fixed size, and interfaces, gateways, VPN devices, DHCP networks and
  rules against their caps), `pf` (the state
  table, tables and their entries against pf's hard limits), `logs`
  (the logs it reads, with their old copies, against what newsyslog
  lets them reach) or `disk` (OPF's memory, the disk its state is on).
  `unit` is `bytes` or `entries`; `current` is absent when it couldn't
  be read, `max` when nothing limits it (`unbounded` says what then).
  `errors` lists what couldn't be read.
- `GET /api/system/updates`: `{"checkedAt", "checking", "patches",
  "error"}`. `patches` are syspatch's names for what's available. The
  check (`syspatch -c`, slow: it asks a mirror about every patch) runs
  on a schedule in the background, when OPF starts if the last answer
  is stale and then every two hours (15 minutes after a failure). The
  answer is kept in the state directory, so a restart shows it at once;
  `checkedAt` is absent only until the very first finishes, and
  `checking` says one is running while the last answer is shown.
- `POST /api/system/updates/check`: checks now, after installing
  patches say, and answers as `GET` does. It does nothing while a check
  runs or within a minute of the last one.
- `GET /api/network/interfaces`: every interface on the system, by
  device name, whether OPF configures it or not: flags, `up` and
  `running`, `status` (the link: `active`, `no carrier`), `media`,
  `mac`, `groups`, `ipv4` and `ipv6` as address/prefix, `vlan`, `carp`,
  `wireguard` (port, public key, and each peer's endpoint, bytes, the
  seconds since its last handshake and its allowed IPs), `counters`
  since the interface was created, and `rxBps`/`txBps`.
- `GET /api/network/gateways`: `{"gateways": {"<id>": {"address",
  "online", "lossPct", "rttMs", "error"}}}` for each gateway in the live
  model. It pings the gateway's monitor address if it has one, else its
  address, else (DHCP) the default route on its interface. Answers are
  reused for 10 seconds.
- `GET /api/network/arp` and `GET /api/network/routes`: the ARP and
  routing tables.

`GET /api/status` also carries `release`, the running OpenBSD release.

### pf's own state

Rules are matched to the model by their labels (`opf:<kind>:<id>`),
never by number: numbers change with every reload.

- `GET /api/pf/status`: `info` (from `pfctl -v -s info`: `enabled`,
  `enabledFor` in seconds, `states`, `halfOpenTcp`, `counters` by
  pfctl's names, and `iface`, the statistics interface's bytes and
  packets passed and blocked), `stateLimit`, and `blockedPerSec` on the
  statistics interface lately.
- `GET /api/pf/states`: `{"states": [...], "truncated"}`, at most 5000.
  Each has `id` and `creatorId`, `iface` (or `all`), `proto`,
  `direction`, `source` and `destination` as the device that opened
  the connection sees them, `translated` (the NAT address it leaves
  with, or the address it was sent to before a port forward), `state`,
  `ageSec`, `expiresSec`, `packets`, `bytes`, `rule` (pf's number) and
  `label` (the rule's).
- `POST /api/pf/states/kill`: `{"id": "<16 hex digits>", "creatorId":
  "<8 hex digits>"}` ends a connection (`pfctl -k id`). 204; 422 for
  ids in any other form, which never reach pfctl. A state that has
  already gone is not an error.
- `GET /api/pf/rules/counters`: `{"labels": {"opf:rule:r3":
  {"evaluations", "packets", "bytes", "states"}}}` since the rules were
  loaded, added up over the rules pf expanded each one into. Only
  OPF's labels are listed.
- `GET /api/logs/firewall`: the latest 500 packets pf logged
  (`/var/log/pflog`), newest first: `time`, `rule` (and `anchor`),
  `reason`, `action`, `direction`, `iface` (the device), `proto`,
  `source`, `destination`, `info` (the rest of tcpdump's line) and
  `label`. `label` is only set for entries after `rulesSince`, the
  last time OPF may have reloaded the rules, since a rule number only
  means the same rule until then.
- `POST /api/dns/reverse`: `{"addresses": ["192.168.1.112",
  "140.82.112.4"]}` (at most 256; any role) answers each address's name
  (its PTR record), `{"names": {"192.168.1.112":
  "priya-mbp.office.arpa", "140.82.112.4": ""}, "failed": []}`: `""`
  for none, and `failed` for those the resolver couldn't answer for.
  The web process asks the firewall's own resolver (unbound on
  127.0.0.1) itself, so the network's own names come from its leases
  and reservations, and keeps the answers in memory: names for 10
  minutes, no name for 5, a failure for 30 seconds. A name that isn't
  a host name is dropped, since it comes from whoever runs the
  address's reverse zone. 400 for anything that isn't an address.

### Downloaded lists

A URL alias is a pf table loaded from a list OPF downloads to
`/var/opf/tables/<name>`. A commit downloads each list that isn't there
yet, before the checks; if a download fails, the commit is refused
(`check_failed`, with ftp's reason) and nothing changes. A list that's
already there is used as it is until it's refreshed. Downloads run
ftp(1) as the unprivileged user; OPF keeps only the lines that are an
address or network (comments after `#` or `;` are fine), at most 32 MB.

- `GET /api/firewall/tables`: `{"tables": [{"name", "url", "fetched",
  "entries", "warning"}]}` for the applied configuration's URL aliases;
  `fetched` is absent until the list has been downloaded.
- `POST /api/firewall/aliases/{name}/refresh`: downloads the list again
  and loads it into pf (`pfctl -T replace`). 200 with its status; a
  `warning` if pf didn't take it. If the download fails (422), the list
  already there stays in use.

Every downloaded list (pf's and DNS's) is downloaded again every
`refreshHours` (24 by default) since the last download; a failed
attempt keeps the list already there and is tried again an hour later.
Each status has `refresh`: `{"everyHours", "next", "lastAttempt",
"lastError"}`.

- `GET /api/dns/blocklists`: `{"lists": [{"id", "name", "url",
  "enabled", "fetched", "blocked", "allowed", "skipped", "refresh",
  "warning"}]}` for the applied configuration's DNS blocklists.
  `blocked` and `allowed` count names (`*.name` is one), and `skipped`
  counts the lines OPF couldn't use, by why (element hiding, a path or
  pattern, narrowed by options, an address, not a name).
- `POST /api/dns/blocklists/{id}/refresh`: downloads it again and
  reloads its zone in unbound (`unbound-control auth_zone_reload`,
  which keeps the cache and the DHCP names). 422 if the download fails;
  the list already there stays in use.

A DNS blocklist can be a hosts file, a list of names (`*.name` for the
name and everything under it), an adblock list (only `||name^` rules,
and `@@||name^` exceptions, are used) or an RPZ zone. OPF keeps its own
copy of the names in `/var/opf/dns-lists/<id>` and writes a response
policy zone for unbound per answer, `/var/unbound/db/opf/<id>.<answer>.rpz`;
unbound.conf names the one in use, so a revert that changes the answer
back finds its zone still there.

A commit that turns on DNSSEC also creates unbound's trust anchor
(`unbound-anchor`) when there isn't one, as rc.d/unbound does before
unbound first starts.

### The resolver's numbers

- `GET /api/dns/stats`: `enabled` (the applied configuration runs the
  resolver; nothing else is read when it doesn't), `stats` (from
  `unbound-control stats_noreset`: `queries`, `cacheHits`,
  `cacheMisses`, `prefetches`, `recursionAvg` and `recursionMedian` in
  seconds, `uptime`, and with `extended` the maps `answers` by response
  code, `rpz` by action, `queryTypes` and `memory`, plus `secure` and
  `bogus`), `queriesPerSec` and `blockedPerSec` over the last few
  seconds (absent across a reload, when the counters start again),
  `memoryBytes` (unbound's resident size, zones included), `lastReload`
  (`{"at", "seconds", "names", "timedOut"}`: how long unbound took to
  answer again after the last commit that reloaded it whole) and
  `errors`.
- `GET /api/dns/blocked`: what the response policy zones did, from
  unbound's rpz-log lines in the daemon log: `since` (the first line
  read), `blocked`, `own`, `byList` (by list id), `allowed` (let through
  by your never-block names) and `names`, the 50 blocked most
  (`{"name", "count", "last", "list", "entry"}`; `list` is absent for
  your own entries). Only DNS names are listed, and which device asked
  isn't kept. While DNS activity is kept (`dns.activity`), unbound logs
  to OPF's file instead, and this is today's from the activity's counts.
- `GET /api/dns/activity?days=N` (admin): DNS activity over the last `N`
  days, today counting as one (at most what's kept). Only `enabled`,
  `perDevice` and `days` while it isn't kept. Otherwise `deviceDays` and
  `detailDays` (how long each device's and the names' when and who are
  kept: `dns.activity.deviceDays` and `detailDays`, at most `days`, 0
  meaning `days`), `maxDevices` (how many devices a day are kept apart,
  the rest pooled as `other`: `dns.activity.maxDevices`, 128 unset),
  `savedBytes` (the store as last saved, about what it
  takes in memory too), `since`, `total`
  and `hours` (counts: `queries`, `blocked`, `allowed`, `nxdomain` (not
  counting blocks), `servfail`, `cached`), `byList` (blocks by list id,
  `""` for your own names), the 50 names looked up (`names`), blocked
  (`blocked`, with `list` and `entry`) and not found (`missing`) most,
  each `{"name", "count", "err", "last"}` where `err` is how much of
  `count` may be other names' (the lists are bounded), and with
  `perDevice`, `devices` (`{"key", "address", "last", ...counts}`) and
  `deviceInfo` by key (`{"kind", "name", "mac"}`; kind is `device`,
  `vpn`, `firewall`, `address` or `other`).
- `GET /api/dns/activity/device?device=key&days=N` (admin): one device's
  activity: its `kind`, `name`, `mac`, `address`, `last`, `total`,
  `hours`, `names`, `blocked` and `missing`. `not_found` when devices
  aren't kept or nothing of it is.
- `GET /api/dns/activity/name?list=names|blocked|missing&name=n&days=N`
  (admin): when and by whom one of the network's names was asked for:
  `count`, `err`, `last`, `hours` (`{"start", "count"}`, hours with
  any), `devices` (`{"key", "count", "err"}`, the 10 that asked most,
  only while devices are kept) with `deviceInfo` by key, and for a
  blocked name `blockList` and `entry`. Hours and devices count from
  when the name took its place in each day's list of 200, so they may
  add up to less than `count`. `not_found` when no day kept it.
- `DELETE /api/dns/activity[?device=key]` (admin): deletes one device's
  activity, or everything kept. Turning DNS activity off deletes it too,
  once that's applied.
- `POST /api/dns/tools` with `{"tool", "name"}`: asks unbound over its
  control socket, and answers `{"lines", "truncated"}` (at most 1,000
  lines). `lookup` (the servers it would ask for `name`), `cache` (the
  cached records and messages for `name` and the names under it) and
  `local` (its local zones and data) only read; `flush` (forget
  `name`), `flush_zone` (forget it and everything under it),
  `flush_bogus` (answers that failed DNSSEC) and `flush_negative` ("no
  such name" and empty answers) change unbound's cache, and aren't a
  change to the configuration. `name` is a DNS name; `invalid` when it
  isn't, the tool isn't one, or the resolver isn't running, and
  `internal` when unbound-control doesn't answer.

### History

The parent samples the system every 10 seconds and keeps each series
for a month: every 10 s for the last hour, every minute for a day,
every 10 minutes for a week and every hour for the month.

- `GET /api/metrics?series=<name>,<name>&range=<seconds>[&step=<seconds>]`:
  `{"series": {"<name>": {"start", "step", "avg", "max"}}, "known": [...], "groups": [...]}`.
  Point `i` is at `start + i*step` (unix seconds), `null` where nothing
  was recorded; `max` is the highest sample in each point. A range
  longer than an hour comes from a coarser ring, and at most 1500
  points come back (a longer range gets a larger step). At most 32
  series a request; a series with nothing recorded is left out, and
  `known` lists every series kept. Names: `if.<device>.rx` and `.tx`
  (bits a second), `cpu.busy` (percent), `mem.used` (bytes), `load.1`,
  `pf.states`, `pf.blocked` (packets a second on the statistics
  interface), `dns.queries` and `dns.blocked` (a second),
  `dns.cachehit` (percent), `gw.<gateway id>.rtt` (ms) and `.loss`
  (percent), `wg.<peer id>.rx` and `.tx` (bits a second) and
  `.handshake` (seconds since), `pf.<label kind>.<id>` (packets a
  second matched by the rule labelled `opf:<kind>:<id>`, as
  `pf.rule.r3`), `dhcp.<interface id>.leases` (leases in use) and
  `time.offset` (ms). Loopback, enc and pflog interfaces aren't kept.

  Series belong to groups, each with its own cap on the things it keeps,
  so a firewall with many rules never crowds out its interfaces:
  `system` (the fixed series), `interfaces` (two series each),
  `gateways` (two), `vpnDevices` (three), `dhcpNetworks` (one) and
  `rules` (one each, kept at 10-minute and hourly detail only, half the
  memory). The model's `system.graphs` sets the caps (0 to 10000; unset,
  the defaults: 32, 16, 64, 32 and 500). `groups` reports each:
  `{"name", "items", "max", "series", "seriesBytes", "itemBytes",
  "default", "refused"}`; `refused` means something new was turned away
  because the group is full. Lowering a cap forgets the things updated
  least recently beyond it.

### Configuration files

The files the configuration manages: what the applied model generates,
what's staged, and what a commit wrote and hasn't removed. Any role may
read them; they hold no secrets (WireGuard keys are in files of their
own, which aren't listed).

- `GET /api/files`: `{"files": [...]}`, each `{"path", "desc",
  "exists", "model", "staged", "outside", "commit"}`. `desc` is what
  the file is for; `staged` is `added`, `modified` or `removed` when the
  staged changes touch it; `outside` means it differs from what OPF last
  wrote there (staging asks before replacing it); `commit` (`{"id",
  "time", "message"}`) is the last commit in effect that wrote it.
- `GET /api/files/content?path=/etc/dhcpd.conf`: the same, plus
  `content` (as it is on the firewall), `stagedDiff` and `outsideDiff`
  (from what OPF last wrote to what's there now). Only a path `GET
  /api/files` lists can be read; anything else is `not_found`.

### System logs

- `GET /api/logs/system/{log}?q=<search>&program=<name>&limit=`: `log` is
  `messages`, `daemon`, `authlog`, `maillog` or `dmesg`. `{"log",
  "lines": [{"time", "host", "program", "pid", "message"}], "matched",
  "read", "programs"}`: the last 5,000 lines of the log, parsed, those
  of `program` containing `q` (case-insensitive), newest first, at most
  `limit` (300 by default, 1000 at most). The kernel's (`dmesg`) have
  only `message`. Lines are cleaned of control characters and capped at
  2,000 characters.

### Events

- `GET /api/events?kind=link,gateway&q=<search>&before=<RFC 3339 time>&limit=`:
  `{"events": [{"time", "kind", "warning", "subject", "message"}], "more"}`,
  newest first, at most `limit` (100 by default, 1000 at most);
  `before` pages further back. Kinds: `link` (an interface's link down
  or up), `address` (a DHCP address changed), `gateway` (stopped or
  started answering), `device` (a MAC address seen for the first time),
  `vpn` (a device connected from a new address), `service` (dhcpd,
  unbound or ntpd stopped or running again), `list` (a download failed
  or recovered), `updates` (new patches), `commit` (from history) and
  `opf` (started). `subject` is what it's about: an interface, gateway,
  VPN device or list id, a MAC address, a daemon or a commit id. The
  newest 5,000 are kept, none older than 90 days.

### WireGuard keys

- `POST /api/wireguard/keys`: makes a tunnel's key pair on the
  firewall (201, `{"publicKey"}`) for a new tunnel's model. The private
  key stays on the firewall, root-only, and staging a tunnel whose key
  it didn't make is `invalid`. Admins only.
- `POST /api/wireguard/keys/import` with `{"privateKey"}`: keeps a
  tunnel's private key made elsewhere, such as the one a VPN provider
  issues for a way out, as `POST /api/wireguard/keys` keeps its own
  (root-only), and answers `{"publicKey"}` (201) for the model. Not a
  WireGuard key (44 characters of base64) is `invalid`. Admins only.
- `POST /api/wireguard/preshared-keys` with `{"key"}`, or `{}` for
  the firewall to make one: keeps a preshared key, in a file of its
  own, and answers `{"id", "key"}` once (uncompressed). A device's
  `presharedKey` in the model is the id, never the key; staging one
  that isn't on the firewall is `invalid`. Admins only.
- A VPN device in `GET /api/network/interfaces` has `lastSeen` and
  `lastFrom`: when it last shook hands and where from, as OPF
  remembers across the interface reloading.
- `POST /api/wireguard/device-keys`: makes a device's key pair (201,
  `{"privateKey", "publicKey"}`), kept nowhere, for a browser that
  can't make one itself (the UI uses WebCrypto's X25519). Sent
  uncompressed. Admins only.

### Webhooks

Which webhooks there are and which events each gets are in the model
(`notifications.webhooks`: `{"id", "name", "enabled", "kinds",
"problemsOnly", "format"}`; `format` is absent for OPF's JSON, or
`slack`, `discord` or `ntfy`). A webhook's URL and signing key are secrets, never in
the model, an answer or the history:

- `GET /api/webhooks`: `{"webhooks": [{"id", "target", "signed",
  "lastAttempt", "lastOk", "lastError", "queued", "dropped"}]}` for the
  live and staged models' webhooks. `target` is the URL's scheme and
  host only.
- `PUT /api/webhooks/{id}/secret`: `{"url", "signing": "keep" | "none" |
  "generate" | "set", "key"}` sets the URL (http or https, no user or
  password, no fragment) and key, taking effect at once. With
  `generate`, the answer's `key` is the new key, the only time it's
  shown; that answer is never compressed.
- `POST /api/webhooks/{id}/test`: sends a test event now and answers
  with the status.

A delivery is a POST of `{"source": "opf", "host", "test", "event":
{…}}` with `X-OPF-Timestamp` (unix seconds) and, with a key,
`X-OPF-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>">`.
The other formats send a message instead: Slack `{"text"}` with `<`,
`>` and `&` escaped so no name in an event mentions anyone; Discord
`{"content", "username": "OPF", "allowed_mentions": {"parse": []}}` with
its markdown escaped; ntfy the message as plain text with `Title` (the
firewall and the kind of event), `Priority` (4 for a problem, else 3)
and `Tags`. Failures are retried after 10 s, 1 min, 5 min, 30 min and
2 h, then dropped; redirects aren't followed.

### Diagnostic tools

The tools run in the privileged process. A request is a form, never a
command line: each field is checked and the command is built from them,
with `--` before the host, so a value can only be an address, a DNS
name or a number. At most four run at once (429 `busy` past that).

- `POST /api/diagnostics/runs` starts one. The body is `{"tool", ...}`:
  - `ping`: `host`, `family` (`ipv4`, `ipv6` or empty), `count`
    (1-50, default 5), `size` (1-9000 data bytes, default 56),
    `dontFragment` (IPv4 only).
  - `traceroute`: `host`, `family`, `protocol` (`udp` or `icmp`),
    `maxHops` (1-64, default 30), `asNumbers`, `names`.
  - `dns`: `name` (an address is a reverse lookup), `type` (A, AAAA,
    CNAME, MX, NS, PTR, SOA, SRV, TXT, CAA, DS, DNSKEY, HTTPS, SVCB,
    ANY), `server` (an address; empty is this firewall's resolver),
    `trace`, `dnssec`.
  - `port`: `host`, `family`, `port`, `protocol` (`tcp` or `udp`).

  201 with the run. 422 names the field it refused in `details`.
- `GET /api/diagnostics/runs/{id}?from=N`: the run with its output
  from line N on: `id`, `tool`, `command` (for showing), `started`,
  `running`, `finished`, `exitCode` (when it ran to the end), `error`
  (why it didn't: stopped, timed out, too much output), `lines`, `next`
  (the line to ask from next) and `truncated`. Output is cleaned of
  control characters and bidi overrides, and kept for 15 minutes after
  the run ends; a run is stopped past 2000 lines or 256 KB.
- `POST /api/diagnostics/runs/{id}/cancel` stops it. 204.

### `POST /api/pf/parse`

`{"text": "pass in on $lan …", "model": {…}}` → `{"rule": {…}}`. The
rule is a guided (`"kind": "form"`) rule when the form can hold it
exactly, and a raw rule otherwise. `model` resolves macros and
interfaces and is optional. The text is at most 4096 bytes. 422 if it
isn't a pf rule.

### `POST /api/pf/render`

`{"model": {…}, "rule": {…}}` → `{"comment": "# Allow DNS", "lines":
["pass in quick on $lan …"]}`, the text the generator writes for one
object in the context of a model: give exactly one of `rule`, `nat` (an
outbound NAT rule) or `forward` (a port forward, which can be several
lines). `comment` is the description as pf.conf carries it, left out
when there's none. This is what a form previews as it's filled in.

### `POST /api/pf/ruleset`

`{"model": {…}}` → `{"lines": [{"text": "…", "origin": {"label":
"Firewall rule “Allow DNS”", "to": "/firewall/rules/lan"}}, …]}`, the
pf.conf the model generates, each line with the page it comes from
(`origin` is left out for lines OPF writes on its own).

### `POST /api/pf/derived`

`{"model": {…}}` → what the pages show that depends on generation:
`automaticNat` (the outbound NAT rules OPF adds on its own),
`localNetworks` (the networks a split-tunnel VPN device is told to
send through the tunnel), `rules` (each firewall rule's pf text, by
id), and `dynamicIfaces` and `selfDynamic` (whether a reference to
each interface, or to self, follows address changes by default).

The models these three take are the ones being edited, not yet valid.
Anything validation would refuse can give odd text rather than an
error; a model too incomplete to generate from at all is a 422.
