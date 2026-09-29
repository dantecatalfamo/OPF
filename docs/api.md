# OPF API

The web UI's only way to change the system. It's served by the
unprivileged web process (`internal/web`) and backed by the root
process (`internal/appliance`, over `internal/privsep`), which validates
everything it's given.

There is no authentication yet; see TODO.md.

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
| `internal` | 500 | logged on the server; the message says only "internal error" |

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
4. If the commit changed a file that could cut off access (`pf.conf`),
   its status is `pending` with a `deadline`. Confirm before then, or the
   server reverts it by itself. Other commits are `applied` straight
   away.

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

Returns the staged resource. `overwrite` is optional. Refused with
`commit_pending` while a commit waits for confirmation.

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

### `POST /api/pf/parse`

`{"text": "pass in on $lan …", "model": {…}}` → `{"rule": {…}}`. The
rule is a guided (`"kind": "form"`) rule when the form can hold it
exactly, and a raw rule otherwise. `model` resolves macros and
interfaces and is optional. The text is at most 4096 bytes. 422 if it
isn't a pf rule.

### `POST /api/pf/render`

`{"rule": {…}, "model": {…}}` → `{"text": "pass in quick on $lan …"}`,
the text the generator writes for the rule.
