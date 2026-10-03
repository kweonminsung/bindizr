# Access Control

Bindizr separates **what a caller may do** from **who the caller is**:

**Roles**
:   A role holds rights, as a list of grants. One role serves any number of
    credentials, so taking a right away is one grant edit.

**Credentials**
:   An [API token](#api-tokens) (HTTP API) or a [TSIG key](#tsig-keys)
    (nsupdate, zone transfers, signed NOTIFY) only proves who is calling.
    Every token and every key names exactly one role and carries no rights of
    its own.

The CLI needs no credential: it runs on the daemon host as the daemon's user
and has full control. An HTTP API with `api.authentication_required = false`
is the same, which is why that setting belongs on a trusted network only.

```bash
# A role, one grant, and a token that authenticates into it
bindizr role create external-dns-prod
bindizr role grant external-dns-prod --zone example.com \
    --actions record:read,record:create,record:delete \
    --pattern '*.apps' --types A,AAAA,CNAME,TXT
bindizr token create cluster-a --role external-dns-prod

# The same role behind an RFC 2136 client
bindizr tsig-key create legacy-rfc2136 --role external-dns-prod
```

## Roles

```bash
# Create a role; it holds no grants yet
bindizr role create dns-admins --description 'Operators of the public zones'

# List roles with how many grants, tokens, and keys each has, or show one
bindizr role list
bindizr role get dns-admins

# The tokens and keys in one role
bindizr token list --role dns-admins
bindizr tsig-key list --role dns-admins
```

Delete an unused role with `bindizr role delete <name>`. Deletion is refused
while a token or TSIG key still belongs to it, and the refusal names them.

### The built-in admin role

The `admin` role exists from the first start: every action, in every zone,
including zones created later. It can be neither changed nor deleted. The
first token is created with it on the daemon host:

```bash
sudo bindizr token create admin --role admin
```

## Grants

A grant is a zone scope, a set of actions, and, for record actions, a name
pattern and a type list:

```bash
# Every zone, including zones created later: leave out --zone
bindizr role grant dns-admins --actions zone:read,zone:update,record:read

# One zone, narrowed to TXT records at _acme-challenge
bindizr role create challenge-txt
bindizr role grant challenge-txt --zone example.com \
    --actions record:create,record:delete \
    --pattern '_acme-challenge' --types TXT

# List a role's grants, then revoke one by its ID
bindizr role grants challenge-txt
bindizr role revoke challenge-txt <GRANT_ID>
```

`--pattern` is `*` (any name, the default), `@` (the apex), `*.sub` (`sub`
and every name under it), or an exact name relative to the zone. `--types` is
`*` (the default) or a comma-separated list. Both narrow the `record:*`
actions only; every other action in the same grant applies to the zone
whole.

An operation is allowed when one of the role's grants covers it; there are no
deny rules. How grants combine, and what each operation needs, is in
[Advanced Access Control](advanced.md).

### Actions

| Action | Allows |
| --- | --- |
| `zone:read` | Zone details, `zone status`, the version list |
| `zone:create` | Creating zones, including `zone import --create` — needs every zone |
| `zone:update` | Zone settings, rollback (with the record actions below), NOTIFY |
| `zone:delete` | Deleting zones |
| `zone:transfer` | A TSIG-signed AXFR/IXFR of the zone |
| `record:read` | Listing and reading records; export, version detail, and diffs |
| `record:create` | Adding records |
| `record:update` | Changing records in place, found by id or name without `record:read` |
| `record:delete` | Deleting records, found by id without `record:read` |
| `dnssec:read` | DNSSEC status, `dnssec check-ds`; listing DNSSEC policies |
| `dnssec:manage` | Every other DNSSEC operation; changing DNSSEC policies |
| `secondary:read` | Listing secondaries, their details and transfers — needs every zone |
| `secondary:manage` | Creating, updating, deleting, and checking secondaries — needs every zone |
| `access:manage` | Tokens, TSIG keys, and roles — needs every zone |

Actions marked "needs every zone" are carried only by a grant without
`--zone`. `access:manage` amounts to `admin` — see
[Actions that need every zone](advanced.md#actions-that-need-every-zone).

## API tokens

API tokens authenticate the [HTTP API](../http-api/index.md#authentication).
A token is identified by a unique name, fixed at creation, and its plaintext
secret is shown once, when it is created.

```bash
# Create a token in a role; the secret is printed here and never again
bindizr token create cluster-b --role external-dns-prod

# Create a token that expires
bindizr token create temp --role external-dns-prod --expires-in-days 30

# List tokens (with their roles), only one role's, or delete one
bindizr token list
bindizr token list --role external-dns-prod
bindizr token delete cluster-b
```

A lost token is replaced, not recovered. The CLI stays the recovery path: if
every token in a role with `access:manage` is lost, create a new one on the
daemon host.

Over HTTP, a token with `access:manage` can manage roles and tokens.
Any token can inspect itself with `GET /tokens/self` and its grants with
`GET /tokens/self/grants`; `GET /permissions` answers what those grants come
to, per zone, as a client deciding what to offer needs. See the
[API Reference](https://kweonminsung.github.io/bindizr/api/) for the endpoints.

## TSIG keys

TSIG keys authenticate [dynamic updates](nsupdate.md), zone transfers, and
the NOTIFY Bindizr sends to a secondary registered with `--notify-key` — see
[Signed NOTIFY](secondaries.md#signed-notify). A key's name is what appears
on the wire.

```bash
# Create a key in a role; use `get` below to retrieve its secret later
bindizr tsig-key create update-key --role external-dns-prod

# Import an existing base64 secret, or pick another HMAC algorithm
bindizr tsig-key create legacy-key --role external-dns-prod --algorithm hmac-sha512 \
    --secret "bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU="

# List keys (secrets are not shown), only one role's, or show one with its secret
bindizr tsig-key list
bindizr tsig-key list --role external-dns-prod
bindizr tsig-key get update-key

# Print the key as a BIND `key` block, to paste into a secondary's named.conf
bindizr tsig-key export update-key

# Delete a key (refused while it still signs a secondary's NOTIFY)
bindizr tsig-key delete update-key
```

Over HTTP the same is `/tsig-keys`, with the role in the body's `role_name`.

A key exercises only `record:read`, `record:create`, and `record:delete` (for
nsupdate) and `zone:transfer` (for AXFR/IXFR); an empty role is enough to sign
NOTIFY. See
[Which actions each credential exercises](advanced.md#which-actions-each-credential-exercises)
and [Signing zone transfers](advanced.md#signing-zone-transfers).

## Examples

### ExternalDNS

The role at the top of this page grants the three actions ExternalDNS needs.
Keep them in one grant so the adapter includes the scope in its domain filter.
See [ExternalDNS](../external-dns.md) for deployment and record-type constraints.

### An ACME DNS-01 client over nsupdate

cert-manager's RFC 2136 solver, or any other ACME client, adds and removes TXT
records at the challenge names and nothing else:

```bash
bindizr role create acme
bindizr role grant acme --zone example.com \
    --actions record:read,record:create,record:delete \
    --pattern '_acme-challenge' --types TXT
bindizr role grant acme --zone example.com \
    --actions record:read,record:create,record:delete \
    --pattern '_acme-challenge.www' --types TXT
bindizr tsig-key create acme-key --role acme
```

The challenge for `www.example.com` lives at `_acme-challenge.www`, so each
name a certificate covers gets its own grant; `record:read` lets the client's
prerequisites check what is there.

### Secondaries pulling over TSIG

A secondary that signs its transfers needs `zone:transfer` in every zone, so
it can pull the catalog zone and every member zone the catalog lists:

```bash
bindizr role create secondaries
bindizr role grant secondaries --actions zone:transfer
bindizr tsig-key create xfr-key --role secondaries
bindizr tsig-key export xfr-key      # paste into the secondary
```

A key that only signs NOTIFY to a secondary still needs a role; an empty one
will do:

```bash
bindizr role create notify-only
bindizr tsig-key create notify-key --role notify-only
```

### Read-only monitoring

A dashboard or an audit job that reads everything and changes nothing:

```bash
bindizr role create monitoring
bindizr role grant monitoring \
    --actions zone:read,record:read,dnssec:read,secondary:read
bindizr token create grafana --role monitoring
```
