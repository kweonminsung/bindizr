# API Tokens

Bindizr uses API tokens for HTTP API authentication. A token is either
**global** — it may manage every zone plus the zone plane (zone lifecycle,
imports, key and policy management) — or **scoped** (the default), acting only
on the record plane of zones granted through token policies, the HTTP twin of
[TSIG policies](tsig-keys.md).

Tokens are identified by a unique name, fixed at creation.

```bash
# Create a scoped API token (no access until policies grant zones)
$ bindizr token create --name external-dns

# Create a global (admin) API token
$ bindizr token create --name admin --global

# Create a token with expiration
$ bindizr token create --name temp --expires-in-days 30

# List all API tokens
$ bindizr token list

# Delete an API token by name
$ bindizr token delete external-dns
```

## Token policies

Grant a scoped token record rights per zone, optionally restricted by a
record name pattern (`*`, `@`, `*.sub`, or an exact relative name) and record
types (`*` or a comma-separated list):

```bash
# Allow the token to manage any record in example.com
$ bindizr zone token-policy add example.com --token external-dns

# Allow only A/TXT records under *.dyn
$ bindizr zone token-policy add example.com --token external-dns --pattern '*.dyn' --types A,TXT

# Inspect and revoke
$ bindizr zone token-policy list example.com
$ bindizr zone token-policy remove example.com <POLICY_ID>
```

A scoped token sees only its granted zones: other zones read as 404 and
writes outside its grants return 403. Creating, updating, or deleting zones —
and managing tokens, keys, or policies over HTTP — always requires a global
token. The CLI talks to the daemon over its local socket and is not subject
to token scoping.

See [HTTP API](../http-api/index.md#authentication) for how to present a token
on a request.
