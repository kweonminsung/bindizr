# API Tokens

Bindizr uses API tokens for HTTP API authentication. A token is either
**global** — it may manage every zone plus the zone plane (zone lifecycle,
imports, key and grant management) — or **scoped** (the default), acting only
on the record plane of the zones it has been granted, the HTTP twin of
[TSIG grants](tsig-keys.md).

Tokens are identified by a unique name, fixed at creation.

```bash
# Create a scoped API token (no access until it is granted zones); the
# plaintext token is shown once, here
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

## Grants

A grant gives a scoped token record rights in one zone, optionally restricted
by a record name pattern (`*`, `@`, `*.sub`, or an exact relative name) and
record types (`*` or a comma-separated list):

```bash
# Allow the token to manage any record in example.com
$ bindizr token grant external-dns example.com

# Allow only A/TXT records under *.dyn
$ bindizr token grant external-dns example.com --pattern '*.dyn' --types A,TXT

# List a token's grants, or every grant that applies to a zone
$ bindizr token grants external-dns
$ bindizr token grants --zone example.com

# Revoke one grant by ID
$ bindizr token revoke external-dns <GRANT_ID>
```

A global token can do all of this over HTTP too: `POST`/`GET /tokens` and
`DELETE /tokens/{name}` for the tokens themselves (`GET /tokens/self`
describes the calling token, scoped ones included), `GET`/`POST
/tokens/{name}/grants` and `DELETE /tokens/{name}/grants/{id}` for grants,
and `GET /zones/{name}/token-grants` for the zone-side view.

A scoped token sees only its granted zones: other zones read as 404 and
writes outside its grants return 403. The name pattern and type list restrict
**writes** only — within a granted zone the token reads every record.
Creating, updating, or deleting zones —
and managing tokens, keys, or grants over HTTP — always requires a global
token. The CLI talks to the daemon over its local socket and is not subject
to token scoping.

See [HTTP API](../http-api/index.md#authentication) for how to present a token
on a request.
