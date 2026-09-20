# TSIG Keys

TSIG keys authenticate [dynamic updates](nsupdate.md) and zone transfers. A key
is a standalone resource; its grants decide which zones, names, and types it
may change, and which zones it may pull.

```bash
# List all TSIG keys (secrets are not shown)
$ bindizr tsig-key list

# Show one key including its secret
$ bindizr tsig-key get update-key

# Print the key as a BIND `key` block, to paste into a secondary's named.conf
$ bindizr tsig-key export xfr-key

# Delete a key (refused while it still holds grants)
$ bindizr tsig-key delete update-key

# List a key's grants, or every TSIG grant that applies to a zone
$ bindizr tsig-key grants update-key
$ bindizr zone tsig-grants example.com

# Revoke every grant a key holds in a zone, or one grant by ID
$ bindizr tsig-key revoke update-key example.com
$ bindizr tsig-key revoke --id 7
```

## Signing zone transfers

A secondary configured the standard way signs what it asks for:

```text
key "xfr-key" {
    algorithm hmac-sha256;
    secret "...";              # bindizr tsig-key export xfr-key
};

zone "example.com" {
    type secondary;
    primaries { 192.0.2.1 key xfr-key; };
};
```

Bindizr answers under the same key: the SOA poll, the AXFR, and every envelope
of it. A request that carries no key is judged by `dns.secondary_addrs` exactly
as before, so a deployment using no keys configures nothing extra.

A transfer hands the zone over whole, so only a key that covers the zone whole
may pull it — a global key, or one granted with the default `*` pattern and
types. A grant narrowed to part of a zone authorizes updates there and no
transfer at all.

```bash
# The secondary pulls the zone but must not rewrite it
$ bindizr tsig-key grant xfr-key example.com --read-only

# A key that both updates and transfers is the default
$ bindizr tsig-key grant update-key example.com
```

A key bindizr does not hold is refused (`BADKEY`) rather than falling back to
the address list: signing must not be a way around the check.

TSIG keys and their grants are also manageable over the HTTP API
(`/tsig-keys`, `/tsig-keys/{name}/grants`, `/zones/{name}/tsig-grants`) — see
the [API Reference](https://kweonminsung.github.io/bindizr/api/).
