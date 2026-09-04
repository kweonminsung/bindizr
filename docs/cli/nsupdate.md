# Dynamic Updates (nsupdate)

Bindizr supports RFC 2136-style dynamic updates through the DNS listener,
authenticated with TSIG. Authorization is built from two pieces:

**Keys**
:   Standalone, reusable resources (name, HMAC algorithm, base64 secret). The
    key name is what appears on the wire in a signed request. A key created with
    `--global` may update every zone — including zones created later — without
    any policy; this is fixed at creation.

**Policies**
:   Grant a non-global key update rights in one zone, optionally restricted to a
    record name pattern and record types.

For each incoming update, bindizr resolves the key named in the TSIG record and
verifies the signature and signing time. A global key is then authorized for
everything; for any other key, bindizr loads its policies for the target zone
and every record in the update must match at least one of them (name pattern and
type). Otherwise the whole update is refused and nothing is partially applied.

## Example

```bash
# Create a key (the secret is generated and printed once; use `get` to re-read it)
$ bindizr tsig-key create --name update-key

# Or import an existing base64 secret / pick another HMAC algorithm
$ bindizr tsig-key create --name legacy-key --algorithm hmac-sha512 --secret "bXktMzItYnl0ZS1pbXBvcnQtc2VjcmV0LWV4YW1wbGU="

# Or create a global key that may update every zone, including future ones,
# without any policy. This is write access to all DNS data — use sparingly.
$ bindizr tsig-key create --name admin-key --global

# Grant a (non-global) key update rights in a zone (pattern/types default to '*')
$ bindizr tsig-policy add example.com --key update-key
$ bindizr tsig-policy add example.com --key acme-key --pattern "*" --types "TXT"

# Send a signed update (hmac-sha256 by default)
$ nsupdate -y "hmac-sha256:update-key:<BASE64_SECRET>" <<EOF
server 127.0.0.1 53
zone example.com
update add sub.example.com. 300 A 1.2.3.4
send
EOF
```

## Unsigned requests

A zone with no policies refuses nsupdate, except from global keys, which may
update any zone.

!!! warning "`nsupdate_allow_unsigned` is a production footgun"

    Setting `dns.nsupdate_allow_unsigned = true` accepts unsigned requests for
    every zone, regardless of its policies. Signed requests are always verified,
    but anyone who can reach the DNS port can write unsigned. Leave it off
    outside of local testing.
