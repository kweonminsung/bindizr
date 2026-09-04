# TSIG Keys

TSIG keys authenticate [dynamic updates](nsupdate.md). Keys are standalone
resources; per-zone policies decide what a key is allowed to change.

```bash
# List all TSIG keys (secrets are not shown)
$ bindizr tsig-key list

# Show one key including its secret
$ bindizr tsig-key get update-key

# Delete a key (refused while zone TSIG policies still reference it)
$ bindizr tsig-key delete update-key

# Inspect or revoke a zone's policies
$ bindizr tsig-policy list example.com
$ bindizr tsig-policy remove example.com <POLICY_ID>
```

TSIG keys and policies are also manageable over the HTTP API
(`/tsig-keys`, `/zones/{name}/tsig-policies`) — see the
[API Reference](https://kweonminsung.github.io/bindizr/api/).
