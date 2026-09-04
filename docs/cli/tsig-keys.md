# TSIG Keys

TSIG keys authenticate [dynamic updates](nsupdate.md). A key is a standalone
resource; its grants decide which zones, names, and types it may change.

```bash
# List all TSIG keys (secrets are not shown)
$ bindizr tsig-key list

# Show one key including its secret
$ bindizr tsig-key get update-key

# Delete a key (refused while it still holds grants)
$ bindizr tsig-key delete update-key

# List a key's grants, or every grant that applies to a zone; revoke one by ID
$ bindizr tsig-key grants update-key
$ bindizr tsig-key grants --zone example.com
$ bindizr tsig-key revoke update-key <GRANT_ID>
```

TSIG keys and their grants are also manageable over the HTTP API
(`/tsig-keys`, `/tsig-keys/{name}/grants`, `/zones/{name}/tsig-grants`) — see
the [API Reference](https://kweonminsung.github.io/bindizr/api/).
