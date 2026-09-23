# Key Import and Export

Keys move in and out as BIND key files, so a zone signed by BIND (or any
signer using that format) migrates without breaking its chain of trust:

```sh
# Print every key in BIND key-file form, one `; K*.key` / `; K*.private`
# block per file
bindizr dnssec keys export example.com

# Bring an existing key set in and sign with it
bindizr dnssec keys import example.com \
    --key Kexample.com.+013+12345.key --private Kexample.com.+013+12345.private
```

The export stream contains the private keys — redirect it only somewhere
with tight permissions.

Import takes the zone's complete key set in one call and signs on the spot:
one CSK pair, or a KSK pair and a ZSK pair (repeat `--key`/`--private`)
under a split-key policy. The keys must match the policy's algorithm and key
layout (`--policy`, or `default`), and the zone must be unsigned; a signed
zone changes keys through
[rollover](rollover.md) instead. Both commands exist only in the CLI —
private keys never transit the HTTP API.

## Handing over a zone mid-rollover

A private key file carries the schedule `dnssec-keygen` and `dnssec-settime`
wrote into it, and import reads each key's place in the rollover from it:
published before its `Activate`, active after, retired after `Inactive`, and
removed at `Delete`. So a zone handed over between signers keeps the rollover
it was in — pass every key the rollover holds, not only the one signing.
Bindizr writes the same fields on export, so its own key files re-import where
they left off. A file without them, and a key set that is simply settled,
imports as active.

An active key is still what signs, so the set needs one for every role the
policy names; a key whose `Publish` has not come, or whose `Delete` has
passed, is refused rather than stored in a state BIND is not serving.
