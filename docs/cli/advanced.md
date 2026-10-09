# Advanced Access Control

How Bindizr decides whether a role's grants allow a request. Creating roles,
grants, tokens, and keys is covered in
[Access Control](access-control.md); this page is the rule book behind
it.

## How grants combine

A role's rights are the union of its grants: an operation is allowed when one
grant covers its action, zone, name, and type. There are no deny rules, so
narrowing a right means replacing a wide grant with narrower ones.

`--pattern` and `--types` narrow the `record:*` actions only; every other
action in the same grant applies to the zone whole.

## Actions that need all zones

`zone:create`, `secondary:read`, `secondary:manage`, `access:manage`, and the
DNSSEC policy actions concern things no single zone owns, so only a grant
without `--zone` carries them.

`access:manage` can issue any role to a new token, so it amounts to `admin`:
give it only where you would give `admin`.

## What an operation needs

| Operation | Needs |
| --- | --- |
| Seeing a zone and its details | Any grant reaching it, whatever its actions |
| Reading records | `record:read` covering their name and type |
| Creating, updating, deleting a record | The matching `record:` action at its name and type, per record in a bulk change |
| Updating a record without `record:read` on it | Every field given: an omitted one would be read from the record |
| Zone export, version detail, version diff | `record:read` with no name or type narrowing |
| `zone import --mode append` | `record:create` with no narrowing |
| `zone import --mode upsert` / `replace` | `record:create` and `record:delete`, with no narrowing |
| `zone import --create` | `zone:create`, and the mode's record actions in a grant without `--zone` |
| Renaming a zone | `zone:update`, and `zone:create` in all zones |
| Rollback | `zone:update`, plus `record:read`, `record:create` and `record:delete` with no narrowing |
| `zone notify` | `zone:update`; for the catalog zone or all zones, `zone:update` in all zones |
| DNSSEC policies | `dnssec:read` to list or show, `dnssec:manage` to change, both in all zones |

A view the zone is rebuilt from — an export, a stored version, a diff, an
import, a rollback — needs a grant with no name or type narrowing: half a zone
re-applied deletes what it left out.

## Not found or forbidden

A zone no grant reaches answers 404, exactly like a missing one, so a role
cannot probe for zones it was not given. A visible zone answers 403 for an
operation the role lacks. A record outside a narrowed grant reads as 404 and
a write to it returns 403.

## Which actions each credential exercises

The same role can stand behind API tokens and TSIG keys, but each credential
reaches only part of the action set:

- An **API token** exercises every action except `zone:transfer`: transfers
  are DNS requests, authorized by a TSIG key or the registered secondaries,
  never by a token.
- A **TSIG key** exercises only the `record:*` actions (for nsupdate) and
  `zone:transfer` (for AXFR/IXFR). Other actions in its role have no effect
  on what it signs.

What a key may sign follows its role:

| Request | Needs |
| --- | --- |
| nsupdate prerequisite | `record:read` at its name and type |
| nsupdate add | `record:create` at its name and type; `record:delete` too when it replaces a CNAME or DNAME, `record:update` when its TTL moves the record set |
| nsupdate delete | `record:delete` at its name and type |
| Signed AXFR/IXFR of a zone | `zone:transfer` reaching the zone |
| Signed transfer of the catalog zone | `zone:transfer` in all zones |
| Signing NOTIFY to a secondary | Nothing: an empty role is enough |

An update with one record its role does not cover is refused whole; nothing is
partially applied.

## Signing zone transfers

A secondary configured the standard way signs what it asks for:

```text
key "xfr-key" {
    algorithm hmac-sha256;
    secret "...";              # bindizr tsig-key export xfr-key
};

zone "example.com" {
    type secondary;
    primaries { 192.0.2.1 port 5300 key xfr-key; };
};
```

Bindizr answers under the same key: the SOA poll, the AXFR, and every envelope
of it. A request that carries no key is judged by the registered
[secondaries](secondaries.md) alone, so a deployment using no keys
configures nothing extra.

A key Bindizr does not hold is refused (`BADKEY`) rather than falling back to
the address list: signing must not be a way around the check. A known key
whose role lacks `zone:transfer` for the zone is refused too. A TSIG record
that is doubled, not last, unreadable, or carries a MAC of a size its
algorithm cannot produce is a `FORMERR` (RFC 8945, Section 5.2), signed by
no one.
