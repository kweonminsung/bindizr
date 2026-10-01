# Technitium DNS

Technitium DNS Server follows a catalog zone through its **Secondary
Catalog** zone type; Bindizr's interoperability run covers 15.5.

## 1. Register the secondary in Bindizr

Register the secondary's address so it receives NOTIFY and can transfer
zones. This example uses a server on the same host, listening on port 53:

```bash
# A Technitium on this host; elsewhere, its address or hostname
sudo bindizr secondary create technitium --address 127.0.0.1
```

## 2. Configure the catalog zone

Create `catalog.bindizr` as a Secondary Catalog zone with Bindizr as its
primary. Technitium creates each member zone as a secondary of that same
primary, so nothing further is needed for the zones themselves. Through
Technitium's HTTP API on port 5380:

```bash
TOKEN=$(curl -s "http://localhost:5380/api/user/login?user=admin&pass=<password>" | jq -r .token)

curl -s "http://localhost:5380/api/zones/create?token=$TOKEN&zone=catalog.bindizr\
&type=SecondaryCatalog&primaryNameServerAddresses=127.0.0.1:5300&zoneTransferProtocol=Tcp"
```

## 3. Check a zone it learned

```bash
dig +norec @127.0.0.1 example.com SOA
```

An authoritative answer carrying Bindizr's serial means the member zone
loaded.

## NOTIFY takes about five seconds

In the interoperability run, Technitium pulled a change about five seconds
after the NOTIFY reached it, against well under a second for BIND, Knot, and
NSD. The transfer itself is an IXFR delta like theirs.

## Sign the transfers

Add the key to Technitium's TSIG keys, then name it when creating the catalog
zone. Technitium signs the catalog transfer and every member transfer with it:

```bash
curl -s "http://localhost:5380/api/settings/set?token=$TOKEN\
&tsigKeys=xfr-key|<base64 secret from bindizr tsig-key create>|hmac-sha256"

curl -s "http://localhost:5380/api/zones/create?token=$TOKEN&zone=catalog.bindizr\
&type=SecondaryCatalog&primaryNameServerAddresses=10.0.0.5:5300&zoneTransferProtocol=Tcp\
&tsigKeyName=xfr-key"
```

`tsigKeys` sets the server's whole key list, so include any keys it already
holds, each as `name|secret|algorithm`.

See [Access Control](../cli/access-control.md#secondaries-pulling-over-tsig)
for creating the key in a role that holds `zone:transfer` in every zone.
