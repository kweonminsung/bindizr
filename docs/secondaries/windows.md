# Windows Server DNS

Windows Server DNS does not read catalog zones, so each zone Bindizr serves is
added to it as a secondary zone. Bindizr's interoperability run covers Windows
Server 2019, 2022, and 2025.

`-MasterServers` takes addresses without a port, so Windows transfers from
port 53: set `dns.listen_port = 53` and a `dns.listen_addr` Windows can
reach, rather than the package's default 5300. The examples use Bindizr at
`10.0.0.5` and Windows at `10.0.0.14`.

## 1. Register the secondary in Bindizr

Register the server's address so it receives NOTIFY and can transfer zones:

```bash
sudo bindizr secondary create windows --address 10.0.0.14
```

## 2. Add the zones

In PowerShell on the Windows server, install the DNS role if it is not there
yet, then add each zone with Bindizr as its primary:

```powershell
Install-WindowsFeature DNS -IncludeManagementTools
Add-DnsServerSecondaryZone -Name example.com -ZoneFile example.com.dns -MasterServers 10.0.0.5
```

A zone created in Bindizr later is added the same way, and a deleted one
removed with `Remove-DnsServerZone -Name example.com -Force`.

Windows accepts NOTIFY from a zone's primary without further configuration.
It answers by asking for an IXFR over UDP; Bindizr replies with the zone's
current SOA (RFC 1995, Section 2), and Windows pulls the change over TCP as an
IXFR delta.

## 3. Check a zone

```powershell
Get-DnsServerZone -Name example.com
Resolve-DnsName -Name example.com -Type SOA -Server 127.0.0.1 -DnsOnly
```

The SOA's `SerialNumber` should match `bindizr zone status example.com`.

## Transfers are unsigned

Windows DNS has no TSIG key for zone transfers; its GSS-TSIG signs Active
Directory dynamic updates only. The registered address is therefore what
authorizes a Windows secondary, as it is for any unsigned transfer.
