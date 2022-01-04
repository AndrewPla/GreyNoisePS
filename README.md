# GreyNoisePS
 PowerShell module to interact with the GreyNoise API. This currently works with the both the paid and community API endpoints.


## Community API Command Usage

### The GNIpInfo command is the only one available for community level accounts

Return information about an IP address.

```
Get-GNIpInfo -Ip 8.8.8.8

ip             : 8.8.8.8
noise          : False
riot           : True
classification : benign
name           : Google Public DNS
link           : https://viz.greynoise.io/riot/8.8.8.8
last_seen      : 2021-03-26

```

Return information about your local TCP connections

```
Get-NetTCPConnection | Where-Object {
   ($_.RemoteAddress -notlike '0.0.0.0') -and
   ($_.RemoteAddress -notlike '127.*') -and
   ($_.RemoteAddress -notlike '*::*') } |
    Sort-Object -Property RemoteAddress -Unique |
	Get-GNIpInfo



ip             : 140.82.113.25
noise          : False
riot           : True
classification : benign
name           : Github
link           : https://viz.greynoise.io/riot/140.82.113.25
last_seen      : 2021-03-26
message        : Success

ip             : 162.159.130.234
noise          : False
riot           : True
classification : benign
name           : Cloudflare CDN
link           : https://viz.greynoise.io/riot/162.159.130.234
last_seen      : 2021-03-26
message        : Success

```


## Paid API Command Usage

### All commands are supported with a Paid API account

Confirm access to the GreyNoise API and API Key status

```
Get-GNPing -Key $key
```

Retrieve full Mass-Internet scanning Context data for multiple IPs

```
Get-GNMultiIpContext -Ips $ips -Key $key
```

Retrieve full Mass-Internet scanning Context data for a single IP

```
Get-GNIpContext -Key $key -Ip $ip -Key $key
```

Perform a GreyNoise Quick Lookup for multiple IPs

```
Get-GnIpQuickCheck -Ip $ip -Key $key
```

Perform a GreyNoise Quick Lookup for a single IP

```
Get-GNMultiIpQuickCheck -Ips $ips -Key $key
```

Perform a GreyNoise Common Business Service IP Lookup for a single IP

```
Get-GNRiotIpLookup -Ip $ip -key $key
```

Perform a GreyNoise Query

```
Get-GNQLQuery -GNQLQuery 'last_seen:today' -Key $key
```

Get Statistics for a GreyNoise Query

```
Get-GNQLStats -Key $key -GNQLQuery '(raw_data.scan.port:445 and raw_data.scan.protocol:TCP) metadata.os:Windows*'
```

Get GreyNoise Tag Details

```
Get-GNTagMetadata -key $key
```