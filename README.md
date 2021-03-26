# GreyNoisePS
 PowerShell module to interact with the GreyNoise API. This currently works with the community API endpoint.


## Usage

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
message        : Success

```

Return information about your local TCP connections

```
Get-NetTCPConnection | Where-Object {
   ($_.RemoteAddress -notlike '0.0.0.0') -and
   ($_.RemoteAddress -notlike '127.*') -and
   ($_.RemoteAddress -notlike '::') } |
    Sort-Object -Unique |
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
