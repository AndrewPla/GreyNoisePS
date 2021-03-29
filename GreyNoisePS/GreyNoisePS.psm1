function Get-GNIpInfo {
	<#
	.Description
	Returns information for the provided Ips from the greynoise community endpoint.
	.Parameter Ip
	Specify one or many IP addresses that you want to look up
	.Parameter Key
	Specify the API key to use. A blank key works for this. See viz.greynoise.io/account/ for API key.
	.Example
	>	Get-GNIpInfo -Ip 8.8.8.8 -key $key

		Returns IP information about the provided IP address.
	.Example
	>	Get-NetTcpConnection | Where state -like 'established' | Get-GNIpInfo

		Returns IP reputation information for all established tcp connections on this computer.
	.Link
	https://developer.greynoise.io/reference/community-api#get_v3-community-ip
	#>
	param(
		[parameter(Mandatory, ValueFromPipelineByPropertyName)]
		[Alias('RemoteAddress','IPAddress')]
		[ipaddress[]]$Ip,
		[string]$Key = ''
	)
	process {
		foreach ($Address in $Ip) {
			try {
				$out = Invoke-RestMethod -Uri "https://api.greynoise.io/v3/community/$Address" -Headers @{key = $Key }
				
				[pscustomobject]@{
					ip             = $out.ip
					noise          = $out.noise
					riot           = $out.riot
					classification = $out.classification
					name           = $out.name
					link           = $out.link
					last_seen      = $out.last_seen
					message        = $out.message
				}
			} Catch {

				# Grab message from web response
				$msg = ($_.ErrorDetails.Message | ConvertFrom-Json | Select -Expandproperty message)

				# grab 
				if (-not $msg) {
					$msg = $_.ErrorDetails.Message
				}
				#$_
				[pscustomobject]@{
					ip             = $Address
					noise          = 'N/A'
					riot           = 'N/A'
					classification = 'N/A'
					NAme           = 'N/A'
					link           = 'N/A'
					last_seen      = 'N/A'
					message        = $msg
				}
			}
		}
	}
}

function Get-GNPing {
	<#
	.Description
	Checks if the GreyNoise API is accessable

	.Parameter Key
	Specify the API key to use.
	
	.Example
	>	Get-GNPing -Key $key
	Checks if the greynoise API is accessible using API key $key

	.Link
	https://developer.greynoise.io/reference/ping-service#get_ping
	#>
	[cmdletbinding()]
	param(
		[Parameter(Mandatory)]$Key
	)
	
	Invoke-RestMethod -Uri 'https://api.greynoise.io/ping' -Headers @{'User-Agent' = 'API-Reference-Test'; key = $Key}

}

function Get-GNMultiIpContext {
	<#
	.Description
	Get more information about a set of IP addresses. Returns time ranges, IP metadata (network owner, ASN, reverse DNS pointer, country), associated actors, activity tags, and raw port scan and web request information.
	.Parameter Key
	Specify the API key to use.
	.Parameter Ips
	Array of IP Addresses to use
	
	.Example
	> $ips = 'reddit.com','microsoft.com' | % {(Resolve-DnsName $_)[0].ipaddress}
	> Get-GNMultiIpContext -Ips $ips -Key $key

	Gets the IP information about the IPs that are returned for reddit.com and microsoft.com.
	.Link
	https://developer.greynoise.io/reference/ip-lookup-1
	#>
	[cmdletbinding()]
	param(
		[Parameter(Mandatory)]
		$Key,
		[Alias('IP','IPAddress','RemoteAddress')]
		[ipaddress[]]$Ips
	)


	$params = @{
		Method  = 'POST'
		URI     = "https://api.greynoise.io/v2/noise/multi/context"
		
		Headers = @{
			'key' = $Key
  }
		Body    = (@{ips = $Ips.IPAddressToString} | ConvertTo-Json)
	}

	$out = Invoke-RestMethod @params
	$out

}

function Get-GNIpContext {
	<#
	.Description
	Get more information about a given IP address. Returns time ranges, IP metadata (network owner, ASN, reverse DNS pointer, country), associated actors, activity tags, and raw port scan and web request information.
	.Parameter Ip
	IP address to query
	.Parameter Key
	Specify the API key to use.

	.Example
	Get-GNIpContext -Key $key -Ip $ip
	returns information about $ip
	
	.Link
	https://developer.greynoise.io/reference/ip-lookup-1#noisecontextip-1
	#>
	[cmdletbinding()]
	param(
		[parameter(Mandatory,ValueFromPipelineByPropertyName)]
		[Alias('IPAddress','RemoteAddress')]	
		[ipaddress[]]$Ip,

		[parameter(Mandatory)]
		$Key

	)

	process {
		foreach ($address in $ip) {
			try {
				$params = @{
					Uri     = "https://api.greynoise.io/v2/noise/context/$($address.IPAddressToString)"
					Headers = @{key = $key}
				}
				Invoke-RestMethod  @params | 
					Add-Member -MemberType NoteProperty -Name 'error' -Value '' -PassThru
			} catch {
				[pscustomobject]@{
					ip    = $address.IPAddressToString
					seen  = 'N/A'
					error = "$(($_.ErrorDetails.message | ConvertFrom-Json).error)"
				}
			}
		} 
	}
}

function Get-GNIpQuickCheck {
	<#
	.Description
	Check whether a given IP address is “Internet background noise”, or has been observed scanning or attacking devices across the Internet.
	.Parameter Ip
	IP address to query
	.Parameter Key
	Specify the API key to use.
	.Notes
	This API endpoint is real-time
	This API endpoint contains a “code” which correlates to why GreyNoise labeled the IP as "noise"
	An IP delivered via this endpoint does not include a “malicious” or “benign” categorizations
	This API endpoint only checks against the last 60 days of Internet scanner data
	.Example
	> Get-GnIpQuickCheck -Ip $ip -Key $key
	returns information about $ip
	.Link 
	https://developer.greynoise.io/reference/ip-lookup-1#quickcheck-1
	#>
	[cmdletbinding()]
	param(
		[parameter(Mandatory,ValueFromPipelineByPropertyName)]
		[Alias('RemoteAddress','IPAddress')]	
		[ipaddress[]]$Ip,

		[parameter(Mandatory)]
		$Key
	)
	process {
		$dict = @{
			'0x00' = 'The IP has never been observed scanning the Internet'
			'0x01' = 'The IP has been observed by the GreyNoise sensor network'
			'0x02' = 'The IP has been observed scanning the GreyNoise sensor network, but has not completed a full connection, meaning this can be spoofed'
			'0x03' = 'The IP is adjacent to another host that has been directly observed by the GreyNoise sensor network'
			'0x04' = 'Reserved'
			'0x05' = 'This IP is commonly spoofed in Internet-scan activity'
			'0x06' = 'This IP has been observed as noise, but this host belongs to a cloud provider where IPs can be cycled frequently'
			'0x07' = 'This IP is invalid'
			'0x08' = 'This IP was classified as noise, but has not been observed engaging in Internet-wide scans or attacks in over 60 days'
		}


		foreach ($Address in $Ip) {

			$params = @{
				Uri     = "https://api.greynoise.io/v2/noise/quick/$($Address.IPAddressToString)"
				Headers = @{key = $key}
			}
			try {
				$out =	Invoke-RestMethod @params
			 [pscustomobject]@{
					ip      = $address.IPAddressToString
					noise   = $out.noise
					code    = $out.code
					codeMsg = $dict[$out.Code]
				} 
			} catch {
				[pscustomobject]@{
					ip      = $address.IPAddressToString
					noise   = 'N/A'
					code    = $out.code
					codeMsg = $dict[$out.Code]
				} 
			}
		}
	}
}

function Get-GNMultiIpQuickCheck {
	<#
	.Description
	Check whether a set of IP addresses are "Internet background noise", or have been observed scanning or attacking devices across the Internet. This endpoint is functionality identical to the /v2/noise/quick/{ip} endpoint, except it processes more than one checks simultaneously. This endpoint is useful for filtering through large log files.
	.Parameter Ips
	Array of IP addresses to query
	.Parameter Key
	Specify the API key to use.
	.Example
	> Get-GNMultiIpQuickCheck -Ips $ips -Key $key
	returns information about a set of IP addresses
	.Notes
	This API endpoint updates in real-time
	This API endpoint can either be used via GET parameter or within the body of the request
	This API endpoint contains a “code” which correlates to why GreyNoise labeled the IP as "noise"
	An IP delivered via this endpoint does not include "malicious" or "benign" categorizations
	This API endpoint only checks against the last 60 days of Internet scanner data
	.Link
	https://developer.greynoise.io/reference/ip-lookup-1#postquickcheckmulti
	#>
	[cmdletbinding()]
	param(
		[parameter(Mandatory,ValueFromPipelineByPropertyName)]
		[Alias('RemoteAddress','IPAddress','IP')]	
		[ipaddress[]]$Ips,

		[parameter(Mandatory)]
		$Key
	)
	process {
		$dict = @{
			'0x00' = 'The IP has never been observed scanning the Internet'
			'0x01' = 'The IP has been observed by the GreyNoise sensor network'
			'0x02' = 'The IP has been observed scanning the GreyNoise sensor network, but has not completed a full connection, meaning this can be spoofed'
			'0x03' = 'The IP is adjacent to another host that has been directly observed by the GreyNoise sensor network'
			'0x04' = 'Reserved'
			'0x05' = 'This IP is commonly spoofed in Internet-scan activity'
			'0x06' = 'This IP has been observed as noise, but this host belongs to a cloud provider where IPs can be cycled frequently'
			'0x07' = 'This IP is invalid'
			'0x08' = 'This IP was classified as noise, but has not been observed engaging in Internet-wide scans or attacks in over 60 days'
		}

		$params = @{
			Body    = (@{ips = $Ips.IPAddressToString} | ConvertTo-Json)
			Uri     = 'https://api.greynoise.io/v2/noise/multi/quick'
			Headers = @{key = $Key}
			Method  = 'POST'
		}
	
		$out = Invoke-RestMethod @params  
				
		foreach ($output in $out) {
			[pscustomobject]@{
				ip      = $output.ip
				noise   = $output.noise
				code    = $output.code
				codeMsg = $dict[$output.Code]
			} 
		}
	}
}

function Get-GNRiotIpLookup {
	<#
	.Description
	RIOT identifies IPs from known benign services and organizations that commonly cause false positives in network security and threat intelligence products. The collection of IPs in RIOT is continually curated and verified to provide accurate results.
	.Parameter Ip
	IP address to query
	.Parameter Key
	Specify the API key to use.
	.Link
	https://developer.greynoise.io/reference/ip-lookup-1#riotip
	.Example
	> Get-GNRiotIpLookup -Ip $ip -key $key

	returns riot information about $ip
	#>
	[cmdletbinding()]
	param(
		[parameter(Mandatory,ValueFromPipelineByPropertyName)]
		[Alias('RemoteAddress','IPAddress')]	
		[ipaddress[]]$Ip,

		[parameter(Mandatory)]
		$Key
	)

	process {
		foreach ($address in $Ip) {
			$params = @{
				Uri     = "https://api.greynoise.io/v2/riot/$($address.IPAddressToString)"
				Headers = @{key = $Key}
			}
			try {Invoke-RestMethod @params }
			catch {
				[pscustomobject]@{
					ip           = ($_.ErrorDetails.Message | ConvertFrom-Json).ip
					riot         = ($_.ErrorDetails.Message | ConvertFrom-Json).riot
					category     = ''
					name         = ''
					description  = ''
					explanation  = ''
					last_updated = ''
					logo_url     = ''
					reference    = ''
				} 
   }
		}
	}
}

function Get-GNQLQuery {
	<#
	.Description
	GNQL (GreyNoise Query Language) is a domain-specific query language that uses Lucene deep under the hood. GNQL aims to enable GreyNoise Enterprise and Research users to make complex and one-off queries against the GreyNoise dataset as new business cases arise. GNQL is built with self-defeat and fully featured product lines in mind. If we do our job correctly, each individual GNQL query that brings our users and customers sufficient value will eventually be transitioned into it's own individual offering.
	.Parameter Key
	Specify the API key to use.
	.Parameter GNQLQuery
	specify the GNQL query string. See the greynoise docs for usage details.
	.Parameter Size
	Maximum amount of results to grab
	.Parameter Scroll
	Scroll token to paginate through results
	.Link
	https://developer.greynoise.io/reference/gnql-1#gnqlquery-1
	.Example
	> Get-GNQLQuery -GNQLQuery 'last_seen:today' -Key $key
	returns information 
	#>
	[cmdletbinding()]
	param(
		[Parameter(Mandatory)]
		$GNQLQuery,
		[parameter(Mandatory)]
		$Key,
		[Int32]$Size = 10000,
		$Scroll
	)
	$Uri = "https://api.greynoise.io/v2/experimental/gnql?query=$GNQLQuery&size=$Size"
	if ($scroll) {$uri = "$uri&scroll=$scroll"}
	$params = @{
		Headers = @{key = $Key}
		Uri     = $uri
	}
	Invoke-RestMethod @params
}

function Get-GNQLStats {
	<#
	.Description
	Get aggregate statistics for the top organizations, actors, tags, ASNs, countries, classifications, and operating systems of all the results of a given GNQL query.
	.Parameter GNQLQuery
	specify the GNQL query string. See the greynoise docs for usage details.
	.Parameter Count
	Number of top aggregates to grab
	.Parameter Key
	Specify the API key to use.
	.Example
	> Get-GNQLStats -Key $key -GNQLQuery '(raw_data.scan.port:445 and raw_data.scan.protocol:TCP) metadata.os:Windows*'
	Returns information
	.Link
	https://developer.greynoise.io/reference/gnql-1#gnqlstats-1
	#>
	[cmdletbinding()]
	param(
		[Parameter(Mandatory)]
		$GNQLQuery,
		[Int32]$count = 10000,
		[parameter(Mandatory)]
		$Key

	)
	$Uri = "https://api.greynoise.io/v2/experimental/gnql/stats?query=$GNQLQuery&count=$count"
	$params = @{
		Headers = @{key = $Key}
		Uri     = $uri
	}
	Invoke-RestMethod @params
}

function Get-GNTagMetadata {
	<#
	.Description
	Get a list of tags and their respective metadata
	.Parameter Key
	Specify the API key to use.
	.Example
	> Get-GNTagMetadata -key $key
	returns tags and their respective metadata
	.Link
	https://developer.greynoise.io/reference/metadata-2#metadata-3
	#>

	[cmdletbinding()]
	param(
		[parameter(Mandatory)]
		$Key
	)
	Invoke-RestMethod -Uri 'https://api.greynoise.io/v2/meta/metadata' -Headers @{key = $Key}
}