
function Get-GNIpInfo {
	<#
	.Description
	Returns information for the provided Ips from the greynoise API. This is for the community API.
	.Parameter Ip
	Specify one or many IP addresses that you want to look up
	.Parameter Key
	Specify the API key to use. A blank key works for this. See viz.greynoise.io/account/ for API key.
	.Example
		Get-GNIpInfo -Ip 8.8.8.8

		Returns IP information about the provided IP address.
	#>
	param(
		[parameter(Mandatory, ValueFromPipelineByPropertyName)]
		[Alias('RemoteAddress')]
		[ipaddress[]]$Ip,
		[string]$Key = ''
	)
	process {
		foreach ($Address in $Ip) {
			Invoke-RestMethod -Method Get -Uri "https://api.greynoise.io/v3/community/$Address" -Headers @{Key = $Key }
		}
	}
}
