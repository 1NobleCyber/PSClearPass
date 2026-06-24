<#
    .SYNOPSIS
    Queries the ClearPass Guest module API (mac_list.php) to retrieve registered devices.

    .DESCRIPTION
    This cmdlet automates interaction with the ClearPass Guest "Manage Devices" module using 
    JSRS (Javascript Remote Scripting). It performs a two-stage transaction: an initial GET request 
    to scrape the hidden `rscsrf` token from the web payload, followed by a POST containing 
    the serialized URL-encoded Search dictionary.

    It requires Connect-ClearPass to be run prior in order to obtain the active WebRequestSession 
    containing the `CPG-PREF` and `JSESSIONID` authentication cookies.

    .PARAMETER MacAddress
    Optional. The precise MAC Address to search for in the Guest Database. If omitted, returns the first 1000 devices.

    .EXAMPLE
    Connect-ClearPass -Server "clearpass-demo.arubaboston.com"
    Get-ClearPassGuestDevice

    .EXAMPLE
    Get-ClearPassGuestDevice -MacAddress "f8-ac-65-7b-2f-14"
#>
function Get-ClearPassGuestDevice {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$MacAddress
    )

    Process {
        if (-not $global:PSClearPassSession) {
            throw "Not connected to ClearPass. Please run 'Connect-ClearPass' first."
        }

        $sessionState = $global:PSClearPassSession
        $baseUrl = "https://$($sessionState.Server)"
        $guestUrl = "$baseUrl/guest/mac_list.php"
        $session = $sessionState.WebSession

        $headers = @{
            "Accept"          = "*/*"
            "Accept-Language" = "en-US,en;q=0.9"
            "Cache-Control"   = "no-cache"
            "Origin"          = $baseUrl
            "Pragma"          = "no-cache"
            "Referer"         = $guestUrl
            "User-Agent"      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0"
        }

        try {
            Write-Verbose "Injecting universal Anti-Forgery token dynamically extracted during logon..."
            $csrfToken = $sessionState.GuestCsrfToken
            if (-not $csrfToken) {
                throw "Global Session missing required 'GuestCsrfToken'. Ensure 'Connect-ClearPass' successfully authorized the endpoint."
            }

            $cookieStrArray = @()
            $cookiePayload = $session.Cookies.GetCookies((New-Object System.Uri($baseUrl)))
            if ($cookiePayload.Count -eq 0 -or $cookiePayload -eq $null) {
                $cookiePayload = $session.Cookies.GetAllCookies()
            }
            foreach ($cookie in $cookiePayload) {
                $cookieStrArray += "$($cookie.Name)=$($cookie.Value)"
            }
            $headers["Cookie"] = $cookieStrArray -join "; "

            $headers["Content-Type"] = "application/x-www-form-urlencoded"
            $rsrnd = [Math]::Truncate((Get-Date -UFormat %s) * 1000)

            # JSRS Serialization uses an "s:size:value" methodology that translates poorly to readable JSON
            $payloadPrefix = "rs=NwaGuestManager_MacDevices_UpdateView&rst=&rsrnd=$rsrnd&rscsrf=$csrfToken&rsargs[]=s%3Adata_model%3Aa%3As%253Aitems%253Aa%253Az%253As%253Asearch%253Aa%253As%25253Afilter%25253As"
            
            $payloadSuffix = ""
            if ($MacAddress) {
                # Add specific MAC target
                $payloadSuffix = "%25253A$MacAddress%25253As%25253Asettings_html%25253As%25253A%25253Az%253As%253Apager%253Aa%253As%25253Acurrent_page%25253As%25253A0%25253As%25253Asize%25253As%25253A1000%25253As%25253Aauto_refresh%25253As%25253A%25253As%25253Arequested_page%25253As%25253A0%25253As%25253Anum_pages%25253As%25253A1%25253As%25253Acounts_html%25253As%25253AShowing%252525201%25252520%252525E2%25252580%25252593%252525201000%25252520of%252525201%25253Az%253As%253Asorting%253Aa%253As%25253Aproperty%25253As%25253Aasset_tag%25253As%25253Adirection%25253As%25253Adescending%25253Az%253As%253Afilters%253Aa%253Az%253As%253AClearListViewMarkup%253Af%253A%253As%253AExtendWith%253As%253A%253As%253AMergeWith%253As%253A%253As%253AJsonEncoded%253As%253A%253As%253Acolumns%253Aa%253As%25253A0%25253Aa%25253As%2525253Asort_direction%2525253An%2525253Anull%2525253Az%25253As%25253A1%25253Aa%25253As%2525253Asort_direction%2525253An%2525253Anull%2525253Az%25253As%25253A2%25253Aa%25253As%2525253Asort_direction%2525253An%2525253Anull%2525253Az%25253As%25253A3%25253Aa%25253As%2525253Asort_direction%2525253As%2525253Adescending%2525253Az%25253As%25253A4%25253Aa%25253As%2525253Asort_direction%2525253An%2525253Anull%2525253Az%25253Az%253Az&rsargt=a"
            } else {
                # Blank MAC query 
                $payloadSuffix = "%25253A%25253Az%253As%253Apager%253Aa%253As%25253Acurrent_page%25253As%25253A0%25253As%25253Asize%25253As%25253A1000%25253As%25253Aauto_refresh%25253As%25253A%25253As%25253Arequested_page%25253As%25253A0%25253Az%253As%253Asorting%253Aa%253As%25253Aproperty%25253As%25253Aasset_tag%25253As%25253Adirection%25253As%25253Adescending%25253Az%253As%253Afilters%253Aa%253Az%253As%253AClearListViewMarkup%253Af%253A%253As%253AExtendWith%253Af%253A%253As%253AMergeWith%253Af%253A%253As%253AJsonEncoded%253Af%253A%253Az%3Az&rsargt=a"
            }

            $body = $payloadPrefix + $payloadSuffix

            Write-Verbose "Submitting JSRS parameter payload block to engine..."
            $response = Invoke-RestMethod -Uri "$baseUrl/guest/mac_list.php" -Method Post -Headers $headers -Body $body -WebSession $global:PSClearPassSession.WebSession -UserAgent $headers."User-Agent" -UseBasicParsing -ErrorAction Stop
        
            # JSRS Payload Architecture: "+:var res = {"data_model":{"items":[{...}]}};"
            # Or native JSON depending on server proxy routing state!
            $cleanResponse = $response.Trim()
            
            # The regex engine hits catastrophic backtracking timeouts matching 600KB payload boundaries.
            # Executing pure string boundary parsing natively isolates the JSON immediately.
            $firstBrace = $cleanResponse.IndexOf('{')
            $lastBrace = $cleanResponse.LastIndexOf('}')

            if ($firstBrace -ge 0 -and $lastBrace -gt $firstBrace) {
                Write-Verbose "JSRS endpoint string successfully sliced natively using literal indices."
                $jsonString = $cleanResponse.Substring($firstBrace, $lastBrace - $firstBrace + 1)
            } else {
                $truncatedResponse = if ($cleanResponse.Length -gt 1500) { $cleanResponse.Substring(0, 1500) + "...[TRUNCATED]" } else { $cleanResponse }
                Write-Error "Failed to locate native JSON string boundaries '{...}'. Raw trace appended below:`n$truncatedResponse"
                return
            }

            try {
                $jsonData = $jsonString | ConvertFrom-Json
                
                # JSRS schemas embed `items` under `data_model`. Native JSON responses embed it at the root.
                if ($null -ne $jsonData.data_model) {
                    $deviceArray = $jsonData.data_model.items
                } elseif ($null -ne $jsonData.items) {
                    $deviceArray = $jsonData.items
                } else {
                    Write-Error "Deserialization critically failed: JSRS schema completely lacked the 'items' data array."
                    return
                }

                Write-Verbose "Formatting UNIX temporal boundaries..."
                $epoch = [datetime]"1970-01-01T00:00:00Z"
                foreach ($dev in $deviceArray) {
                    if ($null -ne $dev.start_time -and [double]'0' -lt [double]$dev.start_time) { $dev.start_time = $epoch.AddSeconds([double]$dev.start_time).ToLocalTime() } else { $dev.start_time = $null }
                    if ($null -ne $dev.expire_time -and [double]'0' -lt [double]$dev.expire_time) { $dev.expire_time = $epoch.AddSeconds([double]$dev.expire_time).ToLocalTime() } else { $dev.expire_time = $null }
                    if ($null -ne $dev.create_time -and [double]'0' -lt [double]$dev.create_time) { $dev.create_time = $epoch.AddSeconds([double]$dev.create_time).ToLocalTime() } else { $dev.create_time = $null }
                }

                Write-Verbose "Successfully parsed $($deviceArray.Count) ClearPass Guest devices."
                return $deviceArray
            } catch {
                Write-Error "Failed to deserialize JSON datastream natively: $_"
            }
            
        } catch {
            Write-Error "Failed to retrieve Guest Device log chunk: $_"
        }
    }
}
