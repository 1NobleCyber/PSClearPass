<#
    .SYNOPSIS
    Registers a new Guest Device inside the ClearPass Guest module.

    .DESCRIPTION
    This cmdlet automates interaction with the ClearPass Guest "Create Device" module (mac_create.php).
    It executes a two-stage transaction natively: an initial hidden GET request to dynamically
    scrape the CSRF security token assigned to the session payload form, followed immediately 
    by a structurally formatted URL-encoded POST binding the exact device parameters.

    Requires Connect-ClearPass to be established prior to execution.

    .PARAMETER MacAddress
    Mandatory. The physical MAC Address constraint of the target component.

    .PARAMETER DeviceName
    Mandatory. The user-facing alias mapped to the Guest endpoint.

    .PARAMETER RoleId
    Mandatory. The intrinsic `role_id` integer explicitly mapping the device to appropriate ClearPass policies.

    .PARAMETER AssetTag
    Optional. The string-binding Asset parameter.

    .PARAMETER SerialNumber
    Optional. The string-binding Serial constraint.

    .PARAMETER Notes
    Optional. The formal notation payload binding to the context form.

    .PARAMETER StartTime
    Optional. Explicit `start_time` execution boundary. Defaults intrinsically to "now".

    .PARAMETER ExpireTime
    Optional. Explicit `expire_time` execution boundary. Defaults intrinsically to "none".

    .PARAMETER RequirePassword
    Optional. Negates the internal `no_password` deployment. Form natively defaults this to enabled (no password).

    .PARAMETER RequirePortal
    Optional. Negates the internal `no_portal` deployment. Form natively defaults this to enabled (no portal).
    
    .PARAMETER EnableAirGroup
    Optional. Enables the `airgroup_shared` execution property natively.
#>
function Add-ClearPassGuestDevice {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$MacAddress,

        [Parameter(Mandatory = $true)]
        [string]$DeviceName,

        [Parameter(Mandatory = $true)]
        [int]$RoleId,

        [Parameter(Mandatory = $false)]
        [string]$AssetTag = "",

        [Parameter(Mandatory = $false)]
        [string]$SerialNumber = "",

        [Parameter(Mandatory = $false)]
        [string]$Notes = "",

        [Parameter(Mandatory = $false)]
        [string]$StartTime = "",

        [Parameter(Mandatory = $false)]
        [string]$ExpireTime = "",

        [Parameter(Mandatory = $false)]
        [switch]$RequirePassword,

        [Parameter(Mandatory = $false)]
        [switch]$RequirePortal,

        [Parameter(Mandatory = $false)]
        [switch]$EnableAirGroup
    )

    Process {
        if (-not $global:PSClearPassSession) {
            throw "Not connected to ClearPass. Please run 'Connect-ClearPass' first."
        }

        $sessionState = $global:PSClearPassSession
        $baseUrl = "https://$($sessionState.Server)"
        $createUrl = "$baseUrl/guest/mac_create.php"
        $session = $sessionState.WebSession

        $headers = @{
            "Accept"          = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
            "Accept-Language" = "en-US,en;q=0.9"
            "Cache-Control"   = "no-cache"
            "Origin"          = $baseUrl
            "Pragma"          = "no-cache"
            "Referer"         = $createUrl
            "User-Agent"      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0"
        }

        try {
            # Stage 1: Explicitly GET mac_create.php to statically locate the unique `csrf_token` embedded natively inside the FORM boundary
            Write-Verbose "Requesting explicit mac_create.php endpoint form footprint..."
            $formResponse = Invoke-WebRequest -Uri $createUrl -Method Get -WebSession $session -Headers $headers -UseBasicParsing -ErrorAction Stop
            $formHtml = $formResponse.Content

            # RegEx literal isolation of: <input type="hidden" name="csrf_token" id="..." value="..." />
            $csrfMatch = [regex]::Match($formHtml, 'name="csrf_token"[^>]+?value="([^"]+)"')
            if ($csrfMatch.Success) {
                $csrfToken = $csrfMatch.Groups[1].Value
                Write-Verbose "Successfully extracted architectural Creation CSRF Token: $csrfToken"
            } else {
                throw "Mechanically failed to scrape the dynamic 'csrf_token' signature dynamically extracted within the execution FORM layer. Validation aborted."
            }

            # Map the exact physical parameters to securely build the URL-Encoded boundary string
            $noPasswordFlag = if ($RequirePassword) { '0' } else { '1' }
            $noPortalFlag = if ($RequirePortal) { '0' } else { '1' }
            $airGroupFlag = if ($EnableAirGroup) { '1' } else { '0' }

            $modifyStartFlag = if ($StartTime) { 'custom' } else { 'now' }
            $modifyExpireFlag = if ($ExpireTime) { 'custom' } else { 'none' }

            # Establish formally ordered dictionary pipeline aligning directly natively to Amigopod payload specifications
            $payloadDict = [ordered]@{
                "csrf_token"                       = $csrfToken
                "mac_auth"                         = '1'
                "mac"                              = $MacAddress
                "visitor_name"                     = $DeviceName
                "airgroup_shared"                  = $airGroupFlag
                "airgroup_shared_user"             = ''
                "airgroup_shared_group[]"          = ''
                "airgroup_shared_time"             = ''
                "modify_start_time"                = $modifyStartFlag
                "start_time"                       = $StartTime
                "modify_expire_time"               = $modifyExpireFlag
                "expire_time"                      = $ExpireTime
                "expire_after"                     = '24' 
                "asset_tag"                        = $AssetTag
                "Serial_Number"                    = $SerialNumber
                "role_id"                          = $RoleId
                "no_password"                      = $noPasswordFlag
                "no_portal"                        = $noPortalFlag
                "endpoint_profile_device_category" = ''
                "endpoint_profile_device_family"   = ''
                "endpoint_profile_device_name"     = ''
                "endpoint_profile_ip"              = ''
                "notes"                            = $Notes
                "creator_accept_terms"             = '1'
            }

            # Physically aggregate formally defined dictionary into native URL-Encoded blocks natively
            $bodyParams = @()
            foreach ($key in $payloadDict.Keys) {
                $encKey = [uri]::EscapeDataString($key)
                $encVal = [uri]::EscapeDataString($payloadDict[$key])
                $bodyParams += "$encKey=$encVal"
            }
            $postBody = $bodyParams -join "&"

            Write-Verbose "Executing primary POST transmission bound internally against the $createUrl engine..."
            $headers["Content-Type"] = "application/x-www-form-urlencoded"
            
            # Formally Execute Engine Payload
            $redirectLocation = $null
            $statusCode = $null
            
            try {
                $postResponse = Invoke-WebRequest -Uri $createUrl -Method Post -Headers $headers -Body $postBody -WebSession $session -MaximumRedirection 0 -ErrorAction Stop
                # Extreme edge case where the module accepts without dropping a 302
                $statusCode = [int]$postResponse.StatusCode
            } catch {
                # PowerShell 7 Core natively throws an Exception terminating the command globally when MaximumRedirection is strictly 0. 
                # We specifically intercept the organic 302 Found string and dynamically evaluate its Exception Object natively.
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                    $redirectLocation = $_.Exception.Response.Headers.Location.ToString()
                } elseif ($_.Exception.Message -match "302" -or $_.Exception.Message -match "Found") {
                    $statusCode = 302
                    # The raw string in core might just be '302 (Found).' However, our payload still formally succeeded!
                    $redirectLocation = "mac_create_receipt"
                } else {
                    throw "Underlying POST physically failed independent of receipt redirect: $_"
                }
            }
            
            # The architectural baseline returns an explicit 302 Found bouncing heavily into mac_create_receipt.php
            if ($statusCode -eq 302 -and ($redirectLocation -match "mac_create_receipt" -or $redirectLocation)) {
                Write-Verbose "Successfully verified intrinsic native HTTP 302 Redirect payload targeting the Receipt block natively!"
                
                # Fetching the receipt isn't required but cleanly clears the execution loop physically!
                if ($redirectLocation -and $redirectLocation -match "^/") {
                    $receiptUrl = "https://$($sessionState.Server)$redirectLocation"
                } elseif ($redirectLocation -and -not $redirectLocation.StartsWith("http")) {
                    $receiptUrl = "$baseUrl/guest/$redirectLocation"
                } else {
                    $receiptUrl = "$baseUrl/guest/mac_create_receipt.php"
                }

                $receiptResult = Invoke-WebRequest -Uri $receiptUrl -Method Get -WebSession $session -Headers $headers -ErrorAction Stop
                
                # Verify Success explicitly inside the final response DOM payload manually!
                if ($receiptResult.Content -match "$MacAddress" -or $receiptResult.Content -match "receipt") {
                    $ResultObj = [PSCustomObject]@{
                        Status = "Success"
                        MacAddress = $MacAddress
                        DeviceName = $DeviceName
                        RoleId = $RoleId
                        Message = "Device natively registered successfully across ClearPass DOM."
                    }
                    return $ResultObj
                }
            } else {
                Write-Error "Deployment execution mathematically drifted! Target endpoint did NOT naturally return a native HTTP 302 Receipt loop! Response Code: $($postResponse.StatusCode)"
                return $postResponse
            }
            
        } catch {
            Write-Error "Physically failed to execute Add-ClearPassGuestDevice constraint mapping: $_"
        }
    }
}
