<#
    .SYNOPSIS
    Queries the ClearPass Access Tracker internal dashboard API to retrieve logs.

    .DESCRIPTION
    This cmdlet uses the internal Direct Web Remoting (DWR) API used by the ClearPass web UI 
    to retrieve Access Tracker logs. It requires Connect-ClearPass to be run prior in order 
    to obtain the authenticated WebRequestSession and DWR ScriptSessionId.

    .PARAMETER RequestId
    Optional. Filter by Request ID.

    .PARAMETER Source
    Optional. Filter by Source.

    .PARAMETER Username
    Optional. Filter access tracker logs by username (contains match).
    
    .PARAMETER NasIpAddress
    Optional. Filter by NAS IP Address.

    .PARAMETER NasPort
    Optional. Filter by NAS Port.

    .PARAMETER NasName
    Optional. Filter by NAS Name.

    .PARAMETER Service
    Optional. Filter by Service.

    .PARAMETER LoginStatus
    Optional. Filter by Login Status.

    .PARAMETER ErrorCode
    Optional. Filter by Error Code.

    .PARAMETER HostMacAddress
    Optional. Filter by Host MAC Address.

    .PARAMETER Alerts
    Optional. Filter by Alerts.

    .PARAMETER MonitorMode
    Optional. Filter by Monitor Mode.

    .PARAMETER AuthType
    Optional. Filter by Auth Type.

    .PARAMETER AuthMethod
    Optional. Filter by Auth Method.

    .PARAMETER Roles
    Optional. Filter by Roles.

    .PARAMETER EnforcementProfiles
    Optional. Filter by Enforcement Profiles.

    .PARAMETER SystemPostureToken
    Optional. Filter by System Posture Token.

    .PARAMETER AuditPostureToken
    Optional. Filter by Audit Posture Token.

    .PARAMETER AfterId
    Optional. Filter logs logically appearing after a specific explicit log backend ID.

    .PARAMETER Limit
    Optional. The maximum number of records to return. Default is 20.

    .PARAMETER Days
    Optional. The time range interval (in days) to query. Default is 1 day.

    .EXAMPLE
    Connect-ClearPass -Server "clearpass-demo.arubaboston.com"
    Get-ClearPassAccessTrackerLog -Username "jane.doe2"
    Get-ClearPassAccessTrackerLog AfterId "R0169ff71-23-69a2fbb5"
#>
function Get-ClearPassAccessTrackerLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)] [string]$RequestId,
        [Parameter(Mandatory = $false)] [string]$Source,
        [Parameter(Mandatory = $false)] [string]$Username,
        [Parameter(Mandatory = $false)] [string]$NasIpAddress,
        [Parameter(Mandatory = $false)] [string]$NasPort,
        [Parameter(Mandatory = $false)] [string]$NasName,
        [Parameter(Mandatory = $false)] [string]$Service,
        [Parameter(Mandatory = $false)] [string]$LoginStatus,
        [Parameter(Mandatory = $false)]    [int]$ErrorCode,
        [Parameter(Mandatory = $false)] [string]$HostMacAddress,
        [Parameter(Mandatory = $false)] [string]$Alerts,
        [Parameter(Mandatory = $false)] [string]$MonitorMode,
        [Parameter(Mandatory = $false)] [string]$AuthType,
        [Parameter(Mandatory = $false)] [string]$AuthMethod,
        [Parameter(Mandatory = $false)] [string]$Roles,
        [Parameter(Mandatory = $false)] [string]$EnforcementProfiles,
        [Parameter(Mandatory = $false)] [string]$SystemPostureToken,
        [Parameter(Mandatory = $false)] [string]$AuditPostureToken,
        [Parameter(Mandatory = $false)] [string]$AfterId,
        [Parameter(Mandatory = $false)]    [int]$Limit = 20,
        [Parameter(Mandatory = $false)]    [int]$Days = 1
    )

    Process {
        if (-not $global:PSClearPassSession) {
            throw "Not connected to ClearPass. Please run 'Connect-ClearPass' first."
        }

        $sessionState = $global:PSClearPassSession
        $baseUrl = "https://$($sessionState.Server)"

        $headers = @{
            "Accept"          = "*/*"
            "Accept-Language" = "en-US,en;q=0.9"
            "Cache-Control"   = "no-cache"
            "Content-Type"    = "text/plain"
            "Origin"          = $baseUrl
            "Pragma"          = "no-cache"
            "Referer"         = "$baseUrl/tips/tipsContent.action"
            "User-Agent"      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0"
        }

        $session = $sessionState.WebSession
        $ScriptSessionId = $sessionState.ScriptSessionId

        $filters = @()
        if ($PSBoundParameters.ContainsKey('RequestId')) { $filters += @{ Field = 'Common.Request-Id'; Value = $RequestId; Type = 'STRING' } }
        if ($PSBoundParameters.ContainsKey('Source')) { $filters += @{ Field = 'Common.Source'; Value = $Source; Type = 'STRING' } }
        if ($PSBoundParameters.ContainsKey('Username')) { $filters += @{ Field = 'Common.Username'; Value = $Username; Type = 'STRING' } }
        if ($PSBoundParameters.ContainsKey('NasIpAddress')) { $filters += @{ Field = 'Common.NAS-IP-Address'; Value = $NasIpAddress; Type = 'STRING' } }
        if ($PSBoundParameters.ContainsKey('NasPort')) { $filters += @{ Field = 'Common.NAS-Port'; Value = $NasPort; Type = 'STRING' } }
        if ($PSBoundParameters.ContainsKey('NasName')) { $filters += @{ Field = 'Common.NAS-Name'; Value = $NasName; Type = 'STRING' } }
        if ($PSBoundParameters.ContainsKey('Service')) { $filters += @{ Field = 'Common.Service'; Value = $Service; Type = 'STRING' } }
        if ($PSBoundParameters.ContainsKey('LoginStatus')) { $filters += @{ Field = 'Common.Login-Status'; Value = $LoginStatus; Type = 'STRING' } }
        if ($PSBoundParameters.ContainsKey('ErrorCode')) { $filters += @{ Field = 'Common.Error-Code'; Value = $ErrorCode.ToString(); Type = 'INTEGER' } }
        if ($PSBoundParameters.ContainsKey('HostMacAddress')) { $filters += @{ Field = 'Common.Host-MAC-Address'; Value = $HostMacAddress; Type = 'MAC' } }
        if ($PSBoundParameters.ContainsKey('Alerts')) { $filters += @{ Field = 'Common.Alerts'; Value = $Alerts; Type = 'STRING' } }
        if ($PSBoundParameters.ContainsKey('MonitorMode')) { $filters += @{ Field = 'Common.Monitor-Mode'; Value = $MonitorMode; Type = 'STRING' } }
        if ($PSBoundParameters.ContainsKey('AuthType')) { $filters += @{ Field = 'Common.Auth-Type'; Value = $AuthType; Type = 'STRING' } }
        if ($PSBoundParameters.ContainsKey('AuthMethod')) { $filters += @{ Field = 'RADIUS.Auth-Method'; Value = $AuthMethod; Type = 'STRING' } }
        if ($PSBoundParameters.ContainsKey('Roles')) { $filters += @{ Field = 'Common.Roles'; Value = $Roles; Type = 'STRING' } }
        if ($PSBoundParameters.ContainsKey('EnforcementProfiles')) { $filters += @{ Field = 'Common.Enforcement-Profiles'; Value = $EnforcementProfiles; Type = 'STRING' } }
        if ($PSBoundParameters.ContainsKey('SystemPostureToken')) { $filters += @{ Field = 'Common.System-Posture-Token'; Value = $SystemPostureToken; Type = 'STRING' } }
        if ($PSBoundParameters.ContainsKey('AuditPostureToken')) { $filters += @{ Field = 'Common.Audit-Posture-Token'; Value = $AuditPostureToken; Type = 'STRING' } }


        # The Private function Get-CPDwrBatch is imported automatically by PSClearPass.psm1

        $sortDirection = "DESC"
        $trimmingActive = $false
        $lastTimestampStr = $null

        if ($PSBoundParameters.ContainsKey('AfterId')) {
            Write-Verbose "Resolving historical timestamp anchor for native ID: $AfterId"
            $sortDirection = "ASC"
            $trimmingActive = $true
            
            $idFilters = @( @{ Field = 'Common.Request-Id'; Value = $AfterId; Type = 'STRING'; Condition = 'equals' } )
            $anchorRecords = Get-CPDwrBatch -CurrentFilters $idFilters -TimeAnchor $null -SortMode "DESC" -BaseUrl $baseUrl -Headers $headers -WebSession $session -ScriptSessionId $ScriptSessionId -Days $Days
            
            if (-not $anchorRecords -or $anchorRecords.Count -eq 0) {
                Write-Error "Could not locate log matching AfterId '$AfterId' to calculate chronological boundary. Returning empty array."
                return @()
            }
            
            $lastTimestampStr = $anchorRecords[0].displayTime
            Write-Verbose "Found baseline ID natively! Locked slice boundary mathematically at: $lastTimestampStr"
        }

        $allRecords = [System.Collections.Generic.List[psobject]]::new()
        $recordsCount = 0
        $seenIds = [System.Collections.Generic.HashSet[string]]::new()

        while ($recordsCount -lt $Limit) {
            $records = Get-CPDwrBatch -CurrentFilters $filters -TimeAnchor $lastTimestampStr -SortMode $sortDirection -BaseUrl $baseUrl -Headers $headers -WebSession $session -ScriptSessionId $ScriptSessionId -Days $Days
            
            if (-not $records -or $records.Count -eq 0) {
                Write-Verbose "No more logs found matching criteria natively."
                break
            }
            
            $chunkAdded = 0
            foreach ($record in $records) {
                if ($trimmingActive) {
                    if ($record.id -eq $AfterId) {
                        Write-Verbose "Encountered AfterId anchor synchronously! Breaking trim lock and absorbing future metadata."
                        $trimmingActive = $false
                    }
                    # We always add it to seenIds during trim phase to inherently blocklist native overlap duplicates
                    $seenIds.Add($record.id) > $null
                    continue
                }

                if (-not $seenIds.Contains($record.id)) {
                    $seenIds.Add($record.id) > $null
                    if ($record.requestTime) {
                        try {
                            $epoch = [long]$record.requestTime
                            $record.requestTime = (Get-Date "1970-01-01 00:00:00.000Z").AddMilliseconds($epoch).ToLocalTime()
                        }
                        catch {}
                    }
                    $allRecords.Add($record)
                    $chunkAdded++
                    
                    if ($allRecords.Count -ge $Limit) {
                        break
                    }
                }
            }
            
            $recordsCount += $chunkAdded

            # If we get less than 10 records, we've hit the present
            if ($chunkAdded -eq 0 -or $records.Count -lt 10) {
                break 
            }

            if ($recordsCount -lt $Limit) {
                $lastTimestampStr = $records[-1].displayTime
            }
        }
        
        # Return the order to the typical DESC
        if ($PSBoundParameters.ContainsKey('AfterId')) {
            $allRecords.Reverse()
        }

        if ($allRecords.Count -gt $Limit) {
            $returnRecords = $allRecords | Select-Object -First $Limit
            return @($returnRecords)
        }

        return @($allRecords)
    }
}

