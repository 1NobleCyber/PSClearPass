function Get-CPDwrBatch {
    param(
        [Parameter(Mandatory=$true)]
        [array]$CurrentFilters,

        [Parameter(Mandatory=$false)]
        [string]$TimeAnchor,

        [Parameter(Mandatory=$true)]
        [string]$SortMode,

        [Parameter(Mandatory=$true)]
        [string]$BaseUrl,

        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,

        [Parameter(Mandatory=$true)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

        [Parameter(Mandatory=$true)]
        [string]$ScriptSessionId,

        [Parameter(Mandatory=$true)]
        [int]$Days
    )

    $payloadLines = [System.Collections.Generic.List[string]]::new()
    
    $payloadLines.Add("callCount=1")
    $payloadLines.Add("nextReverseAjaxIndex=0")
    $payloadLines.Add("c0-scriptName=dashboard")
    $payloadLines.Add("c0-methodName=saveCachedBean")
    $payloadLines.Add("c0-id=0")
    $payloadLines.Add("c0-param0=string:accessTracker")
    
    $payloadLines.Add("c0-e1=boolean:false")
    $payloadLines.Add("c0-e2=null:null")
    $payloadLines.Add("c0-e3=number:0")
    $payloadLines.Add("c0-e4=number:0")
    $payloadLines.Add("c0-e5=null:null")
    $payloadLines.Add("c0-e6=null:null")
    $payloadLines.Add("c0-e7=null:null")
    $payloadLines.Add("c0-e8=boolean:false")
    $payloadLines.Add("c0-e9=string:10")
    $payloadLines.Add("c0-e10=null:null")
    
    $requestedColumns = @(
        "server_name", "Common.Source", "Common.Username", "Common.Service",
        "Common.Login-Status", "Common.Request-Timestamp", "Common.NAS-Name",
        "Common.NAS-Port", "Common.Host-MAC-Address", "Common.NAS-IP-Address",
        "RADIUS.Auth-Method", "Common.Auth-Type", "Common.Enforcement-Profiles",
        "Common.Error-Code", "Common.Monitor-Mode", "Common.Request-Id", "server_ip"
    )
    
    $colRefs = [System.Collections.Generic.List[string]]::new()
    $eIndex = 12
    foreach ($col in $requestedColumns) {
        $payloadLines.Add("c0-e$eIndex=string:$col")
        $colRefs.Add("reference:c0-e$eIndex")
        $eIndex++
    }
    $colArrayStr = $colRefs -join ","
    $payloadLines.Add("c0-e11=array:[$colArrayStr]")
    $payloadLines.Add("c0-e29=string:1") 
    $payloadLines.Add("c0-e31=array:[]")
    $payloadLines.Add("c0-e32=number:1")
    $payloadLines.Add("c0-e33=null:null")

    $filterRefs = [System.Collections.Generic.List[string]]::new()
    $fIndex = 35 
    foreach ($filter in $CurrentFilters) {
        $condition = if ($null -ne $filter.Condition) { $filter.Condition } elseif ($filter.Type -in @('MAC', 'INTEGER')) { 'equals' } else { 'contains' }

        $payloadLines.Add("c0-e$($fIndex+1)=string:$($filter.Field)")
        $payloadLines.Add("c0-e$($fIndex+2)=string:$($filter.Value)")
        $payloadLines.Add("c0-e$($fIndex+3)=string:$($filter.Type)")
        $payloadLines.Add("c0-e$($fIndex+4)=string:$condition")
        $payloadLines.Add("c0-e$($fIndex+5)=string:$condition")
        $payloadLines.Add("c0-e$fIndex=Object_Object:{filterBarSelect:reference:c0-e$($fIndex+1), filterField:reference:c0-e$($fIndex+2), dataType:reference:c0-e$($fIndex+3), filterFieldCondition:reference:c0-e$($fIndex+4), tagColumnCondition:reference:c0-e$($fIndex+5)}")
        
        $filterRefs.Add("reference:c0-e$fIndex")
        $fIndex += 6
    }

    if ($filterRefs.Count -eq 0) {
        $payloadLines.Add("c0-e34=array:[]") 
    }
    else {
        $filterArrayStr = $filterRefs -join ","
        $payloadLines.Add("c0-e34=array:[$filterArrayStr]")
    }

    $bIndex = $fIndex
    $payloadLines.Add("c0-e$($bIndex)=boolean:false")
    $payloadLines.Add("c0-e$($bIndex+1)=boolean:false")
    $payloadLines.Add("c0-e$($bIndex+2)=string:$Days")
    $payloadLines.Add("c0-e$($bIndex+3)=number:1000") 
    $payloadLines.Add("c0-e$($bIndex+4)=boolean:true")
    $payloadLines.Add("c0-e$($bIndex+5)=number:100000") 
    $payloadLines.Add("c0-e$($bIndex+6)=number:50000") 
    $payloadLines.Add("c0-e$($bIndex+7)=number:0") 
    $payloadLines.Add("c0-e$($bIndex+8)=number:1") 
    $payloadLines.Add("c0-e$($bIndex+9)=string:1000")
    $payloadLines.Add("c0-e$($bIndex+10)=boolean:false")
    $payloadLines.Add("c0-e$($bIndex+11)=string:Common.Request-Timestamp")
    $payloadLines.Add("c0-e$($bIndex+12)=string:$SortMode")
    
    if ($TimeAnchor) {
        $cleanDateStr = $TimeAnchor -replace '/', '-'
        $payloadLines.Add("c0-e$($bIndex+13)=string:$cleanDateStr")
        $timeStrRef = "timeStr:reference:c0-e$($bIndex+13)"
    }
    else {
        $payloadLines.Add("c0-e$($bIndex+13)=null:null")
        $timeStrRef = "timeStr:reference:c0-e$($bIndex+13)"
    }

    $payloadLines.Add("c0-e30=Object_Object:{attributesInCriteria:reference:c0-e31, currentRecordInPage:reference:c0-e32, filterCriteria:reference:c0-e33, filterCriteriaList:reference:c0-e34, filterFieldEmpty:reference:c0-e$($bIndex), hasAscending:reference:c0-e$($bIndex+1), interval:reference:c0-e$($bIndex+2), lastRecordInPage:reference:c0-e$($bIndex+3), matchAll:reference:c0-e$($bIndex+4), maxPageNumber:reference:c0-e$($bIndex+5), maxRecordsInFilter:reference:c0-e$($bIndex+6), offset:reference:c0-e$($bIndex+7), pageNumber:reference:c0-e$($bIndex+8), pageSize:reference:c0-e$($bIndex+9), restApiFilter:reference:c0-e$($bIndex+10), sortKey:reference:c0-e$($bIndex+11), sortType:reference:c0-e$($bIndex+12), $timeStrRef}")
    $tIndex = $bIndex + 14
    $payloadLines.Add("c0-e$($tIndex)=null:null")
    $payloadLines.Add("c0-e$($tIndex+1)=null:null")
    
    $payloadLines.Add("c0-param1=Object_Object:{autoRefresh:reference:c0-e1, chartType:reference:c0-e2, dijitFromWhen:reference:c0-e3, dijitLevel:reference:c0-e4, fromWhen:reference:c0-e5, height:reference:c0-e6, level:reference:c0-e7, needCount:reference:c0-e8, queryId:reference:c0-e9, requester:reference:c0-e10, selectedColumns:reference:c0-e11, serverId:reference:c0-e29, tfb:reference:c0-e30, title:reference:c0-e$($tIndex), width:reference:c0-e$($tIndex+1)}")
    
    $payloadLines.Add("batchId=1")
    $payloadLines.Add("instanceId=0")
    $payloadLines.Add("page=%2Ftips%2FtipsContent.action")
    $payloadLines.Add("scriptSessionId=$ScriptSessionId")

    $beanBody = $payloadLines -join "`n"

    try {
        $null = Invoke-RestMethod -Uri "$BaseUrl/tips/dwr/call/plaincall/dashboard.saveCachedBean.dwr" -Method Post -Headers $Headers -Body $beanBody -WebSession $WebSession -UseBasicParsing
        
        $dwrUrl = "$BaseUrl/tips/dwr/call/plaincall/dashboard.filterTableOnServerWithQuery.dwr"
        $fetchBody = "callCount=1`nnextReverseAjaxIndex=0`nc0-scriptName=dashboard`nc0-methodName=filterTableOnServerWithQuery`nc0-id=0`nc0-e1=array:[]`nc0-e2=number:1`nc0-e3=null:null`nc0-e4=array:[]`nc0-e5=boolean:false`nc0-e6=boolean:false`nc0-e7=string:$Days`nc0-e8=number:1000`nc0-e9=boolean:true`nc0-e10=number:100000`nc0-e11=number:50000`nc0-e12=number:0`nc0-e13=number:1`nc0-e14=string:1000`nc0-e15=boolean:false`nc0-e16=string:Common.Request-Timestamp`nc0-e17=string:$SortMode`n"
        if ($TimeAnchor) {
            $fetchBody += "c0-e18=string:$cleanDateStr`nc0-param0=Object_Object:{attributesInCriteria:reference:c0-e1, currentRecordInPage:reference:c0-e2, filterCriteria:reference:c0-e3, filterCriteriaList:reference:c0-e4, filterFieldEmpty:reference:c0-e5, hasAscending:reference:c0-e6, interval:reference:c0-e7, lastRecordInPage:reference:c0-e8, matchAll:reference:c0-e9, maxPageNumber:reference:c0-e10, maxRecordsInFilter:reference:c0-e11, offset:reference:c0-e12, pageNumber:reference:c0-e13, pageSize:reference:c0-e14, restApiFilter:reference:c0-e15, sortKey:reference:c0-e16, sortType:reference:c0-e17, timeStr:reference:c0-e18}`n"
        }
        else {
            $fetchBody += "c0-e18=null:null`nc0-param0=Object_Object:{attributesInCriteria:reference:c0-e1, currentRecordInPage:reference:c0-e2, filterCriteria:reference:c0-e3, filterCriteriaList:reference:c0-e4, filterFieldEmpty:reference:c0-e5, hasAscending:reference:c0-e6, interval:reference:c0-e7, lastRecordInPage:reference:c0-e8, matchAll:reference:c0-e9, maxPageNumber:reference:c0-e10, maxRecordsInFilter:reference:c0-e11, offset:reference:c0-e12, pageNumber:reference:c0-e13, pageSize:reference:c0-e14, restApiFilter:reference:c0-e15, sortKey:reference:c0-e16, sortType:reference:c0-e17, timeStr:reference:c0-e18}`n"
        }
        $fetchBody += "c0-param1=string:10`nc0-e19=string:server_name`nc0-e20=string:Common.Source`nc0-e21=string:Common.Username`nc0-e22=string:Common.Service`nc0-e23=string:Common.Login-Status`nc0-e24=string:Common.Request-Timestamp`nc0-e25=string:Common.NAS-Name`nc0-e26=string:Common.NAS-Port`nc0-e27=string:Common.Host-MAC-Address`nc0-e28=string:Common.NAS-IP-Address`nc0-e29=string:RADIUS.Auth-Method`nc0-e30=string:Common.Auth-Type`nc0-e31=string:Common.Enforcement-Profiles`nc0-e32=string:Common.Error-Code`nc0-e33=string:Common.Monitor-Mode`nc0-e34=string:Common.Request-Id`nc0-e35=string:server_ip`nc0-param2=array:[reference:c0-e19,reference:c0-e20,reference:c0-e21,reference:c0-e22,reference:c0-e23,reference:c0-e24,reference:c0-e25,reference:c0-e26,reference:c0-e27,reference:c0-e28,reference:c0-e29,reference:c0-e30,reference:c0-e31,reference:c0-e32,reference:c0-e33,reference:c0-e34,reference:c0-e35]`nc0-param3=string:20%2C%2021%2C%2022%2C%2023%2C%2024%2C%2025%2C%2034`nc0-param4=boolean:false`nc0-param5=boolean:true`nbatchId=2`ninstanceId=0`npage=%2Ftips%2FtipsContent.action`nscriptSessionId=$ScriptSessionId`n"
        
        $rawResponse = Invoke-RestMethod -Uri $dwrUrl -Method Post -Headers $Headers -Body $fetchBody -WebSession $WebSession -UseBasicParsing
        $flatResponse = ($rawResponse | Out-String) -replace "`r", "" -replace "`n", ""
        
        $startTag = '["SUCCESS",null,'
        $startIndex = $flatResponse.IndexOf($startTag)
        
        if ($startIndex -ge 0) {
            $startIndex += $startTag.Length
            $afterSuccess = $flatResponse.Substring($startIndex)
            
            if ($afterSuccess.StartsWith("[],") -or $afterSuccess.StartsWith("[]{}")) {
                return @()
            }

            $endIndex = $afterSuccess.IndexOf(',{attributesInCriteria')
            if ($endIndex -lt 0) {
                $endIndex = $afterSuccess.IndexOf(']);')
            }
            
            if ($endIndex -gt 0) {
                $jsonPayload = $afterSuccess.Substring(0, $endIndex).Trim()
                $jsonArrayString = [Regex]::Replace($jsonPayload, '([{,]\s*)([a-zA-Z0-9_]+)\s*:', '$1"$2":')
                $jsonArrayString = [Regex]::Replace($jsonArrayString, 'new Date\((\d+)\)', '"$1"')
                
                try {
                    $records = $jsonArrayString | ConvertFrom-Json
                    if ($records) { return @($records) }
                }
                catch {
                    Write-Error "Failed to parse JSON Payload"
                }
            }
        }
    }
    catch {
        Write-Error "Failed to retrieve Access Tracker log chunk: $_"
    }
    return @()
}
