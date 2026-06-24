function Connect-ClearPass {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [pscredential]$Credential
    )

    Begin {
        if ([System.Net.ServicePointManager]::SecurityProtocol -notmatch 'Tls12') {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        }
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }

    Process {
        if (-not $Credential) {
            $Credential = Get-Credential -Message "Please enter your ClearPass credentials."
        }

        $baseUrl = "https://$Server"
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0"

        try {
            Write-Verbose "Fetching login page to acquire initial session and CSRF token..."
            $loginUrl = "$baseUrl/tips/tipsLogin.action"
            $loginPage = Invoke-WebRequest -Uri $loginUrl -Method Get -WebSession $session -UserAgent $userAgent -UseBasicParsing -ErrorAction Stop
            
            $csrfToken = $null
            if ($loginPage.Content -match 'name="token"\s+value="([^"]+)"' -or $loginPage.Content -match 'value="([^"]+)"\s+name="token"') {
                $csrfToken = $matches[1]
            } else {
                Write-Error "Failed to extract CSRF token from login page."
                return
            }

            Write-Verbose "Authenticating to ClearPass Tips System..."
            $loginSubmitUrl = "$baseUrl/tips/tipsLoginSubmit.action"
            $username = $Credential.UserName
            $password = $Credential.GetNetworkCredential().Password
            $encodedUsername = [uri]::EscapeDataString($username)
            $encodedPassword = [uri]::EscapeDataString($password)
            $loginSubmitBody = "struts.token.name=token&token=$csrfToken&username=$encodedUsername&F_password=0&password=$encodedPassword&next="

            $loginResponse = Invoke-WebRequest -Uri $loginSubmitUrl -Method Post -Body $loginSubmitBody -ContentType "application/x-www-form-urlencoded" -WebSession $session -UserAgent $userAgent -Headers @{"Referer"=$loginUrl;"Origin"=$baseUrl;"Upgrade-Insecure-Requests"="1"} -UseBasicParsing -ErrorAction Stop

            Write-Verbose "Initializing DWR session dynamically to harvest DWRSESSIONID telemetry..."
            $generateIdBody = "callCount=1`nc0-scriptName=__System`nc0-methodName=generateId`nc0-id=0`nbatchId=0`ninstanceId=0`npage=%2Ftips%2FtipsContent.action`nscriptSessionId="
            $dwrResponse = Invoke-RestMethod -Uri "$baseUrl/tips/dwr/call/plaincall/__System.generateId.dwr" -Method Post -Body $generateIdBody -WebSession $session -UserAgent $userAgent -ErrorAction Stop

            $dwrSessionId = $null
            if ($dwrResponse -match 'handleCallback\([^,]*,[^,]*,[\x27"]([^"^\x27]+)[\x27"]\)') {
                $dwrSessionId = $matches[1]
                Write-Verbose "DWR ScriptSessionId [$dwrSessionId] successfully spawned."
                $syntheticDwrCookie = New-Object System.Net.Cookie("DWRSESSIONID", $dwrSessionId, "/", $Server)
                $session.Cookies.Add($syntheticDwrCookie)
            }

            Write-Verbose "Executing Single-Sign-On into ClearPass Guest Mac List Tracking array natively..."
            $guestLoginUrl = "$baseUrl/guest/mac_list.php"
            $guestLoginPage = Invoke-WebRequest -Uri $guestLoginUrl -Method Get -WebSession $session -UserAgent $userAgent -UseBasicParsing -ErrorAction Ignore
            
            $sajaxToken = $null
            if ($guestLoginPage.Content -match 'sajax_csrf_token\s*=\s*[\"''\x27]([a-f0-9]{32,40})[\"''\x27]') {
                $sajaxToken = $matches[1]
                Write-Verbose "Successfully extracted Guest CSRF anti-forgery token from transparent SSO payload natively."
            } else {
                Write-Warning "SSO failed! Extracting manual MAC tracking parameters dynamically..."
                $guestPayloadDict = @{}
                $inputs = [regex]::Matches($guestLoginPage.Content, '<input[^>]*type="hidden"[^>]*>')
                foreach ($input in $inputs) {
                    $name = $null; $value = ""
                    if ($input.Value -match 'name="([^"]+)"') { $name = $matches[1] }
                    if ($input.Value -match 'value="([^"]*)"') { $value = $matches[1] }
                    if ($name) { $guestPayloadDict[$name] = $value }
                }

                $guestLoginPairs = @()
                foreach ($key in $guestPayloadDict.Keys) {
                    $safeVal = $guestPayloadDict[$key]
                    if ($key -eq "target") { $safeVal = "/guest/mac_list.php" }
                    if ($null -eq $safeVal) { $safeVal = "" }
                    $guestLoginPairs += "$([uri]::EscapeDataString($key))=$([uri]::EscapeDataString($safeVal))"
                }
                $guestLoginPairs += "username=$encodedUsername"
                $guestLoginPairs += "F_password=0"
                $guestLoginPairs += "password=$encodedPassword"
                $guestLoginBody = $guestLoginPairs -join "&"

                $guestAuthResponse = Invoke-WebRequest -Uri "$baseUrl/guest/auth_login.php" -Method Post -Headers @{"Referer"=$guestLoginUrl;"Origin"=$baseUrl;"Cache-Control"="no-cache";"Pragma"="no-cache"} -Body $guestLoginBody -ContentType "application/x-www-form-urlencoded" -WebSession $session -UserAgent $userAgent -UseBasicParsing -ErrorAction Ignore
                if ($guestAuthResponse.Content -match 'sajax_csrf_token\s*=\s*[\"''\x27]([a-f0-9]{32,40})[\"''\x27]') {
                    $sajaxToken = $matches[1]
                }
            }

            $scriptSessionId = "$dwrSessionId/" + (-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 17 | ForEach-Object { [char]$_ }))
            
            $global:PSClearPassSession = [PSCustomObject]@{
                Server          = $Server
                WebSession      = $session
                ScriptSessionId = $scriptSessionId
                GuestCsrfToken  = $sajaxToken
                ConnectedAt     = Get-Date
                Username        = $username
            }

            Write-Host "Successfully connected to ClearPass internal API on $Server as $($username)." -ForegroundColor Green
        } catch {
            Write-Error "Connection failed: $_"
        }
    }
}
