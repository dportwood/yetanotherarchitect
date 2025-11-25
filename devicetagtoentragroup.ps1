# Parameters - set these before running
$TenantId      = "<YOUR_TENANT_ID>"
$ClientId      = "<YOUR_CLIENT_ID>"        # App registration with both Defender API & Graph permissions (or two apps & two creds)
$ClientSecret  = "<YOUR_CLIENT_SECRET>"
$DefenderTag   = "myTagName"               # Defender device tag to search for
$EntraGroupId  = "<TARGET_ENTRA_GROUP_ID>" # Group (security or M365) to add devices into
$DefenderApi   = "https://api.security.microsoft.com"  # or regional endpoint if needed (see MDE docs)
$GraphScope    = "https://graph.microsoft.com/.default"
$DefenderScope = "https://api.security.microsoft.com/.default"

# Helper: get OAuth token (client credentials)
function Get-OAuthToken {
    param($Tenant, $ClientId, $ClientSecret, $Scope)
    $body = @{
        client_id     = $ClientId
        scope         = $Scope
        client_secret = $ClientSecret
        grant_type    = "client_credentials"
    }
    $tokenResp = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -Body $body
    return $tokenResp.access_token
}

# 1) Get Defender token
$defenderToken = Get-OAuthToken -Tenant $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -Scope $DefenderScope
if (-not $defenderToken) { throw "Failed to obtain Defender token" }

# 2) Call Find machines by tag
$tagEncoded = [System.Web.HttpUtility]::UrlEncode($DefenderTag)
$findUri = "$DefenderApi/api/machines/findbytag?tag=$tagEncoded&useStartsWithFilter=true"
$machinesResp = Invoke-RestMethod -Method Get -Uri $findUri -Headers @{ Authorization = "Bearer $defenderToken" }

if (-not $machinesResp) {
    Write-Output "No machines returned for tag '$DefenderTag'"
    return
}

$machines = $machinesResp | Select-Object -ExpandProperty value -ErrorAction SilentlyContinue
if (-not $machines) { $machines = $machinesResp } # some endpoints return array directly

Write-Output "Found $($machines.Count) machine(s) in Defender with tag '$DefenderTag'."

# 3) Get Graph token (app-only)
$graphToken = Get-OAuthToken -Tenant $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -Scope $GraphScope
if (-not $graphToken) { throw "Failed to obtain Graph token" }

# 4) For each machine: determine Azure AD device id (fallbacks), then add to group
function Add-DeviceToGroup {
    param($deviceId, $groupId, $graphToken)

    # Build body referencing the directoryObject (device)
    $body = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/devices/$deviceId" } | ConvertTo-Json

    $uri = "https://graph.microsoft.com/v1.0/groups/$groupId/members/$ref"
    try {
        Invoke-RestMethod -Method POST -Uri $uri -Headers @{ Authorization = "Bearer $graphToken"; "Content-Type" = "application/json" } -Body $body -ErrorAction Stop
        Write-Host "Added device $deviceId to group $groupId"
    } catch {
        # If the device is already a member, Graph will return 400/409; print message and continue
        Write-Warning "Failed to add device $deviceId to group $groupId - $($_.Exception.Message)"
    }
}

foreach ($m in $machines) {

    # Try common fields (these vary by tenant / Defender API)
    # Common fields observed in Defender: machineId, deviceId, aadDeviceId, azureAdDeviceId, deviceName / computerName
    $aadDeviceId = $null
    if ($m.azureAdDeviceId) { $aadDeviceId = $m.azureAdDeviceId }
    elseif ($m.aadDeviceId) { $aadDeviceId = $m.aadDeviceId }
    elseif ($m.deviceId) { $aadDeviceId = $m.deviceId }              # sometimes this is AAD device id
    elseif ($m.machineId) { $aadDeviceId = $m.machineId }           # fallback (inspect below)
    
    # If still null, try to look up AAD device by device name using Graph
    if (-not $aadDeviceId) {
        $deviceName = $m.computerDnsName
        if (-not $deviceName) { $deviceName = $m.computerName; if (-not $deviceName) { $deviceName = $m.deviceName } }
        if ($deviceName) {
            $filter = "startswith(displayName,'$($deviceName)')"
            $lookupUri = "https://graph.microsoft.com/v1.0/devices`?\$filter=$filter&`$select=id,displayName"
            $lookupResp = Invoke-RestMethod -Method Get -Uri $lookupUri -Headers @{ Authorization = "Bearer $graphToken" } -ErrorAction SilentlyContinue
            if ($lookupResp -and $lookupResp.value.Count -ge 1) {
                # if multiple matched, attempt to pick exact match first
                $match = $lookupResp.value | Where-Object { $_.displayName -eq $deviceName } | Select-Object -First 1
                if (-not $match) { $match = $lookupResp.value[0] }
                $aadDeviceId = $match.id
                Write-Verbose "Resolved device name '$deviceName' to AAD device id $aadDeviceId"
            } else {
                Write-Warning "Could not resolve Defender machine to an AAD device for machine: $($m | ConvertTo-Json -Depth 2)"
            }
        } else {
            Write-Warning "No device identifier or name available in Defender response for machine: $($m | ConvertTo-Json -Depth 2)"
        }
    }

    if ($aadDeviceId) {
        Add-DeviceToGroup -deviceId $aadDeviceId -groupId $EntraGroupId -graphToken $graphToken
    } else {
        Write-Warning "Skipping machine because no AAD device id was found."
    }

    # Friendly throttle to respect Defender / Graph rate limits
    Start-Sleep -Milliseconds 200
}
