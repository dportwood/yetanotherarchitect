Import-Module ActiveDirectory

# 1. Get on-premises AD user object-GUID
$userUPN = "user@domain.com"
$adUser = Get-ADUser -Identity $userUPN -Properties objectGUID

if (-not $adUser) {
    Write-Error "On-prem user not found for UPN $userUPN"
    return
}

$guidBytes = $adUser.objectGUID.ToByteArray()
$immutableId = [Convert]::ToBase64String($guidBytes)
Write-Host "Calculated immutable ID for $userUPN: $immutableId"

# 2. Connect to Graph / Entra ID
Import-Module Microsoft.Graph.Users # or Microsoft.Graph depending on version
Connect-MgGraph -Scopes "User.ReadWrite.All"

# 3. Find the cloud user
$cloudUser = Get-MgUser -Filter "userPrincipalName eq '$userUPN'" -Property OnPremisesImmutableId,Id

if (-not $cloudUser) {
    Write-Error "Cloud user not found for UPN $userUPN"
    return
}

# 4. Compare and update if needed
if ($cloudUser.OnPremisesImmutableId -ne $immutableId) {
    Write-Host "Updating cloud user $userUPN with OnPremisesImmutableId = $immutableId"
    Update-MgUser -UserId $cloudUser -OnPremisesImmutableId $immutableId
}
else {
    Write-Host "Cloud user already has matching OnPremisesImmutableId"
}

# 5. (Optional) Force a sync of your sync engine (if you’re using e.g. Entra Connect)
# On your sync server:
Start-ADSyncSyncCycle -PolicyType Delta
