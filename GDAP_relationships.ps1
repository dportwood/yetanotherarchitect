<#
.SYNOPSIS
  Export GDAP / Delegated Admin Relationships + Role Mappings for Partner Tenant.

.DESCRIPTION
  Connects to Microsoft Graph in the partner tenant, retrieves all active delegated admin relationships,
  then for each relationship retrieves the access assignments (group → roles) and resolves role names,
  then optionally retrieves group member names, and finally exports results to CSV.

.PARAMETER ExportPath
  File path where to write the CSV (defaults below).

.NOTES
  You may need to install the Microsoft.Graph PowerShell module and sign in with appropriate permissions:
    Install-Module Microsoft.Graph -Scope CurrentUser
    Connect-MgGraph -Scopes @("DelegatedAdminRelationship.Read.All","Directory.Read.All","RoleManagement.Read.Directory")
#>

# === PARAMETERS / CONFIGURATION ===
$ExportPath = "C:\Temp\GDAP_RoleMappings.csv"
$IncludeGroupMembers = $true     # Set to $false if you don’t want to enumerate group members
$VerboseLog = $true              # Write verbose output

# === CONNECT TO GRAPH ===
if (-not (Get-MgContext)) {
    Write-Host "Connecting to Microsoft Graph…" -ForegroundColor Cyan
    Connect-MgGraph -Scopes @("DelegatedAdminRelationship.Read.All","Directory.Read.All","RoleManagement.Read.Directory") | Out-Null
}

# === LOAD ALL ROLE DEFINITIONS FOR LOOKUP ===
Write-Host "Retrieving role definitions for lookup…" -ForegroundColor Cyan
$roleDefs = Get-MgRoleManagementDirectoryRoleDefinition -All
# Create a dictionary: RoleDefinitionId → DisplayName
$roleDefMap = @{}
foreach ($rd in $roleDefs) {
    # Some roles may not have DisplayName property populated; fallback to Id if missing
    $roleDefMap[$rd.Id] = if ($rd.DisplayName) { $rd.DisplayName } else { $rd.Id }
}

# === RETRIEVE ALL GDAP RELATIONSHIPS ===
Write-Host "Retrieving delegated admin relationships…" -ForegroundColor Cyan
$relList = Get-MgTenantRelationshipDelegatedAdminRelationship -All | Where-Object { $_.status -eq "active" }

$results = @()

foreach ($rel in $relList) {
    Write-Host "Processing relationship: $($rel.displayName) (ID: $($rel.id))" -ForegroundColor Yellow

    # Retrieve assignments for this relationship
    $uri = "https://graph.microsoft.com/v1.0/tenantRelationships/delegatedAdminRelationships/$($rel.id)/accessAssignments"
    $assignments = Invoke-MgGraphRequest -Method GET -Uri $uri | Select-Object -ExpandProperty value

    foreach ($asgn in $assignments) {
        # Basic properties
        $custTenantId   = $rel.customer.tenantId
        $custName       = $rel.customer.displayName
        $assignId       = $asgn.id
        $status         = $asgn.status
        $created        = $asgn.createdDateTime
        $modified       = $asgn.lastModifiedDateTime
        $groupId        = $asgn.accessContainer.accessContainerId
        $groupType      = $asgn.accessContainer.accessContainerType

        # Optionally get group name
        try {
            $groupObj = Get-MgGroup -GroupId $groupId -ErrorAction Stop
            $groupName = $groupObj.DisplayName
        }
        catch {
            $groupName = "<Unable to resolve group name>"
        }

        # Loop each roleDefinitionId in this assignment
        foreach ($role in $asgn.accessDetails.unifiedRoles) {
            $roleDefId = $role.roleDefinitionId
            $roleName  = if ($roleDefMap.ContainsKey($roleDefId)) { $roleDefMap[$roleDefId] } else { $roleDefId }

            # Build base result object
            $obj = [pscustomobject]@{
                CustomerTenantId     = $custTenantId
                CustomerName         = $custName
                RelationshipId       = $rel.id
                RelationshipName     = $rel.displayName
                AssignmentId         = $assignId
                Status               = $status
                CreatedDateTime      = $created
                LastModifiedDateTime = $modified
                SecurityGroupId      = $groupId
                SecurityGroupName    = $groupName
                SecurityGroupType    = $groupType
                RoleDefinitionId     = $roleDefId
                RoleName             = $roleName
            }

            # Optionally, enumerate group members
            if ($IncludeGroupMembers -and $groupType -eq "securityGroup") {
                try {
                    $members = Get-MgGroupMember -GroupId $groupId -All
                    $memberNames = $members | ForEach-Object { $_.DisplayName } | Sort-Object
                    # Join into single string (or you could create one-row-per-member)
                    $obj | Add-Member -MemberType NoteProperty -Name "GroupMembers" -Value ($memberNames -join "; ")
                }
                catch {
                    $obj | Add-Member -MemberType NoteProperty -Name "GroupMembers" -Value "<Unable to enumerate members>"
                }
            }
            else {
                $obj | Add-Member -MemberType NoteProperty -Name "GroupMembers" -Value ""
            }

            # Add to results
            $results += $obj
        } # end foreach role
    } # end foreach assignment
} # end foreach relationship

# === EXPORT TO CSV ===
Write-Host "Exporting results to CSV: $ExportPath" -ForegroundColor Cyan
$results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8

Write-Host "Export complete. File saved to: $ExportPath" -ForegroundColor Green


