<#
.SYNOPSIS
  Export GDAP / Delegated Admin Relationships + Role Mappings for Partner Tenant.

.DESCRIPTION
  Connects to Microsoft Graph in the partner tenant, retrieves all active delegated admin relationships,
  then for each relationship retrieves the role assignments (security groups → roles) and exports to CSV.

.NOTES
  Modify output path, filter logic or extension to Excel/Word as needed.
#>

# PARAMETERS
$ExportPath = "C:\Temp\GDAP_RoleMappings.csv"

# Connect (if not already connected)
if (-not (Get-MgContext)) {
    Write-Host "Connecting to Microsoft Graph..."
    Connect-MgGraph -Scopes @("DelegatedAdminRelationship.Read.All","Directory.Read.All")
}

# Get all delegated admin relationships
$relList = Get-MgTenantRelationshipDelegatedAdminRelationship -All | Where-Object { $_.status -eq "active" }

$results = @()

foreach ($rel in $relList) {
    Write-Host "Processing relationship: $($rel.displayName) (ID: $($rel.id))"

    # Get access assignments for this relationship
    $assignments = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/tenantRelationships/delegatedAdminRelationships/$($rel.id)/accessAssignments?`$expand=principal,roleDefinition" |
                   Select-Object -ExpandProperty value

    foreach ($asgn in $assignments) {
        $results += [pscustomobject]@{
            CustomerTenantId   = $rel.customer.tenantId
            CustomerName       = $rel.customer.displayName
            RelationshipName   = $rel.displayName
            RelationshipId     = $rel.id
            RoleName           = $asgn.roleDefinition.displayName
            RoleId             = $asgn.roleDefinition.id
            SecurityGroupName  = $asgn.principal.displayName
            SecurityGroupId    = $asgn.principal.id
            AssignmentId       = $asgn.id
            Status             = $asgn.status
            CreatedDateTime    = $asgn.createdDateTime
            LastModifiedDateTime = $asgn.lastModifiedDateTime
        }
    }
}

# Export results
$results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8

Write-Host "Export complete. File saved to: $ExportPath"

