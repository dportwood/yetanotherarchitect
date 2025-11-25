# Pre-req: Connect to Graph in partner tenant context
Connect-MgGraph -Scopes "RoleManagement.ReadDirectory.All","TenantRelationships.Read.All"

# Get all GDAP relationships (delegated admin relationships)
$relationships = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/tenantRelationships/delegatedAdminRelationships"

$relList = $relationships.value | ForEach-Object {
    [pscustomobject]@{
        CustomerId       = $_.customerId
        DisplayName      = $_.displayName
        RelationshipId   = $_.id
        Status           = $_.status
        StartDate        = $_.startDateTime
        EndDate          = $_.endDateTime
        AutoExtend       = $_.autoRenew
    }
}

# For each relationship, get access assignments (which roles/groups)
foreach ($rel in $relList) {
    $assignments = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/tenantRelationships/delegatedAdminRelationships/$($rel.RelationshipId)/accessAssignments?`$expand=principal,roleDefinition"
    foreach ($asgn in $assignments.value) {
        [pscustomobject]@{
            CustomerId     = $rel.CustomerId
            RelationshipId = $rel.RelationshipId
            RoleName       = $asgn.roleDefinition.displayName
            RoleId         = $asgn.roleDefinition.id
            PrincipalName  = $asgn.principal.displayName
            PrincipalType  = $asgn.principal.@odata.type
            AssignmentId   = $asgn.id
        }
    }
}

# Export to CSV for documentation
$relList | Export-Csv -Path "GDAP_Relationships.csv" -NoTypeInformation
