# Install Microsoft Graph modules if not already installed
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Force
Install-Module Microsoft.Graph -Scope CurrentUser -Force

# Connect to Microsoft Graph
$Scopes = @(
    "Policy.ReadWrite.ApplicationConfiguration",
    "Policy.Read.All",
    "Application.Read.All",
    "Application.ReadWrite.All"
)
Connect-MgGraph -Scopes $Scopes

# create the policy definition
$policyDefinition = @(
'{
  "ClaimsMappingPolicy": {
    "Version": 1,
    "IncludeBasicClaimSet": true,
    "ClaimsSchema": [
      {
        "Source": "transformation",
        "ID": "EmailUat",
        "TransformationId": "RegexReplaceTransform",
        "SamlClaimType": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
      }
    ],
    "ClaimsTransformations": [
      {
        "ID": "RegexReplaceTransform",
        "TransformationMethod": "RegexReplace",
        "InputClaims": [
          {
            "ClaimTypeReferenceId": "emailaddress",
            "TransformationClaimType": "sourceClaim"
          }
        ],
        "InputParameters": [
          {
            "ID": "regex",
            "Value": "^(?<full>.+@.+)$"
          },
          {
            "ID": "replacement",
            "Value": "${full}.uat"
          }
        ],
        "OutputClaims": [
          {
            "ClaimTypeReferenceId": "EmailUat",
            "TransformationClaimType": "outputClaim"
          }
        ]
      }
    ]
  }
}'
)

# Create the Claims Mapping Policy
$policy = New-MgPolicyClaimMappingPolicy -Definition $policyDefinition -DisplayName "AppendDomainUat"

# Find your Enterprise App’s Service Principal
$appName = "Salesforce Sandbox"
$sp = Get-MgServicePrincipal -Filter "displayName eq '$appName'"

# Assign the policy
New-MgServicePrincipalClaimMappingPolicyByRef -ServicePrincipalId $sp.Id -BodyParameter @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/policies/claimsMappingPolicies/$($policy.Id)"
}

