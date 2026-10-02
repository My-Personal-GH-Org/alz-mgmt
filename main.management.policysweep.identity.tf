# Dedicated, least-privilege identity for the nightly policy remediation sweep (Scripts/Invoke-PolicyRemediationSweep.ps1).
# Deliberately separate from the Plan/Apply UMIs - only needs Resource Policy Contributor + User Access Administrator,
# not Owner.

resource "azurerm_resource_group" "policysweep_identity" {
  name     = "rg-policysweep-identity-australiaeast"
  location = "australiaeast"
}

resource "azurerm_user_assigned_identity" "policysweep" {
  name                = "id-alzmgmt-policysweep-001"
  resource_group_name = azurerm_resource_group.policysweep_identity.name
  location            = azurerm_resource_group.policysweep_identity.location
}

resource "azurerm_federated_identity_credential" "policysweep" {
  name                = "gh-policy-sweep-dedicated"
  resource_group_name = azurerm_resource_group.policysweep_identity.name
  parent_id           = azurerm_user_assigned_identity.policysweep.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = "https://token.actions.githubusercontent.com"
  subject             = "repo:My-Personal-GH-Org@313274884/alz-mgmt@1324688550:environment:alz-mgmt-policy-sweep:job_workflow_ref:My-Personal-GH-Org/alz-mgmt/.github/workflows/10-azure-policy-sweep.yaml@refs/heads/main"
}

resource "azurerm_role_assignment" "policysweep_policy_contributor" {
  scope                = "/providers/Microsoft.Management/managementGroups/MG-AzLz-Acclrtr"
  role_definition_name = "Resource Policy Contributor"
  principal_id         = azurerm_user_assigned_identity.policysweep.principal_id
}

resource "azurerm_role_assignment" "policysweep_user_access_administrator" {
  scope                = "/providers/Microsoft.Management/managementGroups/MG-AzLz-Acclrtr"
  role_definition_name = "User Access Administrator"
  principal_id         = azurerm_user_assigned_identity.policysweep.principal_id

  # Combines Microsoft's official "Allow most roles, but don't allow others to assign roles" template
  # (blocks granting/removing Owner, RBAC Administrator or User Access Administrator) with a principal-type
  # constraint on the GRANT side (blocks "Constrain roles and principal types" template) - this identity can
  # only grant roles to Managed Identities/Service Principals (ARM's PrincipalType for both is "ServicePrincipal",
  # there's no separate "ManagedIdentity" value), never to a User or Group. Delete-side stays unrestricted by
  # principal type - it must still be able to remove ANY privileged role assignment, not just ones it granted.
  condition_version = "2.0"
  condition         = <<-EOT
    ((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAllValues:GuidNotEquals {8e3af657-a8ff-443c-a75c-2fe8c4bcb635, f58310d9-a9f6-439a-9e8d-f62e7b41a168, 18d7d88d-d35e-4fb5-a5c3-7773c20a72d9} AND @Request[Microsoft.Authorization/roleAssignments:PrincipalType] ForAnyOfAnyValues:StringEqualsIgnoreCase {'ServicePrincipal'}))
    AND
    ((!(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})) OR (@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAllValues:GuidNotEquals {8e3af657-a8ff-443c-a75c-2fe8c4bcb635, f58310d9-a9f6-439a-9e8d-f62e7b41a168, 18d7d88d-d35e-4fb5-a5c3-7773c20a72d9}))
  EOT
}

output "policysweep_identity_client_id" {
  value       = azurerm_user_assigned_identity.policysweep.client_id
  description = "Set this as AZURE_CLIENT_ID on the alz-mgmt-policy-sweep GitHub environment."
}
