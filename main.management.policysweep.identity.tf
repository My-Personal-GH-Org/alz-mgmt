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
  subject             = "repo:My-Personal-GH-Org@313274884/alz-mgmt@1324688550:environment:alz-mgmt-policy-sweep:job_workflow_ref:My-Personal-GH-Org/alz-mgmt/.github/workflows/10-policy-remediation-sweep.yaml@refs/heads/main"
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
}

output "policysweep_identity_client_id" {
  value       = azurerm_user_assigned_identity.policysweep.client_id
  description = "Set this as AZURE_CLIENT_ID on the alz-mgmt-policy-sweep GitHub environment."
}
