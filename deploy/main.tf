###### Local variables ######

locals {
  name_prefix = "test"
}

###### Data sources ######

data "azurerm_location" "this" {
  location = "eastus2"
}

data "azurerm_subscription" "this" {}

###### Foundry ######

resource "random_pet" "this" {
  length = 1
  prefix = local.name_prefix
}

resource "azurerm_resource_group" "this" {
  location = data.azurerm_location.this.location
  name     = "${random_pet.this.id}-rg"
}

resource "azurerm_cognitive_account" "this" {
  custom_subdomain_name = random_pet.this.id
  identity {
    type = "SystemAssigned"
  }
  kind                          = "AIServices"
  local_auth_enabled            = true
  location                      = azurerm_resource_group.this.location
  name                          = "${random_pet.this.id}-rg"
  project_management_enabled    = true
  public_network_access_enabled = true
  resource_group_name           = azurerm_resource_group.this.name
  sku_name                      = "S0"
}

resource "azurerm_cognitive_account_project" "this" {
  cognitive_account_id = azurerm_cognitive_account.this.id
  display_name         = "${random_pet.this.id}-project"
  identity {
    type = "SystemAssigned"
  }
  location = azurerm_resource_group.this.location
  name     = "${random_pet.this.id}-project"

}

resource "azapi_resource" "this" {
  depends_on = [azurerm_cognitive_account_project.this]

  body = {
    properties = {
      model = {
        format  = "Anthropic"
        name    = "claude-opus-5-5-fast"
        version = 2
      }
      modelProviderData = {
        countryCode      = "US"
        industry         = "other"
        organizationName = local.name_prefix
      }
    }
    sku = {
      name     = "GlobalStandard"
      capacity = 1
    }
  }
  name                      = "${random_pet.this.id}-deployment"
  parent_id                 = azurerm_cognitive_account.this.id
  schema_validation_enabled = false
  type                      = "Microsoft.CognitiveServices/accounts/deployments@2025-10-01-preview"
}

###### Outputs ######

output "resource_group_name" {
  value = azurerm_resource_group.this.name
}

output "cognitive_account_name" {
  value = azurerm_cognitive_account.this.name
}

output "cognitive_deployment_name" {
  value = "${random_pet.this.id}-deployment"
}

output "cognitive_deployment_url" {
  value = "https://${azurerm_cognitive_account.this.custom_subdomain_name}.services.ai.azure.com/anthropic"
}
