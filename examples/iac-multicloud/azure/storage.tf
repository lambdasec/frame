resource "azurerm_storage_account" "assets" {
  name                     = "assets"
  resource_group_name      = "web"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

# Public only if the account allows it, and the account leaves that setting out: its default
# changed between provider releases, so the answer depends on which release runs.
resource "azurerm_storage_container" "images" {
  name                  = "images"
  storage_account_id    = azurerm_storage_account.assets.id
  container_access_type = "blob"
}
