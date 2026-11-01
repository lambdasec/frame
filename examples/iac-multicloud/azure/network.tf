resource "azurerm_network_security_group" "bastion" {
  name                = "bastion"
  resource_group_name = "ops"
  location            = "westeurope"

  security_rule {
    name                       = "ssh"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}

# The same Allow, behind a Deny that comes first: SSH is closed.
resource "azurerm_network_security_group" "jump" {
  name                = "jump"
  resource_group_name = "ops"
  location            = "westeurope"

  security_rule {
    name                       = "deny-admin"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "20-3400"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "ssh"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_mssql_firewall_rule" "everyone" {
  name             = "everyone"
  server_id        = "orders-sql"
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}
