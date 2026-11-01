# Azure and Google Cloud in Terraform

Two root modules: `azure/` (a network security group open for SSH and one whose Deny comes first,
a database firewall rule, a blob container) and `gcp/` (firewall rules in two networks, a Cloud SQL
instance, two buckets granted to `allUsers`). Each risky resource sits beside its nearest safe one,
so the output shows what the rule order, the provider's defaults and the cloud's own overrides
decide.

```console
$ frame iac .
azure/network.tf:14: [high] azure-nsg-admin-from-internet (CWE-284) azurerm_network_security_group.bastion: Network security group lets the internet reach SSH or RDP [security_rule[0].source_address_prefix]
azure/network.tf:53: [high] azure-db-firewall-internet (CWE-284) azurerm_mssql_firewall_rule.everyone: Database firewall rule admits every IPv4 address [start_ip_address]
gcp/main.tf:7: [high] gcp-firewall-admin-from-internet (CWE-284) google_compute_firewall.admin: Firewall rule lets the internet reach SSH or RDP [allow[0].ports[0]]
gcp/main.tf:40: [high] gcp-sql-public-network (CWE-284) google_sql_database_instance.orders: Cloud SQL instance accepts connections from the internet [settings[0].ip_configuration[0].authorized_networks[0].value]
gcp/main.tf:54: [high] gcp-bucket-public (CWE-732) google_storage_bucket_iam_member.downloads_public: Cloud Storage bucket is granted to everyone on the internet [member]

Infrastructure: 13 resource(s) in terraform: 3 file(s); 5 finding(s), 1 undecided (depend on values the files do not give)
undecided: azure/storage.tf:14 azure-storage-container-public azurerm_storage_container.images (depends on azurerm_storage_account.assets.allow_nested_items_to_be_public (left out; its..., azurerm_storage_account.assets.id)
```

## Azure

- `bastion` allows TCP 22 from the `Internet` service tag, "the IP address space that's outside the virtual network and reachable by the public internet": reported.
- `jump` has the same Allow, but a Deny with a lower priority number covers ports 20-3400 from every address. Azure applies rules in priority order and stops at the first match, so SSH never reaches the Allow: no finding.
- `everyone` admits 0.0.0.0 to 255.255.255.255, every IPv4 address (0.0.0.0 to 0.0.0.0 would be Azure's "Allow access to Azure services", which is not reported).
- `images` asks for anonymous blob reads. That takes effect only if its account allows nested items to be public, and the account leaves `allow_nested_items_to_be_public` out. The provider's default for it changed between releases (`true` in 3.117 and 4.0, `false` now), so whether the container is public depends on which provider release applies it: undecided, not a finding and not a pass. Set it to `false` and the question goes away; set it to `true` and it is a finding.

## Google Cloud

- `admin` allows TCP 22 and 3389 from 0.0.0.0/0 on `prod`: reported (once, for the resource).
- `staging_rdp` allows RDP the same way, but `staging_deny` denies TCP from 0.0.0.0/0 at priority 900, ahead of the allow's default 1000, for every instance in that network: no finding. (A deny limited by `target_tags` would not count: it covers only some instances.)
- `orders` authorizes 0.0.0.0/0, and `ipv4_enabled`, left out, is `true` in the provider's schema, so the instance has a public address that accepts anyone: reported.
- `downloads_public` grants `allUsers` ("anyone who is on the internet") read access: reported. `reports_public` makes the same grant on a bucket with `public_access_prevention = "enforced"`, which overrides grants to `allUsers`: no finding.

The policies are `frame/sil/packs/data/terraform/azure.toml` and `google.toml`; [docs/iac.md](../../docs/iac.md#azure-and-google-cloud) lists them with their sources.
