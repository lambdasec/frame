"""Azure and Google Cloud Terraform packs (packs/data/terraform/azure.toml, google.toml) and the
policy language's `in_ports`. Each policy is checked against its nearest safe configuration: a
rule from a private range, a Deny ahead of the Allow, a container in an account that forbids
public access, a bucket that enforces public access prevention."""

import pytest

from frame.iac.policy import PolicyError, parse
from frame.iac.scan import scan


def _rules(tmp_path, text):
    (tmp_path / "main.tf").write_text(text)
    run = scan(tmp_path)
    return sorted((f.rule, f.resource) for f in run.findings)


def _nsg(*rules):
    body = "".join(f'''
  security_rule {{
    name = "r{i}"
    {r}
  }}''' for i, r in enumerate(rules))
    return f'resource "azurerm_network_security_group" "g" {{\n  name = "g"\n  resource_group_name = "rg"\n{body}\n}}\n'


ALLOW_SSH = ('priority = 200\n    direction = "Inbound"\n    access = "Allow"\n    protocol = "Tcp"\n'
             '    source_port_range = "*"\n    destination_port_range = "22"\n'
             '    source_address_prefix = "{src}"\n    destination_address_prefix = "*"')
DENY_SSH = ('priority = 100\n    direction = "Inbound"\n    access = "Deny"\n    protocol = "*"\n'
            '    source_port_range = "*"\n    destination_port_range = "{port}"\n'
            '    source_address_prefix = "*"\n    destination_address_prefix = "*"')


@pytest.mark.parametrize("rules, found", [
    ([ALLOW_SSH.format(src="*")], ["azure-nsg-admin-from-internet"]),
    ([ALLOW_SSH.format(src="Internet")], ["azure-nsg-admin-from-internet"]),
    ([ALLOW_SSH.format(src="8.8.8.0/24")], ["azure-nsg-admin-from-internet"]),       # a public range
    ([ALLOW_SSH.format(src="203.0.113.0/24")], []),                                # TEST-NET-3: never on the internet
    ([ALLOW_SSH.format(src="10.0.0.0/8")], []),
    ([ALLOW_SSH.format(src="VirtualNetwork")], []),
    ([ALLOW_SSH.format(src="*"), DENY_SSH.format(port="20-30")], []),               # denied first
    ([ALLOW_SSH.format(src="*"), DENY_SSH.format(port="443")], ["azure-nsg-admin-from-internet"]),
    ([ALLOW_SSH.format(src="*").replace('"22"', '"1000-2000"')], []),
    ([ALLOW_SSH.format(src="*").replace('"22"', '"*"')], ["azure-nsg-all-from-internet"]),
])
def test_azure_network_security_groups(tmp_path, rules, found):
    assert [r for r, _ in _rules(tmp_path, _nsg(*rules))] == found


def test_azure_standalone_rules_and_their_denies(tmp_path):
    rule = '''resource "azurerm_network_security_rule" "{n}" {{
  name = "{n}"
  resource_group_name = "rg"
  network_security_group_name = "{g}"
  {body}
}}
'''
    allow = rule.format(n="ssh", g="g", body=ALLOW_SSH.format(src="*").replace("\n    ", "\n  "))
    deny_same = rule.format(n="deny", g="g", body=DENY_SSH.format(port="22").replace("\n    ", "\n  "))
    deny_other = rule.format(n="deny", g="other", body=DENY_SSH.format(port="22").replace("\n    ", "\n  "))
    assert _rules(tmp_path, allow) == [("azure-nsg-admin-from-internet", "azurerm_network_security_rule.ssh")]
    assert _rules(tmp_path, allow + deny_same) == []
    assert _rules(tmp_path, allow + deny_other) == [("azure-nsg-admin-from-internet", "azurerm_network_security_rule.ssh")]


@pytest.mark.parametrize("text, found", [
    ('resource "azurerm_mssql_firewall_rule" "f" {\n  name = "f"\n  server_id = "s"\n'
     '  start_ip_address = "0.0.0.0"\n  end_ip_address = "255.255.255.255"\n}\n', ["azure-db-firewall-internet"]),
    ('resource "azurerm_mssql_firewall_rule" "f" {\n  name = "f"\n  server_id = "s"\n'
     '  start_ip_address = "0.0.0.0"\n  end_ip_address = "0.0.0.0"\n}\n', []),         # Azure services only
    ('resource "azurerm_redis_firewall_rule" "f" {\n  name = "f"\n  redis_cache_name = "c"\n  resource_group_name = "rg"\n'
     '  start_ip = "0.0.0.0"\n  end_ip = "255.255.255.255"\n}\n', ["azure-db-firewall-internet"]),
    ('resource "azurerm_storage_account" "a" {\n  name = "a"\n  allow_nested_items_to_be_public = true\n}\n'
     'resource "azurerm_storage_container" "c" {\n  name = "c"\n  storage_account_id = azurerm_storage_account.a.id\n'
     '  container_access_type = "blob"\n}\n', ["azure-storage-container-public"]),
    ('resource "azurerm_storage_account" "a" {\n  name = "a"\n  allow_nested_items_to_be_public = false\n}\n'   # forbidden
     'resource "azurerm_storage_container" "c" {\n  name = "c"\n  storage_account_id = azurerm_storage_account.a.id\n'
     '  container_access_type = "blob"\n}\n', []),
    ('resource "azurerm_storage_account" "a" {\n  name = "a"\n  https_traffic_only_enabled = false\n}\n', ["azure-storage-http"]),
    ('resource "azurerm_storage_account" "a" {\n  name = "a"\n}\n', []),
    ('resource "azurerm_role_definition" "r" {\n  name = "r"\n  scope = "/subscriptions/x"\n'
     '  permissions {\n    actions = ["*"]\n  }\n}\n', ["azure-custom-role-all-actions"]),
    ('resource "azurerm_role_definition" "r" {\n  name = "r"\n  scope = "/subscriptions/x"\n'
     '  permissions {\n    actions = ["Microsoft.Storage/*/read"]\n  }\n}\n', []),
])
def test_azure_databases_storage_and_roles(tmp_path, text, found):
    assert [r for r, _ in _rules(tmp_path, text)] == found


def _fw(name, kind, ports, ranges='["0.0.0.0/0"]', extra=""):
    ports_line = f"\n    ports = {ports}" if ports is not None else ""
    return (f'resource "google_compute_firewall" "{name}" {{\n  name = "{name}"\n  network = "vpc"\n{extra}'
            f'  source_ranges = {ranges}\n  {kind} {{\n    protocol = "tcp"{ports_line}\n  }}\n}}\n')


@pytest.mark.parametrize("text, found", [
    (_fw("ssh", "allow", '["22"]'), ["gcp-firewall-admin-from-internet"]),
    (_fw("ssh", "allow", '["20-30"]'), ["gcp-firewall-admin-from-internet"]),
    (_fw("ssh", "allow", '["22"]', ranges='["10.0.0.0/8"]'), []),
    (_fw("ssh", "allow", '["443"]'), []),
    (_fw("ssh", "allow", None), ["gcp-firewall-all-from-internet"]),                   # no ports: every port
    (_fw("ssh", "allow", '["22"]', extra="  disabled = true\n"), []),
    (_fw("ssh", "allow", '["22"]', extra="  direction = \"EGRESS\"\n  destination_ranges = [\"0.0.0.0/0\"]\n"), []),
    (_fw("ssh", "allow", '["22"]') + _fw("deny", "deny", '["22"]', extra="  priority = 900\n"), []),
    (_fw("ssh", "allow", '["22"]') + _fw("deny", "deny", '["22"]', extra="  priority = 1100\n"),
     ["gcp-firewall-admin-from-internet"]),                                             # the deny comes later
    (_fw("ssh", "allow", '["22"]') + _fw("deny", "deny", '["22"]', extra="  target_tags = [\"db\"]\n"),
     ["gcp-firewall-admin-from-internet"]),                                             # a deny for some instances
])
def test_gcp_firewall_rules(tmp_path, text, found):
    assert [r for r, _ in _rules(tmp_path, text)] == found


SQL = '''resource "google_sql_database_instance" "db" {{
  name = "db"
  database_version = "POSTGRES_15"
  settings {{
    tier = "db-f1-micro"
    ip_configuration {{
      {ipv4}
      authorized_networks {{
        name  = "n"
        value = "{cidr}"
      }}
    }}
  }}
}}
'''
BUCKET = 'resource "google_storage_bucket" "b" {{\n  name = "b"\n  location = "US"\n{pap}}}\n'
MEMBER = ('resource "google_storage_bucket_iam_member" "m" {\n  bucket = google_storage_bucket.b.name\n'
          '  role = "roles/storage.objectViewer"\n  member = "allUsers"\n}\n')


@pytest.mark.parametrize("text, found", [
    (SQL.format(ipv4="", cidr="0.0.0.0/0"), ["gcp-sql-public-network"]),               # ipv4_enabled defaults to true
    (SQL.format(ipv4="ipv4_enabled = false\n      private_network = \"vpc\"", cidr="0.0.0.0/0"), []),
    (SQL.format(ipv4="", cidr="203.0.113.7/32"), []),
    (BUCKET.format(pap="") + MEMBER, ["gcp-bucket-public"]),
    (BUCKET.format(pap='  public_access_prevention = "enforced"\n') + MEMBER, []),
    (BUCKET.format(pap="") + MEMBER.replace("allUsers", "user:jane@example.com"), []),
])
def test_gcp_sql_and_buckets(tmp_path, text, found):
    assert [r for r, _ in _rules(tmp_path, text)] == found


def test_in_ports_parses_and_rejects_a_non_number():
    parse('in_ports(r.destination_port_range, 22)')
    with pytest.raises(PolicyError):
        parse('in_ports(r.destination_port_range, "22")')


def test_a_default_that_changed_between_provider_releases_is_undecided(tmp_path):
    """allow_nested_items_to_be_public: true in provider 3.117 / 4.0, false now (terraform-facts.toml)."""
    (tmp_path / "main.tf").write_text(
        'resource "azurerm_storage_account" "a" {\n  name = "a"\n}\n'
        'resource "azurerm_storage_container" "c" {\n  name = "c"\n  storage_account_id = azurerm_storage_account.a.id\n'
        '  container_access_type = "container"\n}\n')
    run = scan(tmp_path)
    assert run.findings == []
    assert [u["rule"] for u in run.undecided] == ["azure-storage-container-public"]
    assert run.undecided[0]["depends_on"][0].startswith("azurerm_storage_account.a.allow_nested_items_to_be_public (left out")


def test_the_2x_spelling_of_public_blob_access(tmp_path):
    assert [r for r, _ in _rules(tmp_path,
            'resource "azurerm_storage_account" "a" {\n  name = "a"\n  allow_blob_public_access = true\n}\n'
            'resource "azurerm_storage_container" "c" {\n  name = "c"\n  storage_account_name = azurerm_storage_account.a.name\n'
            '  container_access_type = "blob"\n}\n')] == ["azure-storage-container-public"]


def test_azure_rule_values_in_any_case(tmp_path):
    """Provider 2.x reads protocol / direction / access in any case (TerraGoat writes "TCP")."""
    rule = ALLOW_SSH.format(src="*").replace('"Tcp"', '"TCP"').replace('"Inbound"', '"inbound"')
    assert [r for r, _ in _rules(tmp_path, _nsg(rule))] == ["azure-nsg-admin-from-internet"]
