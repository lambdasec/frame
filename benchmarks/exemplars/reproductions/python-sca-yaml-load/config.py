import yaml
def parse_config(raw):
    return yaml.load(raw)          # vulnerable: yaml.load on attacker data
