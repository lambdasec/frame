import yaml
def parse_config(raw):
    return yaml.load(raw)          # CWE-502: yaml.load (real PyYAML) on attacker data
