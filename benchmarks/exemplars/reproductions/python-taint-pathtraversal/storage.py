def read_file(name):
    # CWE-22: attacker-controlled path joined onto a base, no containment check
    with open("/srv/data/" + name) as f:
        return f.read()
