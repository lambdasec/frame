# stand-in for PyYAML: load() is the unsafe deserializer (CWE-502)
def load(stream):
    return {"parsed": str(stream)}
