import pickle
def load_session(blob):
    # CWE-502: deserializing attacker-controlled data with the real stdlib pickle
    return pickle.loads(blob)
