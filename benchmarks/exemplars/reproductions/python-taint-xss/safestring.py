def mark_safe(s):                   # vulnerable sink: marks raw HTML as safe (no escaping)
    return s
