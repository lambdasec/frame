from safestring import mark_safe
ALLOWED = {"alice", "bob"}
def profile(name):                  # fixed: reject anything not on the allowlist
    if name not in ALLOWED:
        return "unknown user"       # attacker data never reaches the HTML-marking sink
    html = "<h1>Hello " + name + "</h1>"
    return mark_safe(html)
