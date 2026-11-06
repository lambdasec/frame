from safestring import mark_safe
def profile(name):                  # entry point
    html = "<h1>Hello " + name + "</h1>"
    return mark_safe(html)          # attacker data reaches the HTML-marking sink unescaped
