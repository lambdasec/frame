from jinja2 import Environment

_env = Environment()


def render_body(template_text):
    template = _env.from_string(template_text)  # frame-expect: CWE-1336
    return template.render(name="customer")
