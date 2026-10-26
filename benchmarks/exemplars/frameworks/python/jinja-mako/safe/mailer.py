from jinja2 import Environment

_env = Environment(autoescape=True)


def render_body(subject):
    template = _env.from_string("Dear {{ name }}, re: {{ subject }}")
    return template.render(name="customer", subject=subject)
