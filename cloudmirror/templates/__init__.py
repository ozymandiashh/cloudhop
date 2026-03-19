"""Simple template engine using str.replace for {{variable}} substitution."""
import os

_TEMPLATE_DIR = os.path.dirname(__file__)
_CACHE = {}

def render(template_name: str, **kwargs) -> str:
    """Load and render a template with variable substitution."""
    if template_name not in _CACHE:
        path = os.path.join(_TEMPLATE_DIR, template_name)
        with open(path, 'r') as f:
            _CACHE[template_name] = f.read()

    html = _CACHE[template_name]
    for key, value in kwargs.items():
        html = html.replace('{{' + key + '}}', str(value))
    return html
