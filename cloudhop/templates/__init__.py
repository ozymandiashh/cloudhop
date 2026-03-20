"""Simple template engine using str.replace for {{variable}} substitution."""

import os
import threading

_TEMPLATE_DIR = os.path.dirname(__file__)
_CACHE = {}
_LOCK = threading.Lock()


def render(template_name, **kwargs):
    with _LOCK:
        path = os.path.join(_TEMPLATE_DIR, template_name)
        mtime = os.path.getmtime(path)
        cached = _CACHE.get(template_name)
        if cached is None or cached[0] != mtime:
            with open(path, "r") as f:
                _CACHE[template_name] = (mtime, f.read())
        html = _CACHE[template_name][1]
    for key, value in kwargs.items():
        html = html.replace("{{" + key + "}}", str(value))
    return html
