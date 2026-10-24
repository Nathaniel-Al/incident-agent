import re

from .main import app as _app

_MULTI = re.compile(r"/{2,}")


async def application(scope, receive, send):
    if scope["type"] == "http":
        path = _MULTI.sub("/", scope.get("path", "/"))
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/") or "/"
        if path != scope.get("path"):
            scope = dict(scope)
            scope["path"] = path
            scope["raw_path"] = path.encode()
    await _app(scope, receive, send)
