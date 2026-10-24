import json
import logging
import re
import time
from collections import deque

from .config import settings
from .main import app as _app

log = logging.getLogger("incident.capture")

_MULTI = re.compile(r"/{2,}")
_entries = deque(maxlen=40)
_seq = 0
_SECRET_HDRS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}
_MAX_CAP = 400_000


def _sens_values(obj, out):
    if isinstance(obj, str):
        if len(obj) >= 4:
            out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _sens_values(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _sens_values(v, out)


def _parse(raw: bytes):
    try:
        return json.loads(raw)
    except Exception:
        return raw[:2000].decode("utf-8", "replace")


async def _json(send, status, obj):
    body = json.dumps(obj, default=str).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


async def _debug(scope, send, path):
    hdrs = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
    if not settings.debug_token or hdrs.get("x-debug-token") != settings.debug_token:
        return await _json(send, 404, {"error": "not_found"})
    rest = path[len("/debug/capture"):].strip("/")
    if not rest:
        return await _json(send, 200, [
            {k: e[k] for k in ("seq", "time", "method", "path", "status", "ms", "req_bytes",
                               "resp_bytes", "sensitive_leak_in_response")}
            for e in _entries])
    for e in _entries:
        if str(e["seq"]) == rest:
            return await _json(send, 200, e)
    return await _json(send, 404, {"error": "no_such_entry"})


async def application(scope, receive, send):
    global _seq
    if scope["type"] != "http":
        return await _app(scope, receive, send)

    path = _MULTI.sub("/", scope.get("path", "/"))
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    if path != scope.get("path"):
        scope = dict(scope)
        scope["path"] = path
        scope["raw_path"] = path.encode()

    if path.startswith("/debug/capture"):
        return await _debug(scope, send, path)
    if path == "/healthz":
        return await _app(scope, receive, send)

    t0 = time.monotonic()
    req_chunks, resp_chunks = [], []
    state = {"status": None, "req": 0, "resp": 0}

    async def recv():
        msg = await receive()
        try:
            if msg["type"] == "http.request":
                b = msg.get("body", b"")
                state["req"] += len(b)
                if state["req"] <= _MAX_CAP:
                    req_chunks.append(b)
        except Exception:
            pass
        return msg

    async def snd(msg):
        try:
            if msg["type"] == "http.response.start":
                state["status"] = msg["status"]
            elif msg["type"] == "http.response.body":
                b = msg.get("body", b"")
                state["resp"] += len(b)
                if state["resp"] <= _MAX_CAP:
                    resp_chunks.append(b)
        except Exception:
            pass
        await send(msg)

    try:
        await _app(scope, recv, snd)
    finally:
        try:
            _seq += 1
            req_obj = _parse(b"".join(req_chunks))
            sens = []
            if isinstance(req_obj, dict) and isinstance(req_obj.get("sensitive"), dict):
                _sens_values(req_obj["sensitive"], sens)
                req_obj["sensitive"] = {k: "[REDACTED]" for k in req_obj["sensitive"]}
            resp_raw = b"".join(resp_chunks)
            resp_text = resp_raw.decode("utf-8", "replace")
            leak = any(s in resp_text for s in sens)
            headers = {k.decode(): ("[REDACTED]" if k.decode().lower() in _SECRET_HDRS else v.decode())
                       for k, v in scope.get("headers", [])}
            entry = {
                "seq": _seq, "time": time.strftime("%H:%M:%S"),
                "method": scope.get("method"), "path": path, "status": state["status"],
                "ms": int((time.monotonic() - t0) * 1000),
                "req_bytes": state["req"], "resp_bytes": state["resp"],
                "sensitive_leak_in_response": leak,
                "request_headers": headers, "request": req_obj,
                "response": _parse(resp_raw),
            }
            _entries.append(entry)
            log.info("capture seq=%d %s %s -> %s req=%dB resp=%dB %dms leak=%s",
                     _seq, scope.get("method"), path, state["status"],
                     state["req"], state["resp"], entry["ms"], leak)
        except Exception:
            log.exception("capture_failed")
