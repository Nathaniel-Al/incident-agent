import hashlib
import json
import re
import secrets


class ApiError(Exception):
    def __init__(self, status: int, code: str):
        self.status = status
        self.code = code


def canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def args_digest(args) -> str:
    return sha256_hex(canon(args))


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(6)}"  # >= 8 chars, opaque


def hex_id(nbytes: int) -> str:
    while True:
        v = secrets.token_hex(nbytes)
        if int(v, 16) != 0:
            return v


_TP = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
_TS_MEMBER = re.compile(r"^[a-z0-9][a-z0-9_\-*/@]{0,255}=[\x20-\x2b\x2d-\x3c\x3e-\x7e]{0,256}$")


def parse_traceparent(h):
    if not h:
        return None
    m = _TP.match(h.strip())
    if not m:
        return None
    trace_id, span_id, _ = m.groups()
    if int(trace_id, 16) == 0 or int(span_id, 16) == 0:
        return None
    return trace_id, span_id


def valid_tracestate(v):
    if not v or len(v) > 512:
        return None
    members = [x.strip() for x in v.split(",") if x.strip()]
    if not members or len(members) > 32:
        return None
    if all(_TS_MEMBER.match(m) for m in members):
        return ",".join(members)
    return None


def sensitive_values(obj, out=None):
    out = [] if out is None else out
    if isinstance(obj, str):
        if len(obj) >= 4:
            out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            sensitive_values(v, out)
    elif isinstance(obj, list):
        for v in obj:
            sensitive_values(v, out)
    return out


def scrub(text: str, secret_list) -> str:
    for s in sorted(set(secret_list), key=len, reverse=True):
        text = text.replace(s, "[REDACTED]")
        esc = json.dumps(s, ensure_ascii=False)[1:-1]
        if esc != s:
            text = text.replace(esc, "[REDACTED]")
    return text
