import asyncio
import json
import logging
import os
import sys
import time
from collections import deque
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from . import llm, machine
from .config import settings
from .store import Store
from .util import (ApiError, canon, parse_traceparent, scrub, sensitive_values,
                   sha256_hex, valid_tracestate)

logging.basicConfig(
    level=getattr(logging, settings.log_level, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stdout,
    force=True,
)
print("incident-agent module loaded", flush=True)
log = logging.getLogger("incident")

store = Store(os.path.join(settings.data_dir, "runs.db"))
recent = deque(maxlen=60)
_locks: dict = {}


def lock_for(key: str) -> asyncio.Lock:
    return _locks.setdefault(key, asyncio.Lock())


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.http = httpx.AsyncClient()
    log.info("startup model=%s base=%s token_set=%s data_dir=%s log_bodies=%s",
             settings.llm_model, settings.llm_base_url, bool(settings.aipipe_token),
             settings.data_dir, settings.log_bodies)
    yield
    await app.state.http.aclose()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.exception_handler(ApiError)
async def api_error_handler(request: Request, exc: ApiError):
    log.warning("api_error %s %s -> %s %s", request.method, request.url.path, exc.status, exc.code)
    return JSONResponse({"error": exc.code}, status_code=exc.status)


@app.middleware("http")
async def access_log(request: Request, call_next):
    t0 = time.monotonic()
    if request.url.path != "/healthz":
        log.info("http_in %s %s host=%s clen=%s ctype=%s traceparent=%s",
                 request.method, request.url.path, request.headers.get("host"),
                 request.headers.get("content-length"), request.headers.get("content-type"),
                 request.headers.get("traceparent"))
    try:
        resp = await call_next(request)
    except Exception:
        log.exception("unhandled %s %s", request.method, request.url.path)
        resp = JSONResponse({"error": "internal_error"}, status_code=500)
    if request.url.path != "/healthz":
        log.info("http_out %s %s -> %s %dms", request.method, request.url.path,
                 resp.status_code, int((time.monotonic() - t0) * 1000))
    return resp


# ---------- helpers ----------
def _note(kind: str, **kw):
    recent.append({"t": time.strftime("%H:%M:%S"), "kind": kind, **kw})


async def _read_json(request: Request):
    raw = await request.body()
    if len(raw) > settings.max_body_bytes:
        raise ApiError(413, "body_too_large")
    try:
        obj = json.loads(raw)
    except Exception:
        raise ApiError(400, "invalid_json")
    if not isinstance(obj, dict):
        raise ApiError(400, "invalid_json")
    return obj, len(raw)


def _respond(state: dict, secret_list: list, status: int = 200) -> Response:
    body = json.dumps(machine.render(state), ensure_ascii=False, separators=(",", ":"))
    body = scrub(body, secret_list)
    return Response(body.encode("utf-8"), status_code=status, media_type="application/json")


def _validate_create(req: dict):
    if req.get("profile") != "ga5-incident-agent/v2":
        raise ApiError(400, "unsupported_profile")
    inc, pol = req.get("incident"), req.get("policy")
    ok = (
        isinstance(req.get("runId"), str) and req["runId"].strip() and len(req["runId"]) <= 256
        and isinstance(req.get("publicMarker"), str)
        and isinstance(req.get("sensitive", {}), dict)
        and isinstance(inc, dict) and isinstance(inc.get("transcript"), str)
        and isinstance(inc.get("allowedRootCauses"), list) and inc["allowedRootCauses"]
        and isinstance(req.get("toolCatalog"), list)
        and all(isinstance(t, dict) and isinstance(t.get("name"), str) for t in req["toolCatalog"])
        and isinstance(pol, dict)
    )
    if not ok:
        raise ApiError(422, "invalid_request")


def _log_create_input(req: dict, size: int, request: Request):
    inc = req.get("incident") if isinstance(req.get("incident"), dict) else {}
    pol = req.get("policy") if isinstance(req.get("policy"), dict) else {}
    tr = inc.get("transcript", "") if isinstance(inc.get("transcript"), str) else ""
    sens = req.get("sensitive")
    summary = dict(
        runId=req.get("runId"), profile=req.get("profile"), incidentId=inc.get("incidentId"),
        service=inc.get("service"), sev=inc.get("severity"), bytes=size,
        transcript_lines=tr.count("\n") + 1, transcript_chars=len(tr),
        roots=len(inc.get("allowedRootCauses", []) or []),
        tools=len(req.get("toolCatalog", []) or []) if isinstance(req.get("toolCatalog"), list) else None,
        maxDiag=pol.get("maximumDiagnostics"), effectTools=pol.get("effectTools"),
        approvalFor=pol.get("approvalRequiredFor"),
        sensitive_keys=list(sens.keys()) if isinstance(sens, dict) else None,
        incoming_traceparent=bool(request.headers.get("traceparent")),
    )
    log.info("create_in %s", json.dumps(summary, default=str))
    _note("create_in", runId=summary["runId"], incidentId=summary["incidentId"],
          bytes=summary["bytes"], effectTools=summary["effectTools"])
    if settings.log_bodies:
        red = json.loads(json.dumps(req))
        if isinstance(red.get("sensitive"), dict):
            red["sensitive"] = {k: "[REDACTED]" for k in red["sensitive"]}
        if isinstance(red.get("incident"), dict) and isinstance(red["incident"].get("transcript"), str):
            red["incident"]["transcript"] = red["incident"]["transcript"][:400] + "...[truncated]"
        log.info("create_body %s", json.dumps(red, default=str)[:6000])


# ---------- routes ----------
@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.post("/v2/incidents")
async def create_incident(request: Request):
    started_ns = time.time_ns()
    t0 = time.monotonic()
    req, size = await _read_json(request)
    _log_create_input(req, size, request)
    _validate_create(req)
    run_id = req["runId"]
    body_hash = sha256_hex(canon(req))

    async with lock_for(run_id):
        existing = store.get(run_id)
        if existing:
            if existing[0] != body_hash:
                log.warning("create_conflict run=%s", run_id)
                raise ApiError(409, "run_conflict")
            log.info("create_replay run=%s (no model call)", run_id)
            return _respond(existing[1], existing[2])

        plan = await llm.make_plan(request.app.state.http, req,
                                   settings.request_budget_s - (time.monotonic() - t0))
        tp = parse_traceparent(request.headers.get("traceparent"))
        incoming = None
        if tp:
            incoming = {"traceId": tp[0], "parentSpanId": tp[1],
                        "traceState": valid_tracestate(request.headers.get("tracestate"))}
        state = machine.create_run(req, plan, incoming, started_ns)
        secrets_list = sensitive_values(req.get("sensitive"))
        store.put(run_id, body_hash, state, secrets_list)

    log.info("create_out run=%s root=%s evidence=%s diag=%s effect=%s approval=%s dispatches=%d ms=%d",
             run_id, plan["rootCause"], plan["evidence"],
             [d["toolName"] for d in plan["diagnostics"]], plan["effect"]["toolName"],
             plan["effect"]["requiresApproval"], len(state["newDispatches"]),
             int((time.monotonic() - t0) * 1000))
    _note("create_out", runId=run_id, root=plan["rootCause"],
          diag=[d["toolName"] for d in plan["diagnostics"]], effect=plan["effect"]["toolName"])
    return _respond(state, secrets_list)


@app.post("/v2/incidents/{run_id}/receipts")
async def post_receipt(run_id: str, request: Request):
    body, size = await _read_json(request)
    outs = body.get("outcomes") if isinstance(body.get("outcomes"), list) else []
    apps = body.get("approvals") if isinstance(body.get("approvals"), list) else []
    log.info("receipt_in run=%s receiptId=%s bytes=%d outcomes=%s approvals=%s", run_id,
             body.get("receiptId"), size,
             [(o.get("actionId"), o.get("attempt"), o.get("status"), o.get("resultClass"))
              for o in outs if isinstance(o, dict)],
             [(a.get("approvalId"), a.get("decision")) for a in apps if isinstance(a, dict)])
    _note("receipt_in", runId=run_id, receiptId=body.get("receiptId"),
          outcomes=[(o.get("attempt"), o.get("status")) for o in outs if isinstance(o, dict)],
          approvals=[a.get("decision") for a in apps if isinstance(a, dict)])

    async with lock_for(run_id):
        row = store.get(run_id)
        if not row:
            raise ApiError(404, "unknown_run")
        _, state, secrets_list = row
        changed = machine.process_receipt(state, body, sha256_hex(canon(body)))
        if changed:
            store.put(run_id, row[0], state, secrets_list)
    log.info("receipt_out run=%s changed=%s status=%s stage=%s new_dispatches=%d approvals=%d",
             run_id, changed, state["status"], state["stage"],
             len(state["newDispatches"]), len(state["pendingApprovals"]))
    return _respond(state, secrets_list)


@app.get("/v2/incidents/{run_id}")
async def get_incident(run_id: str):
    row = store.get(run_id)
    if not row:
        raise ApiError(404, "unknown_run")
    log.info("get run=%s status=%s", run_id, row[1]["status"])
    return _respond(row[1], row[2])


def _debug_auth(request: Request):
    if not settings.debug_token or request.headers.get("x-debug-token") != settings.debug_token:
        raise ApiError(404, "not_found")


@app.get("/debug/recent")
async def debug_recent(request: Request):
    _debug_auth(request)
    return list(recent)


@app.get("/debug/llm")
async def debug_llm(request: Request):
    _debug_auth(request)
    t0 = time.monotonic()
    try:
        content, usage = await llm._chat(
            request.app.state.http, settings.llm_model,
            [{"role": "user", "content": 'Reply with the JSON object {"ok": true}'}], 10)
        return {"ok": True, "model": settings.llm_model, "ms": int((time.monotonic() - t0) * 1000),
                "reply": content[:100], "usage": usage}
    except Exception as e:
        return {"ok": False, "model": settings.llm_model, "error": type(e).__name__,
                "status": getattr(e, "status", None), "token_set": bool(settings.aipipe_token)}
