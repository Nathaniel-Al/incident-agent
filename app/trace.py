def _a(k, v):
    if isinstance(v, bool):
        return {"key": k, "value": {"boolValue": v}}
    if isinstance(v, int):
        return {"key": k, "value": {"intValue": v}}
    return {"key": k, "value": {"stringValue": str(v)}}


def build_otlp(st: dict) -> dict:
    tid = st["traceId"]
    base = [_a("ga5.run.id", st["runId"]), _a("ga5.public.marker", st["publicMarker"])]
    spans = []

    stamps = [st["startNs"], st["updatedNs"], st["chat"]["endNs"], st.get("finishedNs") or 0]
    for act in st["actions"].values():
        for at in act["attempts"]:
            stamps += [at["dispatchNs"], at["receiptNs"] or 0]
    end_all = max(stamps)

    def span(sid, parent, name, kind, s, e, attrs, code=1, links=None, msg=None):
        sp = {
            "traceId": tid, "spanId": sid, "name": name, "kind": kind,
            "startTimeUnixNano": str(s), "endTimeUnixNano": str(max(e, s)),
            "attributes": base + attrs,
            "status": {"code": code, **({"message": msg} if msg else {})},
        }
        if parent:
            sp["parentSpanId"] = parent
        if st.get("traceState"):
            sp["traceState"] = st["traceState"]
        if links:
            sp["links"] = [{"traceId": tid, "spanId": x} for x in links]
        spans.append(sp)

    server, agent = st["serverSpanId"], st["agentSpanId"]
    failed = st["status"] == "failed"
    span(server, st["parentSpanId"], "POST /v2/incidents", 2, st["startNs"], end_all,
         [_a("http.request.method", "POST"), _a("url.path", "/v2/incidents"),
          _a("http.response.status_code", 200)])
    span(agent, server, f"invoke_agent {st['agentName']}", 1, st["startNs"], end_all,
         [_a("gen_ai.operation.name", "invoke_agent"), _a("gen_ai.agent.name", st["agentName"])],
         code=2 if failed else 1)

    c = st["chat"]
    chat_attrs = [_a("gen_ai.operation.name", "chat"), _a("gen_ai.request.model", c["model"])]
    u = c.get("usage") or {}
    if _int(u.get("prompt_tokens")):
        chat_attrs.append(_a("gen_ai.usage.input_tokens", u["prompt_tokens"]))
    if _int(u.get("completion_tokens")):
        chat_attrs.append(_a("gen_ai.usage.output_tokens", u["completion_tokens"]))
    span(c["spanId"], agent, "chat incident-plan", 3, c["startNs"], c["endNs"], chat_attrs)

    tool_span_ids = {}
    for act in st["actions"].values():
        if not act["attempts"]:
            continue
        tool_sid = hex_id_stable(act)
        tool_span_ids[act["actionId"]] = tool_sid
        s = min(a["dispatchNs"] for a in act["attempts"])
        e = max((a["receiptNs"] or a["dispatchNs"]) for a in act["attempts"])
        span(tool_sid, agent, f"execute_tool {act['toolName']}", 1, s, e,
             [_a("ga5.action.id", act["actionId"]), _a("gen_ai.tool.name", act["toolName"]),
              _a("gen_ai.tool.call.id", act["callId"]), _a("gen_ai.operation.name", "execute_tool")],
             code=2 if act["state"] == "failed" else 1,
             msg="tool failed" if act["state"] == "failed" else None)
        for at in act["attempts"]:
            r = at["receipt"]
            attrs = [_a("ga5.action.id", act["actionId"]), _a("ga5.attempt", at["attempt"]),
                     _a("http.request.method", "POST"), _a("http.request.resend_count", at["attempt"] - 1)]
            code = 0
            if r:
                status = r["status"]
                attrs += [_a("ga5.receipt.id", r["receiptId"]), _a("ga5.receipt.nonce", r["nonce"]),
                          _a("http.response.status_code", status)]
                if 200 <= status < 300:
                    code = 1
                else:
                    attrs.append(_a("error.type", "timeout" if status == 0 else str(status)))
                    code = 2
            span(at["spanId"], tool_sid, f"POST tool/{act['toolName']}", 3,
                 at["dispatchNs"], at["receiptNs"] or at["dispatchNs"], attrs, code=code)

    j = st.get("join")
    if j:
        links = [tool_span_ids[a] for a in st["diagOrder"] if a in tool_span_ids]
        span(j["spanId"], agent, "incident.join", 1, j["startNs"], j["endNs"], [], links=links)

    ap = st.get("approval")
    if ap:
        attrs = [_a("ga5.approval.id", ap["approvalId"]), _a("ga5.action.id", ap["actionId"])]
        if ap.get("nonce"):
            attrs += [_a("ga5.approval.nonce", ap["nonce"]), _a("ga5.receipt.id", ap["receiptId"]),
                      _a("ga5.receipt.nonce", ap["nonce"]), _a("ga5.approval.decision", ap["decision"])]
        span(ap_span_id(st), agent, "approval_gate", 1, ap["requestedNs"],
             ap["receivedNs"] or ap["requestedNs"], attrs)

    return {"resourceSpans": [{
        "resource": {"attributes": [_a("service.name", "incident-agent")]},
        "scopeSpans": [{"scope": {"name": "incident-agent"}, "spans": spans}],
    }]}


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


# Stable span IDs derived from stored data (no extra state needed, deterministic across renders).
import hashlib


def _derive(seed: str) -> str:
    h = hashlib.sha256(seed.encode()).hexdigest()[:16]
    return h if int(h, 16) != 0 else "0000000000000001"


def hex_id_stable(act: dict) -> str:
    return _derive("tool:" + act["actionId"])


def ap_span_id(st: dict) -> str:
    return _derive("approval:" + st["approval"]["approvalId"])
