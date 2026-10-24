import copy
import time

from .trace import build_otlp
from .util import ApiError, args_digest, hex_id, new_id


def _new_action(phase: str, spec: dict) -> dict:
    return {
        "actionId": new_id("act"),
        "callId": new_id("call"),
        "phase": phase,
        "toolName": spec["toolName"],
        "arguments": spec["arguments"],
        "evidence": spec["evidence"],
        "state": "new",  # new | pending | succeeded | failed
        "attempts": [],
    }


def _dispatch(st: dict, act: dict, attempt: int):
    span = hex_id(8)
    d = {
        "actionId": act["actionId"],
        "callId": act["callId"],
        "phase": act["phase"],
        "toolName": act["toolName"],
        "arguments": act["arguments"],
        "evidence": act["evidence"],
        "attempt": attempt,
        "traceparent": f"00-{st['traceId']}-{span}-01",
    }
    if st.get("traceState"):
        d["tracestate"] = st["traceState"]
    if act.get("approvalId"):
        d["approvalId"] = act["approvalId"]
        d["approvalNonce"] = act["approvalNonce"]
    act["attempts"].append(
        {"attempt": attempt, "spanId": span, "dispatchNs": time.time_ns(), "receipt": None, "receiptNs": None}
    )
    act["state"] = "pending"
    st["actionLog"].append(copy.deepcopy(d))
    st["newDispatches"].append(copy.deepcopy(d))


def create_run(req: dict, plan: dict, incoming, started_ns: int) -> dict:
    if incoming:
        trace_id, parent, tstate = incoming["traceId"], incoming["parentSpanId"], incoming.get("traceState")
    else:
        trace_id, parent, tstate = hex_id(16), None, None
    st = {
        "runId": req["runId"],
        "agentName": req.get("agentName") if isinstance(req.get("agentName"), str) else "incident-response",
        "publicMarker": req["publicMarker"],
        "traceId": trace_id,
        "parentSpanId": parent,
        "traceState": tstate,
        "serverSpanId": hex_id(8),
        "agentSpanId": hex_id(8),
        "startNs": started_ns,
        "updatedNs": time.time_ns(),
        "chat": {
            "spanId": hex_id(8), "model": plan["model"],
            "startNs": plan["startNs"], "endNs": plan["endNs"], "usage": plan.get("usage") or {},
        },
        "diagnosis": {"rootCause": plan["rootCause"], "evidence": plan["evidence"]},
        "actions": {}, "diagOrder": [], "effectId": None,
        "requiresApproval": plan["effect"]["requiresApproval"],
        "stage": "diagnostics", "status": "waiting",
        "chosenEffect": plan["effect"]["toolName"], "suppressed": [],
        "actionLog": [], "receiptLog": [], "newDispatches": [], "pendingApprovals": [],
        "approval": None, "join": None, "receiptHashes": {}, "finishedNs": None,
    }
    for spec in plan["diagnostics"]:
        a = _new_action("diagnostic", spec)
        st["actions"][a["actionId"]] = a
        st["diagOrder"].append(a["actionId"])
    e = _new_action("effect", plan["effect"])
    st["actions"][e["actionId"]] = e
    st["effectId"] = e["actionId"]
    for aid in st["diagOrder"]:
        _dispatch(st, st["actions"][aid], 1)
    return st


def _finish(st: dict, status: str, reason: str):
    eff = st["actions"][st["effectId"]]
    st["status"] = status
    st["stage"] = "done"
    st["finishedNs"] = time.time_ns()
    st["newDispatches"] = []
    st["pendingApprovals"] = []
    if not eff["attempts"]:
        st["chosenEffect"] = None
        st["suppressed"] = [{"actionId": eff["actionId"], "toolName": eff["toolName"], "reason": reason}]
    else:
        st["chosenEffect"] = eff["toolName"]


def _advance(st: dict):
    if st["stage"] == "diagnostics":
        diags = [st["actions"][a] for a in st["diagOrder"]]
        if any(a["state"] == "pending" for a in diags):
            return
        if len(diags) > 1:
            starts = [x["dispatchNs"] for a in diags for x in a["attempts"]]
            ends = [x["receiptNs"] or x["dispatchNs"] for a in diags for x in a["attempts"]]
            st["join"] = {"spanId": hex_id(8), "startNs": min(starts), "endNs": max(ends)}
        if any(a["state"] == "failed" for a in diags):
            return _finish(st, "failed", "diagnostic_failed")
        eff = st["actions"][st["effectId"]]
        if st["requiresApproval"]:
            apr = {
                "approvalId": new_id("apr"),
                "actionId": eff["actionId"],
                "toolName": eff["toolName"],
                "argumentsDigest": args_digest(eff["arguments"]),
            }
            st["approval"] = {**apr, "requestedNs": time.time_ns(), "decision": None,
                              "nonce": None, "receiptId": None, "receivedNs": None}
            st["pendingApprovals"] = [apr]
            st["stage"] = "approval"
        else:
            _dispatch(st, eff, 1)
            st["stage"] = "effect"
    elif st["stage"] == "effect":
        eff = st["actions"][st["effectId"]]
        if eff["state"] == "succeeded":
            _finish(st, "completed", "")
        elif eff["state"] == "failed":
            _finish(st, "failed", "effect_failed")


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def process_receipt(st: dict, body: dict, body_hash: str) -> bool:
    """Returns True if state changed. Validates fully before mutating."""
    rid = body.get("receiptId")
    if not isinstance(rid, str) or not rid.strip():
        raise ApiError(422, "invalid_receipt")
    outcomes = body.get("outcomes") or []
    approvals = body.get("approvals") or []
    if not isinstance(outcomes, list) or not isinstance(approvals, list) or not (outcomes or approvals):
        raise ApiError(422, "invalid_receipt")

    if rid in st["receiptHashes"]:
        if st["receiptHashes"][rid] != body_hash:
            raise ApiError(409, "receipt_conflict")
        return False
    if st["status"] != "waiting":
        raise ApiError(422, "run_not_waiting")

    seen = set()
    for o in outcomes:
        if not isinstance(o, dict):
            raise ApiError(422, "invalid_outcome")
        aid, cid, att, status, nonce = (o.get(k) for k in ("actionId", "callId", "attempt", "status", "nonce"))
        if not (isinstance(aid, str) and isinstance(cid, str) and _is_int(att) and _is_int(status)
                and isinstance(nonce, str) and nonce):
            raise ApiError(422, "invalid_outcome")
        if o.get("resultClass") is not None and not isinstance(o.get("resultClass"), str):
            raise ApiError(422, "invalid_outcome")
        act = st["actions"].get(aid)
        if (not act or act["callId"] != cid or act["state"] != "pending"
                or act["attempts"][-1]["attempt"] != att or aid in seen):
            raise ApiError(422, "outcome_not_pending")
        seen.add(aid)

    if approvals:
        a = approvals[0]
        if (len(approvals) != 1 or st["stage"] != "approval" or not isinstance(a, dict)
                or a.get("approvalId") != st["approval"]["approvalId"]
                or a.get("decision") not in ("approved", "denied", "rejected")
                or not isinstance(a.get("nonce"), str) or not a.get("nonce")):
            raise ApiError(422, "invalid_approval")

    # ---- apply ----
    now = time.time_ns()
    st["newDispatches"] = []
    st["pendingApprovals"] = []
    for o in outcomes:
        act = st["actions"][o["actionId"]]
        at = act["attempts"][-1]
        entry = {"receiptId": rid, "actionId": o["actionId"], "callId": o["callId"],
                 "attempt": o["attempt"], "status": o["status"]}
        if o.get("resultClass") is not None:
            entry["resultClass"] = o["resultClass"]
        entry["nonce"] = o["nonce"]
        at["receipt"], at["receiptNs"] = entry, now
        st["receiptLog"].append(entry)
        s = o["status"]
        if 200 <= s < 300:
            act["state"] = "succeeded"
        elif s == 503 and o["attempt"] == 1:
            _dispatch(st, act, 2)  # exactly one retry
        else:
            act["state"] = "failed"  # timeout (status 0), 5xx after retry, 4xx

    if approvals:
        a = approvals[0]
        ap = st["approval"]
        ap.update(decision=a["decision"], nonce=a["nonce"], receiptId=rid, receivedNs=now)
        st["receiptLog"].append({"receiptId": rid, "approvalId": ap["approvalId"],
                                 "decision": a["decision"], "nonce": a["nonce"]})
        if a["decision"] == "approved":
            eff = st["actions"][st["effectId"]]
            eff["approvalId"], eff["approvalNonce"] = ap["approvalId"], a["nonce"]
            _dispatch(st, eff, 1)
            st["stage"] = "effect"
        else:
            _finish(st, "failed", "approval_denied")

    st["receiptHashes"][rid] = body_hash
    st["updatedNs"] = now
    _advance(st)
    return True


def render(st: dict) -> dict:
    waiting = st["status"] == "waiting"
    return {
        "runId": st["runId"],
        "status": st["status"],
        "diagnosis": st["diagnosis"],
        "chosenEffect": st["chosenEffect"],
        "suppressed": st["suppressed"],
        "dispatches": st["newDispatches"] if waiting else [],
        "approvals": st["pendingApprovals"] if waiting else [],
        "actionLog": st["actionLog"],
        "receiptLog": st["receiptLog"],
        "otlp": build_otlp(st),
    }
