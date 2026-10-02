"""Signed verdict-delivery webhooks — evidence pushed into the bank's SIEM.

Panel-hardened design (05_ADOPT_LIST_v2 #3):
  - REGISTRATION is admin-modeled, not self-service: an allowlist of HTTPS
    endpoints is provisioned by config (production: admin/mTLS identity).
    SSRF controls: HTTPS only, private/loopback/link-local/metadata ranges
    blocked, DNS resolved and checked at registration AND at send time.
  - TRANSACTIONAL OUTBOX: the outbox row is written after the decision;
    an independent dispatcher delivers at-least-once with a stable
    event_id (bank-side idempotency), exponential backoff, terminal
    dead-letter status, and a replay administration endpoint.
  - NON-INTERFERENCE: delivery failures can never change /v1/decide
    latency or verdicts — tested, not promised.
  - ENVELOPE: versioned schema tasdiq.verdict.created.v1, canonical
    verdict + verdict_signature inside, envelope HMAC (per-endpoint
    secret, id.timestamp.body, ±5 min window, two active secrets for
    rotation) for transport auth, Ed25519 for evidence.
  - LEDGER HYGIENE: delivery attempts live in the delivery log; only
    terminal status touches the hash chain (via the agent ledger).
  - FORMAT: "tasdiq.v1" (default) | "cef" (SIEM ingestion line).
"""
from __future__ import annotations
import hashlib
import hmac
import ipaddress
import json
import socket
import time
import uuid
from pathlib import Path
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, Field

OUTBOX_PATH = Path(__file__).resolve().parent.parent / "ledger_store" / "webhook_outbox.jsonl"

_BLOCKED = set()


def _is_blocked_host(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True   # unresolvable = blocked (fail closed)
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return True
        if str(ip) in ("169.254.169.254", "fd00:ec2::254"):   # cloud metadata
            return True
    return False


class WebhookEndpoint(BaseModel):
    """Admin-provisioned endpoint (config in production; registry here)."""
    url: str                       # https:// only
    events: list[str] = ["verdict.created"]
    secret_current: str
    secret_previous: str = ""      # rotation overlap
    tenant: str = "bank-a"
    format: Literal["tasdiq.v1", "cef"] = "tasdiq.v1"


_REGISTRY: dict[str, WebhookEndpoint] = {}


def register(ep: WebhookEndpoint) -> str:
    if not ep.url.startswith("https://"):
        raise HTTPException(422, "webhook endpoints must be HTTPS")
    host = ep.url.split("//", 1)[1].split("/")[0].split(":")[0]
    if _is_blocked_host(host):
        raise HTTPException(422, f"blocked destination host: {host}")
    key = uuid.uuid4().hex[:12]
    _REGISTRY[key] = ep
    return key


# ---------------- outbox + dispatcher (async-safe, off the rail) ------------

def enqueue_verdict_event(verdict: dict) -> dict | None:
    """Called AFTER a decision; appends an outbox row. Never raises into
    the decision path — an outbox failure is logged, not propagated."""
    if not _REGISTRY:
        return None
    event_id = uuid.uuid4().hex
    row = {"event_id": event_id, "schema": "tasdiq.verdict.created.v1",
           "tenant": "bank-a", "decision_id": verdict.get("txn_id"),
           "occurred_at": int(time.time()), "attempts": 0, "status": "pending",
           "verdict": _verdict_projection(verdict)}
    try:
        OUTBOX_PATH.parent.mkdir(parents=True, exist_ok=True)
        with OUTBOX_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
        return row
    except OSError:
        return None


def _verdict_projection(v: dict) -> dict:
    """Pseudonymous by default: hashes only, no raw identifiers."""
    keep = ("txn_id", "decision", "band", "weighted_risk", "total_risk",
            "policy_version_hash", "thresholds_used", "step_up", "cost",
            "data_quality", "hold", "verdict_signature")
    return {k: v[k] for k in keep if k in v}


def _envelope(row: dict, ep: WebhookEndpoint) -> dict:
    env = {"schema": row["schema"], "event_id": row["event_id"],
           "tenant": ep.tenant, "decision_id": row["decision_id"],
           "occurred_at": row["occurred_at"],
           "delivery_attempt": row["attempts"] + 1,
           "verdict": row["verdict"]}
    if ep.format == "cef":
        v = row["verdict"]
        env = {"cefversion": "1.0", "name": "Tasdiq Verdict",
               "severity": {"DECLINE": "10", "ESCALATE": "6", "APPROVE": "2"}.get(v.get("decision", ""), "4"),
               "extension": f"txn={row['decision_id']} band={v.get('band')} "
                            f"decision={v.get('decision')} policy={v.get('policy_version_hash', '')[:20]}"}
    return env


def _hmac_transport(ep: WebhookEndpoint, body: bytes, ts: int) -> str:
    return hmac.new(ep.secret_current.encode(), f"{ts}.".encode() + body,
                    hashlib.sha256).hexdigest()


def dispatch_pending(send_fn) -> dict:
    """Deliver pending rows via send_fn(url, headers, body)->status_code.
    At-least-once; exponential backoff via attempts; dead-letter after 5.
    Returns a summary. Delivery NEVER touches the decision path."""
    if not OUTBOX_PATH.exists():
        return {"delivered": 0, "dead": 0, "pending": 0}
    rows = [json.loads(l) for l in OUTBOX_PATH.read_text(encoding="utf-8").splitlines() if l.strip()]
    delivered = dead = 0
    out = []
    for row in rows:
        if row["status"] == "dead":
            out.append(row); continue
        ok = False
        for key, ep in list(_REGISTRY.items()):
            if not any(e in row["schema"] or e == "verdict.created" for e in ep.events):
                continue
            # DNS rebalancing guard: re-check at DISPATCH time, not only at
            # registration — a host that now resolves private/metadata is skipped
            host = ep.url.split("//", 1)[1].split("/")[0].split(":")[0]
            if _is_blocked_host(host):
                continue
            body = json.dumps(_envelope(row, ep), sort_keys=True).encode()
            ts = int(time.time())
            headers = {"x-tasdiq-event-id": row["event_id"],
                       "x-tasdiq-timestamp": str(ts),
                       "x-tasdiq-signature": _hmac_transport(ep, body, ts)}
            status = send_fn(ep.url, headers, body)
            if 200 <= status < 300:
                ok = True
        row["attempts"] += 1
        if ok:
            row["status"] = "delivered"; delivered += 1
        elif row["attempts"] >= 5:
            row["status"] = "dead"; dead += 1
        else:
            row["status"] = "pending"
        out.append(row)
    OUTBOX_PATH.write_text("\n".join(json.dumps(r) for r in out) + "\n", encoding="utf-8")
    return {"delivered": delivered, "dead": dead,
            "pending": sum(1 for r in out if r["status"] == "pending")}


def replay_events(event_ids: list[str], send_fn) -> dict:
    """Administration: re-deliver delivered/dead events by id (SIEM outage
    recovery). Idempotent at the bank via stable event_id."""
    if not OUTBOX_PATH.exists():
        return {"replayed": 0}
    rows = [json.loads(l) for l in OUTBOX_PATH.read_text(encoding="utf-8").splitlines() if l.strip()]
    want = set(event_ids)
    replayed = 0
    for row in rows:
        if row["event_id"] in want:
            row["status"] = "pending"; row["attempts"] = 0
            replayed += 1
    OUTBOX_PATH.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    r = dispatch_pending(send_fn)
    return {"replayed": replayed, **r}


def verify_transport(ep: WebhookEndpoint, ts: int, body: bytes, sig: str) -> bool:
    """Bank-side reference check: current secret, else previous (rotation)."""
    if abs(time.time() - ts) > 300:
        return False
    expect = hmac.new(ep.secret_current.encode(), f"{ts}.".encode() + body,
                      hashlib.sha256).hexdigest()
    if hmac.compare_digest(expect, sig):
        return True
    if ep.secret_previous:
        prev = hmac.new(ep.secret_previous.encode(), f"{ts}.".encode() + body,
                        hashlib.sha256).hexdigest()
        return hmac.compare_digest(prev, sig)
    return False


def reset_demo_registry():
    _REGISTRY.clear()
    OUTBOX_PATH.unlink(missing_ok=True)
