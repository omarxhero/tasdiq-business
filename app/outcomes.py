"""Outcome Capture — where ground truth becomes a signed, chained asset.

The problem (our own file's finding): "a pilot without labels cannot prove
incremental lift." Every cooling-off hold, every escalation, every decline
creates a disposition moment at the bank — confirmed_scam, confirmed_legit,
unresolved, customer_declined — and today that truth evaporates in the
bank's call-center logs.

This module turns dispositions into evidence:
  POST /v1/outcomes  {txn_id, disposition, loss_amount?, auth_method?, notes?}
    -> signed (maker persona), appended to the AGENT ledger (chained),
       idempotent per (txn_id, disposition source), notes are UNTRUSTED
       free text (same rule as memo) and never enter any model context.
Replay Lab joins outcomes to shadow decisions and reports MEASURED lift:
  incremental recall / false-escalation on real dispositions, continuously.

Callback SLA + priority ride along in the read model (band-based), so the
callback queue itself becomes a label factory.
"""
from __future__ import annotations
import time
from pathlib import Path

from fastapi import HTTPException
from pydantic import BaseModel, Field
from typing import Literal

from app.ledger import DualLedger
from app.policy import canon, doc_hash, load_key

KEYS = Path(__file__).resolve().parent.parent / "keys"
_PERSONA = "maker"

DISPOSITIONS = ("confirmed_scam", "confirmed_legit", "unresolved", "customer_declined")

# callback priority by band (read model — the queue is a label factory)
_BAND_PRIORITY = {
    # callback-GENERATING bands first (the label factory is the hold queue)
    "COOLING_OFF_HOLD": 1, "SIM_SWAP_RECENT": 1, "SIM_SWAP_AGED_CORROBORATION": 1,
    "PAYEE_VELOCITY_TRAP": 2, "PRIMARY_SIGNAL_LOSS": 2,
    "BEHAVIORAL_ANOMALY": 2, "DEGRADED_SIGNAL_ANOMALY": 2,
    "GOVERNOR_HELD_ESCALATE": 3, "WEIGHTED_RISK_BAND": 3,
    # hard declines: money already stopped; callback is confirm-and-document
    "SIM_SWAP_INSTANT_PATTERN": 4, "SIM_SWAP_HIGH_RISK": 4, "COVERAGE_LOW": 4,
    "CLEAN": 5,
}


class OutcomeRequest(BaseModel):
    txn_id: str
    disposition: Literal["confirmed_scam", "confirmed_legit",
                         "unresolved", "customer_declined"]
    loss_amount: float | None = Field(default=None, ge=0)
    auth_method_used: str | None = None       # e.g. SMS_OTP / WEBAUTHN / none
    callback_sla_minutes: float | None = Field(default=None, ge=0)  # read-model hint
    notes: str = ""                           # UNTRUSTED free text — never parsed


def record_outcome(req: OutcomeRequest, ledger: DualLedger,
                   decision_lookup) -> dict:
    """Sign + chain an outcome. decision_lookup(txn_id) -> last recorded
    verdict (dict) or None. Raises 404 if the txn was never decided."""
    verdict = decision_lookup(req.txn_id)
    if verdict is None:
        raise HTTPException(404, "txn not found — outcomes attach to decided transactions only")

    body = {
        "txn_id": req.txn_id,
        "disposition": req.disposition,
        "loss_amount": req.loss_amount,
        "auth_method_used": req.auth_method_used,
        "band": verdict.get("band"),
        "decision": verdict.get("decision"),
        "policy_version_hash": verdict.get("policy_version_hash"),
        "recorded_at": int(time.time()),
        "notes_present": bool(req.notes),      # presence only — content never stored
    }
    sig = load_key(_PERSONA, KEYS).sign(canon(body)).hex()
    record = {**body, "outcome_signature": {
        "algorithm": "Ed25519", "persona": _PERSONA,
        "content_hash": doc_hash(body), "value": sig}}
    ledger.append_agent(req.txn_id, "outcome", record)
    # read-model extras (not signed — operational hints)
    record["callback_priority"] = _BAND_PRIORITY.get(verdict.get("band", ""), 5)
    record["callback_sla_minutes"] = req.callback_sla_minutes
    return record


def verify_outcome(record: dict) -> bool:
    from cryptography.exceptions import InvalidSignature
    sig = record.get("outcome_signature")
    if not sig:
        return False
    body = {k: v for k, v in record.items()
            if k not in ("outcome_signature", "callback_priority", "callback_sla_minutes")}
    if doc_hash(body) != sig.get("content_hash"):
        return False
    try:
        pub = load_key(sig.get("persona", "maker"), KEYS, private=False)
        pub.verify(bytes.fromhex(sig.get("value", "")), canon(body))
        return True
    except (InvalidSignature, ValueError):
        return False


def measured_lift(outcomes: list[dict], shadow_rows: list[dict]) -> dict:
    """Join outcomes to replay rows and compute the pilot's proof numbers:
    incremental recall (confirmed scams the policy caught) and false
    escalation (confirmed-legit traffic escalated/declined)."""
    by_txn = {r["txn_id"]: r for r in shadow_rows}
    scam_total = legit_total = 0
    scam_caught = 0           # confirmed_scam AND decision != APPROVE
    scam_bypassed = 0         # confirmed_scam AND decision == APPROVE
    legit_friction = 0        # confirmed_legit AND decision != APPROVE
    loss_avoided = 0.0        # loss on caught scams
    loss_suffered = 0.0       # loss on bypassed scams
    for o in outcomes:
        row = by_txn.get(o["txn_id"])
        if row is None:
            continue
        dec = row.get("governor_tasdiq_rail") or row.get("decision")
        if o["disposition"] == "confirmed_scam":
            scam_total += 1
            if dec != "APPROVE":
                scam_caught += 1
                loss_avoided += o.get("loss_amount") or 0.0
            else:
                scam_bypassed += 1
                loss_suffered += o.get("loss_amount") or 0.0
        elif o["disposition"] == "confirmed_legit":
            legit_total += 1
            if dec != "APPROVE":
                legit_friction += 1
    return {
        "labeled_outcomes": len(outcomes),
        "scam_total": scam_total, "scam_caught": scam_caught,
        "scam_bypassed": scam_bypassed,
        "incremental_recall": round(scam_caught / scam_total, 4) if scam_total else None,
        "legit_total": legit_total, "legit_frictioned": legit_friction,
        "false_escalation_rate": round(legit_friction / legit_total, 4) if legit_total else None,
        "loss_avoided_total": round(loss_avoided, 2),
        "loss_suffered_total": round(loss_suffered, 2),
        "definition": "incremental recall = confirmed scams the policy did not APPROVE; "
                      "false escalation = confirmed-legit traffic not approved. Measured on "
                      "bank dispositions — not synthetic labels.",
    }
