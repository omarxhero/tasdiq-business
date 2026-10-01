"""Verdict signatures — "every decision is signed", literally.

The verdict payload always carried policy_version_hash (which RULES ran)
but not a signature over the decision itself. This module signs a
CANONICAL, REPLAY-STABLE subset of the verdict with the maker persona
(the artifact-signing key, same as Replay Lab reports; production moves
it to KMS/HSM with key rotation):

  signed fields: txn_id · msisdn_hash · decision · band · total_risk ·
                 weighted_risk · policy_version_hash · thresholds_used ·
                 step_up · cost{tier, signals_bought, cost_estimate_usd,
                 trigger, decision_basis} · data_quality (when present)

Deliberately EXCLUDED: latency (end-to-end/external ms) and per-signal
reasons (they embed per-run latencies) — signing them would break
idempotent replay, where the SAME decision returns with fresh timing.
The signature therefore proves WHAT was decided and under WHICH policy
and thresholds — the audit-relevant content — not how fast it ran.
"""
from __future__ import annotations
import hashlib

from app.policy import canon, doc_hash, load_key
from pathlib import Path

KEYS = Path(__file__).resolve().parent.parent / "keys"
PERSONA = "maker"
KEY_ID = "maker@1"

_SIGNED_COST_KEYS = ("tier", "signals_bought", "cost_estimate_usd",
                     "trigger", "decision_basis")


def canonical_verdict(verdict: dict, msisdn: str) -> dict:
    """The stable, signable projection of a verdict."""
    cost = verdict.get("cost", {})
    out = {
        "txn_id": verdict.get("txn_id"),
        "msisdn_hash": "msisdn_" + hashlib.sha256(
            (msisdn + _pepper()).encode()).hexdigest()[:16],
        "decision": verdict.get("decision"),
        "band": verdict.get("band"),
        "total_risk": verdict.get("total_risk"),
        "weighted_risk": verdict.get("weighted_risk"),
        "policy_version_hash": verdict.get("policy_version_hash"),
        "thresholds_used": verdict.get("thresholds_used"),
        "step_up": verdict.get("step_up"),
        "cost": {k: cost.get(k) for k in _SIGNED_COST_KEYS},
    }
    if verdict.get("data_quality"):
        out["data_quality"] = verdict["data_quality"]
    if verdict.get("hold"):
        out["hold"] = verdict["hold"]
    return out


def _pepper() -> str:
    from app.config import cfg
    return cfg.VAULT_KEY


def sign_verdict(verdict: dict, msisdn: str) -> dict:
    """Attach-and-return the signature block for a verdict."""
    body = canonical_verdict(verdict, msisdn)
    sig = load_key(PERSONA, KEYS).sign(canon(body)).hex()
    return {"algorithm": "Ed25519", "signing_key_id": KEY_ID,
            "content_hash": doc_hash(body), "value": sig,
            "signed_fields": sorted(body.keys())}


def verify_verdict(verdict: dict, msisdn: str) -> bool:
    """Recompute the canonical body + signature. Any edit to a signed
    field breaks verification; latency edits do not (by design)."""
    from cryptography.exceptions import InvalidSignature
    sig = verdict.get("verdict_signature")
    if not sig:
        return False
    body = canonical_verdict(verdict, msisdn)
    if doc_hash(body) != sig.get("content_hash"):
        return False
    pub = load_key(PERSONA, KEYS, private=False)
    try:
        pub.verify(bytes.fromhex(sig.get("value", "")), canon(body))
        return True
    except (InvalidSignature, ValueError):
        return False
