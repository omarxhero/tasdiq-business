"""Replay Lab — the bank's own history, replayed, measured, signed.

Purpose: first real-ish numbers in a week instead of a 60-day pilot.
Input: a pseudonymized historical transaction log (JSON list of
DecideRequest-shaped records; optional per-record `confirmed_fraud`
label, `incumbent_decision`, and recorded `signals` when the bank kept
them). No network: replay is offline — signals come from the record or
are modeled as UNAVAILABLE (fail-strict, the engine's own semantics).

Report (Ed25519-signed with the maker persona — artifact, not a policy):
  volumes      n, decision/band/tier distribution, would-cost totals
  bypass       confirmed-fraud records the current setup APPROVES —
               the damning number (each listed with its inputs)
  caught       confirmed-fraud records escalated/declined
  friction     non-fraud records escalated/declined (false-escalation proxy)
  exposure     tier-0 counterfactuals — quiet approvals that would change
               under a hypothetical live SIM swap (no-coverage exposure)
  incumbent    agreement matrix + added-by-tasdiq when incumbent_decision
               present (never-downgrade verified on real history)

Honesty rules baked in: synthetic/absent signals are labeled in the
report header; bypass counts are only computed when labels exist; the
signature covers the exact report bytes (sha256 canonical), and
verification recomputes content — tampering breaks it.
"""
from __future__ import annotations
import time
from pathlib import Path

from app.engine.decide import DecisionEngine
from app.engine.weighting import Behavioral
from app.governor import counterfactual as _counterfactual
from app.engine.weighting import evaluate as _evaluate
from app.policy import canon, doc_hash, load_key
from pathlib import Path as _P  # alias to avoid clashing with Path import below
KEYS = _P(__file__).resolve().parent.parent / "keys"
from app.signals.nac import Signal

_REPORT_PERSONA = "maker"


class OfflineNac:
    """Offline signal source: recorded values when the bank kept them,
    otherwise UNAVAILABLE (confidence 0 + label — the engine's fail-strict
    semantics, never a fabricated green)."""

    def __init__(self, recorded: dict | None):
        self.recorded = recorded or {}

    def _sig(self, name, value, risk, conf, deg):
        return Signal(name, value, conf, risk, degradation=deg)

    _RISK = {"sim_swap": lambda v: 40.0 if (isinstance(v, dict) and v.get("swapped")) else 0.0,
             "number_verify": lambda v: 25.0 if v == "MISMATCH" else 0.0,
             "device_status": lambda v: 8.0 if (isinstance(v, dict) and v.get("roaming")) else 0.0,
             "device_swap": lambda v: 20.0 if (isinstance(v, dict) and v.get("swapped")) else 0.0}

    def _get(self, name, key):
        rec = self.recorded.get(key)
        if rec is None:
            return self._sig(name, None, 0.0, 0.0, "UNAVAILABLE(replay)")
        value = rec.get("value") if isinstance(rec, dict) else rec
        conf = rec.get("confidence", 1.0) if isinstance(rec, dict) else 1.0
        risk = self._RISK[key](value)
        return self._sig(name, value, risk, conf,
                         None if conf >= 1.0 else "DEGRADED(replay)")

    def sim_swap(self, msisdn, hours, deadline_remaining=None):
        return self._get("SIM_SWAP", "sim_swap")

    def number_verify(self, msisdn, dual, deadline_remaining=None):
        return self._get("NUMBER_VERIFY", "number_verify")

    def roaming(self, msisdn, deadline_remaining=None):
        return self._get("DEVICE_STATUS", "device_status")

    def device_swap(self, msisdn, deadline_remaining=None):
        return self._get("DEVICE_SWAP", "device_swap")


def _behavioral(rec: dict) -> Behavioral:
    return Behavioral(
        beneficiary_first_seen_minutes=rec.get("beneficiary_first_seen_minutes", 9999),
        attempts_last_hour=rec.get("attempts_last_hour", 0),
        amount_vs_mean=(rec["amount"] / rec["account_mean"]) if rec.get("account_mean") else 1.0,
        declared_multi_sim=rec.get("declared_multi_sim", False),
        new_payee_repeats=rec.get("new_payee_repeats", 1),
        call_in_progress=rec.get("call_in_progress", False),
        call_direction=rec.get("call_direction", "none"),
        call_duration_minutes=rec.get("call_duration_minutes", 0.0),
    )


def replay(records: list[dict], bundle: dict, title: str = "Replay Lab report") -> dict:
    """Replay records through the engine (offline) and build the signed report."""
    engine = DecisionEngine(None)          # engine only touches nac inside decide
    out_rows, bands, tiers, costs = [], {}, {}, 0.0
    bypass, caught, friction, exposure = [], [], [], []
    incumbent_matrix = {"agree": 0, "tasdiq_added": 0, "tasdiq_softer": 0, "total_labeled": 0}
    ST = {"APPROVE": 0, "ESCALATE": 1, "DECLINE": 2}

    for i, rec in enumerate(records):
        r = dict(rec)
        r.setdefault("txn_id", f"replay-{i}")
        nac = OfflineNac(r.get("signals"))
        # engine with injected offline nac
        engine.nac = nac
        verdict = engine.decide(r, bundle)
        dec, band, tier = verdict["decision"], verdict["band"], verdict["cost"]["tier"]
        # metric honesty: in sidecar mode classify by TASDIQ'S OWN rail verdict —
        # an incumbent-held escalation is not our friction, and an incumbent
        # DECLINE must not mask a Tasdiq bypass
        gov = verdict.get("governor")
        if gov:
            dec = gov["tasdiq_rail"]
        costs += verdict["cost"]["cost_estimate_usd"]
        bands[band] = bands.get(band, 0) + 1
        tiers[tier] = tiers.get(tier, 0) + 1

        row = {"txn_id": r["txn_id"], "decision": dec, "band": band, "tier": tier}
        if verdict.get("governor"):
            row["governor_tasdiq_rail"] = verdict["governor"]["tasdiq_rail"]
        if verdict.get("data_quality"):
            row["data_quality"] = verdict["data_quality"]
        fraud = rec.get("confirmed_fraud")

        if fraud is True:
            (bypass if dec == "APPROVE" else caught).append(row)
        elif fraud is False and dec != "APPROVE":
            friction.append(row)

        if tier == 0:
            b = _behavioral(r)
            cf = _counterfactual(b, {"decline_gte": verdict["thresholds_used"]["decline_gte"],
                                     "escalate_gte": verdict["thresholds_used"]["escalate_gte"]},
                                 _evaluate)
            if cf["verdict"] != "APPROVE":
                exposure.append({**row, "counterfactual": cf["verdict"]})

        inc = rec.get("incumbent_decision")
        if inc in ST:
            incumbent_matrix["total_labeled"] += 1
            if ST[dec] == ST[inc.upper()]:
                incumbent_matrix["agree"] += 1
            elif ST[dec] > ST[inc.upper()]:
                incumbent_matrix["tasdiq_added"] += 1
            else:
                incumbent_matrix["tasdiq_softer"] += 1
        out_rows.append(row)

    labeled = sum(1 for r in records if r.get("confirmed_fraud") is not None)
    # Outcome join: measured lift on REAL dispositions when provided
    lift_block = None
    if records and any(r.get("_outcome") for r in records):
        from app.outcomes import measured_lift
        outs = [r["_outcome"] for r in records if r.get("_outcome")]
        lift_block = measured_lift(outs, out_rows)
    report = {
        "title": title,
        "generated_at": int(time.time()),
        "engine": "tasdiq-replaylab/1.0",
        "policy_id": bundle.get("policy_id"),
        "policy_version_hash": None,     # filled by caller via verify_bundle result
        "signal_source": "recorded-where-available; UNAVAILABLE(replay) otherwise — offline replay, no network",
        "volumes": {"records": len(records), "labeled": labeled,
                    "bands": bands, "tiers": tiers,
                    "would_cost_usd": round(costs, 4)},
        "bypass": {"count": len(bypass), "rows": bypass,
                   "definition": "confirmed_fraud records APPROVED by the policy"},
        "caught": {"count": len(caught)},
        "friction": {"count": len(friction), "rows": friction,
                     "definition": "non-fraud records escalated/declined (false-escalation proxy)"},
        "exposure": {"count": len(exposure), "rows": exposure,
                     "definition": "tier-0 quiet approvals whose verdict would change under a hypothetical live SIM swap"},
        "incumbent": incumbent_matrix,
        **({"measured_lift": lift_block} if lift_block else {}),
        "rows": out_rows,
    }
    # policy hash + single artifact signature (maker persona by design)
    from app.policy import verify_bundle
    report["policy_version_hash"] = verify_bundle(bundle)["policy_version_hash"]
    body = {k: v for k, v in report.items() if k != "signature"}
    sig_block = {"persona": _REPORT_PERSONA, "algorithm": "Ed25519",
                 "content_hash": doc_hash(body)}
    value = load_key(_REPORT_PERSONA, KEYS).sign(canon({**body, "signature": sig_block})).hex()
    report["signature"] = {**sig_block, "value": value}
    return report


def verify_report(report: dict) -> bool:
    """Recompute the content hash + signature — any silent edit breaks it."""
    from cryptography.exceptions import InvalidSignature
    sig = report.get("signature", {})
    body = {k: v for k, v in report.items() if k != "signature"}
    if doc_hash(body) != sig.get("content_hash"):
        return False
    pub = load_key(sig.get("persona", "maker"), KEYS, private=False)
    try:
        pub.verify(bytes.fromhex(sig.get("value", "")),
                   canon({**body, "signature": {"persona": sig.get("persona"),
                                                "algorithm": sig.get("algorithm"),
                                                "content_hash": sig.get("content_hash")}}))
        return True
    except (InvalidSignature, ValueError):
        return False
