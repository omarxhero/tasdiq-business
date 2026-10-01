"""Governor / sidecar mode — Tasdiq sits BESIDE the bank's incumbent fraud
engine instead of replacing it.

Input: the bank's existing fraud output (vendor score and/or decision)
rides along with the payment request in `mode="sidecar"`.
Semantics (the two guarantees):
  G1 NEVER DOWNGRADE — the final recommendation is always at least as
     strong as the incumbent's (monotone: raising the incumbent score can
     never weaken the final).
  G2 CAN HARDEN — Tasdiq's telecom/behavioral hard rules still fire on
     top: a live swap escalates/declines and dictates channel policy
     whatever the incumbent ML says.
Output: `governor` block on the verdict — incumbent, tasdiq (rail),
final, added reasons, and the COUNTERFACTUAL: on Tier-0 quiet traffic
(zero telecom signals bought) the verdict also states what it WOULD have
been under a hypothetical live SIM swap — per-decision evidence of the
exposure the bank is carrying without telecom entitlement. That number
aggregated over a shadow pilot IS the business case for buying coverage.

`mode="rail"` (default) runs the pure decision rail — governor block
absent, existing behavior byte-identical.
"""
from __future__ import annotations

from app.signals.nac import Signal

_STRENGTH = {"APPROVE": 0, "ESCALATE": 1, "DECLINE": 2}


def incumbent_strength(req: dict, policy: dict) -> str:
    """Map the incumbent's output to a strength using the bank's own
    thresholds (an explicit incumbent_decision overrides the score)."""
    d = (req.get("incumbent_decision") or "").upper()
    if d in _STRENGTH:
        return d
    s = req.get("incumbent_score")
    if s is None:
        return "APPROVE"
    if s >= policy.get("decline_gte", 80):
        return "DECLINE"
    if s >= policy.get("escalate_gte", 55):
        return "ESCALATE"
    return "APPROVE"


def counterfactual(behavioral, policy: dict, evaluate) -> dict:
    """What the verdict WOULD be under a hypothetical live SIM swap.
    Synthetic signal — labeled, costs $0, never enters signals_bought."""
    hypo = Signal("SIM_SWAP", {"swapped": True}, 1.0, 40.0,
                  degradation=None)
    out = evaluate([hypo], behavioral, policy)
    return {"hypothetical": "live_sim_swap",
            "verdict": out["decision"], "band": out["band"],
            "note": "synthetic signal — evidence of exposure without telecom entitlement, $0"}


def apply_governor(verdict: dict, req: dict, policy: dict, behavioral,
                   evaluate) -> dict:
    """Attach the governor block. Mutates + returns the verdict with
    `governor` and, where relevant, an upgraded final recommendation."""
    inc = incumbent_strength(req, policy)
    rail = verdict["decision"]
    final = max((inc, rail), key=lambda d: _STRENGTH[d])

    gov = {
        "mode": "sidecar",
        "incumbent": {"strength": inc,
                      "score": req.get("incumbent_score"),
                      "vendor": req.get("incumbent_vendor", ""),
                      "decision": req.get("incumbent_decision")},
        "tasdiq_rail": rail,
        "final": final,
        "added_by_tasdiq": _STRENGTH[rail] > _STRENGTH[inc],
        "counterfactual": None,
    }
    # Tier-0 quiet traffic carries the counterfactual (that is where the
    # no-coverage exposure lives)
    if verdict.get("cost", {}).get("tier") == 0:
        gov["counterfactual"] = counterfactual(behavioral, policy, evaluate)

    verdict["governor"] = gov
    if final != rail:
        # incumbent is stricter — keep Tasdiq's channel prohibitions if it
        # produced any (a swap band's SMS ban survives an incumbent-driven
        # downgrade of severity), else standard escalate allowance
        if verdict["step_up"]["prohibited"]:
            verdict["step_up"] = {"allowed": ["SMS"], "prohibited": []} \
                if not verdict["step_up"]["prohibited"] else verdict["step_up"]
        else:
            verdict["step_up"] = {"allowed": ["SMS"], "prohibited": []}
        verdict["decision"] = final
        verdict["band"] = f"GOVERNOR_HELD_{final}"
    return verdict
