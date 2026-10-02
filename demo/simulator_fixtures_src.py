"""Demo-tenant policy simulator fixtures.

Every preset is a JSON fixture consumed by BOTH the simulator page
(demo/policy_simulator.html) and pytest (tests/test_simulator.py) —
demo and tests can never drift apart. Each fixture pins the EXPECTED
verdict, so the page's claims are contract-tested.

Rules (panel-corrected spec):
  - demo tenant only, sandbox numbers only, demo policy, demo ledger
  - presets demo the FIXES, not just the engine
  - bands + reasons shown; raw thresholds never shown (no oracle)
"""
import json
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "demo" / "simulator_fixtures"

# sandbox numbers (simulator-only; the commercial coverage gate stays closed)
SWAPPED = "+99999991000"
CLEAN = "+99999991001"

BASE = {"amount": 120.0, "account_mean": 100.0,
        "beneficiary_first_seen_minutes": 9999, "attempts_last_hour": 0}

PRESETS = [
    {
        "scenario_id": "quiet_legitimate_v1",
        "title_en": "Quiet legitimate transfer",
        "title_ar": "تحويل عادي سليم",
        "input": {**BASE, "msisdn": CLEAN},
        "expected": {"decision": "APPROVE", "band": "CLEAN",
                     "tier": 0, "cost_usd": 0.0,
                     "sms_grantable": False},
        "teaches_en": "Tier 0 — no signal bought, $0, no OTP at all",
        "teaches_ar": "المستوى ٠ — لا إشارة، صفر تكلفة، لا OTP إطلاقًا",
    },
    {
        "scenario_id": "sim_swap_attack_v1",
        "title_en": "Live SIM swap + value spike",
        "title_ar": "تبديل شريحة نشط + مبلغ ضخم",
        "input": {"msisdn": SWAPPED, "amount": 50000.0, "account_mean": 1000.0,
                  "beneficiary_first_seen_minutes": 9999, "attempts_last_hour": 0},
        "expected": {"decision": "DECLINE", "band": "SIM_SWAP_INSTANT_PATTERN",
                     "tier": 2, "cost_usd": 0.07,
                     "sms_grantable": False, "sms_prohibited": True},
        "teaches_en": "Phase-1 early exit — the OTP never had a chance",
        "teaches_ar": "خروج مبكر — الـOTP لم تتح له فرصة",
    },
    {
        "scenario_id": "patient_attacker_v1",
        "title_en": "Patient attacker (Tier-0 bypass attempt)",
        "title_ar": "مهاجم صبور (محاولة تجاوز)",
        "input": {"msisdn": SWAPPED, "amount": 1500.0, "account_mean": 100.0,
                  "beneficiary_first_seen_minutes": 120, "attempts_last_hour": 0,
                  "recent_sensitive_event": "credential_reset",
                  "sensitive_event_minutes_ago": 15},
        "expected": {"decision": "ESCALATE", "band": "SIM_SWAP_RECENT",
                     "tier": 2, "cost_usd": 0.21,
                     "sms_prohibited": True},
        "teaches_en": "Waits out the radar — but a credential reset forces the SIM check (I6)",
        "teaches_ar": "ينتظر خارج الرادار — لكن إعادة تعيين كلمة المرور تفرض فحص الشريحة",
    },
    {
        "scenario_id": "dilution_attack_v1",
        "title_en": "Dilution attack (floor holds)",
        "title_ar": "هجوم التمييع (الأرضية تصمد)",
        "input": {"msisdn": SWAPPED, "amount": 3000.0, "account_mean": 100.0,
                  "beneficiary_first_seen_minutes": 3, "attempts_last_hour": 0},
        "expected": {"decision": "DECLINE", "band": "SIM_SWAP_HIGH_RISK",
                     "tier": 2, "weighted_risk_min": 36.0,   # floor property: >= 0.9x40 even under cached-fallback conf
                     "sms_prohibited": True, "biometric_allowed": True},
        "teaches_en": "Three green signals cannot wash one red — the floor keeps 40",
        "teaches_ar": "ثلاث إشارات خضراء لا تغسل الحمراء — الأرضية تحفظ ٤٠",
    },
    {
        "scenario_id": "coached_call_v1",
        "title_en": "Coached payment (call in progress)",
        "title_ar": "دفعة تحت التوجيه (مكالمة جارية)",
        "input": {"msisdn": CLEAN, "amount": 150.0, "account_mean": 100.0,
                  "beneficiary_first_seen_minutes": 9999, "attempts_last_hour": 0,
                  "call_in_progress": True, "call_direction": "inbound",
                  "call_duration_minutes": 9.0},
        "expected": {"decision": "ESCALATE", "band": "COOLING_OFF_HOLD",
                     "hold_release_minutes": 30, "no_channel_grantable": True},
        "teaches_en": "Nothing completes while the scammer is on the line (R8)",
        "teaches_ar": "لا يكتمل شيء والمحتال على الخط",
    },
    {
        "scenario_id": "payee_velocity_v1",
        "title_en": "Mule-distribution tell (trap fires)",
        "title_ar": "نمط التوزيع (الفخ ينطلق)",
        "input": {"msisdn": CLEAN, "amount": 150.0, "account_mean": 100.0,
                  "beneficiary_first_seen_minutes": 4, "attempts_last_hour": 0,
                  "new_payee_repeats": 2},
        "expected": {"decision": "ESCALATE", "band": "PAYEE_VELOCITY_TRAP",
                     "sms_prohibited": True},
        "teaches_en": "Second attempt to a fresh payee — hard rule, no threshold can disable it",
        "teaches_ar": "المحاولة الثانية لمستفيد جديد — قاعدة صلبة لا يعطلها أي حد",
    },
    {
        "scenario_id": "governor_green_incumbent_v1",
        "title_en": "Incumbent says risky, telecom clean",
        "title_ar": "المحرك الحالي يقول خطر والشبكة سليمة",
        "input": {"msisdn": CLEAN, "amount": 120.0, "account_mean": 100.0,
                  "beneficiary_first_seen_minutes": 9999, "attempts_last_hour": 0,
                  "mode": "sidecar", "incumbent_score": 55.0,
                  "incumbent_vendor": "feedzai"},
        "expected": {"decision": "ESCALATE", "band": "GOVERNOR_HELD_ESCALATE",
                     "governor_final": "ESCALATE", "counterfactual": True},
        "teaches_en": "Never downgrades your engine — and shows what a swap would have changed",
        "teaches_ar": "لا يُضعف محركك أبدًا — ويعرض ما كان سيغيّره التبديل",
    },
    {
        "scenario_id": "unknown_context_v1",
        "title_en": "Missing context (screened, never clean)",
        "title_ar": "سياق ناقص (فحص، لا افتراض سلامة)",
        "input": {"msisdn": CLEAN, "amount": 1500.0,
                  "beneficiary_first_seen_minutes": 120},
        "expected": {"decision": "APPROVE", "band": "CLEAN",
                     "tier": 1, "trigger_prefix": "unknown:",
                     "unknown_fields": ["attempts", "account_mean"]},
        "teaches_en": "Omitted fields are UNKNOWN — screened with evidence, never assumed clean",
        "teaches_ar": "الحقول الغائبة مجهولة — فحص بدليل، لا افتراض سلامة",
    },
]


def write_fixtures() -> list[Path]:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    written = []
    for p in PRESETS:
        f = FIXTURES_DIR / f"{p['scenario_id']}.json"
        f.write_text(json.dumps(p, indent=2, ensure_ascii=False), encoding="utf-8")
        written.append(f)
    return written


if __name__ == "__main__":
    for f in write_fixtures():
        print("wrote", f.name)
