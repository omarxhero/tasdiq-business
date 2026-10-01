# Tasdiq — Deterministic Security, Generative Compliance
## A telecom-verified decision architecture for MENA instant payments
**تصديق — طبقة قرار موثّقة بإشارات الاتصالات لمدفوعات MENA الفورية**

*Technical white paper · v1.0 · September 2026 · github.com/omarxhero/tasdiq · tasdiq-demo.onrender.com*

---

### 1. The problem

Instant payment rails (Sarie, InstaPay, Aani, FAST) settle in seconds;
account-takeover fraud that succeeds is unrecoverable. The strongest early
signal of a takeover — a fresh SIM swap, a device re-registration — lives at
the telecom layer, standardized today by GSMA Open Gateway / CAMARA. But an
operator sells *facts*; a bank needs a *decision* it can defend to a
regulator. Tasdiq is the operator-neutral layer between them, built on one
principle: **the machine that decides must be deterministic; the machine
that explains may be generative.**

### 2. Three defensible claims

**C1 — Deadline-budgeted progressive telecom fusion with
degrade-never-approve semantics.** One API call queries CAMARA signals in
two phases inside a 450 ms budget (phase 1: SIM Swap with early exit;
phase 2: parallel signals + bank behavioral scoring). Confidence weighting
folds signal reliability into the score; six hard rules override it. When a
signal is missing or degraded — outage, timeout, consent unavailable — its
confidence drops to zero and the rules *tighten*: coverage and
primary-loss rules escalate, step-up collapses to in-app biometrics, and
SMS one-time codes are prohibited after any swap signal (the OTP would be
delivered to the attacker's SIM). **An attacker who forces a degraded state
forces a stricter bank, never a blinder one.** Idempotent by transaction
identifier; retried requests replay the recorded decision, never re-decide.

**C2 — Cryptographically signed maker-checker policy, bound to every
decision.** Bank policy bundles (thresholds, multipliers, windows) are
Ed25519-signed by two personas; a tampered bundle is rejected on every
call, and each decision record carries the policy version hash it was
evaluated under — a decision can be replayed against the exact rules that
produced it. Every decision appends to a hash-chained, pseudonymized audit
ledger (HMAC-masked MSISDNs) whose verifier *recomputes* record content, so
silent edits break the chain, not just links; tips are anchored to RFC 3161
timestamps on a background worker — anchoring latency never touches the
decision path (our own load test caught and fixed that).

**C3 — A PII-sealed AI lane where the model structurally cannot see free
text.** The generative agent runs strictly *after* the decision. Its tools
take opaque identifiers; the vault resolves phone numbers inside the tool
boundary only. Untrusted text (memos) is excluded from model context by
construction — asserted by a structural injection canary in CI. Outputs are
schema-constrained server-side with deterministic template fallback, and
probe selection during attack investigations is a deterministic
proportionality policy in code — **the policy decides, the agent executes,
the LLM explains.** Every action, including skipped probes, is
ledger-recorded.

### 3. Receipts (independent verification)

| Claim | Evidence |
|---|---|
| 27/27 automated tests | rule ordering, tamper rejection, injection canary, ledger integrity under concurrency, idempotent replay — CI-enforced |
| Latency, dual-reported | live: p50 334 ms end-to-end / 3 ms internal (16 runs, raw data in repo); offline: ledger append p99 <1 ms, engine internal p99 ≈ 3.7 ms |
| Throughput | ~3,000 chained appends/s single process (evidence/load_test.json) |
| Detection | 208-case three-split ablation: +0.51 incremental recall from telecom signals on held-out; **2 boundary misses published** — honestly scoped as internal consistency on our generator, not field accuracy |
| Live integrations | 3 CAMARA signals live through the pipeline; Number Verification: full OAuth client wired, device-bound consent documented as the environmental limit — degraded, never fabricated |

### 4. What Tasdiq is not

Not legal identity verification; not APP-scam or mule coverage; not a
certified product. The bank remains controller and decision owner; Tasdiq
supplies signed, explainable risk evidence. Production deltas — KMS/HSM key
custody (today's maker-checker keys are single-machine and we say so),
mTLS, data residency, MNP-aware routing — are stated in
`docs/PRODUCTION_DELTA.md` before any reviewer finds them.

---

### الملخص التنفيذي (عربي)

**تصديق** طبقةُ قرارٍ وسيطة بين مشغّلي الاتصالات والمصارف لمدفوعات MENA
الفورية. قبل إطلاق أي دفعة، يستعلم المحرّك عن إشارات CAMARA (تبديل الشريحة،
التحقّق من الرقم، حالة الجهاز، تبديل الجهاز) خلال ميزانية 450 ملّي ثانية،
ويدمجها مع سلوك العميل في قرار حتمي: اعتماد، تصعيد، أو رفض. بعد أي تبديل
شريحة يُمنع التحقّق عبر الرسائل النصية قطعياً — لأن رمز التحقق سيصل إلى
المهاجم — ويُستبدل بالبصمة داخل التطبيق. غيابُ أي إشارة يشدّد القرار ولا
يُضعفه أبداً. سياسات المصرف موقّعة رقمياً (Ed25519) ومرتبطة بكل قرار في
سجلّ تدقيقٍ متسللسل التشفير ومُلبَّه الهوية. أمّا الوكيل الذكائي فيعمل بعد
القرار فقط: يكتب التقارير الثنائية اللغة للمُشرّف، ويحقّق في الهجمات
المنسّقة عبر حزام أدواتٍ مختوم لا يرى النصوص الحرة — **السياسة تقرّر،
والذكاء يشرح.** كل الادعاءات مُثبتة باختبارات آلية (27/27) وقياسات منشورة،
والحدود المعلنة جزء من التصميم: لا نتاجر بالثقة.

---

*Omar Chehade · Beirut Arab University · built during MENA Ignite 2026 (GSMA + Nokia NaC program). Contact: tasdiq.project@gmail.com ·  · [entity]*
