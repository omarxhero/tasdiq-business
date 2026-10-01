"""CAMARA Number Verification — full OAuth client (friend-review F1).

The 3-legged flow has three steps; only the third is environmentally blocked
in this headless prototype:

  1. client-credentials token         — implemented here, verified live
  2. authorization-code w/ device      — NaC sandbox: device-bound consent,
                                         fast-flow endpoint 404s server-side
                                         (HANDOFF §7.5, dated attempt log)
  3. verify call (phone-number match) — implemented here; requires the token
                                         from step 2, so returns a labeled
                                         error in the sandbox instead of a
                                         fabricated MATCH

Set NUMVERIFY_MODE=oauth to activate. Any failure degrades exactly like the
labeled-degraded path (confidence 0.30) — never fabricates a verification.
"""
from __future__ import annotations
import base64, json, time, urllib.request, urllib.error
import os


class NvOAuthClient:
    def __init__(self, client_id: str, client_secret: str,
                 token_endpoint: str, verify_url: str):
        self.client_id, self.client_secret = client_id, client_secret
        self.token_endpoint, self.verify_url = token_endpoint, verify_url
        self._token: str | None = None
        self._token_exp: float = 0.0

    def _get_token(self) -> str:
        if self._token and time.time() < self._token_exp - 30:
            return self._token
        basic = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode()).decode()
        req = urllib.request.Request(
            self.token_endpoint,
            data=b"grant_type=client_credentials",
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Authorization": "Basic " + basic})
        r = json.load(urllib.request.urlopen(req, timeout=10))
        self._token = r["access_token"]
        self._token_exp = time.time() + int(r.get("expires_in", 3600))
        return self._token

    def verify(self, msisdn: str) -> dict:
        """Returns {"ok": bool, "match": bool|None, "error": str|None}."""
        try:
            token = self._get_token()
        except Exception as e:
            return {"ok": False, "match": None,
                    "error": f"TOKEN({repr(e)[:60]})"}
        req = urllib.request.Request(
            self.verify_url,
            data=json.dumps({"phoneNumber": msisdn}).encode(), method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer " + token})
        try:
            raw = urllib.request.urlopen(req, timeout=10).read()
            data = json.loads(raw)
            return {"ok": True,
                    "match": bool(data.get("devicePhoneNumberVerified")),
                    "error": None}
        except urllib.error.HTTPError as e:
            return {"ok": False, "match": None, "error": f"HTTP{e.code}"}
        except Exception as e:
            return {"ok": False, "match": None, "error": repr(e)[:60]}


def client_from_env() -> NvOAuthClient | None:
    """Builds the client from NAC_OAUTH_* env vars; None when unconfigured."""
    cid, sec = os.getenv("NAC_OAUTH_CLIENT_ID"), os.getenv("NAC_OAUTH_CLIENT_SECRET")
    tok = os.getenv("NAC_OAUTH_TOKEN_ENDPOINT")
    base = os.getenv("NAC_BASE_URL",
                     "https://network-as-code.p-eu.apihub.nokia.io")
    verify_path = os.getenv(
        "NAC_NV_VERIFY_PATH",
        "passthrough/camara/v1/number-verification/number-verification/v0/verify")
    if not (cid and sec and tok):
        return None
    return NvOAuthClient(cid, sec, tok, base + "/" + verify_path)
