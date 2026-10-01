"""First-run bootstrap: the repo ships PUBLIC keys only (signatures verify);
private keypairs for local test runs are generated here if missing — the
same personas the fixtures use (maker / checker / channellock)."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.policy import gen_keypair

KEYS = Path(__file__).resolve().parent.parent / "keys"
for persona in ("maker", "checker", "channellock"):
    if not (KEYS / f"{persona}.key").exists():
        gen_keypair(persona, KEYS)
