from pathlib import Path
from checkpoint_verifier import verify_checkpoint_signature

BASE_DIR = Path(__file__).resolve().parent

checkpoint_path = BASE_DIR / "checkpoint.json"
public_key_path = (
    BASE_DIR / "keys" / "ambulance_signing_public.pem"
)

result = verify_checkpoint_signature(
    checkpoint_path,
    public_key_path,
)

print("Checkpoint signature verified:", result)

if not result:
    raise SystemExit("Checkpoint verification FAILED")