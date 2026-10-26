
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


BASE_DIR = Path(__file__).resolve().parent

LEDGER_PATH = BASE_DIR / "data" / "ledger" / "ledger.json"
CHECKPOINT_PATH = BASE_DIR / "data" / "ledger" / "checkpoint.json"

PRIVATE_KEY_PATH = (
    BASE_DIR / "data" / "keys" / "ambulance_signing_private.pem"
)
PUBLIC_KEY_PATH = (
    BASE_DIR / "data" / "keys" / "ambulance_signing_public.pem"
)


def canonical_json(data):
    """Serialize checkpoint data consistently for signing."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def load_ledger():
    """Load the existing ledger without modifying it."""
    if not LEDGER_PATH.exists():
        raise FileNotFoundError(f"Ledger not found: {LEDGER_PATH}")

    with LEDGER_PATH.open("r", encoding="utf-8") as file:
        ledger = json.load(file)

    if isinstance(ledger, list):
        blocks = ledger
    elif isinstance(ledger, dict) and isinstance(ledger.get("chain"), list):
        blocks = ledger["chain"]
    elif isinstance(ledger, dict) and isinstance(ledger.get("blocks"), list):
        blocks = ledger["blocks"]
    else:
        raise ValueError(
            "Unrecognized ledger structure. "
            "Expected a list, a 'chain' list, or a 'blocks' list."
        )

    if not blocks:
        raise ValueError("Cannot create a checkpoint for an empty ledger.")

    return blocks


def get_block_hash(block):
    """Find the stored hash field without changing the block."""
    for field in ("hash", "block_hash", "current_hash"):
        value = block.get(field)
        if isinstance(value, str) and value:
            return value

    raise ValueError(
        "Could not find the block hash field. "
        f"Available fields: {list(block.keys())}. "
        "Check your ledger.py block structure."
    )


def load_private_key():
    if not PRIVATE_KEY_PATH.exists():
        raise FileNotFoundError(
            f"Signing private key not found: {PRIVATE_KEY_PATH}\n"
            "Run: python generate_signing_keys.py"
        )

    return serialization.load_pem_private_key(
        PRIVATE_KEY_PATH.read_bytes(),
        password=None,
    )


def load_public_key():
    if not PUBLIC_KEY_PATH.exists():
        raise FileNotFoundError(
            f"Signing public key not found: {PUBLIC_KEY_PATH}"
        )

    return serialization.load_pem_public_key(
        PUBLIC_KEY_PATH.read_bytes()
    )


def sign_checkpoint():
    """Sign a checkpoint representing the latest saved ledger block."""
    blocks = load_ledger()
    latest_block = blocks[-1]

    checkpoint = {
        "checkpoint_version": 1,
        "block_count": len(blocks),
        "latest_index": latest_block["index"],
        "latest_hash": get_block_hash(latest_block),
    }

    private_key = load_private_key()

    signature = private_key.sign(
        canonical_json(checkpoint),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    signed_checkpoint = {
        **checkpoint,
        "signature": signature.hex(),
    }

    CHECKPOINT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with CHECKPOINT_PATH.open("w", encoding="utf-8") as file:
        json.dump(signed_checkpoint, file, indent=2)

    print("Checkpoint signed successfully.")
    print(f"Blocks: {checkpoint['block_count']}")
    print(f"Latest index: {checkpoint['latest_index']}")
    print(f"Latest hash: {checkpoint['latest_hash']}")
    print(f"Saved to: {CHECKPOINT_PATH}")


def verify_checkpoint():
    """Verify the checkpoint signature and compare it to the current ledger."""
    if not CHECKPOINT_PATH.exists():
        raise FileNotFoundError(
            f"Checkpoint not found: {CHECKPOINT_PATH}"
        )

    with CHECKPOINT_PATH.open("r", encoding="utf-8") as file:
        signed_checkpoint = json.load(file)

    signature_hex = signed_checkpoint.get("signature")
    if not isinstance(signature_hex, str):
        print("FAIL: Checkpoint signature is missing.")
        return False

    checkpoint = {
        key: value
        for key, value in signed_checkpoint.items()
        if key != "signature"
    }

    try:
        signature = bytes.fromhex(signature_hex)
        public_key = load_public_key()

        public_key.verify(
            signature,
            canonical_json(checkpoint),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError, TypeError):
        print("FAIL: Checkpoint signature is invalid.")
        return False

    print("PASS: Checkpoint signature is valid.")

    # Compare the signed checkpoint against the current saved ledger.
    try:
        blocks = load_ledger()
        latest_block = blocks[-1]

        if len(blocks) != checkpoint.get("block_count"):
            print("FAIL: Ledger block count does not match checkpoint.")
            return False

        if latest_block.get("index") != checkpoint.get("latest_index"):
            print("FAIL: Latest block index does not match checkpoint.")
            return False

        if get_block_hash(latest_block) != checkpoint.get("latest_hash"):
            print("FAIL: Latest block hash does not match checkpoint.")
            return False

    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"FAIL: Could not verify checkpoint against ledger: {error}")
        return False

    print("PASS: Checkpoint matches the current ledger's latest block.")
    return True

if __name__ == "__main__":
    sign_checkpoint()

    if verify_checkpoint():
        print("Checkpoint verification completed successfully.")
    else:
        raise SystemExit("Checkpoint verification failed.")