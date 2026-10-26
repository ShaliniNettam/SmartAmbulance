import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def canonical_json(data: dict) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def verify_checkpoint_signature(
    checkpoint_path: Path,
    trusted_public_key_path: Path,
) -> bool:
    """Verify a checkpoint using the hospital's trusted public key."""

    with checkpoint_path.open("r", encoding="utf-8") as file:
        signed_checkpoint = json.load(file)

    signature_hex = signed_checkpoint.get("signature")
    if not isinstance(signature_hex, str):
        return False

    checkpoint = {
        key: value
        for key, value in signed_checkpoint.items()
        if key != "signature"
    }

    try:
        signature = bytes.fromhex(signature_hex)

        public_key = serialization.load_pem_public_key(
            trusted_public_key_path.read_bytes()
        )

        public_key.verify(
            signature,
            canonical_json(checkpoint),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return True

    except (InvalidSignature, ValueError, TypeError):
        return False