# ============================================================
# SMART AMBULANCE - HOSPITAL BACKEND
# Event Verification + Decryption + Ledger Verification
# ============================================================

import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
KEYS_DIR = BASE_DIR / "keys"

HOSPITAL_PRIVATE_KEY_PATH = KEYS_DIR / "hospital_private.pem"
AMBULANCE_PUBLIC_KEY_PATH = KEYS_DIR / "ambulance_signing_public.pem"

# Actual ambulance ledger location
AMBULANCE_LEDGER_PATH = (
    BASE_DIR.parent
    / "AMBULANCE"
    / "data"
    / "ledger"
    / "ledger.json"
)

AMBULANCE_CHECKPOINT_PATH = (
    BASE_DIR.parent
    / "AMBULANCE"
    / "data"
    / "ledger"
    / "checkpoint.json"
)

# ============================================================
# CREATE API
# ============================================================

app = FastAPI(
    title="Smart Ambulance Hospital Backend",
    description=(
        "Hospital event verification, decryption, "
        "and independent ledger verification"
    ),
    version="1.4.0",
)


# ============================================================
# REQUEST MODELS
# ============================================================

class AmbulanceEvent(BaseModel):
    event_id: str
    nonce: str
    ciphertext: str
    wrapped_aes_key: str
    sha256: str
    signature: str


class LedgerVerificationRequest(BaseModel):
    blocks: list[dict[str, Any]]


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "message": "Smart Ambulance Hospital Backend is running",
        "status": "active",
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "signature_verification": "RSA-PSS-SHA256",
        "encryption": "AES-256-GCM",
        "ledger_verification": "SHA-256 hash chain",
    }


# ============================================================
# HOSPITAL DASHBOARD
# ============================================================

@app.get("/dashboard", include_in_schema=False)
def hospital_dashboard():
    dashboard_file = BASE_DIR / "hospital_dashboard.html"

    if not dashboard_file.is_file():
        raise HTTPException(
            status_code=404,
            detail="Hospital dashboard file not found.",
        )

    return FileResponse(dashboard_file)


# ============================================================
# RECEIVE AND VERIFY AMBULANCE EVENT
# ============================================================

@app.post("/receive-event")
def receive_event(event: AmbulanceEvent):

    # Decode incoming data
    try:
        nonce = base64.b64decode(event.nonce, validate=True)
        ciphertext = base64.b64decode(
            event.ciphertext, validate=True
        )
        wrapped_key = base64.b64decode(
            event.wrapped_aes_key, validate=True
        )
        signature = base64.b64decode(
            event.signature, validate=True
        )

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid base64 encoding in event data.",
        ) from exc

    if len(nonce) != 12:
        raise HTTPException(
            status_code=400,
            detail="Invalid AES-GCM nonce length.",
        )

    # Verify event hash
    actual_hash = hashlib.sha256(
        nonce + ciphertext
    ).hexdigest()

    if not hmac.compare_digest(actual_hash, event.sha256):
        raise HTTPException(
            status_code=400,
            detail="Event hash verification failed.",
        )

    # Verify ambulance digital signature
    try:
        with open(AMBULANCE_PUBLIC_KEY_PATH, "rb") as file:
            public_key = serialization.load_pem_public_key(
                file.read()
            )

        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Ambulance public key must be RSA.")

        public_key.verify(
            signature,
            nonce + ciphertext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    except InvalidSignature as exc:
        raise HTTPException(
            status_code=401,
            detail="Ambulance digital signature verification failed.",
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Could not verify ambulance signature. "
                "Check keys/ambulance_signing_public.pem."
            ),
        ) from exc

    # Recover AES key using hospital private key
    try:
        with open(HOSPITAL_PRIVATE_KEY_PATH, "rb") as file:
            private_key = serialization.load_pem_private_key(
                file.read(),
                password=None,
            )

        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Hospital private key must be RSA.")

        aes_key = private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Hospital could not recover the AES key.",
        ) from exc

    # Decrypt event
    try:
        plaintext = AESGCM(aes_key).decrypt(
            nonce,
            ciphertext,
            None,
        )

        decrypted_event = json.loads(
            plaintext.decode("utf-8")
        )

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Event decryption or JSON validation failed.",
        ) from exc

    # Verify event ID
    if decrypted_event.get("event_id") != event.event_id:
        raise HTTPException(
            status_code=400,
            detail="Event ID does not match decrypted event.",
        )

    return {
        "status": "success",
        "message": (
            "Event hash, ambulance signature, "
            "and decryption verified successfully."
        ),
        "hash_verified": True,
        "signature_verified": True,
        "signature_algorithm": "RSA-PSS-SHA256",
        "decryption_successful": True,
        "decrypted_event": decrypted_event,
    }


# ============================================================
# INDEPENDENT LEDGER BLOCK HASH CALCULATION
# Must match the ambulance ledger.py algorithm
# ============================================================

def calculate_hospital_block_hash(
    block: dict[str, Any]
) -> str:

    block_data = (
        str(block["index"])
        + block["event_id"]
        + block["ambulance_id"]
        + str(block["timestamp"])
        + block["model_version"]
        + block["ciphertext_sha256"]
        + block["previous_hash"]
    )

    return hashlib.sha256(
        block_data.encode("utf-8")
    ).hexdigest()


# ============================================================
# VERIFY LEDGER BLOCKS
# Shared by both ledger verification endpoints
# ============================================================

def verify_ledger_blocks(blocks: list[dict[str, Any]]):

    if not isinstance(blocks, list) or not blocks:
        raise HTTPException(
            status_code=400,
            detail="Ledger is empty or invalid.",
        )

    required_fields = {
        "index",
        "event_id",
        "ambulance_id",
        "timestamp",
        "model_version",
        "ciphertext_sha256",
        "previous_hash",
        "block_hash",
    }

    seen_event_ids = set()

    for position, block in enumerate(blocks):

        if not isinstance(block, dict):
            raise HTTPException(
                status_code=400,
                detail=f"Block {position} must be a JSON object.",
            )

        missing = required_fields - set(block.keys())

        if missing:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Block {position} is missing fields: "
                    f"{sorted(missing)}"
                ),
            )

        # Verify block index
        if (
            type(block["index"]) is not int
            or block["index"] != position
        ):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid block index at position {position}.",
            )

        # Validate string fields
        for field in (
            "event_id",
            "ambulance_id",
            "model_version",
            "ciphertext_sha256",
            "previous_hash",
            "block_hash",
        ):
            if not isinstance(block[field], str) or not block[field]:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid {field} in block {position}.",
                )

        # Verify unique event IDs
        if block["event_id"] in seen_event_ids:
            raise HTTPException(
                status_code=400,
                detail=f"Duplicate event ID in block {position}.",
            )

        seen_event_ids.add(block["event_id"])

        # Validate timestamp
        timestamp = block["timestamp"]

        if isinstance(timestamp, bool) or not isinstance(
            timestamp, (int, float)
        ):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid timestamp in block {position}.",
            )

        # Verify chain linkage
        if position == 0:
            expected_previous_hash = "0" * 64
        else:
            expected_previous_hash = blocks[position - 1][
                "block_hash"
            ]

        if block["previous_hash"] != expected_previous_hash:
            raise HTTPException(
                status_code=400,
                detail=f"Previous-hash link failed at block {position}.",
            )

        # Independently recalculate the block hash
        calculated_hash = calculate_hospital_block_hash(block)

        if not hmac.compare_digest(
            calculated_hash,
            block["block_hash"],
        ):
            raise HTTPException(
                status_code=400,
                detail=f"Block hash verification failed at block {position}.",
            )

    return {
        "status": "success",
        "message": "Hospital independently verified the ledger chain.",
        "ledger_valid": True,
        "blocks_verified": len(blocks),
        "latest_event_id": blocks[-1]["event_id"],
        "latest_block_hash": blocks[-1]["block_hash"],
    }


# ============================================================
# VERIFY LEDGER PROVIDED IN REQUEST
# POST /verify-ledger
# ============================================================

@app.post("/verify-ledger")
def verify_ledger(request: LedgerVerificationRequest):
    return verify_ledger_blocks(request.blocks)


# ============================================================
# VERIFY THE ACTUAL AMBULANCE ledger.json FILE
# GET /verify-local-ledger
# ============================================================

@app.get("/verify-local-ledger")
def verify_local_ledger():

    if not AMBULANCE_LEDGER_PATH.is_file():
        raise HTTPException(
            status_code=404,
            detail=(
                "Ambulance ledger file not found at: "
                f"{AMBULANCE_LEDGER_PATH}"
            ),
        )

    try:
        with open(
            AMBULANCE_LEDGER_PATH,
            "r",
            encoding="utf-8",
        ) as file:
            blocks = json.load(file)

    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail="Ambulance ledger.json contains invalid JSON.",
        ) from exc

    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail="Could not read the ambulance ledger file.",
        ) from exc

    # Verify the actual blocks read from disk
    result = verify_ledger_blocks(blocks)

    result["ledger_source"] = str(AMBULANCE_LEDGER_PATH)

    return result
# ============================================================
# LEDGER TAMPER TEST
# Tests a modified copy without changing the real ledger
# ============================================================

@app.get("/test-ledger-tampering")
def test_ledger_tampering():

    if not AMBULANCE_LEDGER_PATH.is_file():
        raise HTTPException(
            status_code=404,
            detail="Ambulance ledger file not found.",
        )

    with open(AMBULANCE_LEDGER_PATH, "r", encoding="utf-8") as file:
        original_blocks = json.load(file)

    if not original_blocks:
        raise HTTPException(
            status_code=400,
            detail="Ledger is empty.",
        )

    # Make an independent copy in memory
    tampered_blocks = json.loads(json.dumps(original_blocks))

    # Change data in the copy, without updating its hash
    tampered_blocks[0]["event_id"] = (
        tampered_blocks[0]["event_id"] + "-TAMPERED"
    )

    try:
        verify_ledger_blocks(tampered_blocks)

    except HTTPException as exc:
        if exc.status_code == 400:
            return {
                "status": "success",
                "tamper_detected": True,
                "message": "SUCCESS: Hospital detected the tampered ledger.",
                "real_ledger_modified": False,
                "details": exc.detail,
            }
        raise

    return {
        "status": "failed",
        "tamper_detected": False,
        "message": "WARNING: Tampering was not detected.",
        "real_ledger_modified": False,
    }

@app.get("/test-signature-tampering")
def test_signature_tampering():
    import base64
    import json
    from copy import deepcopy
    from fastapi import HTTPException

    events_dir = AMBULANCE_LEDGER_PATH.parent.parent / "encrypted_events"

    event_files = sorted(
        events_dir.glob("EVENT-*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if not event_files:
        raise HTTPException(
            status_code=404,
            detail="No encrypted event files found."
        )

    with open(event_files[0], "r", encoding="utf-8") as f:
        original_data = json.load(f)

    # Modify a copy only; the real event file stays unchanged.
    test_data = deepcopy(original_data)

    signature = bytearray(
        base64.b64decode(test_data["signature"], validate=True)
    )
    signature[0] ^= 1
    test_data["signature"] = base64.b64encode(
        bytes(signature)
    ).decode("ascii")

    try:
        receive_event(AmbulanceEvent(**test_data))
    except HTTPException as exc:
        if exc.status_code == 401:
            return {
                "status": "success",
                "tamper_detected": True,
                "message": "SUCCESS: Hospital rejected the tampered digital signature.",
                "real_event_modified": False,
            }

        return {
            "status": "test_failed",
            "tamper_detected": False,
            "http_status": exc.status_code,
            "details": str(exc.detail),
            "real_event_modified": False,
        }

    return {
        "status": "test_failed",
        "tamper_detected": False,
        "message": "The tampered signature was not rejected.",
        "real_event_modified": False,
    }