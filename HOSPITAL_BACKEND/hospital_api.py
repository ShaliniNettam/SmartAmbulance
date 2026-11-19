
import os
import base64
import hashlib
import hmac
import json
from copy import deepcopy
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

from db import hospital_events, hospital_checkpoints
from pymongo.errors import DuplicateKeyError

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# PATHS AND KEY LOADERS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
KEYS_DIR = BASE_DIR / "keys"

HOSPITAL_PRIVATE_KEY_PATH = KEYS_DIR / "hospital_private.pem"
AMBULANCE_PUBLIC_KEY_PATH = KEYS_DIR / "ambulance_signing_public.pem"


def load_ambulance_public_key():
    """Load ambulance signing public key from Render environment or local file."""
    key_data = os.getenv("AMBULANCE_SIGNING_PUBLIC_KEY")

    if key_data:
        key_data = key_data.replace("\\n", "\n").encode("utf-8")
    else:
        with open(AMBULANCE_PUBLIC_KEY_PATH, "rb") as file:
            key_data = file.read()

    public_key = serialization.load_pem_public_key(key_data)

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Ambulance public key must be RSA.")

    return public_key


def load_hospital_private_key():
    """Load hospital private key from Render environment or local file."""
    key_data = os.getenv("HOSPITAL_PRIVATE_KEY")

    if key_data:
        key_data = key_data.replace("\\n", "\n").encode("utf-8")
    else:
        with open(HOSPITAL_PRIVATE_KEY_PATH, "rb") as file:
            key_data = file.read()

    private_key = serialization.load_pem_private_key(
        key_data,
        password=None,
    )

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Hospital private key must be RSA.")

    return private_key


# ============================================================
# CREATE API
# ============================================================

app = FastAPI(
    title="Smart Ambulance Hospital Backend",
    description=(
        "Hospital event verification, decryption, "
        "and independent ledger verification"
    ),
    version="1.5.0",
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
    ledger_blocks: list[dict[str, Any]]
    checkpoint: dict[str, Any]


class LedgerVerificationRequest(BaseModel):
    blocks: list[dict[str, Any]]


class CheckpointVerificationRequest(BaseModel):
    blocks: list[dict[str, Any]]
    checkpoint: dict[str, Any]


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
        "checkpoint_verification": "RSA-PSS-SHA256",
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
# AUTOMATIC VERIFIED PATIENT EVENT HISTORY
# ============================================================

@app.get("/dashboard/events")
def get_dashboard_events():
    try:
        records = list(
            hospital_events.find(
                {
                    "hash_verified": True,
                    "signature_verified": True,
                    "checkpoint_verified": True,
                    "ledger_verified": True,
                    "event_ledger_verified": True,
                },
                {"_id": 0},
            ).sort("_id", -1).limit(100)
        )

        return {
            "status": "success",
            "count": len(records),
            "events": records,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve verified hospital events.",
        ) from exc


# ============================================================
# INDEPENDENT LEDGER BLOCK HASH CALCULATION
# ============================================================

def calculate_hospital_block_hash(
    block: dict[str, Any],
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

        if (
            type(block["index"]) is not int
            or block["index"] != position
        ):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid block index at position {position}.",
            )

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

        if block["event_id"] in seen_event_ids:
            raise HTTPException(
                status_code=400,
                detail=f"Duplicate event ID in block {position}.",
            )

        seen_event_ids.add(block["event_id"])

        timestamp = block["timestamp"]

        if isinstance(timestamp, bool) or not isinstance(
            timestamp, (int, float)
        ):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid timestamp in block {position}.",
            )

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
# VERIFY SIGNED CHECKPOINT AND EVENT LEDGER ENTRY
# ============================================================

def verify_checkpoint_and_event(
    event_id: str,
    event_sha256: str,
    blocks: list[dict[str, Any]],
    checkpoint: dict[str, Any],
) -> dict[str, bool]:

    if not isinstance(checkpoint, dict):
        raise HTTPException(
            status_code=400,
            detail="Invalid checkpoint format.",
        )

    ledger_result = verify_ledger_blocks(blocks)

    if not ledger_result.get("ledger_valid"):
        raise HTTPException(
            status_code=400,
            detail="Ambulance ledger verification failed.",
        )

    if not blocks:
        raise HTTPException(
            status_code=400,
            detail="The received ledger is empty.",
        )

    signature_hex = checkpoint.get("signature")

    if not isinstance(signature_hex, str):
        raise HTTPException(
            status_code=400,
            detail="Checkpoint signature is missing.",
        )

    try:
        checkpoint_signature = bytes.fromhex(signature_hex)

        signed_data = {
            key: value
            for key, value in checkpoint.items()
            if key != "signature"
        }

        canonical_data = json.dumps(
            signed_data,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        public_key = load_ambulance_public_key()

        public_key.verify(
            checkpoint_signature,
            canonical_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    except InvalidSignature as exc:
        raise HTTPException(
            status_code=401,
            detail="Checkpoint digital signature verification failed.",
        ) from exc

    except (ValueError, TypeError, OSError) as exc:
        raise HTTPException(
            status_code=400,
            detail="Checkpoint signature or format is invalid.",
        ) from exc

    latest_block = blocks[-1]

    if (
        checkpoint.get("block_count") != len(blocks)
        or checkpoint.get("latest_index") != latest_block["index"]
        or checkpoint.get("latest_hash") != latest_block["block_hash"]
    ):
        raise HTTPException(
            status_code=400,
            detail="Checkpoint does not match the received ledger.",
        )

    matching_blocks = [
        block
        for block in blocks
        if block.get("event_id") == event_id
    ]

    if len(matching_blocks) != 1:
        raise HTTPException(
            status_code=400,
            detail=(
                "Event is missing from the ledger "
                "or appears more than once."
            ),
        )

    ledger_event_hash = matching_blocks[0].get("ciphertext_sha256")

    if (
        not isinstance(ledger_event_hash, str)
        or not hmac.compare_digest(
            ledger_event_hash,
            event_sha256,
        )
    ):
        raise HTTPException(
            status_code=400,
            detail="Event hash does not match its ledger entry.",
        )

    return {
        "checkpoint_verified": True,
        "ledger_verified": True,
        "event_ledger_verified": True,
    }


# ============================================================
# CHECKPOINT FRESHNESS
# ============================================================

def validate_checkpoint_freshness(
    ambulance_id: str,
    checkpoint: dict,
) -> dict:

    try:
        block_count = int(checkpoint["block_count"])
        latest_index = int(checkpoint["latest_index"])
        latest_hash = checkpoint["latest_hash"]

    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=400,
            detail="Checkpoint metadata is invalid.",
        ) from exc

    if (
        block_count < 1
        or latest_index != block_count - 1
        or not isinstance(latest_hash, str)
        or len(latest_hash) != 64
    ):
        raise HTTPException(
            status_code=400,
            detail="Checkpoint metadata is inconsistent.",
        )

    stored = hospital_checkpoints.find_one(
        {"ambulance_id": ambulance_id}
    )

    if stored is None:
        return {
            "ambulance_id": ambulance_id,
            "block_count": block_count,
            "latest_index": latest_index,
            "latest_hash": latest_hash,
        }

    stored_count = stored["block_count"]
    stored_hash = stored["latest_hash"]

    if block_count < stored_count:
        raise HTTPException(
            status_code=409,
            detail="Rollback rejected: checkpoint is older than the accepted checkpoint.",
        )

    if block_count == stored_count and not hmac.compare_digest(
        latest_hash, stored_hash
    ):
        raise HTTPException(
            status_code=409,
            detail="Checkpoint conflict: different ledger hash at the same height.",
        )

    return {
        "ambulance_id": ambulance_id,
        "block_count": block_count,
        "latest_index": latest_index,
        "latest_hash": latest_hash,
    }


# ============================================================
# SAVE ACCEPTED CHECKPOINT
# ============================================================

def save_accepted_checkpoint(checkpoint_record: dict) -> None:

    ambulance_id = checkpoint_record["ambulance_id"]
    block_count = checkpoint_record["block_count"]
    latest_hash = checkpoint_record["latest_hash"]

    stored = hospital_checkpoints.find_one(
        {"ambulance_id": ambulance_id}
    )

    if stored is None:
        try:
            hospital_checkpoints.insert_one({
                **checkpoint_record,
                "accepted_at": datetime.now(timezone.utc),
            })
            return

        except DuplicateKeyError:
            stored = hospital_checkpoints.find_one(
                {"ambulance_id": ambulance_id}
            )

    if stored is None:
        raise HTTPException(
            status_code=500,
            detail="Could not read the accepted checkpoint.",
        )

    stored_count = stored["block_count"]

    if block_count < stored_count:
        raise HTTPException(
            status_code=409,
            detail="Checkpoint became stale while processing the event.",
        )

    if block_count == stored_count:
        if not hmac.compare_digest(
            latest_hash, stored["latest_hash"]
        ):
            raise HTTPException(
                status_code=409,
                detail="Checkpoint conflict detected while saving.",
            )
        return

    result = hospital_checkpoints.update_one(
        {
            "_id": stored["_id"],
            "block_count": stored_count,
            "latest_hash": stored["latest_hash"],
        },
        {
            "$set": {
                **checkpoint_record,
                "accepted_at": datetime.now(timezone.utc),
            }
        },
    )

    if result.modified_count != 1:
        raise HTTPException(
            status_code=409,
            detail="Checkpoint changed concurrently. Retry the request.",
        )


# ============================================================
# RECEIVE AND VERIFY AMBULANCE EVENT
# ============================================================

@app.post("/receive-event")
def receive_event(event: AmbulanceEvent):

    try:
        nonce = base64.b64decode(event.nonce, validate=True)
        ciphertext = base64.b64decode(event.ciphertext, validate=True)
        wrapped_key = base64.b64decode(event.wrapped_aes_key, validate=True)
        signature = base64.b64decode(event.signature, validate=True)

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

    actual_hash = hashlib.sha256(
        nonce + ciphertext
    ).hexdigest()

    if not hmac.compare_digest(actual_hash, event.sha256):
        raise HTTPException(
            status_code=400,
            detail="Event hash verification failed.",
        )

    # Verify ambulance digital signature.
    try:
        public_key = load_ambulance_public_key()

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
            detail="Could not verify ambulance signature. Check the ambulance signing public key configuration.",
        ) from exc

    # Verify checkpoint and ledger.
    checkpoint_status = verify_checkpoint_and_event(
        event.event_id,
        event.sha256,
        event.ledger_blocks,
        event.checkpoint,
    )

    # Recover AES key using the hospital private key.
    try:
        private_key = load_hospital_private_key()

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

    # Decrypt event using AES-256-GCM.
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

    if decrypted_event.get("event_id") != event.event_id:
        raise HTTPException(
            status_code=400,
            detail="Event ID does not match decrypted event.",
        )

    ambulance_ids = {
        block.get("ambulance_id")
        for block in event.ledger_blocks
    }

    if len(ambulance_ids) != 1 or None in ambulance_ids:
        raise HTTPException(
            status_code=400,
            detail="Ledger contains inconsistent ambulance IDs.",
        )

    ambulance_id = next(iter(ambulance_ids))

    checkpoint_record = validate_checkpoint_freshness(
        ambulance_id,
        event.checkpoint,
    )

    hospital_record = {
        "event_id": event.event_id,
        "event_sha256": event.sha256,
        "decrypted_event": decrypted_event,
        "hash_verified": True,
        "signature_verified": True,
        "checkpoint_verified": checkpoint_status["checkpoint_verified"],
        "ledger_verified": checkpoint_status["ledger_verified"],
        "event_ledger_verified": checkpoint_status[
            "event_ledger_verified"
        ],
    }

    try:
        hospital_events.insert_one(hospital_record)
        save_accepted_checkpoint(checkpoint_record)

    except DuplicateKeyError:
        raise HTTPException(
            status_code=409,
            detail="This event has already been stored.",
        )

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Verified event or checkpoint could not be saved.",
        ) from exc

    return {
        "status": "success",
        "message": (
            "Event hash, ambulance signature, checkpoint, "
            "ledger, and decryption verified successfully."
        ),
        "hash_verified": True,
        "signature_verified": True,
        "signature_algorithm": "RSA-PSS-SHA256",
        "checkpoint_verified": checkpoint_status[
            "checkpoint_verified"
        ],
        "ledger_verified": checkpoint_status["ledger_verified"],
        "event_ledger_verified": checkpoint_status[
            "event_ledger_verified"
        ],
        "decryption_successful": True,
        "decrypted_event": decrypted_event,
    }


# ============================================================
# VERIFY LEDGER PROVIDED IN REQUEST
# ============================================================

@app.post("/verify-ledger")
def verify_ledger(request: LedgerVerificationRequest):
    return verify_ledger_blocks(request.blocks)


@app.post("/verify-local-ledger")
def verify_local_ledger(request: LedgerVerificationRequest):
    """Verify supplied ledger blocks without reading ambulance files."""
    return verify_ledger_blocks(request.blocks)


# ============================================================
# VERIFY CHECKPOINT PROVIDED BY THE REQUEST
# ============================================================

@app.post("/verify-checkpoint")
def verify_checkpoint(request: CheckpointVerificationRequest):

    if not request.blocks:
        raise HTTPException(
            status_code=400,
            detail="Ledger is empty.",
        )

    result = verify_checkpoint_and_event(
        event_id=request.blocks[-1]["event_id"],
        event_sha256=request.blocks[-1]["ciphertext_sha256"],
        blocks=request.blocks,
        checkpoint=request.checkpoint,
    )

    latest_block = request.blocks[-1]

    return {
        "status": "success",
        "message": "Supplied checkpoint signature and ledger verified.",
        **result,
        "block_count": len(request.blocks),
        "latest_index": latest_block["index"],
        "latest_hash": latest_block["block_hash"],
    }


# ============================================================
# LEDGER TAMPERING TEST
# ============================================================

@app.post("/test-ledger-tampering")
def test_ledger_tampering(request: LedgerVerificationRequest):

    tampered_blocks = deepcopy(request.blocks)

    if not tampered_blocks:
        raise HTTPException(
            status_code=400,
            detail="Ledger is empty.",
        )

    tampered_blocks[0]["event_id"] += "-TAMPERED"

    try:
        verify_ledger_blocks(tampered_blocks)

    except HTTPException as exc:
        if exc.status_code == 400:
            return {
                "status": "success",
                "tamper_detected": True,
                "message": "Hospital detected the tampered ledger.",
                "original_request_modified": False,
                "details": exc.detail,
            }
        raise

    return {
        "status": "failed",
        "tamper_detected": False,
        "message": "Tampering was not detected.",
        "original_request_modified": False,
    }


# ============================================================
# SIGNATURE TAMPERING TEST
# ============================================================

@app.post("/test-signature-tampering")
def test_signature_tampering(event: AmbulanceEvent):

    test_data = event.model_dump()
    signature_text = test_data.get("signature", "")

    try:
        signature = bytearray(
            base64.b64decode(signature_text, validate=True)
        )

        if not signature:
            raise ValueError("Event signature is empty.")

        signature[0] ^= 1

        test_data["signature"] = base64.b64encode(
            bytes(signature)
        ).decode("ascii")

    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=400,
            detail="Could not prepare the signature tampering test.",
        ) from exc

    try:
        receive_event(AmbulanceEvent(**test_data))

    except HTTPException as exc:
        if exc.status_code == 401:
            return {
                "status": "success",
                "tamper_detected": True,
                "message": "Hospital rejected the tampered digital signature.",
                "original_request_modified": False,
            }

        return {
            "status": "test_failed",
            "tamper_detected": False,
            "http_status": exc.status_code,
            "details": str(exc.detail),
            "original_request_modified": False,
        }

    return {
        "status": "test_failed",
        "tamper_detected": False,
        "message": "The tampered signature was not rejected.",
        "original_request_modified": False,
    }
