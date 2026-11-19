import requests
from checkpoint import sign_checkpoint, verify_checkpoint
# ============================================================
# SMART AMBULANCE - FASTAPI BACKEND
# AES-256-GCM + RSA-OAEP-SHA256 + DIGITAL SIGNATURE
# ============================================================

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from predict import predict_risk
from crypto import (
    generate_key,
    encrypt_data,
    calculate_sha256,
    wrap_aes_key,
    sign_event,
)
from ledger import HashChainLedger

import json
import time
import base64
import os
import uuid


app = FastAPI(
    title="Smart Ambulance API",
    description="Phase 1 Emergency Healthcare Backend",
    version="1.2.0",
)


# ============================================================
# DIRECTORY CONFIGURATION
# ============================================================

LEDGER_PATH = os.path.join("data", "ledger", "ledger.json")
CHECKPOINT_PATH = os.path.join("data", "ledger", "checkpoint.json")
ENCRYPTED_EVENTS_DIR = os.path.join("data", "encrypted_events")

os.makedirs(ENCRYPTED_EVENTS_DIR, exist_ok=True)

# ============================================================
# HOSPITAL API CONFIGURATION
# ============================================================

HOSPITAL_API_URL = "http://127.0.0.1:8001"
HOSPITAL_RECEIVE_URL = f"{HOSPITAL_API_URL}/receive-event"
HOSPITAL_TIMEOUT_SECONDS = 10
# ============================================================
# INITIALIZE LEDGER
# ============================================================

ledger = HashChainLedger(ledger_path=LEDGER_PATH)

print(f"Loaded {len(ledger.chain)} existing ledger blocks.")
print(
    f"Ledger integrity: "
    f"{'VALID' if ledger.verify_chain() else 'INVALID'}"
)


# ============================================================
# INPUT MODEL
# ============================================================

class VitalSignsRequest(BaseModel):
    sequence: list[list[float]]


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
def root():
    return {
        "message": "Smart Ambulance API is running",
        "status": "active",
        "encryption": "AES-256-GCM",
        "key_wrapping": "RSA-OAEP-SHA256",
        "digital_signature": "RSA-PSS-SHA256",
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "ledger_valid": ledger.verify_chain(),
        "ledger_blocks": len(ledger.chain),
    }


# ============================================================
# PREDICT, ENCRYPT, SIGN AND STORE EVENT
# ============================================================

@app.post("/predict")
def predict(request: VitalSignsRequest):

    # Validate input
    if not request.sequence:
        raise HTTPException(
            status_code=400,
            detail="The vital-sign sequence cannot be empty.",
        )

    if any(len(reading) != 6 for reading in request.sequence):
        raise HTTPException(
            status_code=400,
            detail="Each reading must contain exactly 6 vital signs.",
        )

    # Verify ledger before processing
    if not ledger.verify_chain():
        raise HTTPException(
            status_code=500,
            detail="Ledger integrity verification failed.",
        )

    # Predict patient risk
    try:
        result = predict_risk(request.sequence)
    except Exception as exc:
        print("PREDICTION ERROR:", repr(exc))
        raise HTTPException(
            status_code=500,
            detail=f"Risk prediction failed: {exc}",
        ) from exc

    # Generate a fresh AES-256 key
    key = generate_key()

    # Generate unique event ID
    event_id = f"EVENT-{uuid.uuid4().hex}"

    # Create patient event
    event = {
        "event_id": event_id,
        "patient_id": "P001",
        "ambulance_id": "AMBULANCE-001",
        "timestamp": time.time(),
        "heart_rate": request.sequence[-1][0],
        "spo2": request.sequence[-1][1],
        "respiratory_rate": request.sequence[-1][2],
        "sbp": request.sequence[-1][3],
        "dbp": request.sequence[-1][4],
        "temperature": request.sequence[-1][5],
        "risk": result["risk"],
        "probabilities": result["probabilities"],
        "model_version": "BiLSTM-Attention-v1",
    }

    # Serialize event
    event_json = json.dumps(event)

    # Encrypt event using AES-256-GCM
    nonce, ciphertext = encrypt_data(event_json, key)

    # Wrap AES key using hospital RSA public key
    try:
        wrapped_key = wrap_aes_key(key)
    except Exception as exc:
        print("KEY WRAPPING ERROR:", repr(exc))
        raise HTTPException(
            status_code=500,
            detail="Failed to wrap the AES key. Check hospital_public.pem.",
        ) from exc

    # Calculate SHA-256 of nonce + ciphertext
    ciphertext_hash = calculate_sha256(nonce, ciphertext)

    # Sign nonce + ciphertext using ambulance signing key
    try:
        signature_bytes = sign_event(nonce + ciphertext)
        signature = base64.b64encode(
            signature_bytes
        ).decode("utf-8")
    except Exception as exc:
        print("SIGNATURE ERROR:", repr(exc))
        raise HTTPException(
            status_code=500,
            detail="Failed to sign the encrypted event.",
        ) from exc

    # Prepare encrypted event
    encrypted_event_path = os.path.join(
        ENCRYPTED_EVENTS_DIR,
        f"{event_id}.json",
    )

    encrypted_event = {
        "event_id": event_id,
        "encryption_algorithm": "AES-256-GCM",
        "key_wrapping_algorithm": "RSA-OAEP-SHA256",
        "signature_algorithm": "RSA-PSS-SHA256",
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "wrapped_aes_key": base64.b64encode(
            wrapped_key
        ).decode("utf-8"),
        "sha256": ciphertext_hash,
        "signature": signature,
    }

    # Save event without overwriting an existing file
    try:
        with open(
            encrypted_event_path,
            "x",
            encoding="utf-8",
        ) as file:
            json.dump(encrypted_event, file, indent=4)
            file.flush()
            os.fsync(file.fileno())
    except OSError as exc:
        print("EVENT SAVE ERROR:", repr(exc))
        raise HTTPException(
            status_code=500,
            detail="Failed to save the encrypted patient event.",
        ) from exc

    # Append event to ledger
    try:
        ledger.add_block(
            event_id=event_id,
            ambulance_id=event["ambulance_id"],
            model_version=event["model_version"],
            ciphertext_sha256=ciphertext_hash,
        )
    except Exception as exc:
        print("LEDGER ERROR:", repr(exc))
        try:
            if os.path.exists(encrypted_event_path):
                os.remove(encrypted_event_path)
        except OSError:
            pass

        raise HTTPException(
            status_code=500,
            detail="Failed to append the event to the ledger.",
        ) from exc

    # Verify ledger after insertion
    ledger_valid = ledger.verify_chain()

    if not ledger_valid:
        raise HTTPException(
            status_code=500,
            detail="Ledger verification failed after event insertion.",
        )

    # Generate and verify a fresh checkpoint.
    try:
        sign_checkpoint()

        if not verify_checkpoint():
            raise RuntimeError("Checkpoint verification failed.")

    except Exception as exc:
        print("CHECKPOINT ERROR:", repr(exc))
        raise HTTPException(
            status_code=500,
            detail=(
                "Event saved, but checkpoint generation or "
                "verification failed. Hospital delivery skipped."
            ),
        ) from exc

    # Send the encrypted event and verification data to the hospital.
    try:
        # Load the latest signed checkpoint.
        with open(CHECKPOINT_PATH, "r", encoding="utf-8") as file:
            checkpoint = json.load(file)

        # Include the ledger and checkpoint with the encrypted event.
        hospital_payload = {
            **encrypted_event,
            "ledger_blocks": ledger.chain,
            "checkpoint": checkpoint,
        }

        response = requests.post(
            HOSPITAL_RECEIVE_URL,
            json=hospital_payload,
            timeout=HOSPITAL_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        hospital_result = response.json()

    except (requests.RequestException, OSError, json.JSONDecodeError) as exc:
        print("HOSPITAL DELIVERY ERROR:", repr(exc))
        raise HTTPException(
            status_code=502,
            detail={
                "message": (
                    "Event and checkpoint saved, but hospital "
                    "delivery failed. Do not create another event "
                    "to retry delivery."
                ),
                "event_id": event_id,
            },
        ) from exc
    # Return the prediction and hospital verification result.
    return {
        "event_id": event_id,
        "risk": result["risk"],
        "probabilities": result["probabilities"],
        "inference_time_ms": result["inference_time_ms"],
        "encryption_key_generated": True,
        "key_wrapped_for_hospital": True,
        "encryption_algorithm": "AES-256-GCM",
        "key_wrapping_algorithm": "RSA-OAEP-SHA256",
        "signature_generated": True,
        "signature_algorithm": "RSA-PSS-SHA256",
        "sha256": ciphertext_hash,
        "ledger_valid": ledger_valid,
        "ledger_blocks": len(ledger.chain),
        "checkpoint_updated": True,
        "hospital_delivery": "success",
        "hospital_response": hospital_result,
    }

# ============================================================
# MAX30102 SENSOR EVENT - SECURE HOSPITAL DELIVERY
# Does not modify or invoke the existing prediction model.
# ============================================================

class SensorEventRequest(BaseModel):
    heart_rate: float
    spo2: float
    device: str = "MAX30102"
    timestamp: str | None = None


@app.post("/sensor-event")
def create_sensor_event(request: SensorEventRequest):

    if not 30 <= request.heart_rate <= 220:
        raise HTTPException(
            status_code=400,
            detail="Heart rate is outside the accepted sensor range."
        )

    if not 70 <= request.spo2 <= 100:
        raise HTTPException(
            status_code=400,
            detail="SpO2 is outside the accepted sensor range."
        )

    if not ledger.verify_chain():
        raise HTTPException(
            status_code=500,
            detail="Ledger integrity verification failed."
        )

    event_id = f"SENSOR-{uuid.uuid4().hex}"

    event = {
        "event_id": event_id,
        "event_type": "sensor_telemetry",
        "patient_id": "P001",
        "ambulance_id": "AMBULANCE-001",
        "timestamp": time.time(),
        "sensor_timestamp": request.timestamp,
        "heart_rate": request.heart_rate,
        "spo2": request.spo2,
        "device": request.device,
        "risk": None,
        "prediction_status": "not_performed",
        "model_version": "MAX30102-SENSOR-v1"
    }

    key = generate_key()
    event_json = json.dumps(event)

    nonce, ciphertext = encrypt_data(event_json, key)
    wrapped_key = wrap_aes_key(key)

    ciphertext_hash = calculate_sha256(nonce, ciphertext)

    signature = base64.b64encode(
        sign_event(nonce + ciphertext)
    ).decode("utf-8")

    encrypted_event = {
        "event_id": event_id,
        "encryption_algorithm": "AES-256-GCM",
        "key_wrapping_algorithm": "RSA-OAEP-SHA256",
        "signature_algorithm": "RSA-PSS-SHA256",
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "wrapped_aes_key": base64.b64encode(wrapped_key).decode("utf-8"),
        "sha256": ciphertext_hash,
        "signature": signature
    }

    encrypted_event_path = os.path.join(
        ENCRYPTED_EVENTS_DIR,
        f"{event_id}.json"
    )

    try:
        with open(encrypted_event_path, "x", encoding="utf-8") as file:
            json.dump(encrypted_event, file, indent=4)
            file.flush()
            os.fsync(file.fileno())

        ledger.add_block(
            event_id=event_id,
            ambulance_id=event["ambulance_id"],
            model_version=event["model_version"],
            ciphertext_sha256=ciphertext_hash
        )

        if not ledger.verify_chain():
            raise RuntimeError("Ledger verification failed.")

        sign_checkpoint()

        if not verify_checkpoint():
            raise RuntimeError("Checkpoint verification failed.")

        with open(CHECKPOINT_PATH, "r", encoding="utf-8") as file:
            checkpoint = json.load(file)

        hospital_payload = {
            **encrypted_event,
            "ledger_blocks": ledger.chain,
            "checkpoint": checkpoint
        }

        response = requests.post(
            HOSPITAL_RECEIVE_URL,
            json=hospital_payload,
            timeout=HOSPITAL_TIMEOUT_SECONDS
        )
        response.raise_for_status()

        hospital_result = response.json()

    except Exception as exc:
        print("SENSOR EVENT ERROR:", repr(exc))

        raise HTTPException(
            status_code=502,
            detail={
                "message": (
                    "Sensor event processing or hospital delivery failed. "
                    "Check the saved event and ledger before retrying."
                ),
                "event_id": event_id
            }
        ) from exc

    return {
        "status": "success",
        "event_id": event_id,
        "event_type": "sensor_telemetry",
        "prediction_performed": False,
        "encryption": "AES-256-GCM",
        "signature": "RSA-PSS-SHA256",
        "ledger_valid": True,
        "checkpoint_verified": True,
        "hospital_delivery": "success",
        "hospital_response": hospital_result
    }

