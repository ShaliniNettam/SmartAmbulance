from datetime import datetime, timezone
from pymongo.errors import DuplicateKeyError
from db import hospital_events, hospital_checkpoints

# ============================================================
# SMART AMBULANCE - HOSPITAL BACKEND
# Event Verification + Decryption + Ledger Verification
# ============================================================

import base64
import hashlib
import hmac
import json
from copy import deepcopy
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
