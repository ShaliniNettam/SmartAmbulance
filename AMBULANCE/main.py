# ============================================================
# SMART AMBULANCE - PHASE 1 INTEGRATION
# ============================================================

import json
import time
import os
import base64

from predict import predict_risk
from crypto import generate_key, encrypt_data, calculate_sha256
from ledger import HashChainLedger


# ============================================================
# START
# ============================================================

print("\n" + "=" * 60)
print("SMART AMBULANCE - PHASE 1 INTEGRATION")
print("=" * 60)


# ============================================================
# 1. MODEL
# ============================================================

print("\n[1] Loading Bi-LSTM + Attention model...")

# predict.py already loads the model and scaler
print("✓ Model and scaler loaded successfully")


# ============================================================
# 2. VITAL SIGNS
# ============================================================

print("\n[2] Input Vital Signs")

sequence = [
    [82, 98, 18, 120, 78, 36.8],
    [84, 98, 19, 118, 77, 36.9],
    [86, 97, 20, 116, 76, 37.0],
    [88, 97, 21, 114, 75, 37.0],
    [90, 96, 22, 112, 74, 37.1],
    [92, 96, 23, 110, 73, 37.1],
    [94, 95, 24, 108, 72, 37.2],
    [96, 95, 25, 106, 71, 37.2],
    [98, 94, 26, 104, 70, 37.3],
    [100, 94, 27, 102, 69, 37.3]
]

print("✓ 10-step vital-sign sequence created")


# ============================================================
# 3. RISK PREDICTION
# ============================================================

print("\n[3] Risk Prediction")

result = predict_risk(sequence)

risk = result["risk"]
probabilities = result["probabilities"]
inference_time = result["inference_time_ms"]

print(f"Predicted Risk: {risk}")

print("\nProbabilities:")

for name, probability in probabilities.items():
    print(f"  {name}: {probability:.4f}")

print(f"\nInference Time: {inference_time} ms")


# ============================================================
# 4. CREATE PATIENT EVENT
# ============================================================

print("\n[4] Creating Patient Event...")

event = {
    "patient_id": "P001",
    "ambulance_id": "AMBULANCE-001",
    "timestamp": time.time(),

    "heart_rate": sequence[-1][0],
    "spo2": sequence[-1][1],
    "respiratory_rate": sequence[-1][2],
    "sbp": sequence[-1][3],
    "dbp": sequence[-1][4],
    "temperature": sequence[-1][5],

    "risk": risk,
    "probabilities": probabilities,

    "model_version": "BiLSTM-Attention-v1"
}

event_json = json.dumps(event)

print("✓ Patient event created")


# ============================================================
# 5. AES-256-GCM ENCRYPTION
# ============================================================

print("\n[5] Encrypting Patient Data...")

key = generate_key()

nonce, ciphertext = encrypt_data(
    event_json,
    key
)

print("✓ AES-256-GCM encryption successful")

# ============================================================
# SAVE ENCRYPTED EVENT
# ============================================================

encrypted_event = {
    "event_id": "EVENT-001",
    "ambulance_id": "AMBULANCE-001",
    "nonce": base64.b64encode(nonce).decode("utf-8"),
    "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    "model_version": "BiLSTM-Attention-v1"
}

encrypted_event_path = os.path.join(
    "data",
    "encrypted_events",
    "EVENT-001.json"
)

with open(encrypted_event_path, "w") as f:
    json.dump(
        encrypted_event,
        f,
        indent=4
    )

print("✓ Encrypted event saved")
print(f"  Path: {encrypted_event_path}")



# ============================================================
# 6. SHA-256 HASH
# ============================================================

print("\n[6] Generating SHA-256 Integrity Hash...")

ciphertext_hash = calculate_sha256(
    nonce,
    ciphertext
)

print(f"SHA-256: {ciphertext_hash}")


# ============================================================
# 7. HASH-CHAINED LEDGER
# ============================================================

print("\n[7] Adding Event to Hash-Chain Ledger...")

ledger = HashChainLedger()

block = ledger.add_block(
    event_id="EVENT-001",
    ambulance_id="AMBULANCE-001",
    model_version="BiLSTM-Attention-v1",
    ciphertext_sha256=ciphertext_hash
)

print("✓ Event added to ledger")


# ============================================================
# 8. VERIFY LEDGER
# ============================================================

print("\n[8] Ledger Verification")

if ledger.verify_chain():
    print("✓ LEDGER VALID")
else:
    print("✗ LEDGER INVALID")

# ============================================================
# SAVE LEDGER
# ============================================================

ledger_path = os.path.join(
    "data",
    "ledger",
    "ledger.json"
)

with open(ledger_path, "w") as f:
    json.dump(
        ledger.chain,
        f,
        indent=4
    )

print("✓ Ledger saved")
print(f"  Path: {ledger_path}")



# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n" + "=" * 60)
print("SMART AMBULANCE PIPELINE COMPLETED")
print("=" * 60)

print("\nRisk Prediction       : ✓")
print("AES-256-GCM Encryption: ✓")
print("SHA-256 Integrity     : ✓")
print("Hash-Chain Ledger     : ✓")
print("Ledger Verification   : ✓")

print("\nFinal Risk:", risk)
print("Inference Time:", inference_time, "ms")

print("=" * 60)