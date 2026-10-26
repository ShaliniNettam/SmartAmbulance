# ============================================================
# SMART AMBULANCE - TAMPER DETECTION TEST
# ============================================================

import json
import base64

from crypto import calculate_sha256


# ============================================================
# LOAD SAVED ENCRYPTED EVENT
# ============================================================

with open(
    "data/encrypted_events/EVENT-001.json",
    "r"
) as f:
    encrypted_event = json.load(f)


# ============================================================
# EXTRACT DATA
# ============================================================

nonce = base64.b64decode(
    encrypted_event["nonce"]
)

ciphertext = bytearray(
    base64.b64decode(
        encrypted_event["ciphertext"]
    )
)


# ============================================================
# ORIGINAL HASH
# ============================================================

original_hash = calculate_sha256(
    nonce,
    bytes(ciphertext)
)


print("\n" + "=" * 60)
print("SMART AMBULANCE - TAMPER DETECTION TEST")
print("=" * 60)

print("\nOriginal SHA-256:")
print(original_hash)


# ============================================================
# SIMULATE TAMPERING
# ============================================================

ciphertext[0] ^= 1


# ============================================================
# HASH AFTER TAMPERING
# ============================================================

tampered_hash = calculate_sha256(
    nonce,
    bytes(ciphertext)
)


print("\nTampered SHA-256:")
print(tampered_hash)


# ============================================================
# VERIFY TAMPERING
# ============================================================

if original_hash != tampered_hash:
    print("\n✓ TAMPERING DETECTED")
    print("✓ SHA-256 HASH MISMATCH")
else:
    print("\n✗ TAMPERING NOT DETECTED")


print("=" * 60)