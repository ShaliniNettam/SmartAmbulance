# ============================================================
# SMART AMBULANCE - LEDGER TAMPER DETECTION TEST
# ============================================================

import json
from ledger import HashChainLedger


# ============================================================
# LOAD SAVED LEDGER
# ============================================================

with open(
    "data/ledger/ledger.json",
    "r"
) as f:
    saved_chain = json.load(f)


# ============================================================
# CREATE LEDGER OBJECT
# ============================================================

ledger = HashChainLedger()

ledger.chain = saved_chain


# ============================================================
# VERIFY ORIGINAL LEDGER
# ============================================================

print("\n" + "=" * 60)
print("SMART AMBULANCE - LEDGER TAMPER DETECTION TEST")
print("=" * 60)

print("\nOriginal Ledger Verification:")

if ledger.verify_chain():
    print("✓ LEDGER VALID")
else:
    print("✗ LEDGER INVALID")


# ============================================================
# SIMULATE TAMPERING
# ============================================================

print("\nSimulating tampering...")

ledger.chain[0]["ciphertext_sha256"] = "TAMPERED_HASH"


# ============================================================
# VERIFY AFTER TAMPERING
# ============================================================

print("\nAfter Tampering:")

if ledger.verify_chain():
    print("✗ TAMPERING NOT DETECTED")
else:
    print("✓ TAMPERING DETECTED")
    print("✓ LEDGER INVALID")


print("=" * 60)