
# ============================================================
# SMART AMBULANCE - HOSPITAL DECRYPTION & INTEGRITY TEST
# ============================================================

import os
import json
import base64
import glob

from crypto import unwrap_aes_key, decrypt_data, calculate_sha256
from checkpoint import verify_checkpoint
from ledger import HashChainLedger


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVENTS_DIR = os.path.join(BASE_DIR, "data", "encrypted_events")
LEDGER_PATH = os.path.join(BASE_DIR, "data", "ledger", "ledger.json")


def load_ledger_blocks():
    """Load ledger blocks without modifying the saved ledger."""
    with open(LEDGER_PATH, "r", encoding="utf-8") as file:
        ledger_data = json.load(file)

    if isinstance(ledger_data, list):
        return ledger_data

    if isinstance(ledger_data, dict):
        if isinstance(ledger_data.get("chain"), list):
            return ledger_data["chain"]
        if isinstance(ledger_data.get("blocks"), list):
            return ledger_data["blocks"]

    raise ValueError("Unrecognized ledger.json structure.")


def find_event_block(blocks, event_id):
    """Find the ledger block corresponding to an event ID."""
    matches = [
        block for block in blocks
        if block.get("event_id") == event_id
    ]

    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one ledger block for {event_id}; "
            f"found {len(matches)}."
        )

    return matches[0]


def main():
    print("=" * 65)
    print("SMART AMBULANCE - HOSPITAL DECRYPTION & INTEGRITY TEST")
    print("=" * 65)

    # --------------------------------------------------------
    # 1. FIND THE MOST RECENT ENCRYPTED EVENT
    # --------------------------------------------------------

    files = glob.glob(os.path.join(EVENTS_DIR, "EVENT-*.json"))

    if not files:
        print("FAIL: No encrypted event files found.")
        return

    latest_file = max(files, key=os.path.getmtime)
    print(f"\nEvent file: {latest_file}")

    # --------------------------------------------------------
    # 2. LOAD THE ENCRYPTED EVENT
    # --------------------------------------------------------

    try:
        with open(latest_file, "r", encoding="utf-8") as file:
            encrypted_event = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: Could not read event file: {exc}")
        return

    required_fields = {
        "event_id",
        "nonce",
        "ciphertext",
        "wrapped_aes_key",
        "sha256",
    }

    if not required_fields.issubset(encrypted_event):
        print("FAIL: Event file is missing required fields.")
        return

    event_id = encrypted_event["event_id"]

    # --------------------------------------------------------
    # 3. DECODE STORED VALUES
    # --------------------------------------------------------

    try:
        nonce = base64.b64decode(
            encrypted_event["nonce"], validate=True
        )
        ciphertext = base64.b64decode(
            encrypted_event["ciphertext"], validate=True
        )
        wrapped_key = base64.b64decode(
            encrypted_event["wrapped_aes_key"], validate=True
        )
    except (ValueError, TypeError) as exc:
        print(f"FAIL: Invalid Base64 data: {exc}")
        return

    # --------------------------------------------------------
    # 4. VERIFY THE EVENT'S OWN SHA-256 HASH
    # --------------------------------------------------------

    calculated_hash = calculate_sha256(nonce, ciphertext)

    if calculated_hash != encrypted_event["sha256"]:
        print("FAIL: Event ciphertext hash mismatch.")
        return

    print("PASS: Event ciphertext hash matches the event file.")

    # --------------------------------------------------------
    # 5. VERIFY THE EVENT AGAINST THE LEDGER
    # --------------------------------------------------------

    try:
        blocks = load_ledger_blocks()
        event_block = find_event_block(blocks, event_id)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"FAIL: Could not find a unique ledger block: {exc}")
        return

    ledger_event_hash = event_block.get("ciphertext_sha256")

    if not isinstance(ledger_event_hash, str):
        print("FAIL: Ledger block has no ciphertext_sha256 field.")
        return

    if calculated_hash != ledger_event_hash:
        print("FAIL: Event hash does not match its ledger block.")
        return

    print("PASS: Event hash matches its corresponding ledger block.")

    # --------------------------------------------------------
    # 6. VERIFY THE FULL HASH-CHAIN LEDGER
    # --------------------------------------------------------

    try:
        ledger = HashChainLedger(ledger_path=LEDGER_PATH)
        chain_valid = ledger.verify_chain()
    except Exception as exc:
        print(f"FAIL: Ledger verification could not run: {exc}")
        return

    if not chain_valid:
        print("FAIL: Ledger hash-chain integrity check failed.")
        return

    print("PASS: Ledger hash-chain integrity verified.")

    # --------------------------------------------------------
    # 7. VERIFY THE SIGNED CHECKPOINT
    # --------------------------------------------------------

    try:
        checkpoint_valid = verify_checkpoint()
    except Exception as exc:
        print(f"FAIL: Checkpoint verification could not run: {exc}")
        return

    if not checkpoint_valid:
        print("FAIL: Signed checkpoint verification failed.")
        return

    print("PASS: Signed checkpoint verified.")

    # --------------------------------------------------------
    # 8. UNWRAP AES KEY USING HOSPITAL PRIVATE KEY
    # --------------------------------------------------------

    try:
        aes_key = unwrap_aes_key(wrapped_key)
    except Exception as exc:
        print(f"FAIL: AES key could not be unwrapped: {exc}")
        return

    if len(aes_key) != 32:
        print("FAIL: Recovered AES key is not 256 bits.")
        return

    print("PASS: Hospital RSA private key recovered the AES key.")

    # --------------------------------------------------------
    # 9. DECRYPT EVENT USING AES-256-GCM
    # --------------------------------------------------------

    try:
        plaintext = decrypt_data(nonce, ciphertext, aes_key)
    except Exception as exc:
        print(f"FAIL: Event decryption/authentication failed: {exc}")
        return

    # --------------------------------------------------------
    # 10. VALIDATE THE DECRYPTED JSON
    # --------------------------------------------------------

    try:
        event = json.loads(plaintext)
    except (json.JSONDecodeError, TypeError):
        print("FAIL: Decrypted content is not valid JSON.")
        return

    if event.get("event_id") != event_id:
        print("FAIL: Decrypted event ID does not match.")
        return

    print("PASS: AES-256-GCM decryption succeeded.")
    print("PASS: Decrypted event ID matches the stored event.")

    # --------------------------------------------------------
    # 11. DISPLAY SAFE TEST SUMMARY
    # --------------------------------------------------------

    print("\nVerified event summary:")
    print(f"Event ID: {event.get('event_id')}")
    print(f"Model version: {event.get('model_version')}")
    print(f"Predicted risk: {event.get('risk')}")

    print("\n" + "=" * 65)
    print("SUCCESS: EVENT, LEDGER, CHECKPOINT AND DECRYPTION VERIFIED")
    print("=" * 65)


if __name__ == "__main__":
    main()
