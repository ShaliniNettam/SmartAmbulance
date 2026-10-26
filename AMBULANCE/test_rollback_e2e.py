
import json
import requests
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

BASE_DIR = Path(__file__).resolve().parent
LEDGER_PATH = BASE_DIR / "data" / "ledger" / "ledger.json"
EVENT_ID = "EVENT-2beb168aa1174f8c8d30ab2c378cf276"
EVENT_PATH = BASE_DIR / "data" / "encrypted_events" / f"{EVENT_ID}.json"
PRIVATE_KEY_PATH = BASE_DIR / "data" / "keys" / "ambulance_signing_private.pem"

HOSPITAL_URL = "http://127.0.0.1:8001/receive-event"


def canonical_json(data):
    return json.dumps(
        data, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def get_blocks(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("chain"), list):
            return data["chain"]
        if isinstance(data.get("blocks"), list):
            return data["blocks"]
    raise ValueError("Unrecognized ledger format")


def main():
    # Read existing files only. This script does not modify them.
    ledger_data = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
    blocks = get_blocks(ledger_data)

    if len(blocks) != 32:
        raise RuntimeError(
            f"Expected the current 32-block ledger; found {len(blocks)}. "
            "Stop and review the ledger before testing."
        )

    historical_blocks = blocks[:31]

    if not any(block.get("event_id") == EVENT_ID
               for block in historical_blocks):
        raise RuntimeError(
            "Selected event is not present in the first 31 ledger blocks."
        )

    saved_event = json.loads(EVENT_PATH.read_text(encoding="utf-8"))

    # Build a correctly signed checkpoint for the historical 31-block ledger.
    checkpoint_data = {
        "checkpoint_version": 1,
        "block_count": len(historical_blocks),
        "latest_index": historical_blocks[-1]["index"],
        "latest_hash": historical_blocks[-1]["block_hash"],
    }

    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_PATH.read_bytes(),
        password=None,
    )

    signature = private_key.sign(
        canonical_json(checkpoint_data),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    signed_checkpoint = {
        **checkpoint_data,
        "signature": signature.hex(),
    }

    payload = {
        "event_id": saved_event["event_id"],
        "nonce": saved_event["nonce"],
        "ciphertext": saved_event["ciphertext"],
        "wrapped_aes_key": saved_event["wrapped_aes_key"],
        "sha256": saved_event["sha256"],
        "signature": saved_event["signature"],
        "ledger_blocks": historical_blocks,
        "checkpoint": signed_checkpoint,
    }

    print("Submitting historical checkpoint to hospital API...")
    print(f"Event ID: {EVENT_ID}")
    print(f"Submitted checkpoint blocks: {checkpoint_data['block_count']}")
    print(f"Submitted latest index: {checkpoint_data['latest_index']}")
    print("Expected result: HTTP 409 — rollback rejected")
    print("No ledger or checkpoint files will be changed.")

    try:
        response = requests.post(
            HOSPITAL_URL,
            json=payload,
            timeout=15,
        )
    except requests.RequestException as exc:
        print("\nTEST COULD NOT RUN: hospital API was unreachable.")
        print(f"Details: {exc}")
        return

    print(f"\nHTTP status: {response.status_code}")

    try:
        body = response.json()
    except ValueError:
        body = response.text

    print("Response:", body)

    detail = body.get("detail", "") if isinstance(body, dict) else ""

    if response.status_code == 409 and "checkpoint" in str(detail).lower():
        print("\nPASS: Hospital API rejected the stale checkpoint.")
    else:
        print(
            "\nNOT CONFIRMED: The response was not the expected HTTP 409. "
            "Check the response detail before drawing a conclusion."
        )


if __name__ == "__main__":
    main()