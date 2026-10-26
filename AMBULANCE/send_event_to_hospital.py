
import json
import urllib.request
from pathlib import Path

event_id = "EVENT-526cc2a89ae0452490e2c04f2e7e5853"

base_dir = Path(__file__).resolve().parent
event_path = base_dir / "data" / "encrypted_events" / f"{event_id}.json"

if not event_path.exists():
    raise FileNotFoundError(f"Event file not found: {event_path}")

with open(event_path, "r", encoding="utf-8") as file:
    saved_event = json.load(file)

# Send only the fields expected by the hospital API.
payload = {
    "event_id": saved_event["event_id"],
    "nonce": saved_event["nonce"],
    "ciphertext": saved_event["ciphertext"],
    "wrapped_aes_key": saved_event["wrapped_aes_key"],
    "sha256": saved_event["sha256"],
    "signature": saved_event["signature"],
}

request = urllib.request.Request(
    "http://127.0.0.1:8001/receive-event",
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST",
)

try:
    with urllib.request.urlopen(request, timeout=15) as response:
        print("Hospital response:")
        print(json.dumps(json.loads(response.read().decode("utf-8")), indent=2))
except Exception as error:
    print("Sending failed:", error)
    if hasattr(error, "read"):
        print(error.read().decode("utf-8", errors="replace"))
