
import json
import os
from ledger import HashChainLedger

LEDGER_PATH = "data/ledger/ledger.json"

if not os.path.exists(LEDGER_PATH):
    raise FileNotFoundError(f"Ledger not found: {LEDGER_PATH}")

with open(LEDGER_PATH, "r", encoding="utf-8") as f:
    saved_chain = json.load(f)

if not isinstance(saved_chain, list):
    raise ValueError("Ledger must contain a JSON list.")

ledger = HashChainLedger()
ledger.chain = saved_chain

print(f"\nBlocks loaded: {len(ledger.chain)}")

if not ledger.verify_chain():
    raise SystemExit("FAIL: Ledger verification failed.")

for i, block in enumerate(ledger.chain):
    if block.get("index") != i:
        raise SystemExit(f"FAIL: Incorrect index at block {i}.")

print("PASS: Block hashes and links are valid.")
print("PASS: Block indexes are sequential.")
print("Ledger verification completed.")
