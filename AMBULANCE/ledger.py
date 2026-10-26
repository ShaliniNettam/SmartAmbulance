
# ============================================================
# SMART AMBULANCE - PERSISTENT HASH-CHAINED LEDGER
# ============================================================

import hashlib
import hmac
import json
import os
import tempfile
import time


class HashChainLedger:

    def __init__(
        self,
        ledger_path="data/ledger/ledger.json",
        auto_load=True
    ):
        self.ledger_path = ledger_path
        self.chain = []

        if auto_load and os.path.exists(self.ledger_path):
            with open(self.ledger_path, "r", encoding="utf-8") as f:
                saved_chain = json.load(f)

            if not isinstance(saved_chain, list):
                raise ValueError("Ledger must be a JSON list.")

            self.chain = saved_chain

            if not self.verify_chain():
                self.chain = []
                raise ValueError(
                    "Saved ledger is INVALID. "
                    "Refusing to continue or overwrite it."
                )

    # ========================================================
    # CREATE BLOCK HASH
    # Preserve the original algorithm for existing blocks.
    # ========================================================

    def calculate_block_hash(self, block):

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

    # ========================================================
    # VERIFY LEDGER
    # ========================================================

    def verify_chain(self):

        if not isinstance(self.chain, list):
            return False

        seen_event_ids = set()

        try:
            for i, block in enumerate(self.chain):

                required_fields = {
                    "index",
                    "event_id",
                    "ambulance_id",
                    "timestamp",
                    "model_version",
                    "ciphertext_sha256",
                    "previous_hash",
                    "block_hash"
                }

                if not isinstance(block, dict):
                    return False

                if not required_fields.issubset(block.keys()):
                    return False

                if block["index"] != i:
                    return False

                event_id = block["event_id"]

                if not isinstance(event_id, str) or not event_id:
                    return False

                if event_id in seen_event_ids:
                    return False

                seen_event_ids.add(event_id)

                if not isinstance(block["timestamp"], (int, float)):
                    return False

                if i == 0:
                    expected_previous_hash = "0" * 64
                else:
                    expected_previous_hash = (
                        self.chain[i - 1]["block_hash"]
                    )

                if block["previous_hash"] != expected_previous_hash:
                    return False

                calculated_hash = self.calculate_block_hash(block)

                if not hmac.compare_digest(
                    str(block["block_hash"]),
                    calculated_hash
                ):
                    return False

        except (KeyError, TypeError, ValueError, IndexError):
            return False

        return True

    # ========================================================
    # SAVE LEDGER SAFELY
    # ========================================================

    def save(self):

        directory = os.path.dirname(self.ledger_path) or "."
        os.makedirs(directory, exist_ok=True)

        temp_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=directory,
                delete=False
            ) as temp_file:

                json.dump(self.chain, temp_file, indent=4)
                temp_file.flush()
                os.fsync(temp_file.fileno())
                temp_path = temp_file.name

            os.replace(temp_path, self.ledger_path)

        except Exception:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
            raise

    # ========================================================
    # ADD BLOCK
    # ========================================================

    def add_block(
        self,
        event_id,
        ambulance_id,
        model_version,
        ciphertext_sha256
    ):

        if not self.verify_chain():
            raise ValueError(
                "Cannot append to an invalid ledger."
            )

        if not isinstance(event_id, str) or not event_id:
            raise ValueError(
                "event_id must be a non-empty string."
            )

        if any(
            block["event_id"] == event_id
            for block in self.chain
        ):
            raise ValueError(
                f"Duplicate event ID: {event_id}"
            )

        values = (
            ambulance_id,
            model_version,
            ciphertext_sha256
        )

        if not all(
            isinstance(value, str) and value
            for value in values
        ):
            raise ValueError(
                "Ambulance ID, model version and ciphertext hash "
                "must be non-empty strings."
            )

        index = len(self.chain)

        if self.chain:
            previous_hash = self.chain[-1]["block_hash"]
        else:
            previous_hash = "0" * 64

        block = {
            "index": index,
            "event_id": event_id,
            "ambulance_id": ambulance_id,
            "timestamp": time.time(),
            "model_version": model_version,
            "ciphertext_sha256": ciphertext_sha256,
            "previous_hash": previous_hash
        }

        block["block_hash"] = self.calculate_block_hash(block)

        self.chain.append(block)

        try:
            self.save()
        except Exception:
            self.chain.pop()
            raise

        return block


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":

    print("\n" + "=" * 60)
    print("SMART AMBULANCE - PERSISTENT LEDGER TEST")
    print("=" * 60)

    ledger = HashChainLedger()

    print(f"Loaded blocks: {len(ledger.chain)}")
    print(f"Ledger valid: {ledger.verify_chain()}")
    print(f"Ledger path: {ledger.ledger_path}")

    print("=" * 60)
