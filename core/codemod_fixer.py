import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List


class DeterministicCodemodEngine:


    def __init__(self, ledger_path: str):
        self.ledger_path = Path(ledger_path)
        if not self.ledger_path.exists():
            self.ledger_path.write_text("[]", encoding="utf-8")

    def _load_ledger(self) -> List[Dict[str, Any]]:
        if not self.ledger_path.exists():
            return []
        try:
            return json.loads(self.ledger_path.read_text(encoding="utf-8"))
        except Exception:
            return []

    def apply_surgical_patch(
        self,
        file_path: str,
        rule_id: str,
        vulnerable_block: str,
        patched_block: str,
        approver: str,
    ) -> Dict[str, Any]:
        target = Path(file_path)
        original_code = target.read_text(encoding="utf-8")
        sha_before = hashlib.sha256(original_code.encode("utf-8")).hexdigest()

        if vulnerable_block in original_code:
            updated_code = original_code.replace(vulnerable_block, patched_block, 1)
            target.write_text(updated_code, encoding="utf-8")
        else:
            updated_code = original_code

        sha_after = hashlib.sha256(updated_code.encode("utf-8")).hexdigest()
        ledger = self._load_ledger()
        prev_hash = ledger[-1]["entry_hash"] if ledger else "0" * 64
        entry_id = f"LEDGER-{len(ledger) + 1:03d}"
        timestamp = datetime.now(timezone.utc).isoformat()

        chain_payload = f"{entry_id}|{rule_id}|{sha_before}|{sha_after}|{approver}|{prev_hash}|{timestamp}"
        entry_hash = hashlib.sha256(chain_payload.encode("utf-8")).hexdigest()

        entry = {
            "entry_id": entry_id,
            "timestamp": timestamp,
            "rule_id": rule_id,
            "file_path": str(target),
            "approved_by": approver,
            "sha256_before": sha_before,
            "sha256_after": sha_after,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
        }
        ledger.append(entry)
        self.ledger_path.write_text(json.dumps(ledger, indent=2), encoding="utf-8")
        return entry
