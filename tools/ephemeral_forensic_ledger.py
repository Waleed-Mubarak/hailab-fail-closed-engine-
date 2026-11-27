from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any

from tools.ephemeral_evidence import RefusalProofLedger


def build_ephemeral_forensic_payload(
    ledger: RefusalProofLedger,
    *,
    witness_key: bytes | None = None,
) -> dict[str, Any]:
    summary = ledger.build_summary(witness_key=witness_key)
    jsonl_text = ledger.to_jsonl()
    records = [json.loads(line) for line in jsonl_text.splitlines() if line.strip()]
    return {
        "evidence_type": "ephemeral_refusal_chain",
        "summary": summary,
        "jsonl": jsonl_text,
        "records": records,
    }


def write_ephemeral_forensic_artifact(
    ledger: RefusalProofLedger,
    output_json_path: str | Path,
    *,
    witness_key: bytes | None = None,
) -> Path:
    dest = Path(output_json_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = build_ephemeral_forensic_payload(ledger, witness_key=witness_key)
    content = json.dumps(payload, indent=2, sort_keys=True) + "\n"

    fd, tmp_name = tempfile.mkstemp(dir=dest.parent, prefix=f".{dest.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
            tmp_file.write(content)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.replace(tmp_name, dest)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise

    return dest

