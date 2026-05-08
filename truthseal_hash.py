from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """
    TruthSeal hashing contract:
    - open file in 'rb'
    - stream in fixed-size chunks
    - SHA-256 hex digest (lowercase)

    This function is imported by both guard_sealer.py and verify_trust.py to
    prevent drift and false negatives.
    """
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()

