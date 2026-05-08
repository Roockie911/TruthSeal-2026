from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional, Set, Tuple

from truthseal_hash import sha256_file

VENV_PYTHON = Path(r"C:\Users\SETUP\Desktop\TruthSeal\.venv\Scripts\python.exe")

try:
    import cv2  # opencv-python
except Exception:  # pragma: no cover
    cv2 = None

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception:  # pragma: no cover
    serialization = None
    Ed25519PublicKey = None


def _registry_entries(registry_path: Path) -> list:
    if not registry_path.exists():
        return []

    try:
        raw = registry_path.read_text(encoding="utf-8")
        if not raw.strip():
            return []
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise ValueError(f"Registry JSON is invalid: {registry_path}")

    if data is None:
        return []
    if not isinstance(data, list):
        raise ValueError(f"Registry JSON must be a list of entries: {registry_path}")
    return data


def read_registry_hashes(registry_path: Path) -> Set[str]:
    hashes: Set[str] = set()
    for entry in _registry_entries(registry_path):
        if not isinstance(entry, dict):
            continue
        v = entry.get("sha256_hash")
        if isinstance(v, str) and len(v.strip()) == 64:
            hashes.add(v.strip().lower())
    return hashes


def global_receipt_for_hash(registry_path: Path, digest_hex_lower: str) -> Optional[str]:
    """
    Return global_receipt from the last registry entry matching this hash
    (same content sealed multiple times → latest receipt).
    """
    receipt: Optional[str] = None
    for entry in _registry_entries(registry_path):
        if not isinstance(entry, dict):
            continue
        v = entry.get("sha256_hash")
        if not isinstance(v, str) or len(v.strip()) != 64:
            continue
        if v.strip().lower() != digest_hex_lower:
            continue
        gr = entry.get("global_receipt")
        if isinstance(gr, str) and gr.strip():
            receipt = gr.strip()
    return receipt


def _entry_for_hash(registry_path: Path, digest_hex_lower: str) -> Optional[dict]:
    found: Optional[dict] = None
    for entry in _registry_entries(registry_path):
        if not isinstance(entry, dict):
            continue
        v = entry.get("sha256_hash")
        if not isinstance(v, str) or len(v.strip()) != 64:
            continue
        if v.strip().lower() != digest_hex_lower:
            continue
        found = entry
    return found


def _ots_verify(ots_proof_path: Path) -> Tuple[bool, str]:
    """
    Attempt to verify an OpenTimestamps proof via:
      <venv python> -m opentimestamps.client verify <file>.ots
    Note: full verification may require a local Bitcoin node depending on proof state.
    """
    if not VENV_PYTHON.exists():
        return False, f"Venv python not found: {VENV_PYTHON}"
    p = subprocess.run(
        [str(VENV_PYTHON), "-m", "opentimestamps.client", "verify", str(ots_proof_path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    out = (p.stdout or "").strip()
    err = (p.stderr or "").strip()
    msg = err or out or f"verify exited with code {p.returncode}"
    return p.returncode == 0, msg


def _decode_qr_from_image(image_path: Path) -> str:
    if cv2 is None:
        raise RuntimeError("opencv-python is required for QR scanning (pip install -r requirements.txt).")

    img = cv2.imread(str(image_path))
    if img is None:
        raise RuntimeError("Failed to read image (corrupted or unsupported format).")

    det = cv2.QRCodeDetector()
    data, _, _ = det.detectAndDecode(img)
    if not data:
        raise RuntimeError("No QR code detected in the provided image.")
    return data


def _verify_signed_qr_payload(qr_text: str) -> Tuple[dict, bool]:
    """
    Expected QR JSON:
      {"payload": {"sha256":..., "global_receipt":..., "pubkey":..., ...}, "sig_ed25519": "...hex..."}
    """
    if Ed25519PublicKey is None:
        # Can't verify signature; still return payload for informational checks.
        obj = json.loads(qr_text)
        return obj.get("payload") or {}, False

    obj = json.loads(qr_text)
    payload = obj.get("payload")
    sig_hex = obj.get("sig_ed25519")
    if not isinstance(payload, dict) or not isinstance(sig_hex, str):
        raise RuntimeError("QR payload format is invalid.")

    pub_hex = payload.get("pubkey")
    if not isinstance(pub_hex, str):
        raise RuntimeError("QR payload missing pubkey.")

    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    payload_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = bytes.fromhex(sig_hex)
    try:
        pub.verify(sig, payload_bytes)
        return payload, True
    except Exception:
        return payload, False


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a file (or a QR scan) against registry.json and OpenTimestamps."
    )
    parser.add_argument(
        "path",
        help="Path to a file to verify, or path to a photo/screenshot when using --scan.",
    )
    parser.add_argument(
        "--registry",
        default="registry.json",
        help="Registry path (default: registry.json in current directory)",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Treat the input as an image containing a TruthSeal QR (printed counterpart verification).",
    )
    args = parser.parse_args(argv)

    file_path = Path(args.path)
    if not file_path.exists():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        print(
            "Tip: If this asset was sealed with Guard, you can verify it using the "
            "Global Blockchain Receipt printed when you ran guard_sealer.py—use it to "
            "look up the OpenTimestamps proof / broadcast even if the local file is missing."
        )
        return 2
    if file_path.is_dir():
        print(f"Error: expected a file, got directory: {file_path}", file=sys.stderr)
        return 2

    registry_path = Path(args.registry)

    try:
        if args.scan:
            qr_text = _decode_qr_from_image(file_path)
            payload, sig_ok = _verify_signed_qr_payload(qr_text)
            digest = str(payload.get("sha256", "")).lower()
            receipt = str(payload.get("global_receipt", ""))
            if len(digest) != 64:
                raise RuntimeError("QR code did not contain a valid sha256.")
        else:
            digest = sha256_file(file_path).lower()
            receipt = None

        registry_hashes = read_registry_hashes(registry_path)
    except Exception as e:
        print(f"Error: verification failed: {e}", file=sys.stderr)
        return 1

    digest_key = digest.lower()
    if digest_key in registry_hashes:
        print("✅ PASS: This file is an authentic original from the registry.")
        entry = _entry_for_hash(registry_path, digest_key) or {}
        rid = entry.get("global_receipt") or global_receipt_for_hash(registry_path, digest_key)
        if isinstance(rid, str) and rid.strip():
            print(f"Global Blockchain Receipt: {rid.strip()}")

        ots_path = entry.get("ots_proof_path")
        if isinstance(ots_path, str) and ots_path.strip():
            ok, msg = _ots_verify(Path(ots_path))
            if ok:
                print("Blockchain anchor: VERIFIED via OpenTimestamps.")
            else:
                print(f"Blockchain anchor: NOT VERIFIED ({msg})")

        if args.scan:
            print(f"QR signature: {'VALID' if sig_ok else 'UNVERIFIED'}")
            if receipt:
                print(f"QR global_receipt: {receipt}")
        return 0

    print("❌ FAIL: This file is not in the registry or has been modified.")
    return 3


if __name__ == "__main__":
    raise SystemExit(main())

