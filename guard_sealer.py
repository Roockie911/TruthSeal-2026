from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Tuple

from truthseal_hash import sha256_file
from truthseal_gitignore import ensure_gitignore

# ABSOLUTE PATH RULE (Windows): never call generic "python"/"pip" or rely on PATH hijacks.
VENV_PYTHON = Path(r"C:\Users\SETUP\Desktop\TruthSeal\.venv\Scripts\python.exe")
# Project root (used for Root of Trust + session identity material).
REPO_ROOT = Path(__file__).resolve().parent

try:
    import fitz  # PyMuPDF
except Exception:  # pragma: no cover
    fitz = None

try:
    import qrcode
except Exception:  # pragma: no cover
    qrcode = None

try:
    from PIL import Image
except Exception:  # pragma: no cover
    Image = None

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.exceptions import UnsupportedAlgorithm, InternalError
except Exception:  # pragma: no cover
    serialization = None
    Ed25519PrivateKey = None
    Ed25519PublicKey = None
    x509 = None
    NameOID = None
    UnsupportedAlgorithm = Exception  # type: ignore
    InternalError = Exception  # type: ignore

try:
    import c2pa
except Exception:  # pragma: no cover
    c2pa = None


def _load_registry_entries(registry_path: Path) -> list[dict]:
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


def _write_registry_entries(registry_path: Path, entries: list[dict]) -> None:
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(
        json.dumps(entries, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_ots(*args: str) -> subprocess.CompletedProcess[str]:
    """
    Run OpenTimestamps via the venv interpreter, not the PATH 'ots' shim:
      <venv python> -m opentimestamps.client <args...>
    """
    if not VENV_PYTHON.exists():
        raise RuntimeError(f"Venv python not found: {VENV_PYTHON}")
    return subprocess.run(
        [str(VENV_PYTHON), "-m", "opentimestamps.client", *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _ots_stamp(file_path: Path) -> Tuple[Optional[Path], str, str]:
    """
    Create an OpenTimestamps proof sidecar: <file>.ots
    Uses `python -m opentimestamps.client` from the venv.
    """
    ots_path = file_path.with_name(file_path.name + ".ots")
    p = _run_ots("stamp", str(file_path))
    out = (p.stdout or "").strip()
    err = (p.stderr or "").strip()
    msg = err or out or f"stamp exited with code {p.returncode}"

    if p.returncode != 0:
        return None, "error", msg

    if not ots_path.exists():
        return None, "error", "stamp reported success but .ots proof was not created."
    return ots_path, "stamped", msg


def _ots_upgrade(ots_path: Path) -> Tuple[str, str]:
    """
    Try to upgrade an OTS proof so it carries blockchain attestations.
    This may not complete immediately (calendars / confirmations).
    """
    p = _run_ots("upgrade", str(ots_path))
    out = (p.stdout or "").strip()
    err = (p.stderr or "").strip()
    msg = err or out or f"upgrade exited with code {p.returncode}"
    if p.returncode == 0:
        return "upgraded_or_pending", msg
    # Non-fatal: keep proof and record status for later.
    return "pending_or_error", msg


def _ots_receipt_id(ots_path: Path) -> str:
    # Stable receipt identifier that can be shared even if filenames differ.
    return sha256_file(ots_path)


def _load_or_create_qr_signing_key(key_path: Path) -> Tuple["Ed25519PrivateKey", "Ed25519PublicKey"]:
    if Ed25519PrivateKey is None or serialization is None:
        raise RuntimeError("cryptography is required for signed QR codes (pip install -r requirements.txt).")

    if key_path.exists():
        try:
            raw = key_path.read_bytes()
            priv = serialization.load_pem_private_key(raw, password=None)
        except (ValueError, OSError, UnsupportedAlgorithm, InternalError) as e:
            raise RuntimeError(f"QR signing key unreadable ({key_path}): {e}") from e
        if not isinstance(priv, Ed25519PrivateKey):
            raise RuntimeError(f"Unexpected key type in {key_path}; expected Ed25519 private key.")
        return priv, priv.public_key()

    priv = Ed25519PrivateKey.generate()
    try:
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(pem)
    except OSError as e:
        raise RuntimeError(f"Could not write QR signing key {key_path}: {e}") from e
    return priv, priv.public_key()


def _make_signed_qr_payload(sha256_hex: str, global_receipt: str, pubkey: "Ed25519PublicKey", privkey: "Ed25519PrivateKey") -> str:
    payload_obj = {
        "v": 1,
        "sha256": sha256_hex,
        "global_receipt": global_receipt,
        "pubkey": pubkey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex(),
        "ts": _utc_now_iso(),
    }
    payload = json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = privkey.sign(payload).hex()
    wrapped = {"payload": payload_obj, "sig_ed25519": sig}
    return json.dumps(wrapped, separators=(",", ":"), ensure_ascii=False)


def _qr_png_bytes(data: str) -> bytes:
    if qrcode is None:
        raise RuntimeError("qrcode is required for QR generation (pip install -r requirements.txt).")
    import io

    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _watermark_image_with_qr(src: Path, dest: Path, qr_png: bytes) -> None:
    if Image is None:
        raise RuntimeError("Pillow is required for image watermarking (pip install -r requirements.txt).")
    from io import BytesIO

    with Image.open(src) as base:
        base = base.convert("RGBA")
        qr = Image.open(BytesIO(qr_png)).convert("RGBA")

        # Scale QR to ~20% of the shortest side, clamped.
        short = min(base.size)
        target = max(160, min(512, int(short * 0.20)))
        qr = qr.resize((target, target))

        # Add a slight alpha to act as watermark.
        alpha = qr.split()[-1].point(lambda p: int(p * 0.75))
        qr.putalpha(alpha)

        margin = max(12, int(short * 0.02))
        x = base.size[0] - target - margin
        y = base.size[1] - target - margin
        base.alpha_composite(qr, dest=(x, y))

        out = base.convert("RGB") if base.mode == "RGBA" else base
        out.save(dest)


def _watermark_pdf_with_qr(src: Path, dest: Path, qr_png: bytes) -> None:
    if fitz is None:
        raise RuntimeError("PyMuPDF is required for PDF watermarking (pip install -r requirements.txt).")

    doc = fitz.open(str(src))
    try:
        for page in doc:
            rect = page.rect
            size = min(rect.width, rect.height) * 0.18
            margin = min(rect.width, rect.height) * 0.03
            box = fitz.Rect(
                rect.x1 - size - margin,
                rect.y1 - size - margin,
                rect.x1 - margin,
                rect.y1 - margin,
            )
            page.insert_image(box, stream=qr_png, overlay=True)
        # Saving "in place" is risky; write to temp then replace.
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        doc.save(str(tmp))
        tmp.replace(dest)
    finally:
        doc.close()


ROOT_AUTHORITY_CERT = "root_authority.pem"
ROOT_AUTHORITY_KEY = "root_authority_key.pem"  # Master Identity Key (private)
USER_IDENTITY_CERT = "User_Identity.pem"
USER_IDENTITY_KEY = "User_Identity_key.pem"


def _load_or_create_root_of_trust(repo_root: Path) -> Tuple["x509.Certificate", "Ed25519PrivateKey"]:
    """
    Persistent local Root of Trust.
    - If root_authority.pem is missing: generate CA once; warn to back up Master Identity Key.
    - If present: load CA cert + root_authority_key.pem and use it to issue session identities.
    """
    if serialization is None or Ed25519PrivateKey is None or x509 is None or NameOID is None:
        raise RuntimeError("cryptography is required for C2PA identity chain.")

    cert_path = repo_root / ROOT_AUTHORITY_CERT
    key_path = repo_root / ROOT_AUTHORITY_KEY

    now = datetime.now(timezone.utc)

    if not cert_path.exists():
        ca_priv = Ed25519PrivateKey.generate()
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TruthSeal Root of Trust"),
                x509.NameAttribute(NameOID.COMMON_NAME, "TruthSeal Local Root CA"),
            ]
        )
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key=ca_priv, algorithm=None)
        )

        try:
            cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(
                ca_priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        except OSError as e:
            raise RuntimeError(f"Failed to write Root of Trust files: {e}") from e

        print(
            "WARNING: TruthSeal created a new Root of Trust (Master Identity Key).\n"
            f"  BACK UP these files securely and NEVER commit them: {cert_path.name}, {key_path.name}\n"
            "  Without the private key, you cannot issue new User_Identity certificates.",
            file=sys.stderr,
        )
        return ca_cert, ca_priv

    if not key_path.exists():
        raise RuntimeError(
            f"{ROOT_AUTHORITY_CERT} exists but {ROOT_AUTHORITY_KEY} is missing. "
            "Restore your Master Identity Key, or (development only) remove both root files to regenerate."
        )

    try:
        ca_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except (ValueError, UnsupportedAlgorithm, InternalError) as e:
        raise RuntimeError(f"Invalid or unreadable {ROOT_AUTHORITY_CERT}: {e}") from e

    try:
        ca_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (ValueError, UnsupportedAlgorithm, InternalError, OSError) as e:
        raise RuntimeError(f"Invalid or unreadable {ROOT_AUTHORITY_KEY}: {e}") from e

    if not isinstance(ca_key, Ed25519PrivateKey):
        raise RuntimeError("Root CA private key must be Ed25519 for TruthSeal C2PA.")

    return ca_cert, ca_key


def _mint_session_user_identity(
    repo_root: Path,
    ca_cert: "x509.Certificate",
    ca_key: "Ed25519PrivateKey",
    user_id: str,
) -> Tuple[str, str]:
    """
    Issue a fresh end-entity cert signed by root_authority for this sealing session.
    Writes User_Identity.pem (certificate chain: leaf + root) and User_Identity_key.pem (leaf key).
    Returns (cert_chain_pem, leaf_private_key_pem) for C2PASignerInfo.
    """
    if serialization is None or Ed25519PrivateKey is None or x509 is None or NameOID is None:
        raise RuntimeError("cryptography is required for C2PA identity chain.")

    ee_priv = Ed25519PrivateKey.generate()
    session_id = uuid.uuid4().hex[:16]
    uid_short = (user_id or "user")[:64]

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TruthSeal User"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, uid_short),
            x509.NameAttribute(NameOID.COMMON_NAME, f"TruthSeal-Session-{session_id}"),
        ]
    )

    now = datetime.now(timezone.utc)
    user_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(ee_priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=None)
    )

    leaf_pem = user_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    root_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    cert_chain_pem = leaf_pem + root_pem

    key_pem = ee_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    try:
        (repo_root / USER_IDENTITY_CERT).write_text(cert_chain_pem, encoding="utf-8")
        (repo_root / USER_IDENTITY_KEY).write_text(key_pem, encoding="utf-8")
    except OSError as e:
        raise RuntimeError(f"Failed to write session identity files: {e}") from e

    return cert_chain_pem, key_pem


def _get_c2pa_session_signing_material(repo_root: Path, user_id: str) -> Tuple[str, str]:
    ca_cert, ca_key = _load_or_create_root_of_trust(repo_root)
    return _mint_session_user_identity(repo_root, ca_cert, ca_key, user_id)


def _maybe_embed_c2pa_manifest(src: Path, dest: Path, user_id: str) -> dict:
    """
    Embed C2PA manifest using a session User_Identity signed by root_authority.
    Returns registry fields: c2pa_status, c2pa_message.
    """
    out: dict = {"c2pa_status": "skipped", "c2pa_message": ""}

    if c2pa is None:
        out["c2pa_message"] = "c2pa-python not available"
        return out

    ext = src.suffix.lower()
    mime = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".mp4": "video/mp4",
    }.get(ext)
    if not mime:
        out["c2pa_message"] = f"C2PA skipped for extension {ext!r}"
        return out

    manifest = {
        "claim_generator": "TruthSeal/2026",
        "title": src.name,
        "assertions": [
            {
                "label": "org.truthseal.guard",
                "data": {
                    "user_id": user_id,
                    "sealed_at": _utc_now_iso(),
                },
            }
        ],
    }

    try:
        cert_chain_pem, key_pem = _get_c2pa_session_signing_material(REPO_ROOT, user_id)
        signer_info = c2pa.C2paSignerInfo(
            c2pa.C2paSigningAlg.ED25519,
            cert_chain_pem,
            key_pem,
            None,
        )
        signer = c2pa.Signer.from_info(signer_info)
        builder = c2pa.Builder.from_json(manifest)
        builder.sign_file(str(dest), str(dest), signer)
        out["c2pa_status"] = "embedded"
        out["c2pa_message"] = "C2PA manifest signed with User_Identity chain"
    except (UnsupportedAlgorithm, InternalError, ValueError, OSError, RuntimeError) as e:
        out["c2pa_status"] = "error"
        out["c2pa_message"] = str(e)
    except Exception as e:  # pragma: no cover — C2paError / OpenSSL backend
        out["c2pa_status"] = "error"
        out["c2pa_message"] = f"{type(e).__name__}: {e}"

    return out


def append_registry(registry_path: Path, entry: dict) -> None:
    entries = _load_registry_entries(registry_path)
    entries.append(entry)
    _write_registry_entries(registry_path, entries)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="TruthSeal Guard: seal a file with SHA-256 + OpenTimestamps + (optional) QR watermark + C2PA."
    )
    parser.add_argument("path", help="Path to a file to seal (image/pdf/audio/video/etc.)")
    parser.add_argument(
        "--registry",
        default="registry.json",
        help="Registry output path (default: registry.json in current directory)",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output sealed file path. If omitted, a sealed copy is written as '<stem>.sealed<ext>' next to the input.",
    )
    parser.add_argument(
        "--no-watermark",
        action="store_true",
        help="Disable QR watermarking even for images/PDFs.",
    )
    parser.add_argument(
        "--user-id",
        default=os.environ.get("TRUTHSEAL_USER_ID", "local-user"),
        help="User identifier embedded into the C2PA manifest (default: TRUTHSEAL_USER_ID or 'local-user').",
    )
    parser.add_argument(
        "--qr-key",
        default="truthseal_qr_ed25519.pem",
        help="Ed25519 private key (PEM) used to sign QR payloads (default: truthseal_qr_ed25519.pem).",
    )
    args = parser.parse_args(argv)

    src_path = Path(args.path)
    if not src_path.exists():
        print(f"Error: file not found: {src_path}", file=sys.stderr)
        return 2
    if src_path.is_dir():
        print(f"Error: expected a file, got directory: {src_path}", file=sys.stderr)
        return 2

    registry_path = Path(args.registry)

    try:
        ensure_gitignore(REPO_ROOT)
    except Exception as e:
        print(f"Warning: could not update .gitignore: {e}", file=sys.stderr)

    try:
        # Step 1: produce a sealed artifact (never modify the original by default).
        dest_path = Path(args.out) if args.out else src_path.with_name(f"{src_path.stem}.sealed{src_path.suffix}")
        is_pdf = src_path.suffix.lower() == ".pdf"
        is_image = src_path.suffix.lower() in (".png", ".jpg", ".jpeg")

        dest_path.write_bytes(src_path.read_bytes())

        # Step 2: embed C2PA manifest into the sealed artifact (best-effort).
        c2pa_info = _maybe_embed_c2pa_manifest(src_path, dest_path, args.user_id)

        # Step 3: hash sealed artifact (source-of-truth bytes).
        digest = sha256_file(dest_path)

        # Step 4: OpenTimestamps anchor for sealed artifact.
        ots_proof, ots_stamp_status, ots_stamp_msg = _ots_stamp(dest_path)
        if not ots_proof:
            raise RuntimeError(f"OpenTimestamps stamp failed: {ots_stamp_msg}")

        ots_upgrade_status, ots_upgrade_msg = _ots_upgrade(ots_proof)
        # Global receipt is the shareable OpenTimestamps proof identifier.
        global_receipt = _ots_receipt_id(ots_proof)

        # Step 5: create a printable watermarked copy for images/PDFs (optional).
        printable_path: Optional[Path] = None
        printable_error: Optional[str] = None
        if not args.no_watermark and (is_pdf or is_image):
            try:
                printable_path = src_path.with_name(f"{src_path.stem}.print{src_path.suffix}")
                printable_path.write_bytes(dest_path.read_bytes())

                priv, pub = _load_or_create_qr_signing_key(Path(args.qr_key))
                qr_payload = _make_signed_qr_payload(digest, global_receipt, pub, priv)
                qr_png = _qr_png_bytes(qr_payload)
                if is_image:
                    _watermark_image_with_qr(printable_path, printable_path, qr_png)
                elif is_pdf:
                    _watermark_pdf_with_qr(printable_path, printable_path, qr_png)
            except (RuntimeError, ValueError, OSError, UnsupportedAlgorithm, InternalError) as e:
                printable_path = None
                printable_error = str(e)
                print(f"Warning: printable QR copy failed (sealed file is still valid): {e}", file=sys.stderr)

        entry = {
            "file_name": dest_path.name,
            "sha256_hash": digest,
            "timestamp": _utc_now_iso(),
            "global_receipt": global_receipt,
            "ots_proof_path": str(ots_proof) if ots_proof else None,
            "ots_stamp_status": ots_stamp_status,
            "ots_stamp_message": ots_stamp_msg,
            "ots_upgrade_status": ots_upgrade_status,
            "ots_upgrade_message": ots_upgrade_msg,
            "sealed_path": str(dest_path),
            "printable_path": str(printable_path) if printable_path else None,
            **c2pa_info,
        }
        if printable_error:
            entry["printable_error"] = printable_error
        append_registry(registry_path, entry)
    except Exception as e:
        print(f"Error: failed to seal file: {e}", file=sys.stderr)
        return 1

    print(digest)
    print(f"Global Blockchain Receipt: {global_receipt}")
    print(f"Sealed File: {dest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

