from __future__ import annotations

import json
import subprocess
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import argparse

from truthseal_gitignore import ensure_gitignore

# ABSOLUTE PATH RULE (Windows): bypass Store Python / PATH hijacks.
VENV_PYTHON = Path(r"C:\Users\SETUP\Desktop\TruthSeal\.venv\Scripts\python.exe")

REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_REGISTRY = REPO_ROOT / "registry.json"
LOG_FILE = REPO_ROOT / "watchdog_log.txt"


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log_line(msg: str) -> None:
    line = f"{_utc_iso()} {msg}\n"
    try:
        with LOG_FILE.open("a", encoding="utf-8", newline="\n") as f:
            f.write(line)
    except OSError as e:
        print(f"Warning: could not write watchdog log: {e}", file=sys.stderr)


def _load_registry(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        raw = path.read_text(encoding="utf-8")
        if not raw.strip():
            return []
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        _log_line(f"FAIL registry JSON corrupt: {e}")
        raise
    if data is None:
        return []
    if not isinstance(data, list):
        raise ValueError("registry.json must be a list of entries")
    return [e for e in data if isinstance(e, dict)]


def _write_registry(path: Path, entries: list[dict[str, Any]]) -> None:
    path.write_text(json.dumps(entries, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _run_ots_upgrade(ots_path: Path) -> subprocess.CompletedProcess[str]:
    if not VENV_PYTHON.exists():
        raise RuntimeError(f"Venv python not found: {VENV_PYTHON}")
    try:
        return subprocess.run(
            [str(VENV_PYTHON), "-m", "opentimestamps.client", "upgrade", str(ots_path)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as e:
        raise RuntimeError(f"subprocess / OpenSSL-related failure: {e}") from e


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="TruthSeal OpenTimestamps watchdog: retry pending upgrades.")
    parser.add_argument(
        "--registry",
        default=str(DEFAULT_REGISTRY),
        help="Path to registry.json",
    )
    args = parser.parse_args(argv)
    registry_path = Path(args.registry)

    try:
        ensure_gitignore(REPO_ROOT)
    except Exception as e:
        print(f"Warning: .gitignore update failed: {e}", file=sys.stderr)

    try:
        entries = _load_registry(registry_path)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    pending = [
        (i, e)
        for i, e in enumerate(entries)
        if str(e.get("ots_upgrade_status", "")).strip() == "pending_or_error"
    ]
    if not pending:
        _log_line("OK no pending ots_upgrade_status entries")
        print("No pending OpenTimestamps upgrades.")
        return 0

    updated = 0
    for idx, entry in pending:
        ots_raw = entry.get("ots_proof_path")
        if not isinstance(ots_raw, str) or not ots_raw.strip():
            _log_line(f"SKIP idx={idx} missing ots_proof_path")
            continue
        ots_path = Path(ots_raw.strip())
        if not ots_path.exists():
            _log_line(f"SKIP idx={idx} ots missing: {ots_path}")
            entry["ots_upgrade_message"] = f"watchdog: .ots file not found: {ots_path}"
            continue

        _log_line(f"TRY upgrade idx={idx} file={ots_path}")
        try:
            p = _run_ots_upgrade(ots_path)
        except Exception as e:
            tb = traceback.format_exc()
            _log_line(f"FAIL idx={idx} exception={e}\n{tb}")
            entry["ots_upgrade_message"] = f"watchdog error: {e}"
            continue

        out = (p.stdout or "").strip()
        err = (p.stderr or "").strip()
        msg = err or out or f"upgrade exit {p.returncode}"

        if p.returncode == 0:
            entry["ots_upgrade_status"] = "confirmed_on_blockchain"
            entry["ots_upgrade_message"] = msg
            entry["ots_watchdog_last_run"] = _utc_iso()
            _log_line(f"OK confirmed idx={idx} {msg[:500]}")
            updated += 1
        else:
            entry["ots_upgrade_message"] = f"watchdog pending: {msg}"
            _log_line(f"PENDING idx={idx} code={p.returncode} {msg[:500]}")

    try:
        _write_registry(registry_path, entries)
    except OSError as e:
        _log_line(f"FAIL write registry: {e}")
        print(f"Error: could not write registry: {e}", file=sys.stderr)
        return 1

    print(f"Processed {len(pending)} pending entr(y/ies); confirmed {updated}. Log: {LOG_FILE}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as e:
        try:
            log = REPO_ROOT / "watchdog_log.txt"
            with log.open("a", encoding="utf-8", newline="\n") as f:
                f.write(f"{datetime.now(timezone.utc).isoformat()} FATAL {e}\n")
        except OSError:
            pass
        print(f"Fatal: {e}", file=sys.stderr)
        raise SystemExit(1)
