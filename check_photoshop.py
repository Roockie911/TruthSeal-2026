from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from PIL import Image, ExifTags


def _safe_decode(b: bytes) -> str:
    return b.decode("utf-8", errors="ignore")


def _extract_xmp_xml(file_bytes: bytes) -> Optional[str]:
    """
    Extract an embedded XMP XML packet if present.
    Many JPEGs store XMP in an APP1 segment, but searching for the XMP XML
    markers works across several formats that embed XMP.
    """
    start = file_bytes.find(b"<x:xmpmeta")
    if start == -1:
        start = file_bytes.find(b"<xmpmeta")
    if start == -1:
        return None

    end = file_bytes.find(b"</x:xmpmeta>", start)
    if end == -1:
        end = file_bytes.find(b"</xmpmeta>", start)
        if end == -1:
            return None
        end += len(b"</xmpmeta>")
    else:
        end += len(b"</x:xmpmeta>")

    return _safe_decode(file_bytes[start:end])


def _normalize(s: str) -> str:
    return " ".join(s.split()).strip()


@dataclass
class Finding:
    source: str
    key: str
    value: str
    confidence: str  # "low" | "medium" | "high"


PHOTOSHOP_STRINGS: List[Tuple[str, str]] = [
    ("Adobe Photoshop", "high"),
    ("AdobePhotoshop", "high"),
    ("photoshop", "medium"),
]

XMP_KEYS: List[Tuple[str, str]] = [
    ("xmp:CreatorTool", "medium"),
    ("xmp:ModifyDate", "low"),
    ("xmpMM:History", "medium"),
    ("photoshop:Creator", "high"),
    ("photoshop:History", "high"),
    ("photoshop:DocumentAncestors", "medium"),
    ("tiff:Software", "medium"),
]


def _detect_in_text(source: str, text: str) -> List[Finding]:
    findings: List[Finding] = []
    low_text = text.lower()

    for needle, conf in PHOTOSHOP_STRINGS:
        if needle.lower() in low_text:
            findings.append(
                Finding(
                    source=source,
                    key="contains",
                    value=needle,
                    confidence=conf,
                )
            )

    for key, conf in XMP_KEYS:
        if key.lower() in low_text:
            findings.append(
                Finding(
                    source=source,
                    key="contains",
                    value=key,
                    confidence=conf,
                )
            )

    return findings


def _read_exif(path: Path) -> Dict[str, Any]:
    try:
        with Image.open(path) as img:
            exif = img.getexif()
            if not exif:
                return {}
            out: Dict[str, Any] = {}
            for tag_id, value in exif.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                # Keep values JSON-friendly
                if isinstance(value, bytes):
                    value_str = _safe_decode(value)
                    out[tag_name] = _normalize(value_str)
                else:
                    out[tag_name] = value
            return out
    except Exception:
        return {}


def _find_photoshop_indicators(exif: Dict[str, Any], xmp_xml: Optional[str]) -> List[Finding]:
    findings: List[Finding] = []

    # Common EXIF tag for editor
    software = exif.get("Software")
    if isinstance(software, str) and software.strip():
        if "photoshop" in software.lower():
            findings.append(Finding(source="exif", key="Software", value=_normalize(software), confidence="high"))
        else:
            findings.append(Finding(source="exif", key="Software", value=_normalize(software), confidence="low"))

    # Some cameras/editors set "ProcessingSoftware" or similar (not always present)
    for k in ("ProcessingSoftware", "Artist", "ImageDescription"):
        v = exif.get(k)
        if isinstance(v, str) and v.strip():
            if "photoshop" in v.lower() or "adobe" in v.lower():
                findings.append(Finding(source="exif", key=k, value=_normalize(v), confidence="medium"))

    if xmp_xml:
        findings.extend(_detect_in_text("xmp", xmp_xml))

    # De-dup exact repeats
    uniq: Dict[Tuple[str, str, str, str], Finding] = {}
    for f in findings:
        uniq[(f.source, f.key, f.value, f.confidence)] = f
    return list(uniq.values())


def _verdict(findings: List[Finding]) -> str:
    """
    Conservative verdict:
    - "likely" if we see explicit Photoshop strings or EXIF Software mentions Photoshop
    - "possible" if only weaker Adobe/keywords appear
    - "not_detected" otherwise
    """
    confs = [f.confidence for f in findings]
    has_high = "high" in confs
    has_medium = "medium" in confs

    if has_high:
        return "likely_photoshop_edit"
    if has_medium:
        return "possible_edit_or_adobe_tooling"
    return "not_detected"


def analyze_image(path: Path) -> Dict[str, Any]:
    file_bytes = path.read_bytes()
    exif = _read_exif(path)
    xmp_xml = _extract_xmp_xml(file_bytes)
    findings = _find_photoshop_indicators(exif=exif, xmp_xml=xmp_xml)

    return {
        "file": str(path),
        "verdict": _verdict(findings),
        "findings": [asdict(f) for f in sorted(findings, key=lambda f: (f.source, f.key, f.value))],
        "exif_excerpt": {k: exif[k] for k in ("Software", "ProcessingSoftware", "Artist", "ImageDescription") if k in exif},
        "has_xmp": xmp_xml is not None,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check an image's metadata for common Adobe Photoshop fingerprints (EXIF/XMP)."
    )
    parser.add_argument("image", type=str, help="Path to an image file (JPEG/PNG/TIFF/etc.)")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args(argv)

    path = Path(args.image)
    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 2
    if path.is_dir():
        print(f"Error: expected a file, got directory: {path}", file=sys.stderr)
        return 2

    try:
        result = analyze_image(path)
    except Exception as e:
        print(f"Error: failed to analyze image: {e}", file=sys.stderr)
        return 1

    if args.pretty:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(result, separators=(",", ":"), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

