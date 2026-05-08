# Photoshop metadata checker (Python)

This small tool inspects an image’s **EXIF** and embedded **XMP** metadata and reports whether it contains common fingerprints associated with **Adobe Photoshop** (or other Adobe tooling).

It **cannot prove** an image was (or wasn’t) edited—metadata can be stripped, forged, or rewritten. This tool only reports what it can detect in the file you provide.

## Setup

Install Python 3.9+ (3.10+ recommended), then in this folder:

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
python check_photoshop.py "path\to\image.jpg" --pretty
```

Output is JSON, for example:

- `verdict`: one of
  - `likely_photoshop_edit`: explicit Photoshop indicators found (highest confidence)
  - `possible_edit_or_adobe_tooling`: weaker indicators found
  - `not_detected`: nothing obvious found
- `findings`: list of indicators (where they were found and why they matter)
- `exif_excerpt`: quick view of a few relevant EXIF fields (if present)
- `has_xmp`: whether an XMP packet was detected

## What the tool checks

- **EXIF `Software`**: often contains the editor name (e.g., “Adobe Photoshop …”)
- **Other EXIF fields** (`ProcessingSoftware`, `Artist`, `ImageDescription`) if present
- **XMP packet** (if embedded): searches for common Photoshop-related fields and strings

## Notes / limitations

- Many platforms (social media, messengers) strip metadata when re-encoding images.
- Some editors write `Software` but are not Photoshop; and Photoshop can be configured to preserve/strip metadata.
- A “not detected” result is common even for edited images if metadata is missing.

