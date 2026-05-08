# TruthSeal 2026

**Bridging Digital Integrity and Physical Sovereignty**

TruthSeal 2026 is a next-generation cybersecurity utility designed to ensure the immutable integrity of documents across both digital and physical mediums. Architected in Tunisia for the 2026 threat landscape, this tool provides a robust defense against sophisticated metadata manipulation and forgery.

## 🛡️ Three-Layer Security Model

TruthSeal employs a defense-in-depth strategy, integrating three distinct layers of verification:

1.  **LAYER 1: Digital Provenance (C2PA & Ed25519)**
    Uses industry-standard C2PA (Coalition for Content Provenance and Authenticity) manifests and Ed25519 digital signatures. Every file is cryptographically signed at the source, providing an undeniable record of origin and author identity.
2.  **LAYER 2: Blockchain Anchoring (OpenTimestamps)**
    Digital hashes are anchored to the Bitcoin blockchain via OpenTimestamps (OTS). This provides a decentralized, immutable timestamp that proves the document existed in a specific state at a certain point in time, independent of any central authority.
3.  **LAYER 3: Physical Verification (.print & QR Watermark)**
    The project bridges the "analog gap" by generating a `.print` version of documents. These files feature a unique, signed QR watermark containing identity metadata. This watermark can be scanned from physical paper to verify digital authenticity.

---

## ⚠️ The Absolute Path Rule (VENV_PYTHON)

**CRITICAL INSTALLATION REQUIREMENT:**
Due to conflicts with the Windows Store Python distribution (which often hijacks the `python` alias or creates Path collisions), TruthSeal 2026 utilizes a **hardcoded absolute path logic** for system stability.

To ensure the utility functions correctly, you **MUST** update the `VENV_PYTHON` variable with the absolute path to your local virtual environment's executable in the following files:

- `guard_sealer.py`
- `verify_trust.py`
- `ots_watchdog.py`

*Example configuration in PowerShell:*
`$VENV_PYTHON = "C:\Users\Name\truthseal-env\Scripts\python.exe"`

---

## 🛠️ The Core Engine: Script Architecture

- **`truthseal_hash.py`**: The "Source of Truth." Performs high-performance binary hashing using 1MB chunking, ensuring even multi-gigabyte files are hashed with consistent memory efficiency.
- **`guard_sealer.py`**: The primary sealing engine. Orchestrates the generation of `.sealed` (encrypted/signed metadata) and `.print` (watermarked physical readiness) files.
- **`verify_trust.py`**: The detective suite. Verifies digital signatures and utilizes OpenCV to scan and decode QR watermarks from physical documents via the `--scan` command.
- **`ots_watchdog.py`**: An asynchronous background service that monitors pending blockchain proofs and automatically upgrades them once they reach sufficient confirmations on the Bitcoin network.
- **`check_photoshop.py`**: A specialized pre-sealing tool that analyzes document metadata for Adobe Photoshop fingerprints, flagging potential AI-assisted or manual alterations before the document enters the trust pipeline.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- A valid Bitcoin network node access (via public OTS calendars)
- Webcam (required for physical QR scanning features via OpenCV)

### Installation

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/your-org/truthseal-2026.git
    cd truthseal-2026
    ```

2.  **Initialize the Environment:**
    Ensure you create a virtual environment and update the **Absolute Path Rule** as mentioned above.

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Initialize Registry:**
    The utility requires a local registry for tracking sealed assets. Initialize this as an empty list:
    ```bash
    echo "[]" > registry.json
    ```

### Execution Example

To seal a document using the absolute path methodology in PowerShell:
```powershell
& $VENV_PYTHON guard_sealer.py --input "contract_v1.pdf" --output "contract_v1.sealed"
```

To verify a physical document via webcam:
```powershell
& $VENV_PYTHON verify_trust.py --scan
```

---

## ⚖️ License & Disclosure

TruthSeal 2026 is released as a **Hardened Production Build** for Beta trials. It is built on the philosophy of **Preventive Cybersecurity**—move fast, but secure everything.

*Immutable Data. Absolute Integrity. 2026.*
