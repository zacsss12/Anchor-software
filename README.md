# Anchor

Anchor is a **local, offline integrity verification tool**.

It allows you to verify that files or folders remain **exactly the same over time**, without relying on servers, accounts, certificates, or network access.

Anchor is designed for **personal verification**, not third-party trust.

---

## Core Principles

- Fully offline
- Deterministic and reproducible
- No accounts
- No servers
- No network
- User-controlled seed

---

## Features

### 🔐 File Proofs

Anchor can create cryptographic proofs for individual files.

- SHA-256 hashing of file contents
- Deterministic proof generation using a 24-word user seed
- Verify later that:
  - The file has not changed
  - The same seed still controls the proof

This answers the practical question:

> “Is this file **exactly the same** as when I anchored it?”

---

### 🖥️ System Baseline (NEW)

Anchor includes a **System mode** that allows you to create a reproducible baseline of a folder and verify integrity drift over time.

You can:

- Recursively scan a folder
- Generate a deterministic manifest (`baseline.manifest.json`)
- Bind it to a cryptographic proof (`baseline.proof.json`)
- Verify later and detect:
  - Added files
  - Removed files
  - Modified files

This is useful for:

- Post-install OS snapshots (e.g. Arch Linux)
- Important folders (documents, configs, datasets)
- Detecting unexpected or accidental changes over time

**Notes:**

- On Windows, baselines are intended for user folders (Desktop, Documents, etc.)
- On Linux, full system baselining is possible (excluding virtual filesystems)
- All operations are local and offline

---

## What Anchor Is NOT

- Not a public-key signature system
- Not a blockchain or timestamping service
- Not designed for non-repudiation
- Not intended for third-party verification

Anchor focuses on **local, human-scale integrity verification**.

---

## 📦 Prebuilt Binary (Windows)

This repository includes a prebuilt Windows binary:

- `Anchor.rar`

This is provided for users who want to **run Anchor without Python or source code**.

The archive contains:
- A standalone Windows executable
- No installation required
- No network access

The **full source code** used to build the binary is available in this repository.

---

## 🪟 Windows Notes

Windows SmartScreen or antivirus software may show generic warnings because the application is unsigned (common for PyInstaller-based apps).

---

## License

MIT License
