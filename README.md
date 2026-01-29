<center><h1>Onyx</h1></center>

![Security Status](https://img.shields.io/badge/security-audited-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-yellow)
![License](https://img.shields.io/badge/license-MIT-green)

**Onyx** is a proof-of-concept encrypted file sharing tool designed to demonstrate the power of **Zero-Knowledge Proofs (ZKP)** and **Key Sharding** in securing user data.

Unlike traditional cloud storage where the provider holds the keys, Onyx implements a "Split-Key" architecture. The master decryption key is never stored in one place; it is split into shards—one stored on the server, and one derived dynamically from the user's passphrase—ensuring that neither the server nor a compromised device alone can decrypt the data.

## 🛡️ Core Concepts

* **Zero-Knowledge Architecture:** The server verifies your identity and rights to the data without ever "seeing" your password or the decryption key.
* **Key Sharding:** The Master Key is split using a proprietary splitting algorithm (conceptually similar to Shamir's Secret Sharing).
    * *Shard A:* Stored on the remote server (encrypted).
    * *Shard B:* Reconstructed locally from the user's passphrase.
* **Reconstruction:** The full Master Key exists only in RAM for the milliseconds required to encrypt/decrypt, then is immediately wiped.

## 🚀 Features

* **AES-256-GCM Encryption:** Industry-standard authenticated encryption for file content.
* **Terminal Interface:** A clean, hacker-friendly CLI for managing vaults and keys.
* **Offline Mode:** Capable of local-only encryption for sensitive air-gapped operations.
* **Modular Design:** The ZKP and Sharding logic are decoupled, allowing for easy updates to the cryptographic primitives.

## 🛠️ Tech Stack

* **Language:** Python 3.10+
* **Cryptography:** `pycryptodome`, `hashlib`, `secrets`
* **CLI:** `argparse` / `click`
* **Storage:** Local JSON vaults (for metadata) / SQLite

## 📂 Project Structure

```bash
onyx-zkp/
├── core/
│   ├── crypto_engine.py   # AES-256 implementation
│   ├── zkp_auth.py        # Zero-Knowledge authentication logic
│   └── shard_manager.py   # Key splitting and reconstruction
├── cli/
│   └── interface.py       # Terminal UI
├── tests/
│   └── test_vectors.py    # Crypto correctness tests
├── config.py
├── main.py
└── requirements.txt
