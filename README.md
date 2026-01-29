<h1 align="center">Onyx</h1>

<div align="center">
<img src="https://github.com/Joel-Shine/onyx/blob/main/onyx.png" alt="onyx logo" height=300px width=300px>

![Security Status](https://img.shields.io/badge/security-audited-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-yellow)
![License](https://img.shields.io/badge/license-MIT-green)

</div>

**Onyx** is a high-security, terminal-based file transfer utility. It allows two peers to exchange files and folders without a middleman—or even the relay server—ever having access to the raw data or the decryption keys. 
By combining **Zero-Knowledge Proof (ZKP)** principles with **SRP-hardened** key exchange, Onyx ensures that security is maintained even if the server infrastructure is compromised.

---

## ✨ Key Features

* **Zero-Knowledge Handshake**: Uses a password-derived generator ($g$) and RFC 3526 Group 14 primes ($P$) to establish a shared AES-256 key without the password ever leaving your machine.
* **SRP-Hardened Math**: Implements **PBKDF2-HMAC-SHA256** with 100,000 iterations to derive a secure generator, making brute-force attacks computationally expensive.
* **End-to-End Encryption**: All data is encrypted using **AES-GCM (Authenticated Encryption)**, providing both confidentiality and built-in tamper detection.
* **Blind Relay Architecture**: The FastAPI server acts as a "dumb" pipe; it synchronizes the two peers and relays raw bytes without any ability to decrypt the stream.
* **Auto-Compression**: Automatically handles folder transfers by zipping them into temporary archives and performing zero-trace cleanup post-transfer.
* **Integrity Verification**: Performs SHA-256 checksum validation after the transfer to ensure bit-for-bit accuracy.

---

## 🚀 Quick Start

### Usage
* Generate a Passphrase
One user generates a secure 8-word code to share (via a secure channel like Signal or in person) [OPTIONAL]:
```bash
python onyx.py gen-code
```

* Prepare to Receive
The receiver starts the listener and enters the shared code:
```bash
python onyx.py receive
```

3. Send the Data
The sender points to a file or folder and enters the same code:
```bash
python onyx.py send ./my_project_files
```

## 🧠 How it Works (The Tech Stack)

### 1. The Secure Handshake
Onyx doesn't just use the password as a key. It uses the password to derive a unique mathematical generator ($g$) using **PBKDF2-HMAC-SHA256** with 100,000 iterations. Both clients then perform a **Diffie-Hellman** exchange using **MODP Group 14** (a 2048-bit prime):
1.  **Client A** sends $A = g^a \pmod P$
2.  **Client B** sends $B = g^b \pmod P$
3.  Both derive the same **Shared Secret** $S = B^a \pmod P = A^b \pmod P$, which is then hashed into a 256-bit AES key.

### 2. The Relay Logic
The server (`server.py`) identifies the "room" using a 16-character hash of the passphrase to ensure privacy. It acts as a synchronization barrier, waiting until exactly two users are present before sending a `READY` signal to trigger the handshake.

### 3. Secure Streaming & Integrity
* **Chunking**: Files are read and encrypted in **64KB chunks**.
* **AES-GCM**: Each chunk is wrapped in its own Authenticated Encryption envelope with a unique 12-byte nonce, protecting against replay and bit-flipping attacks.
* **Checksums**: A SHA-256 hash is calculated pre-transfer and verified post-transfer to ensure the file is bit-for-bit identical.

---

## 🛠️ Development & Contributions

This project was built as a secure alternative for peer-to-peer sharing during development, specifically designed for terminal-based workflows. 

**Future Roadmap:**
* **NAT Traversal**: Implementing STUN/TURN support to allow direct P2P connections and bypass the relay server entirely.
* **Performance Tuning**: Implementing concurrent stream processing to maximize bandwidth utilization.
* **Cross-Platform Binaries**: Using PyInstaller to provide standalone `.exe` and Unix binaries for easier distribution.

We welcome contributions! If you find a bug (especially in the crypto logic) or have a feature request, please open an issue or submit a pull request.
