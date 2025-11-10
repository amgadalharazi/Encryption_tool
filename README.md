---

### 🔐 Secure File Encryption System

A Python-based AES-256 encryption tool that securely encrypts and decrypts any file type.
It automatically manages encryption keys, metadata, and directory structure for easy restoration of original files.

**Features:**

* AES-256 (GCM mode) encryption and decryption
* Batch encryption/decryption for all files in a directory
* Metadata tracking to restore original filenames and extensions
* Secure random key generation and storage
* Simple interactive CLI for file management

**Usage:**

1. Place files inside the `input` directory.
2. Run `encrypt.py` and choose an option from the menu.
3. Encrypted files and keys are saved in the `output` directory.

---
