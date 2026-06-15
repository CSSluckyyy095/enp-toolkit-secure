# enp-toolkit-secure
Secure Encryption Toolkit built with Python and Cryptography
# 🔐 ENP-Toolkit-Secure

ENP-Toolkit-Secure is a Python-based cryptographic desktop application built with Tkinter and the Cryptography library. It provides secure encryption and decryption capabilities for both text and files through multiple modern cryptographic algorithms.

The project was developed as a cybersecurity-focused application emphasizing secure key management, password-based encryption, cryptographic best practices, and an intuitive graphical user interface.

## ✨ Features

* Encrypt and decrypt text or files
* Support for multiple cryptographic algorithms
* Password-based encryption using PBKDF2-HMAC-SHA256
* RSA public/private key generation
* Secure key vault storage protected by a master password
* Password strength indicator
* Multi-threaded processing to maintain UI responsiveness
* Modern dark-themed graphical interface
* Output copy, save, and swap functionality

## 🛡️ Security Features

### Memory Sanitization

Sensitive cryptographic material such as encryption keys is overwritten after use through a custom buffer sanitization mechanism.

### Protected Key Storage

Fernet and RSA private keys can be stored in encrypted form using AES encryption derived from a master password.

### Key Derivation

Password-based encryption uses PBKDF2-HMAC-SHA256 with high iteration counts to derive strong encryption keys.

### RSA Hybrid Encryption

Uses a hybrid encryption model where data is encrypted using AES and the AES key is protected using RSA-2048 with OAEP padding.

### Responsive Processing

Encryption and decryption operations run in background threads to prevent application freezing during large file operations.

## 🔑 Supported Algorithms

| Algorithm  | Type                               |
| ---------- | ---------------------------------- |
| AES-128    | Symmetric                          |
| AES-192    | Symmetric                          |
| AES-256    | Symmetric                          |
| ChaCha20   | Stream Cipher                      |
| TripleDES  | Legacy Symmetric Cipher            |
| Fernet     | Authenticated Symmetric Encryption |
| RSA-Hybrid | Asymmetric + AES Hybrid Encryption |

## 📂 Supported File Types

The toolkit can encrypt virtually any file type. Commonly tested formats include:

* Documents: TXT, PDF, DOC, DOCX, PPT, PPTX
* Images: JPG, JPEG, PNG, GIF
* Audio: MP3
* Video: MP4
* Archives: ZIP, RAR

## 🚀 Installation

### Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/enp-toolkit-secure.git
cd enp-toolkit-secure
```

### Install Dependencies

```bash
pip install cryptography
```

### Run Application

```bash
python enp_toolkit_secure.py
```

## 🧰 Technologies Used

* Python
* Tkinter
* Cryptography Library
* AES Encryption
* RSA Cryptography
* ChaCha20
* Fernet
* JSON
* Multithreading

## 📚 Educational Purpose

This project was created to explore practical cryptography, secure key management, encryption workflows, and desktop application development in Python.

## 👨‍💻 Author



Cybersecurity Enthusiast | Python Developer | Security Research Learner
