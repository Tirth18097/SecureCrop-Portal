# 🌾 SecureCrop — Agricultural Data Security Portal

A full-stack cryptography project implementing **AES-128**, **SHA-256**, and **RSA-2048 Digital Signatures** for securing farmer crop data.

---

## 🔐 Cryptography Stack

| Algorithm | Purpose | Details |
|-----------|---------|---------|
| **AES-128** | Confidentiality | CBC mode, random 16-byte key per record |
| **SHA-256** | Integrity | Detects any data tampering |
| **RSA-2048** | Authentication | PKCS#1 v1.5 digital signature |

---

## 📁 Project Structure

```
secure_crop_portal/
├── app.py                  # Flask backend (all crypto logic)
├── requirements.txt        # Python dependencies
├── crop_data.db            # SQLite database (auto-created)
├── templates/
│   └── index.html          # Frontend portal
└── README.md
```

---

## 🚀 Setup & Run

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Flask server
```bash
python app.py
```

### 3. Open in browser
```
http://localhost:5000
```

---

## 🔄 System Workflow

```
Farmer Login
    ↓
Enter Crop Data
    ↓
SHA-256 Hash Generated  ────────────────────────┐
    ↓                                            │
AES-128 Encryption (CBC)                         │
    ↓                                            │
RSA-2048 Digital Signature                       │
    ↓                                            │
Stored in SQLite Database ◄──────────────────────┘
    ↓
Agricultural Department Retrieves
    ↓
AES Decryption
    ↓
SHA-256 Integrity Check ✅
    ↓
RSA Signature Verification ✅
    ↓
Original Data Displayed
```

---

## 📌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/encrypt` | Encrypt & store crop data |
| `GET` | `/api/decrypt/<id>` | Decrypt & verify record |
| `GET` | `/api/records` | List all stored records |

---

## 🎓 Algorithm Details

### AES Encryption (app.py: `aes_encrypt`)
- Generates a fresh random 16-byte key per record
- CBC mode with random IV for semantic security
- Data is padded to AES block size (PKCS7)

### SHA-256 Hashing (app.py: `sha256_hash`)
- Hash computed on raw crop data before encryption
- Stored alongside encrypted data
- Re-computed on decryption and compared

### RSA Digital Signature (app.py: `sign_data`, `verify_signature`)
- 2048-bit RSA key pair generated per upload
- Private key signs SHA-256 hash of data
- Public key stored in DB for later verification
- PKCS#1 v1.5 scheme

---

## ✅ Three Goals of Cryptography Achieved

1. **Confidentiality** → AES encryption
2. **Integrity** → SHA-256 hashing
3. **Authentication** → RSA digital signatures
