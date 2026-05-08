# BRAC University Anonymous Legal Whistleblowing System

A high-security, end-to-end encrypted whistleblowing platform designed for BRAC University. This system allows students and staff to report legal or ethical violations with guaranteed anonymity through custom-built asymmetric cryptography.

## 🛡️ Security Architecture

Unlike standard applications, this system implements **Custom Cryptography from Scratch** to ensure no reliance on external libraries for core security:

- **Asymmetric RSA (256-bit+):** Used for encrypting report content and attachments.
- **ECC (SECP256k1):** Used for encrypting and protecting user identity metadata.
- **Custom HMAC:** Ensures data integrity and non-repudiation of reports.
- **Zero-Plaintext Storage:** Sensitive user profiles and report contents are stored as mathematical cipher-blocks.
- **Role-Based Access Control (RBAC):** Strict separation of duties between Reporters, Auditors, and Admins.

---

## 🔄 Operational Workflow

### 1. Reporter Phase
- **Registration:** Students must use `@g.bracu.ac.bd` emails. Identity is ECC-encrypted for Admin eyes only.
- **Submission:** Reports are RSA-encrypted using the **Admin's Public Key**. The system supports optional attachments (Doc/PDF/Image/Video) which undergo heavy mathematical chunked encryption.

### 2. Administrative Oversight
- **Case Review:** Admin views a list of pending cases. Upon opening a case, the Admin can decrypt the reporter's identity and the report content.
- **Assignment:** Admin assigns a report to an **Auditor (Proctor)**. 
- **Cryptographic Handover:** The system decrypts the report with the Admin's private key and **re-encrypts** it using the specific Auditor's Public RSA key.

### 3. Auditor Validation
- **Independent Audit:** Auditors (Proctors) log in and see cases assigned specifically to them.
- **Anonymity:** The Auditor **cannot** see who reported the case (Identity Withheld).
- **Feedback:** Auditors provide descriptive analysis and feedback, then mark the report as "Validated."

### 4. Final Resolution
- **Decision:** Admin reviews the Auditor's feedback and makes the final status update (Approved, Rejected, or Need More Information).

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- Node.js 16+
- SQLite3

### Backend Setup (FastAPI)
1. Navigate to the `backend` directory.
2. Install dependencies:
   ```bash
   pip install fastapi uvicorn pydantic requests
   ```
3. Run the server:
   ```bash
   python -m uvicorn main:app --reload --port 8000
   ```
   *Note: On first run, the system will auto-generate the Admin account and keystore.*

### Frontend Setup (Next.js)
1. Navigate to the `frontend` directory.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run the development server:
   ```bash
   npm run dev
   ```
   *Access the UI at `http://localhost:3000`*

---

## 🔑 Default Credentials
- **Admin Email:** `admin@university.edu`
- **Admin Password:** `adminPassword123`

---

## ⚠️ Known Constraints
- **Computational Load:** Because RSA/ECC are implemented in pure Python math, decrypting large attachments (>1MB) is computationally expensive. Use the "Lazy Decryption" feature implemented in the UI.
- **Key Management:** Private keys are stored in `keystore.json`. For production, integrate a hardware security module (HSM).
