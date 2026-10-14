# Smart Cloud Shield (SCS)

> **Zero-Trust Cloud DLP & Intelligent Behavioral Threat Detection Platform**

Smart Cloud Shield (SCS) is an enterprise cloud security platform built with Flask, SQLAlchemy, Scikit-Learn, and Cryptography. It scans, classifies, and encrypts uploaded documents using attribute-gated envelope encryption (Fernet DEK/KEK), then dynamically scores **every download attempt** across 4 risk pillars (File Sensitivity + Volume Velocity + Device/Time Context + Isolation Forest ML Anomaly Detection) to **Allow, Warn, or Block** downloads in real time.

---

## ⚡ Quick Start Options

### Option 1: 1-Click Launchers (Recommended)
Cloned the repository? Just run the script for your platform — it automatically creates the virtual environment, installs dependencies, initializes and seeds the database, and boots the server:

* **Windows:** Double-click [`start.bat`](start.bat) or run `powershell -ExecutionPolicy Bypass -File .\start.ps1`
* **Linux / macOS / WSL:** Run `chmod +x start.sh && ./start.sh`

Navigate to: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

### Option 2: Docker / Docker Compose
Ensure Docker is installed and running:

```bash
docker compose up --build
```
The application will be live at **http://127.0.0.1:5000**.

---

### Option 3: Manual Setup (Cross-Platform)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/San245o/smart_cloud_shield.git
   cd smart_cloud_shield
   ```

2. **Create and activate a virtual environment:**
   ```bash
   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate

   # Windows (CMD / PowerShell)
   python -m venv venv
   .\venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize and seed the database:**
   ```bash
   python seed.py
   ```
   *(This generates master encryption keys, creates demo users, populates sample sensitive files with DLP tags, and trains the Isolation Forest ML baseline).*

5. **Start the application:**
   ```bash
   python app.py
   ```
   Access the web console at **http://127.0.0.1:5000**.

---

## 🔑 Demo Accounts & Credentials

All seeded accounts share the default development password: **`Pass@12345`**

| Username | Role | Department | Clearance Level | Access Scope |
|---|---|---|---|---|
| **`admin`** | Administrator | IT / Security | Level 3 (Top Secret) | Full access to Admin SIEM, Threat Copilot, Incidents, and Audit Logs |
| **`alice`** | Employee | Finance | Level 3 (Secret) | Financial records, payroll data, high-sensitivity files |
| **`bob`** | Employee | HR | Level 2 (Confidential) | Team contacts, employee sync notes |
| **`carol`** | Employee | Engineering | Level 3 (Secret) | Server configs, architecture specs |
| **`dave`** | Employee | General | Level 1 (Internal) | Public brochures, company-wide docs |
| **`guest1`** | Guest | General | Level 0 (Public) | Publicly viewable documents only |

> ℹ️ **MFA / OTP in Dev Mode:** With default settings (`SHOW_OTP=1`), the 6-digit MFA OTP is automatically displayed on-screen and printed in your terminal window upon login. No external email server configuration is required to test!

---

## ⚙️ Configuration & Environment Variables

SCS works **100% out-of-the-box** without any configuration. To customize SMTP relays, Google Gemini AI keys, or storage backends, copy the example file:

```bash
cp .env.example .env     # Windows: copy .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | *(Auto-generated)* | Flask session secret key |
| `SHOW_OTP` | `1` | Set to `0` to hide on-screen dev OTP banners once real email is configured |
| `DEMO_MODE` | `0` | Set to `1` to run in isolated evaluation mode |
| `MAIL_SERVER` | *None* | SMTP server host (e.g. `smtp.gmail.com`). When omitted, emails log to the simulated outbox |
| `MAIL_PORT` | `587` | SMTP port (587 for TLS, 465 for SSL) |
| `MAIL_USER` | *None* | SMTP account username / email |
| `MAIL_PASSWORD` | *None* | SMTP app password |
| `ADMIN_ALERT_EMAIL` | *None* | Recipient email for real-time security alerts on blocked exfiltration |
| `GEMINI_API_KEY` | *None* | Google Gemini API key. When omitted, SCS uses its built-in Local Threat Synthesizer |
| `GEMINI_MODEL` | `gemini-1.5-flash` | Gemini model name |
| `STORAGE_BACKEND` | `local` | `local` or `s3` |
| `S3_BUCKET` | *None* | AWS S3 bucket name if using S3 storage |

---

## 🧪 Running Automated Tests

Run the test suite with `pytest`:

```bash
pytest
```
*Includes 34 comprehensive test cases covering DLP pattern matching, Luhn & Verhoeff checksums, envelope encryption benchmarks, ML scoring, audit hash chains, and access control policies.*

---

## 🎯 Viva & Defense Simulation Demo

Run the automated attack simulator to demonstrate risk engine decisions:

```bash
python seed.py && python simulate.py
```
This demonstrates 4 distinct operational scenarios:
1. **Normal Day:** Low risk, download allowed.
2. **Legitimate Busy Day:** 12 rapid downloads of low-risk files; triggers warnings at most, never blocked (demonstrating false-positive resilience).
3. **Insider Threat Exfiltration:** Bulk downloading confidential files from a trusted device; allowed, warned, and **blocked at the 13th file**.
4. **Stolen Credentials:** Login from an untrusted device at 2:00 AM; **blocked on the very first attempt**, account auto-restricted after repeated blocks.

Then log in as `admin` to inspect:
* **Dashboard:** Live risk metrics, threat distribution, and active users.
* **Incident Center:** Root cause analysis, DLP highlights, and 1-click account lockout / file quarantine.
* **Audit Trail:** Cryptographically verified SHA-256 hash chain with tamper detection.
* **GenAI Threat Copilot:** CISO executive threat summaries and root-cause forensics.

---

## 🏗️ Architecture & Module Mapping

| Component | Primary File | Description |
|---|---|---|
| **Authentication & MFA** | `scs/routes/auth.py` | Scrypt password hashing, rate limiting (5 fails = 15 min lock), 6-digit OTP MFA |
| **RBAC + ABAC Access Control** | `scs/services/access.py` | Role permissions + department boundaries + clearance levels vs file classification |
| **DLP & OCR Inspection** | `scs/services/dlp.py` | Aadhaar (Verhoeff), Credit Cards (Luhn), PAN, IFSC, API keys, private keys + Tesseract OCR |
| **Envelope Encryption** | `scs/services/crypto.py` | Unique AES-128-CBC / Fernet DEK per file, wrapped by Master KEK stored securely outside DB |
| **Secure Deduplication** | `scs/routes/files.py` | SHA-256 file fingerprinting with storage reference counting |
| **Storage Integrity** | `scs/routes/admin.py` | On-demand cryptographic checksum & decryption verification |
| **IDPS Incident Quarantine** | `scs/routes/admin.py` | Active quarantine and download blocking against data exfiltration |
| **Safe Redaction & Watermark** | `scs/routes/files.py` | In-browser preview with diagonal anti-leak watermark and redaction |
| **Behavioral ML Anomaly** | `scs/services/ml.py` | Isolation Forest trained on 6 behavioural telemetry features |
| **4-Pillar Risk Engine** | `scs/services/risk.py` | Composite risk score: Sensitivity (30) + Velocity (20) + Context (25) + ML (25) |
| **Tamper-Evident Audit Log** | `scs/models/models.py` | SHA-256 hash-chained ledger verifying chronological log integrity |
| **Email Alert Pipeline** | `scs/services/mailer.py` | HTML MFA emails, high-risk security alert dispatches, and dev simulation outbox |
| **GenAI Threat Intelligence** | `scs/services/ai_agent.py` | Gemini 1.5 Flash threat analysis + offline autonomous local NLP synthesizer fallback |

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
