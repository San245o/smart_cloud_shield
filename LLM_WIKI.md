# Smart Cloud Shield (SCS) — LLM Developer Wiki

> **Purpose:** This wiki serves as the authoritative architectural blueprint and operating manual for LLMs and developers working with the **Smart Cloud Shield** codebase.

---

## 1. Project Overview & Identity

* **Name:** Smart Cloud Shield (SCS)
* **Domain:** Cloud Data Security, Zero-Trust Architecture, Data Loss Prevention (DLP), Insider Threat Detection.
* **Tech Stack:**
  * **Language:** Python 3.12+
  * **Framework:** Flask 3.x with Application Factory & Blueprints
  * **ORM & Database:** Flask-SQLAlchemy / SQLAlchemy 2.x (SQLite default, PostgreSQL ready)
  * **Authentication:** Flask-Login, Werkzeug (`scrypt`), Custom Email/Dev OTP MFA
  * **Cryptography:** `cryptography` (Fernet Envelope Encryption: DEK + KEK)
  * **Machine Learning:** `scikit-learn` (Isolation Forest) with Pure-Python Heuristic Fallback
  * **Testing:** `pytest` (27 comprehensive unit & integration tests)

---

## 2. Directory Structure & Codebase Map

```
smart_cloud_shield/
│
├── scs/                         # Core Application Package
│   ├── __init__.py              # Application factory (create_app), extension setup, blueprint registration
│   ├── config.py                # BaseConfig, paths, environment variables, security defaults
│   │
│   ├── models/                  # Data Layer
│   │   ├── __init__.py          # Exports all models and DB utilities
│   │   └── models.py            # User, Device, Otp, File, Event, Incident, Audit (Hash-Chained)
│   │
│   ├── services/                # Core Security & Business Engines
│   │   ├── __init__.py          # Unified service exports
│   │   ├── access.py            # RBAC + ABAC authorization logic
│   │   ├── crypto.py            # Envelope encryption (per-file DEK wrapped by KEK)
│   │   ├── dlp.py               # Data Loss Prevention, regex scanners, Luhn/Verhoeff checksums
│   │   ├── ml.py                # Behavioral anomaly detection (Isolation Forest + fallback)
│   │   ├── risk.py              # 4-pillar explainable risk scoring engine (0-100)
│   │   └── storage.py           # Pluggable storage abstraction (LocalStorage / S3Storage)
│   │
│   ├── routes/                  # Modular Presentation Layer (Flask Blueprints)
│   │   ├── __init__.py          # Blueprint aggregator
│   │   ├── auth.py              # /login, /register, /otp, /logout
│   │   ├── files.py             # /, /files, /upload, /download/<id>, /delete/<id>
│   │   ├── admin.py             # /admin, /api/stats, /admin/incidents, /admin/users, /admin/audit
│   │   └── helpers.py           # Context extractors, device tracking, event logging, OTP dispatch
│   │
│   ├── templates/               # Jinja2 HTML templates
│   │   ├── base.html            # Global layout, navbar, flash messages
│   │   ├── login.html           # Login page
│   │   ├── register.html        # User registration
│   │   ├── otp.html             # Multi-factor authentication code entry
│   │   ├── files.html           # File list & upload interface
│   │   ├── admin.html           # Real-time monitoring dashboard with Chart.js
│   │   ├── incidents.html       # Security incidents triage & review
│   │   ├── users.html           # User privileges & clearance management
│   │   └── audit.html           # Cryptographic hash-chain audit log inspector
│   │
│   └── static/                  # CSS, JS, and Vendor Libraries
│       ├── app.css              # Custom styling
│       ├── bootstrap.min.css    # Responsive UI framework
│       ├── chart.umd.js         # Charting library
│       └── dashboard.js         # Real-time dashboard poller (/api/stats every 5s)
│
├── scripts/                     # Automation, Seeding & Simulations
│   ├── __init__.py
│   ├── seed.py                  # Database wipe, mock users, file classification, and model training
│   └── simulate.py              # 4 automated real-world attack & access scenarios
│
├── tests/                       # Automated Test Suite
│   ├── __init__.py
│   └── test_all.py              # 19 unit & integration tests covering auth, DLP, risk, and crypto
│
├── instance/                    # Runtime Storage (Excluded from Git)
│   ├── scs.db                   # SQLite primary database
│   ├── kek.key                  # Master Key Encryption Key (Fernet)
│   ├── secret.key               # Flask session secret key
│   ├── iforest.joblib           # Serialized Isolation Forest model
│   └── blobs/                   # Local encrypted file storage
│
├── start.bat                    # 1-click Windows launcher (double-clickable)
├── start.ps1                    # 1-click PowerShell launcher
├── start.sh                     # 1-click Linux/macOS launcher
├── app.py                       # Root launcher (`python app.py`)
├── seed.py                      # Root launcher (`python seed.py`)
├── simulate.py                  # Root launcher (`python simulate.py`)
├── requirements.txt             # Project dependencies
├── .env.example                 # Configurable environment variable reference
└── README.md                    # Quickstart guide & viva documentation
```

---

## 3. Core Pipelines & Security Mechanics

### 3.1 Upload Pipeline (Scan $\rightarrow$ Classify $\rightarrow$ Encrypt $\rightarrow$ Store)
1. **Validation:** Checks file extension against `ALLOWED_EXT` (`txt, csv, xlsx, docx, pdf, png, jpg, jpeg, tiff, bmp, json, log, md`).
2. **Text Extraction & OCR (`dlp.py:extract_text`):**
   * **Documents:** Parses raw text from binaries (Word XML, Excel cell streams, PDF digital text).
   * **Images & Scanned PDFs (OCR):** Uses Tesseract OCR via `Pillow` and `pytesseract` to scan photos, screenshots, and image-based PDFs for confidential text.
   * **Graceful Fallback:** If Tesseract is not installed locally, falls back to printable string inspection without failing.
3. **DLP Inspection (`dlp.py:scan_text`):**
   * Scans for Aadhaar (with **Verhoeff** check digit algorithm).
   * Scans for Credit Cards (with **Luhn** algorithm).
   * Scans for PAN cards, IFSC codes, API keys (`AKIA...`, `sk-...`, `ghp_...`), passwords, private keys, emails, phones, and sensitive keywords.
   * **Privacy by Design:** Stores **only counts**, never raw values.
4. **Classification (`dlp.py:classify`):**
   * Multiplies match counts by risk weights $\rightarrow$ maps to `public`, `internal`, `confidential`, or `highly_confidential`.
5. **Envelope Encryption (`crypto.py:encrypt`):**
   * Generates a random 256-bit Data Encryption Key (DEK).
   * Encrypts file payload using DEK.
   * Wraps (encrypts) the DEK using the server Master Key (KEK).
6. **Storage (`storage.py`):**
   * Writes the ciphertext to disk/S3 under a UUID key. Wrapped DEK is stored in the database.

---

### 3.2 Download Pipeline (Verify May They $\rightarrow$ Verify Is It Safe $\rightarrow$ Enforce)

#### Step 1: Authorization Check (`access.py:can_download`)
* Answers: *"Is this user theoretically allowed to access this file?"*
* **RBAC:** Checks role permissions (`admin`, `employee`, `guest`).
* **ABAC:**
  * Checks user clearance against file sensitivity requirement:
    * `public`: Clearance 0+
    * `internal`: Clearance 1+
    * `confidential`: Clearance 2+
    * `highly_confidential`: Clearance 3+
  * Department Wall: Confidential and Highly Confidential files can **only** be accessed by users in the same department (admins bypass).

#### Step 2: Risk Scoring Engine (`risk.py:assess`)
* Answers: *"Does this download look safe right now?"*
* Total Score: **0 to 100 points**, calculated across 4 pillars:

| Pillar | Max Pts | Logic / Criteria |
|---|:---:|---|
| **1. Sensitivity** | 30 | Public (0), Internal (8), Confidential (18), Highly Confidential (30) |
| **2. Volume / Rate** | 20 | Rapid download bursts: $\min(20, \max(0, n - 3) \times 2)$ within 1 hour |
| **3. Context** | 25 | Unverified/New Device ($<24\text{h}$ old): **+15 pts**<br>Unusual Hour ($<06:00$ or $\ge 22:00$): **+10 pts** |
| **4. ML Anomaly** | 25 | Isolation Forest percentile on 6-feature vector ($>90\text{th}$ percentile) |

#### Step 3: Dynamic Action Enforcement
* **Score 0 – 30 (`allow`):** Decrypt file with unwrapped DEK and stream to client.
* **Score 31 – 70 (`warn`):** Log warning incident, flash warning message, stream file.
* **Score 71 – 100 (`block`):**
  * Reject download, alert administrator, log `Incident`.
  * **Auto-Restriction:** If an account receives **3 blocks within 1 hour**, the system automatically sets `user.status = "restricted"`.

---

### 3.3 Tamper-Evident Audit Trail (`models.py`)
* Every security-relevant event (`login`, `login_fail`, `upload`, `download_allowed`, `download_warned`, `download_blocked`, `user_update`) is recorded in the `Audit` table.
* **Cryptographic Hash Chain:** Each record contains:
  $$\text{hash} = \text{SHA256}(\text{prev\_hash} + \text{ts} + \text{actor} + \text{action} + \text{detail})$$
* **Verification:** `verify_audit_chain()` walks the table in order. Any deletion, insertion, or row edit breaks the hash chain and pinpoints the exact corrupted ID.

---

## 4. Platform Gotchas & Windows WDAC Guidelines

### Windows Application Control (WDAC) / AppLocker
* **Issue:** On Windows systems, executable C-extension binaries (`.pyd` DLLs) located in user folders (e.g. `Desktop\...\venv`) are blocked by security policy, causing:
  `ImportError: DLL load failed while importing _check_build: An Application Control policy has blocked this file.`
* **Rules for Developers/LLMs:**
  1. **SQLAlchemy:** Always ensure `DISABLE_SQLALCHEMY_CEXT=1` is set in environment/config so SQLAlchemy runs in native pure-Python mode.
  2. **Scikit-Learn (`ml.py`):** Keep the try/except guard around `IsolationForest`. If C-extensions are blocked, the system automatically falls back to `HeuristicAnomalyDetector` without crashing.

---

## 5. Development & Testing Cheatsheet

### 5.1 Environment Setup
```powershell
# Activate Virtual Environment
.\venv\Scripts\activate

# Install Dependencies
pip install -r requirements.txt
```

### 5.2 Seeding & Demos
```powershell
# 1. Reset database, seed demo users & sample files, train model:
python seed.py

# 2. Run automated attack simulation:
python simulate.py

# 3. Start development server:
python app.py
```

### 5.3 Test Suite Execution
```powershell
# Run all 27 tests
python -m pytest -v tests
```

### 5.4 Demo User Credentials
* Default Password: `Pass@12345`
* Users:
  * `admin` (Role: admin, Dept: it, Clearance: 3)
  * `alice` (Role: employee, Dept: finance, Clearance: 3)
  * `bob` (Role: employee, Dept: hr, Clearance: 2)
  * `carol` (Role: employee, Dept: engineering, Clearance: 3)
  * `dave` (Role: employee, Dept: general, Clearance: 1)
  * `guest1` (Role: guest, Dept: general, Clearance: 0)

---

## 6. Cloud Deployment & Containerization

### 6.1 Docker Container Deployment
A production-ready [`Dockerfile`](file:///c:/Users/sanke/Desktop/smart_cloud_shield/Dockerfile) and [`.dockerignore`](file:///c:/Users/sanke/Desktop/smart_cloud_shield/.dockerignore) are provided:
```bash
# Build Docker image
docker build -t smart-cloud-shield .

# Run container locally
docker run -p 5000:5000 smart-cloud-shield
```

### 6.2 AWS EC2 / Linux VPS Automated Script
Use [`scripts/deploy_ec2.sh`](file:///c:/Users/sanke/Desktop/smart_cloud_shield/scripts/deploy_ec2.sh) on any fresh Ubuntu/Debian server. It automatically:
* Installs system packages, Python 3, venv, and Nginx.
* Installs dependencies with full native C performance.
* Seeds data and validates test suite.
* Configures systemd background service `scs.service`.

### 6.3 1-Click Free Cloud Hosting (Render / Railway)
The repository includes [`render.yaml`](file:///c:/Users/sanke/Desktop/smart_cloud_shield/render.yaml) for automated provisioning on Render.com or Railway.

---

## 7. Advanced Security Features Added

### 7.1 DLP Content Redaction (Safe Copy)
* **Function:** [`dlp.redact_text()`](file:///c:/Users/sanke/Desktop/smart_cloud_shield/scs/services/dlp.py)
* **Mechanics:** Dynamically scrubs Credit Cards (`****-****-****-1234`), Aadhaar numbers (`********1234`), PAN cards (`ABCPD****E`), API keys (`[REDACTED_API_KEY]`), and passwords while preserving document layout.
* **Access Control Synergy:** Allows employees without high clearance or from another department to download a sanitized, safe copy without leaking restricted PII (`/download/<fid>?mode=redacted`).

### 7.2 Active Incident Remediation & Device Management
* **Admin Portal Enhancements:**
  * **Trust Device:** 1-click promotion of an employee's new laptop to trusted status to eliminate recurring false-positive warnings.
  * **Lock Account:** Instant emergency lockout of compromised user accounts directly from [`incidents.html`](file:///c:/Users/sanke/Desktop/smart_cloud_shield/templates/incidents.html).

### 7.3 Optical Character Recognition (OCR) Engine
* **Supported Formats:** `.png`, `.jpg`, `.jpeg`, `.tiff`, `.bmp`, and scanned image-only `.pdf`.
* **Libraries:** `Pillow>=10.0` and `pytesseract>=0.3.10`.
* **Container Ready:** The included [`Dockerfile`](file:///c:/Users/sanke/Desktop/smart_cloud_shield/Dockerfile) automatically provisions `tesseract-ocr` and `tesseract-ocr-eng` for native Linux cloud deployment.
* **Resilience:** If Tesseract is not installed on a local Windows machine, it seamlessly uses binary printable extraction as a safe fallback without crashing.

### 7.4 Secure Cloud Storage Deduplication
* **Report Reference:** Section 2.7 & Section 6.6 ("Secure Cloud Storage using Data Deduplication").
* **Implementation:** During file upload, a SHA-256 hash of the unencrypted payload is calculated. If an identical file exists in the database, the system reuses the existing encrypted blob key (`stored_name`) and wrapped DEK without allocating duplicate disk/S3 space.
* **Reference-Counted Deletion:** When a file is deleted, `store.delete()` is only triggered if no other `File` record references that `stored_name`.
* **UI Indicator:** Deduplicated files display a distinct `Dedup` badge in the file registry.

### 7.5 Active Incident File Quarantine
* **Report Reference:** Section 5 (IDPS Preventive Actions) & Fig 6.1 Step 8 ("Quarantining infected files / Isolate suspicious files").
* **Implementation:**
  * Files can be quarantined directly by administrators from `incidents.html` or `files.html`.
  * Quarantined files are immediately flagged with a prominent red `QUARANTINED` badge.
  * All raw downloads, redacted copies, and in-browser previews for quarantined files are strictly locked down, preventing data exfiltration during active security reviews.

### 7.6 Zero-Exfiltration In-Browser Watermarked Preview
* **Endpoint:** `/preview/<int:fid>`
* **Features:**
  * Displays text, source code, data tables, and scanned images directly in the browser without requiring local file downloads.
  * Dynamically embeds an anti-leak repeating diagonal watermark containing: `SmartCloud Shield • {USERNAME} ({DEPARTMENT}) • IP: {CLIENT_IP} • {UTC_TIMESTAMP}`.
  * Deterrents: Disables text selection and includes `@media print { body { display: none !important; } }` to block print-to-PDF leaks.
  * Automatically serves redacted text if the viewing user lacks full clearance for confidential files.

### 7.7 Cryptographic Storage Integrity Verification
* **Report Reference:** Section 6.6 ("Regular integrity checks are performed to ensure that stored data is not modified, corrupted, or tampered with by unauthorized users").
* **Endpoint:** `/admin/integrity`
* **Features:**
  * Audits all storage blobs against their recorded SHA-256 content hashes and tests envelope decryption with per-file DEKs.
  * Displays a live dashboard of verified blobs, deduplicated references, and flags any tampered or missing objects.

### 7.8 Enterprise Email & Multi-Tier Notification Pipeline
* **Module:** [`scs/services/mailer.py`](file:///c:/Users/sanke/Desktop/smart_cloud_shield/scs/services/mailer.py)
* **Configuration:** `.env` variables (`MAIL_SERVER`, `MAIL_PORT`, `MAIL_USE_TLS`, `MAIL_USE_SSL`, `MAIL_USER`, `MAIL_PASSWORD`, `MAIL_FROM`, `ADMIN_ALERT_EMAIL`).
* **Capabilities:**
  * **Branded Multi-Factor Authentication (MFA):** Generates styled HTML emails displaying the 6-digit OTP, expiry duration, IP origin, and hardware fingerprint.
  * **Automated Security Incident Dispatches:** Automatically triggers high-priority HTML alert emails to administrators whenever downloads are blocked (`level="block"`) or DLP policies are violated.
  * **Account Restriction Alerts:** Dispatches immediate notifications to administrators and users when an account is locked or auto-restricted following repeated policy violations.
  * **Non-Blocking Background Delivery:** Uses daemon threads for SMTP dispatch, guaranteeing user requests never experience latency from mail servers.
  * **Simulated Development Outbox:** When running without an SMTP server configured, safely records all dispatched emails in memory for instant inspection in the admin dashboard.
  * **Interactive Testing Console:** Administrators can dispatch test verification messages directly from `/admin` to validate mail routing.

### 7.9 GenAI Security Log Summarizer & AI Threat Intelligence Hub
* **Module:** [`scs/services/ai_agent.py`](file:///c:/Users/sanke/Desktop/smart_cloud_shield/scs/services/ai_agent.py)
* **Endpoints:** `/admin/ai-insights`, `/api/admin/ai-summary`, `/api/admin/ai-incident/<iid>`
* **Capabilities:**
  * **Dual-Engine Architecture (Gemini Flash + Local Statistical NLP):**
    * **Google Gemini Live:** Connects via zero-dependency native standard library HTTP requests to `gemini-1.5-flash` (or custom models via `GEMINI_MODEL`).
    * **Local Intelligent Fallback:** When offline or when no `GEMINI_API_KEY` is provided, an intelligent statistical NLP engine computes the zero-trust risk matrix, actor anomaly vectors, and provides a structured executive threat report with zero crashes.
  * **Executive CISO Threat Posture Assessment:** Analyzes telemetry across selectable time windows (6h, 24h, 72h, 7d) to compute a 0-100 Security Posture Score, threat grade, anomalous actor list, and DLP blast radius.
  * **One-Click Incident Forensic Deep Dive:** Evaluates individual incidents, explaining why specific actions were flagged, assessing intentional insider exfiltration vs accidental policy violation, and suggesting prioritized remediation (Quarantine, Device Trust, User Restriction).
  * **Export Capabilities:** Supports instant 1-click clipboard copying and text/markdown report export.

---


## 8. Academic Project Information
* **Institution:** MVJ College of Engineering (Autonomous Institute, VTU), Bangalore.
* **Department:** Computer Science and Design (CSD).
* **Academic Year:** 2025 – 2026.
* **Project Title:** Smart Cloud Shield: Data Leakage Detection and Prevention using Cloud Computing.
* **Project Team:**
  * Raghavendra NR (`1MJ23CG032`)
  * Sreemanth (`1MJ24CG042`)
  * V. Harshavardhan (`1MJ24CG045`)
* **Project Guide:** Prof. Sreethu T S (Assistant Professor, Dept. of CSD).
* **Head of Department:** Prof. B. Sivasakthi (Assistant Professor & HOD, Dept. of CSD).


