"""
Generates a comprehensive, visually rich, multi-page Technical Project Guide & User Manual
for Smart Cloud Shield (SCS) with vector diagrams, modular breakdowns, and step-by-step user guide.
"""
import os
import sys
from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Group, Polygon
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """Canvas that computes total pages dynamically for 'Page X of Y' footers."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Header (pages after page 1)
        if self._pageNumber > 1:
            self.drawString(40, 755, "Smart Cloud Shield (SCS) • Comprehensive Architecture & User Guide")
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.75)
            self.line(40, 747, 572, 747)

        # Footer (all pages)
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.75)
        self.line(40, 38, 572, 38)
        self.drawString(40, 26, "CONFIDENTIAL & PROPRIETARY • SMART CLOUD SHIELD PLATFORM")
        self.drawRightString(572, 26, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


def draw_pipeline_diagram():
    """Renders vector 5-stage security pipeline diagram."""
    d = Drawing(532, 60)
    stages = [
        ("1. Identity & MFA", "Brevo OTP / Devices", "#0284c7"),
        ("2. DLP Inspection", "Regex / PII Classifier", "#0ea5e9"),
        ("3. Cryptographic Core", "AES-256 Storage Cipher", "#10b981"),
        ("4. AI Risk Radar", "Behavioral Scoring", "#f59e0b"),
        ("5. Hash Audit", "SHA-256 Block Ledger", "#6366f1")
    ]
    box_w = 95
    box_h = 44
    gap = 14
    start_x = 0

    for i, (title, sub, color_hex) in enumerate(stages):
        x = start_x + i * (box_w + gap)
        # Main box
        d.add(Rect(x, 8, box_w, box_h, rx=5, ry=5, fillColor=colors.HexColor(color_hex), strokeColor=None))
        # Inner white pill for contrast
        d.add(Rect(x + 2, 10, box_w - 4, box_h - 4, rx=4, ry=4, fillColor=colors.HexColor("#ffffff"), strokeColor=None))
        # Top banner in card
        d.add(Rect(x + 2, 34, box_w - 4, 18, rx=3, ry=3, fillColor=colors.HexColor(color_hex), strokeColor=None))
        d.add(String(x + box_w / 2, 39, title, fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.white, textAnchor="middle"))
        d.add(String(x + box_w / 2, 18, sub, fontName="Helvetica", fontSize=7, fillColor=colors.HexColor("#334155"), textAnchor="middle"))

        # Arrow to next stage
        if i < len(stages) - 1:
            arr_x = x + box_w
            d.add(Line(arr_x + 2, 30, arr_x + gap - 4, 30, strokeColor=colors.HexColor("#94a3b8"), strokeWidth=1.5))
            d.add(Polygon([arr_x + gap - 4, 33, arr_x + gap, 30, arr_x + gap - 4, 27], fillColor=colors.HexColor("#94a3b8"), strokeColor=None))

    return d


def draw_encryption_flow_diagram():
    """Renders vector data upload and encryption lifecycle diagram."""
    d = Drawing(532, 52)
    steps = [
        ("Plaintext File", "Client Upload", "#475569"),
        ("DLP & Content Scan", "Aadhaar, PAN, Cards", "#0284c7"),
        ("DEK Wrapping", "Key Derivation", "#8b5cf6"),
        ("Ciphertext Blob", "Storage Volume", "#10b981"),
        ("Audit & Integrity", "Merkle Commit", "#0f172a")
    ]
    box_w = 95
    box_h = 38
    gap = 14
    for i, (title, sub, color_hex) in enumerate(steps):
        x = i * (box_w + gap)
        d.add(Rect(x, 6, box_w, box_h, rx=4, ry=4, fillColor=colors.HexColor("#f8fafc"), strokeColor=colors.HexColor(color_hex), strokeWidth=1.2))
        d.add(Rect(x, 26, box_w, 18, rx=3, ry=3, fillColor=colors.HexColor(color_hex), strokeColor=None))
        d.add(String(x + box_w / 2, 31, title, fontName="Helvetica-Bold", fontSize=7.5, fillColor=colors.white, textAnchor="middle"))
        d.add(String(x + box_w / 2, 12, sub, fontName="Helvetica", fontSize=6.8, fillColor=colors.HexColor("#475569"), textAnchor="middle"))

        if i < len(steps) - 1:
            arr_x = x + box_w
            d.add(Line(arr_x + 2, 25, arr_x + gap - 4, 25, strokeColor=colors.HexColor("#cbd5e1"), strokeWidth=1.5))
            d.add(Polygon([arr_x + gap - 4, 28, arr_x + gap, 25, arr_x + gap - 4, 22], fillColor=colors.HexColor("#64748b"), strokeColor=None))

    return d


def generate_pdf(filename="Smart_Cloud_Shield_Complete_Project_Guide.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=46,
        bottomMargin=46
    )

    styles = getSampleStyleSheet()

    # Typography tokens
    doc_title = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#0f172a'),
        alignment=1,
        spaceAfter=3
    )

    doc_sub = ParagraphStyle(
        'DocSub',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#0284c7'),
        alignment=1,
        spaceAfter=12
    )

    h1 = ParagraphStyle(
        'H1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=11,
        spaceAfter=5
    )

    h2 = ParagraphStyle(
        'H2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor('#0369a1'),
        spaceBefore=7,
        spaceAfter=3
    )

    body = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.8,
        leading=12.5,
        textColor=colors.HexColor('#334155'),
        spaceAfter=5
    )

    bullet_style = ParagraphStyle(
        'Bullet',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#334155'),
        leftIndent=12,
        spaceAfter=3
    )

    table_th = ParagraphStyle(
        'TableTH',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor('#0f172a')
    )

    table_td = ParagraphStyle(
        'TableTD',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#334155')
    )

    callout_box = ParagraphStyle(
        'Callout',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#0c4a6e')
    )

    story = []

    # =========================================================================
    # HEADER & EXECUTIVE SUMMARY (Page 1)
    # =========================================================================
    story.append(Paragraph("Smart Cloud Shield (SCS)", doc_title))
    story.append(Paragraph("Enterprise Cloud Security Architecture & Comprehensive Operations Guide", doc_sub))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=8))

    story.append(Paragraph("1. Executive Summary: What is Smart Cloud Shield?", h1))
    p1 = (
        "<b>Smart Cloud Shield (SCS)</b> is an intelligent, zero-trust cloud file storage and access governance platform. "
        "Standard cloud drives (like basic Dropbox or S3 buckets) implicitly trust any authenticated session; if user credentials "
        "are leaked or an insider gains direct storage access, files are exposed. "
        "SCS enforces a <b>Defense-in-Depth model</b> where every access request is validated by dynamic Multi-Factor Authentication, "
        "scanned for sensitive data patterns (DLP), encrypted at rest before hitting physical disks, and continuously evaluated "
        "by a real-time behavioral AI risk radar."
    )
    story.append(Paragraph(p1, body))
    story.append(Spacer(1, 4))

    # Flow Diagram 1
    story.append(Paragraph("<b>Figure 1: The 5-Stage Zero-Trust Security Pipeline</b>", h2))
    story.append(draw_pipeline_diagram())
    story.append(Spacer(1, 8))

    # Key Architectural Stats Table
    stats_data = [
        [
            Paragraph("<b>Pillar</b>", table_th),
            Paragraph("<b>Core Technology</b>", table_th),
            Paragraph("<b>Operational Capability</b>", table_th),
            Paragraph("<b>Target Threat Mitigated</b>", table_th)
        ],
        [
            Paragraph("<b>Authentication</b>", table_td),
            Paragraph("Brevo HTTPS API (Port 443)", table_td),
            Paragraph("Dynamic 6-digit OTP (10 min TTL)", table_td),
            Paragraph("Credential stuffing, password spraying", table_td)
        ],
        [
            Paragraph("<b>Data at Rest</b>", table_td),
            Paragraph("Fernet / AES-CBC Symmetric Cipher", table_td),
            Paragraph("Envelope encryption + per-file wrapped DEK", table_td),
            Paragraph("Physical server compromise, storage theft", table_td)
        ],
        [
            Paragraph("<b>DLP Scanner</b>", table_td),
            Paragraph("Verhoeff checksum + Regex Classifier", table_td),
            Paragraph("Detects Aadhaar, PAN, Credit Cards, RSA keys", table_td),
            Paragraph("Accidental data leaks, PII compliance breach", table_td)
        ],
        [
            Paragraph("<b>AI Risk Radar</b>", table_td),
            Paragraph("Isolation Forest ML + Gemini LLM", table_td),
            Paragraph("Real-time 0–100 risk scoring & incident flagging", table_td),
            Paragraph("Insider exfiltration, off-hours brute force", table_td)
        ],
        [
            Paragraph("<b>Audit Ledger</b>", table_td),
            Paragraph("SHA-256 Hash-Chaining", table_td),
            Paragraph("Block-style immutable log verification", table_td),
            Paragraph("Log tampering, non-repudiation evasion", table_td)
        ]
    ]
    st = Table(stats_data, colWidths=[1.1 * inch, 1.8 * inch, 2.3 * inch, 2.1 * inch])
    st.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')),
        ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(st)
    story.append(Spacer(1, 8))

    # =========================================================================
    # SECTION 2: SYSTEM MODULES EXPLAINED (Page 1 & 2)
    # =========================================================================
    story.append(Paragraph("2. Deep-Dive: The 8 Modular Components of SCS", h1))

    modules = [
        ("Module 1: Landing Page & Live Pipeline Visualizer",
         "The entry portal features an interactive 5-stage security pipeline and a real-time SVG risk telemetry gauge. "
         "Users can review platform capabilities and jump directly into the demo or authentication portal."),

        ("Module 2: Authentication & Device-Fingerprinted MFA",
         "Implements salted password authentication coupled with dynamic 6-digit One-Time Passwords delivered via the "
         "<b>Brevo REST API</b> over HTTPS port 443 (bypassing cloud provider SMTP port 587 firewall blocks). "
         "It inspects browser telemetry to identify known vs. untrusted devices, increasing the risk score for unknown hardware."),

        ("Module 3: Secure Cloud Drive & Sensitive Data Inspection (DLP)",
         "Users upload and manage files with instant Data Loss Prevention (DLP) classification. The scanner evaluates Aadhaar numbers "
         "using the official Verhoeff checksum algorithm, PAN patterns, credit card formats, and private SSH/API keys. Files are classified "
         "as Public, Internal, Confidential, or Highly Confidential with a 0–100 sensitivity score."),

        ("Module 4: Storage Encryption at Rest & Secure Deduplication",
         "Raw file payloads are never written as plaintext. The platform generates an envelope key, encrypts the byte stream using "
         "symmetric ciphers, and stores ciphertext on disk. When identical files are uploaded, cryptographic SHA-256 deduplication saves "
         "disk space while maintaining independent ownership and access control records."),

        ("Module 5: SOC Security Operations & Live Telemetry Dashboard",
         "The centralized administrative dashboard monitors 24-hour telemetry: Allowed Downloads, Warned Accesses, Blocked Exfiltrations, "
         "and Open Incidents. Includes interactive outcome charts, risk trend graphs, and an instant test email dispatcher."),

        ("Module 6: Autonomous Incident Management & Threat Quarantine",
         "When high-risk actions occur (e.g. guest accessing privileged credentials from an unknown IP), the system raises a security incident. "
         "Security analysts can review severity scores, examine causal reasons, inspect quarantine states, and mark incidents as Investigating, "
         "Resolved, or False Positive."),

        ("Module 7: Role-Based Access Control (RBAC) & Governance",
         "Enforces two distinct tiers: Standard Employees (Alice, Bob, Carol) restricted to their own department files, and Administrators "
         "with elevated privileges for system-wide auditing, user account modifications, and threat resolution."),

        ("Module 8: Cryptographic Audit Ledger & File Integrity Verification",
         "Every security event is appended to an immutable, hash-chained audit log where each block's cryptographic hash commits to the "
         "previous entry. An automated integrity verification routine recalculates SHA-256 hashes across stored blobs to catch unauthorized tampering.")
    ]

    for title, desc in modules:
        m_item = [
            Paragraph(f"<b>{title}</b>", h2),
            Paragraph(desc, body)
        ]
        story.append(KeepTogether(m_item))

    story.append(Spacer(1, 6))

    # Flow Diagram 2
    story.append(Paragraph("<b>Figure 2: Cryptographic Storage & Encryption at Rest Lifecycle</b>", h2))
    story.append(draw_encryption_flow_diagram())
    story.append(Spacer(1, 10))

    # Page Break for User Guide Section
    story.append(PageBreak())

    # =========================================================================
    # SECTION 3: STEP-BY-STEP USER & DEMO GUIDE (Page 3)
    # =========================================================================
    story.append(Paragraph("3. Step-by-Step User Guide & Live Demo Walkthrough", h1))

    guide_intro = (
        "Follow these workflows to demonstrate and operate the live application on Render or locally. "
        "Use the credentials table below to test different roles and clearance levels."
    )
    story.append(Paragraph(guide_intro, body))

    # Credentials Table
    cred_data = [
        [
            Paragraph("<b>Username</b>", table_th),
            Paragraph("<b>Password</b>", table_th),
            Paragraph("<b>Role & Clearance</b>", table_th),
            Paragraph("<b>Registered Email (MFA Destination)</b>", table_th),
            Paragraph("<b>Demo Scenario</b>", table_th)
        ],
        [
            Paragraph("<b>admin</b>", table_td),
            Paragraph("Pass@12345", table_td),
            Paragraph("Admin (Level 3)", table_td),
            Paragraph("banagarsankeerth@gmail.com", table_td),
            Paragraph("Full SOC Dashboard, Incidents, Audit Logs", table_td)
        ],
        [
            Paragraph("<b>alice</b>", table_td),
            Paragraph("Pass@12345", table_td),
            Paragraph("Employee - Finance (L3)", table_td),
            Paragraph("raghavendranr28781@gmail.com", table_td),
            Paragraph("Owns payroll and customer card data", table_td)
        ],
        [
            Paragraph("<b>bob</b>", table_td),
            Paragraph("Pass@12345", table_td),
            Paragraph("Employee - HR (L2)", table_td),
            Paragraph("raghavendranr1218@gmail.com", table_td),
            Paragraph("Owns HR contacts and meeting notes", table_td)
        ],
        [
            Paragraph("<b>carol</b>", table_td),
            Paragraph("Pass@12345", table_td),
            Paragraph("Employee - Eng (L3)", table_td),
            Paragraph("carol@corp.example", table_td),
            Paragraph("Owns server credentials & infrastructure files", table_td)
        ],
        [
            Paragraph("<b>guest1</b>", table_td),
            Paragraph("Pass@12345", table_td),
            Paragraph("Guest - General (L0)", table_td),
            Paragraph("guest1@corp.example", table_td),
            Paragraph("Untrusted actor used to trigger exfiltration blocks", table_td)
        ]
    ]
    ct = Table(cred_data, colWidths=[0.85 * inch, 0.95 * inch, 1.4 * inch, 2.1 * inch, 1.9 * inch])
    ct.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
        ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(ct)
    story.append(Spacer(1, 10))

    # Detailed Step Workflows
    workflows = [
        ("Workflow A: User Authentication & Live MFA Verification", [
            "1. Navigate to the login portal (<code>/login</code>) and enter credentials (e.g. <code>alice</code> / <code>Pass@12345</code>).",
            "2. The server verifies password hash, generates a secure 6-digit OTP, and dispatches it via Brevo's HTTPS API directly to the user's registered inbox.",
            "3. The browser redirects to the OTP verification screen (<code>/otp</code>).",
            "4. Check the inbox (or terminal in local mode), enter the 6-digit code, and click <b>Verify Code</b> to complete login."
        ]),
        ("Workflow B: Encrypted File Upload & Automated DLP Tagging", [
            "1. From the top navigation bar, click <b>Files</b> to access the storage repository.",
            "2. Click <b>Choose File</b>, select a sample document (e.g. CSV or TXT with sensitive data), and click <b>Upload & Encrypt</b>.",
            "3. SCS executes DLP regex and Verhoeff checks, categorizes the sensitivity, encrypts the payload with Fernet symmetric cipher, and stores the ciphertext on disk.",
            "4. To retrieve the file, click <b>Download</b>. The system validates the clearance level, decrypts the bytes in-memory, and streams the decrypted file."
        ]),
        ("Workflow C: SOC Telemetry Monitoring & Test Dispatch Delivery", [
            "1. Log in as <code>admin</code> and click <b>Dashboard</b> in the top navigation bar.",
            "2. Review the top telemetry cards: Allowed Downloads, Warned Requests, Blocked Exfiltrations, and Open Incidents.",
            "3. Review the <b>Download Outcomes</b> bar chart and the <b>Risk Trend</b> progression graph.",
            "4. In the <b>Alert Dispatches</b> card, type your email address and click <b>Send Test</b> to verify real-time email delivery via Brevo."
        ]),
        ("Workflow D: Incident Management & Threat Mitigation", [
            "1. In the Admin navbar, click <b>Incidents</b> to inspect all flagged security events.",
            "2. Click on any active incident to review the causal breakdown (e.g. unknown IP, off-hours access, privilege escalation).",
            "3. Use the status control to transition the incident from <b>Open</b> to <b>Investigating</b> or <b>Resolved</b>."
        ]),
        ("Workflow E: Cryptographic Audit & File Integrity Verification", [
            "1. Click <b>Audit</b> in the navbar to inspect the hash-chained ledger. Each row displays the previous hash and the current SHA-256 digest.",
            "2. Click <b>Integrity</b> in the navbar. Click <b>Run Verification Check</b> to scan all stored ciphertext blobs against their original hashes.",
            "3. The system reports 100% integrity match or flags any simulated file tampering."
        ]),
        ("Workflow F: AI Threat Insights Hub", [
            "1. In the Admin navbar, click <b>AI Insights</b>.",
            "2. Click <b>Generate 24h Summary</b>. The Google Gemini AI model analyzes recent telemetry, incident counts, and audit logs to output a synthesized executive threat briefing."
        ])
    ]

    for title, steps in workflows:
        w_flow = [
            Paragraph(f"<b>{title}</b>", h2)
        ]
        for s in steps:
            w_flow.append(Paragraph(f"&bull; {s}", bullet_style))
        story.append(KeepTogether(w_flow))

    story.append(Spacer(1, 10))

    # =========================================================================
    # SECTION 4: TECHNICAL TERMINOLOGY GLOSSARY (Page 4)
    # =========================================================================
    story.append(Paragraph("4. Essential Technical Terminologies & Exam Reference", h1))

    glossary = [
        ("Zero-Trust Architecture", "A cybersecurity paradigm based on 'never trust, always verify'. Every transaction, user, and device is continually authenticated regardless of network location."),
        ("Multi-Factor Authentication (MFA)", "Security control requiring two or more independent credentials for access: something you know (password) and something you have (time-limited email OTP)."),
        ("Encryption at Rest", "Cryptographic protection of stored files on physical storage disks so data cannot be extracted even if the underlying volume is stolen or inspected."),
        ("Envelope Encryption (DEK / KEK)", "A two-tier cryptographic hierarchy where files are encrypted using a Data Encryption Key (DEK), which is in turn wrapped by a Master Key Encryption Key (KEK)."),
        ("Data Loss Prevention (DLP)", "Automated content inspection using patterns and mathematical checksums (e.g. Verhoeff algorithm) to identify and restrict sensitive data (Aadhaar, PAN, PCI cards)."),
        ("Hash-Chained Audit Ledger", "A sequence of tamper-evident log records where each entry incorporates the cryptographic SHA-256 digest of the prior entry, creating an immutable blockchain-style audit history."),
        ("Role-Based Access Control (RBAC)", "Restricting system access and capabilities according to authorized enterprise roles (Admin, Employee, Guest) and numerical clearance levels."),
        ("Telemetry Risk Index (0–100)", "A normalized composite metric synthesized from contextual signals (IP novelty, device trust, failed login velocity, request time) to dynamically detect attacks.")
    ]

    for term, defn in glossary:
        g_item = [
            Paragraph(f"<b>&bull; {term}:</b> {defn}", body)
        ]
        story.append(KeepTogether(g_item))

    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e1'), spaceAfter=8))
    story.append(Paragraph(
        "<i>Smart Cloud Shield Platform &bull; End-to-End System Documentation & Operations Manual &bull; Ready for Vivas, Demos, and Reviews</i>",
        ParagraphStyle('FooterNotice', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor('#64748b'), alignment=1)
    ))

    # Build document using NumberedCanvas for dynamic page numbering
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Comprehensive Project Guide successfully generated: {filename}")


if __name__ == "__main__":
    generate_pdf()
