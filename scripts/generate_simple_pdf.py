"""
Generates a clear, college-undergrad level Technical Reference & Viva Guide for Smart Cloud Shield.
Professional presentation, direct concepts, zero unnecessary fluff or childish analogies.
"""
import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

def create_undergrad_guide_pdf(filename="Smart_Cloud_Shield_Technical_Guide.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Typography styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        alignment=1,
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#0284c7'),
        alignment=1,
        spaceAfter=12
    )

    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12.5,
        leading=16,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=10,
        spaceAfter=4
    )

    body_style = ParagraphStyle(
        'BodyText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor('#334155'),
        spaceAfter=6
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor('#0f172a')
    )

    table_body_style = ParagraphStyle(
        'TableBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )

    qa_question_style = ParagraphStyle(
        'QAQuestion',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#0369a1'),
        spaceBefore=5,
        spaceAfter=2
    )

    qa_answer_style = ParagraphStyle(
        'QAAnswer',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=6
    )

    story = []

    # Title & Subtitle Header
    story.append(Paragraph("Smart Cloud Shield (SCS)", title_style))
    story.append(Paragraph("System Architecture & Technical Viva Reference Guide", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=10))

    # Section 1: Project Overview
    story.append(Paragraph("1. System Overview & Problem Statement", section_heading))
    overview_text = (
        "<b>Core Objective:</b> Traditional cloud storage models rely solely on standard perimeter access controls. "
        "If credentials leak or an insider accesses the physical server storage, stored data is entirely exposed.<br/>"
        "<b>Smart Cloud Shield (SCS)</b> implements an end-to-end <b>Defense-in-Depth</b> security model combining three pillars: "
        "<b>Multi-Factor Authentication (MFA)</b> at entry, <b>Server-Side Encryption at Rest</b> on storage, and "
        "<b>Real-Time Behavioral Anomaly Detection</b> to detect and isolate threats dynamically."
    )
    story.append(Paragraph(overview_text, body_style))
    story.append(Spacer(1, 4))

    # Section 2: Core Architectural Components Table
    story.append(Paragraph("2. Architectural Components & Implementation", section_heading))

    components_data = [
        [
            Paragraph("<b>Component</b>", table_header_style),
            Paragraph("<b>Implementation Details</b>", table_header_style),
            Paragraph("<b>Key Security Purpose</b>", table_header_style)
        ],
        [
            Paragraph("<b>Authentication & MFA</b>", table_body_style),
            Paragraph("Password hashed with salted algorithm + time-limited 6-digit dynamic OTP dispatched via Brevo REST API over HTTPS port 443.", table_body_style),
            Paragraph("Protects against credential theft, automated bots, and brute-force logins.", table_body_style)
        ],
        [
            Paragraph("<b>Data Encryption (At Rest)</b>", table_body_style),
            Paragraph("Cryptographic symmetric encryption (Fernet / AES). Files are encrypted before disk write; decrypted only in-memory upon download.", table_body_style),
            Paragraph("Ensures that direct server storage breaches yield only unintelligible ciphertext.", table_body_style)
        ],
        [
            Paragraph("<b>AI Threat & Risk Engine</b>", table_body_style),
            Paragraph("Analyzes user telemetry (failed attempt count, unrecognized IP addresses, device user-agents, request velocity) into a 0–100 score.", table_body_style),
            Paragraph("Flags anomalous behavior early and automatically logs security incidents for admins.", table_body_style)
        ],
        [
            Paragraph("<b>RBAC & Audit Pipeline</b>", table_body_style),
            Paragraph("Two role tiers: Standard Users (file management) and Administrators (system monitoring, user management, incident logs).", table_body_style),
            Paragraph("Maintains strict principle of least privilege and immutable audit trails for forensic tracking.", table_body_style)
        ]
    ]

    comp_table = Table(components_data, colWidths=[1.5 * inch, 3.4 * inch, 2.3 * inch])
    comp_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e2e8f0')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(comp_table)
    story.append(Spacer(1, 8))

    # Section 3: Data Flow & Lifecycles
    story.append(Paragraph("3. End-to-End Operational Workflows", section_heading))
    flow_text = (
        "&bull; <b>Authentication Lifecycle:</b> User inputs username & password &rarr; Credentials verified &rarr; "
        "Server generates cryptographically secure 6-digit OTP (10 min TTL) &rarr; Dispatched via Brevo HTTPS API &rarr; "
        "User enters OTP &rarr; Session created with role-based JWT/cookie.<br/>"
        "&bull; <b>Secure File Upload Lifecycle:</b> User submits file multipart payload &rarr; Metadata extracted & stored in DB &rarr; "
        "Raw payload encrypted with symmetric cipher &rarr; Ciphertext written to storage volume &rarr; Audit log generated.<br/>"
        "&bull; <b>Threat Incident Lifecycle:</b> Anomaly detected (e.g. 5 failed logins from new IP) &rarr; "
        "Telemetry engine calculates risk index &gt; 70 &rarr; Incident record generated &rarr; Admin alert dispatched & visible on live dashboard."
    )
    story.append(Paragraph(flow_text, body_style))
    story.append(Spacer(1, 6))

    # Section 4: Technical Viva / Exam Questions & Answers
    story.append(Paragraph("4. Technical Viva & Presentation Questions with Model Answers", section_heading))

    qa_list = [
        (
            "Q1: What is the core problem Smart Cloud Shield solves?",
            "Traditional cloud drives rely solely on perimeter authentication. If a password leaks or the storage volume is accessed directly, files are compromised. SCS enforces Defense-in-Depth: mandatory email MFA, server-side encryption before writing to disk, and real-time behavioral anomaly scoring."
        ),
        (
            "Q2: How does the encryption at rest work in this system?",
            "When a user uploads a file, the server encrypts the raw byte stream using AES/Fernet symmetric encryption before storing it on disk. Even if an attacker compromises the server filesystem, they only see ciphertext. Decryption happens strictly in-memory when an authenticated user requests a download."
        ),
        (
            "Q3: Why use Brevo's HTTPS REST API instead of standard SMTP port 587?",
            "Free and cloud container platforms (like Render Free, AWS sandboxes, and restricted college networks) deliberately block outbound traffic on standard SMTP ports (25, 465, 587) to prevent spam abuse. Using an external transactional provider's REST API over HTTPS (port 443) bypasses port blocks and guarantees reliable OTP delivery."
        ),
        (
            "Q4: How does the Risk Scoring engine calculate threat levels?",
            "The engine evaluates contextual indicators: login failure velocity, unrecognized IP addresses, device user-agent changes, and abnormal request patterns. It computes a normalized score (0–100). Scores exceeding established thresholds trigger security alerts and automated incident logging on the Admin dashboard."
        ),
        (
            "Q5: What is the full technology stack and why was each chosen?",
            "Backend: Python & Flask for lightweight, modular microservices. Database: SQLite with SQLAlchemy ORM for relational modeling of users, file metadata, logs, and incidents. Cryptography: Python's cryptography library for Fernet/AES symmetric ciphers. Frontend: Semantic HTML5, CSS custom design with dark-mode telemetry dashboards. Email: Brevo transactional HTTPS API."
        ),
        (
            "Q6: How is Role-Based Access Control (RBAC) enforced?",
            "Users belong to either 'User' or 'Admin' role. Standard users only have access to their isolated files and profile endpoints. Administrators have elevated privileges to inspect system-wide audit trails, view risk telemetry gauges, manage user accounts, and resolve security incidents."
        ),
        (
            "Q7: What happens during a brute-force attack on a user's account?",
            "Repeated authentication failures immediately increase the telemetry risk index, trigger an audit event, and create a high-priority incident on the Admin dashboard. Even if the password is breached, authentication cannot complete without the dynamic, time-limited 6-digit OTP delivered to the verified email address."
        ),
        (
            "Q8: What is stored in the database versus what is stored on the disk filesystem?",
            "The database stores structured metadata: user credentials (hashed), file metadata (filename, owner ID, file hash, size, timestamp), audit logs, and security incidents. The physical disk volume only stores encrypted ciphertext blocks, ensuring separation of metadata from data payload."
        )
    ]

    for q, a in qa_list:
        item = [
            Paragraph(f"<b>{q}</b>", qa_question_style),
            Paragraph(f"<b>Answer:</b> {a}", qa_answer_style)
        ]
        story.append(KeepTogether(item))

    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e1'), spaceAfter=6))
    story.append(Paragraph("<i>Smart Cloud Shield &bull; Architecture & Viva Quick Reference &bull; Prepared for Technical Reviews</i>", ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor('#64748b'), alignment=1)))

    doc.build(story)
    print(f"Technical Undergrad Guide generated: {filename}")

if __name__ == "__main__":
    create_undergrad_guide_pdf("Smart_Cloud_Shield_Technical_Guide.pdf")
    # Also update the original file path so user's existing open document gets refreshed
    create_undergrad_guide_pdf("Smart_Cloud_Shield_Simple_Guide.pdf")
