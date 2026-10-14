import logging
import os
import smtplib
import threading
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any, Dict, List, Optional

from flask import current_app

logger = logging.getLogger("scs.mailer")

# In-memory outbox for development & test inspection when SMTP server is not configured
SIMULATED_OUTBOX: List[Dict[str, Any]] = []
MAX_SIMULATED_HISTORY = 50


def get_simulated_outbox() -> List[Dict[str, Any]]:
    """Returns copy of recent simulated emails."""
    return list(reversed(SIMULATED_OUTBOX))


def clear_simulated_outbox():
    """Clears the simulated outbox."""
    SIMULATED_OUTBOX.clear()


def is_smtp_configured() -> bool:
    """Checks if a valid live email service (Resend HTTPS API or SMTP host) is configured."""
    if os.environ.get("DEMO_MODE") == "1" or os.environ.get("TESTING") == "1":
        return False
    if current_app and (current_app.config.get("DEMO_MODE") or current_app.config.get("TESTING") or getattr(current_app, "testing", False)):
        return False

    # Check Resend API key (uses HTTPS port 443 — works seamlessly on cloud free tiers like Render!)
    resend_key = os.environ.get("RESEND_API_KEY")
    if current_app:
        resend_key = current_app.config.get("RESEND_API_KEY") or resend_key
    if resend_key and resend_key.strip():
        return True

    server = os.environ.get("MAIL_SERVER")
    user = os.environ.get("MAIL_USER")
    if current_app:
        server = current_app.config.get("MAIL_SERVER") or server
        user = current_app.config.get("MAIL_USER") or user
    if not server or not server.strip():
        return False
    if "gmail" in server.lower() or "google" in server.lower():
        return bool(user and user.strip())
    return True


def _dispatch_resend_api(
    api_key: str,
    mail_from: str,
    to: str,
    subject: str,
    text_body: str,
    html_body: Optional[str] = None,
) -> Dict[str, Any]:
    """Synchronously delivers an email via Resend's REST API over HTTPS port 443."""
    import json
    import urllib.request
    import urllib.error

    try:
        sender = mail_from if mail_from and "@" in mail_from and not mail_from.endswith(".local") else "Smart Cloud Shield <onboarding@resend.dev>"
        # Use Resend sandbox address if custom domain not explicitly verified
        if "resend.dev" not in sender and not os.environ.get("RESEND_CUSTOM_DOMAIN"):
            sender = "Smart Cloud Shield <onboarding@resend.dev>"

        url = "https://api.resend.com/emails"
        headers = {
            "Authorization": f"Bearer {api_key.strip()}",
            "Content-Type": "application/json",
            "User-Agent": "SmartCloudShield/1.0",
        }
        payload = {
            "from": sender,
            "to": [to],
            "subject": subject,
            "text": text_body,
        }
        if html_body:
            payload["html"] = html_body

        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            logger.info(f"Email successfully delivered via Resend API to {to}: id={data.get('id')}")
            print(f"[RESEND DELIVERED] Email successfully sent to {to} via Resend HTTPS API (id={data.get('id')})", flush=True)
            return {"success": True, "error": None, "id": data.get("id"), "provider": "resend"}
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="ignore")
        logger.error(f"Resend API HTTP error {e.code}: {err}")
        print(f"[RESEND ERROR] HTTP {e.code}: {err}", flush=True)
        return {"success": False, "error": f"HTTP {e.code}: {err}", "provider": "resend"}
    except Exception as e:
        logger.error(f"Resend dispatch exception: {e}")
        print(f"[RESEND ERROR] Exception: {e}", flush=True)
        return {"success": False, "error": str(e), "provider": "resend"}


def _dispatch_smtp_sync(
    msg: EmailMessage,
    server: str,
    port: int,
    use_tls: bool,
    use_ssl: bool,
    user: Optional[str],
    password: Optional[str],
) -> Dict[str, Any]:
    """Synchronously delivers an EmailMessage over SMTP."""
    try:
        if use_ssl:
            with smtplib.SMTP_SSL(server, port, timeout=10) as s:
                if user and password:
                    s.login(user, password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(server, port, timeout=10) as s:
                if use_tls:
                    s.starttls()
                if user and password:
                    s.login(user, password)
                s.send_message(msg)
        return {"success": True, "error": None, "simulated": False}
    except Exception as e:
        logger.error(f"Failed to dispatch email via SMTP {server}:{port}: {e}")
        return {"success": False, "error": str(e), "simulated": False}


def send_email(
    subject: str,
    to: str,
    text_body: str,
    html_body: Optional[str] = None,
    async_send: bool = True,
) -> Dict[str, Any]:
    """
    Sends an email using Resend HTTPS API (preferred for cloud hosts) or SMTP parameters.
    If no provider is configured, stores message in SIMULATED_OUTBOX and logs to console.
    """
    cfg = current_app.config if current_app else {}
    resend_key = cfg.get("RESEND_API_KEY") or os.environ.get("RESEND_API_KEY")
    mail_from = cfg.get("MAIL_FROM") or os.environ.get("MAIL_FROM", "security@smartcloudshield.local")

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    is_dummy_recipient = not to or any(to.lower().endswith(d) for d in ("@corp.example", ".example", ".local", "@example.com"))

    # Priority 1: Resend HTTP API (HTTPS port 443 — works everywhere without SMTP firewall blocks)
    if resend_key and resend_key.strip() and not is_dummy_recipient:
        if async_send:
            t = threading.Thread(
                target=_dispatch_resend_api,
                args=(resend_key, mail_from, to, subject, text_body, html_body),
                daemon=True,
            )
            t.start()
            return {"success": True, "error": None, "simulated": False, "queued": True, "provider": "resend"}
        else:
            return _dispatch_resend_api(resend_key, mail_from, to, subject, text_body, html_body)

    # Priority 2: Traditional SMTP Relay
    server = cfg.get("MAIL_SERVER") or os.environ.get("MAIL_SERVER")
    port = int(cfg.get("MAIL_PORT") or os.environ.get("MAIL_PORT", 587))
    use_tls = bool(cfg.get("MAIL_USE_TLS", True))
    use_ssl = bool(cfg.get("MAIL_USE_SSL", False))
    user = cfg.get("MAIL_USER") or os.environ.get("MAIL_USER")
    password = cfg.get("MAIL_PASSWORD") or os.environ.get("MAIL_PASSWORD")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = mail_from
    msg["To"] = to
    msg.set_content(text_body)

    if html_body:
        msg.add_alternative(html_body, subtype="html")

    # If no SMTP server configured or dummy/local domain, record in simulated outbox
    if not is_smtp_configured() or is_dummy_recipient:
        simulated_record = {
            "timestamp": now_iso,
            "to": to,
            "from": mail_from,
            "subject": subject,
            "text": text_body,
            "html": html_body,
        }
        SIMULATED_OUTBOX.append(simulated_record)
        if len(SIMULATED_OUTBOX) > MAX_SIMULATED_HISTORY:
            SIMULATED_OUTBOX.pop(0)

        try:
            logger.info(f"[MAIL SIMULATED] To: {to} | Subject: '{subject}'")
            print(f"[MAIL SIMULATED] To: {to} | Subject: '{subject}'\n{text_body}\n")
        except UnicodeEncodeError:
            safe_subj = subject.encode("ascii", errors="replace").decode("ascii")
            safe_text = text_body.encode("ascii", errors="replace").decode("ascii")
            print(f"[MAIL SIMULATED] To: {to} | Subject: '{safe_subj}'\n{safe_text}\n")
        except Exception:
            pass
        return {"success": True, "error": None, "simulated": True}

    # Dispatch via SMTP
    if async_send:
        t = threading.Thread(
            target=_dispatch_smtp_sync,
            args=(msg, server, port, use_tls, use_ssl, user, password),
            daemon=True,
        )
        t.start()
        return {"success": True, "error": None, "simulated": False, "queued": True}
    else:
        return _dispatch_smtp_sync(msg, server, port, use_tls, use_ssl, user, password)


# =====================================================================
# Branded HTML Email Builders & Use-case Workflows
# =====================================================================

def _render_email_base(title: str, badge_text: str, badge_color: str, content_html: str) -> str:
    """Wraps body in modern, responsive, cyber-security branded HTML layout."""
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>
    body {{
      margin: 0;
      padding: 0;
      background-color: #0b0f19;
      color: #e2e8f0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.6;
    }}
    .wrapper {{
      width: 100%;
      background-color: #0b0f19;
      padding: 40px 15px;
    }}
    .container {{
      max-width: 600px;
      margin: 0 auto;
      background: #151d30;
      border: 1px solid #1e293b;
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
    }}
    .header {{
      background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
      padding: 24px 30px;
      border-bottom: 1px solid #2d3748;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }}
    .logo {{
      font-size: 18px;
      font-weight: 700;
      color: #38bdf8;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      text-decoration: none;
    }}
    .badge {{
      display: inline-block;
      padding: 4px 10px;
      font-size: 11px;
      font-weight: 700;
      border-radius: 6px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      background: {badge_color};
      color: #ffffff;
    }}
    .content {{
      padding: 30px;
    }}
    h1 {{
      font-size: 22px;
      color: #f8fafc;
      margin-top: 0;
      margin-bottom: 16px;
    }}
    p {{
      margin: 0 0 16px 0;
      color: #cbd5e1;
      font-size: 15px;
    }}
    .code-box {{
      background: #0f172a;
      border: 2px dashed #38bdf8;
      border-radius: 8px;
      padding: 20px;
      text-align: center;
      margin: 25px 0;
    }}
    .code-digits {{
      font-family: 'Courier New', Courier, monospace;
      font-size: 34px;
      font-weight: bold;
      letter-spacing: 10px;
      color: #38bdf8;
    }}
    .meta-table {{
      width: 100%;
      border-collapse: collapse;
      margin: 20px 0;
      font-size: 13px;
    }}
    .meta-table td {{
      padding: 8px 12px;
      border-bottom: 1px solid #1e293b;
    }}
    .meta-label {{
      color: #94a3b8;
      width: 35%;
      font-weight: 600;
    }}
    .meta-value {{
      color: #f1f5f9;
      font-family: monospace;
    }}
    .alert-box {{
      background: rgba(239, 68, 68, 0.1);
      border-left: 4px solid #ef4444;
      padding: 12px 16px;
      margin: 20px 0;
      border-radius: 0 6px 6px 0;
      font-size: 13px;
      color: #fca5a5;
    }}
    .footer {{
      background: #0f172a;
      padding: 20px 30px;
      border-top: 1px solid #1e293b;
      font-size: 12px;
      color: #64748b;
      text-align: center;
    }}
    .footer a {{
      color: #38bdf8;
      text-decoration: none;
    }}
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="container">
      <div class="header">
        <div class="logo">🛡️ Smart Cloud Shield</div>
        <div class="badge">{badge_text}</div>
      </div>
      <div class="content">
        {content_html}
      </div>
      <div class="footer">
        Zero-Trust Cloud Data Loss Prevention & Insider Threat Defense<br>
        Automated Security Dispatch • Do not reply directly to this automated email.
      </div>
    </div>
  </div>
</body>
</html>"""


def send_otp_email(user, code: str, ip: str = "Unknown", device_id: str = "Unknown") -> Dict[str, Any]:
    """Sends a high-security MFA one-time passcode to the user."""
    subject = f"Smart Cloud Shield: Verification Code {code}"
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    text_body = f"""Smart Cloud Shield Security Verification

Hello {user.username},

Your one-time authentication code is: {code}

This code is valid for 5 minutes. Never share this code with anyone.

Security Details:
- Target Account: {user.username} ({user.email})
- Timestamp: {now_str}
- IP Address: {ip}
- Device Identifier: {device_id[:16]}...

If you did not request this login code, someone may have compromised your password. Please alert your security administrator immediately.
"""

    content_html = f"""
      <h1>Multi-Factor Verification Code</h1>
      <p>Hello <strong>{user.username}</strong>,</p>
      <p>A sign-in request was initiated for your Smart Cloud Shield account. Use the one-time verification code below to complete authentication:</p>
      
      <div class="code-box">
        <div style="font-size: 12px; color: #94a3b8; margin-bottom: 8px; text-transform: uppercase;">One-Time Passcode</div>
        <div class="code-digits">{code}</div>
        <div style="font-size: 12px; color: #f59e0b; margin-top: 8px;">⏱️ Expires in 5 minutes</div>
      </div>

      <table class="meta-table">
        <tr>
          <td class="meta-label">Account:</td>
          <td class="meta-value">{user.username} ({user.email})</td>
        </tr>
        <tr>
          <td class="meta-label">Request Time:</td>
          <td class="meta-value">{now_str}</td>
        </tr>
        <tr>
          <td class="meta-label">Client IP:</td>
          <td class="meta-value">{ip}</td>
        </tr>
        <tr>
          <td class="meta-label">Device Hash:</td>
          <td class="meta-value">{device_id[:20]}...</td>
        </tr>
      </table>

      <div class="alert-box">
        <strong>⚠️ Security Notice:</strong> If you did not initiate this login, an attacker may have obtained your password. Contact your system administrator to lock your account immediately.
      </div>
    """

    html_body = _render_email_base(
        title="Your MFA Verification Code",
        badge_text="MFA AUTHENTICATION",
        badge_color="#0284c7",
        content_html=content_html,
    )

    return send_email(subject, user.email, text_body, html_body, async_send=True)


def send_security_alert_email(incident, recipient_email: Optional[str] = None) -> Dict[str, Any]:
    """
    Sends an immediate security alert email to administrators upon high-risk download,
    policy violation, or insider exfiltration attempt.
    """
    cfg = current_app.config if current_app else {}
    to_email = recipient_email or cfg.get("ADMIN_ALERT_EMAIL") or os.environ.get("ADMIN_ALERT_EMAIL") or os.environ.get("MAIL_USER") or "sankeerthbanagar2@gmail.com"
    
    user_name = incident.user.username if incident.user else "Unknown"
    file_name = incident.file.original_name if incident.file else "Unknown"
    sensitivity = incident.file.sensitivity if incident.file else "unknown"
    score = incident.risk_score
    level = incident.level.upper()
    now_str = incident.ts.strftime("%Y-%m-%d %H:%M:%S UTC") if incident.ts else datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Format reasons list
    reasons_list = incident.reasons
    reasons_text = "\n".join([f"- {r.get('text', '')} (+{r.get('points', 0)} pts)" for r in reasons_list])
    reasons_html_items = "".join([f"<li><strong>+{r.get('points', 0)} pts:</strong> {r.get('text', '')}</li>" for r in reasons_list])

    subject = f"⚠️ [SECURITY ALERT] Incident #{incident.id}: {level} ({score}/100) by {user_name}"

    text_body = f"""SMART CLOUD SHIELD SECURITY ALERT

Incident ID: #{incident.id}
Level: {level}
Risk Score: {score}/100
Timestamp: {now_str}

User Details:
- Username: {user_name}
- Department: {incident.user.department if incident.user else 'N/A'}
- Role: {incident.user.role if incident.user else 'N/A'}

Target Asset:
- File: {file_name}
- Sensitivity: {sensitivity.upper()}

Risk Breakdown Reasons:
{reasons_text}

Action Required:
Review this incident in the Smart Cloud Shield Admin Console to inspect audit trails, quarantine the file, or restrict the user.
"""

    badge_color = "#ef4444" if level == "BLOCK" else "#f59e0b"

    content_html = f"""
      <h1 style="color: {'#ef4444' if level == 'BLOCK' else '#f59e0b'};">
        Security Incident #{incident.id}: {level}
      </h1>
      <p>A high-risk action triggered an automated policy intervention in the Smart Cloud Shield zero-trust engine.</p>

      <table class="meta-table">
        <tr>
          <td class="meta-label">Overall Risk Score:</td>
          <td class="meta-value" style="font-size: 16px; font-weight: bold; color: {'#ef4444' if score >= 70 else '#f59e0b'};">
            {score} / 100 ({level})
          </td>
        </tr>
        <tr>
          <td class="meta-label">User / Department:</td>
          <td class="meta-value">{user_name} ({incident.user.department if incident.user else 'N/A'})</td>
        </tr>
        <tr>
          <td class="meta-label">Target File:</td>
          <td class="meta-value">{file_name}</td>
        </tr>
        <tr>
          <td class="meta-label">Sensitivity Level:</td>
          <td class="meta-value">{sensitivity.upper()}</td>
        </tr>
        <tr>
          <td class="meta-label">Detected Timestamp:</td>
          <td class="meta-value">{now_str}</td>
        </tr>
      </table>

      <h3 style="color: #94a3b8; font-size: 14px; margin-top: 20px; text-transform: uppercase;">Identified Risk Factors:</h3>
      <ul style="color: #cbd5e1; font-size: 14px; padding-left: 20px;">
        {reasons_html_items or '<li>High-risk anomaly threshold exceeded</li>'}
      </ul>

      <div class="alert-box">
        <strong>Recommended Administrator Action:</strong> Navigate to the <strong>Incidents</strong> dashboard to review this session, inspect the cryptographic audit chain, or isolate the file/account.
      </div>
    """

    html_body = _render_email_base(
        title=f"Security Alert: Incident #{incident.id}",
        badge_text=f"INCIDENT: {level}",
        badge_color=badge_color,
        content_html=content_html,
    )

    return send_email(subject, to_email, text_body, html_body, async_send=True)


def send_account_restriction_alert(user, reason: str, admin_email: Optional[str] = None) -> Dict[str, Any]:
    """Notifies admin and user when an account has been locked or restricted."""
    cfg = current_app.config if current_app else {}
    to_admin = admin_email or cfg.get("ADMIN_ALERT_EMAIL") or cfg.get("MAIL_FROM") or "admin@smartcloudshield.local"

    subject = f"🛑 [SECURITY NOTICE] User Account Restricted: {user.username}"
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    text_body = f"""SMART CLOUD SHIELD ACCOUNT RESTRICTION NOTICE

User: {user.username} ({user.email})
Department: {user.department}
Reason: {reason}
Timestamp: {now_str}

The account has been placed into 'RESTRICTED' status. File downloads and sensitive actions are blocked until reviewed by a security administrator.
"""

    content_html = f"""
      <h1 style="color: #ef4444;">User Account Restricted</h1>
      <p>The account <strong>{user.username}</strong> has been restricted due to automated policy enforcement or administrator action.</p>

      <table class="meta-table">
        <tr>
          <td class="meta-label">Username:</td>
          <td class="meta-value">{user.username}</td>
        </tr>
        <tr>
          <td class="meta-label">Email:</td>
          <td class="meta-value">{user.email}</td>
        </tr>
        <tr>
          <td class="meta-label">Department:</td>
          <td class="meta-value">{user.department}</td>
        </tr>
        <tr>
          <td class="meta-label">Enforcement Reason:</td>
          <td class="meta-value">{reason}</td>
        </tr>
        <tr>
          <td class="meta-label">Enforcement Time:</td>
          <td class="meta-value">{now_str}</td>
        </tr>
      </table>

      <div class="alert-box">
        <strong>Status:</strong> The user's download and sensitive operational permissions have been revoked. An administrator can reinstate this account from the Users management console.
      </div>
    """

    html_body = _render_email_base(
        title=f"Account Restricted: {user.username}",
        badge_text="ENFORCEMENT: RESTRICTED",
        badge_color="#ef4444",
        content_html=content_html,
    )

    # Notify admin
    res = send_email(subject, to_admin, text_body, html_body, async_send=True)
    # Also notify user if email is valid
    if user.email and "@" in user.email:
        send_email(subject, user.email, text_body, html_body, async_send=True)
    return res


def send_test_email(to_email: str) -> Dict[str, Any]:
    """Dispatches a test message synchronously to verify SMTP configuration."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    subject = "Smart Cloud Shield: SMTP Email Pipeline Test"

    text_body = f"""Smart Cloud Shield Test Email

This is an automated test message sent from the Smart Cloud Shield security platform to confirm that your SMTP email settings are working properly.

Dispatch Timestamp: {now_str}
Destination: {to_email}
Zero-Trust DLP & Cloud Security Engine
"""

    content_html = f"""
      <h1 style="color: #38bdf8;">SMTP Configuration Test</h1>
      <p>Congratulations! If you are reading this email, your <strong>Smart Cloud Shield</strong> email delivery pipeline is configured and operating successfully.</p>
      
      <table class="meta-table">
        <tr>
          <td class="meta-label">Recipient:</td>
          <td class="meta-value">{to_email}</td>
        </tr>
        <tr>
          <td class="meta-label">Dispatch Time:</td>
          <td class="meta-value">{now_str}</td>
        </tr>
        <tr>
          <td class="meta-label">Transport:</td>
          <td class="meta-value">{"Live SMTP Relay" if is_smtp_configured() else "Simulated Dev Mailbox"}</td>
        </tr>
      </table>

      <div class="alert-box" style="background: rgba(16, 185, 129, 0.1); border-left-color: #10b981; color: #6ee7b7;">
        ✅ <strong>Verified:</strong> Authentication codes, incident security alerts, and restriction notices will be delivered to authorized recipients.
      </div>
    """

    html_body = _render_email_base(
        title="SMTP Test Email",
        badge_text="SYSTEM TEST",
        badge_color="#10b981",
        content_html=content_html,
    )

    # Use synchronous delivery for test email so caller can immediately inspect result
    return send_email(subject, to_email, text_body, html_body, async_send=False)
