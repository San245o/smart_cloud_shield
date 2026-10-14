import json
import logging
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from flask import current_app

logger = logging.getLogger("scs.ai_agent")


def get_gemini_api_key() -> Optional[str]:
    """Retrieves the Gemini API key from application config or environment."""
    if current_app:
        key = current_app.config.get("GEMINI_API_KEY")
        if key:
            return key.strip()
    return os.environ.get("GEMINI_API_KEY", "").strip() or None


def get_gemini_model() -> str:
    """Retrieves the Gemini model name."""
    if current_app:
        m = current_app.config.get("GEMINI_MODEL")
        if m:
            return m.strip()
    return os.environ.get("GEMINI_MODEL", "gemini-1.5-flash").strip()


def _call_gemini_api(prompt: str, system_instruction: Optional[str] = None) -> Optional[str]:
    """
    Directly calls the Google Gemini REST API using Python's standard library urllib.
    Ensures zero external dependency conflicts and works seamlessly across environments.
    """
    api_key = get_gemini_api_key()
    if not api_key:
        return None

    model = get_gemini_model()
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"

    contents = []
    if system_instruction:
        contents.append({
            "role": "user",
            "parts": [{"text": f"System Context & Instructions:\n{system_instruction}\n\nTask:\n{prompt}"}]
        })
    else:
        contents.append({
            "role": "user",
            "parts": [{"text": prompt}]
        })

    payload = {
        "contents": contents,
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 2500,
        },
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            if response.status == 200:
                resp_json = json.loads(response.read().decode("utf-8"))
                candidates = resp_json.get("candidates", [])
                if candidates and "content" in candidates[0]:
                    parts = candidates[0]["content"].get("parts", [])
                    if parts and "text" in parts[0]:
                        return parts[0]["text"].strip()
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="ignore")
        logger.warning(f"Gemini API HTTP Error {e.code}: {err_msg}")
    except Exception as e:
        logger.warning(f"Failed to query Gemini API: {e}")

    return None


# =====================================================================
# Intelligent Local NLP Fallback & Threat Synthesis
# =====================================================================

def _compute_posture_score(counts: Dict[str, int], open_incidents: int, tampered_files: int) -> Dict[str, Any]:
    """Calculates overall zero-trust security posture score (0 - 100)."""
    score = 100
    score -= counts.get("blocked", 0) * 10
    score -= counts.get("denied", 0) * 4
    score -= counts.get("warned", 0) * 3
    score -= open_incidents * 8
    score -= tampered_files * 30
    score = max(5, min(100, score))

    if score >= 90:
        grade = "A+"
        status = "Optimal"
        badge_class = "success"
    elif score >= 80:
        grade = "A"
        status = "Secure"
        badge_class = "success"
    elif score >= 65:
        grade = "B"
        status = "Elevated Caution"
        badge_class = "warning"
    elif score >= 50:
        grade = "C"
        status = "High Threat Activity"
        badge_class = "warning"
    else:
        grade = "Critical Risk"
        status = "Active Breach / Multiple Blocked Exfiltrations"
        badge_class = "danger"

    return {"score": score, "grade": grade, "status": status, "badge_class": badge_class}


def _generate_local_threat_summary(
    events: List[Any],
    incidents: List[Any],
    audit_rows: List[Any],
    counts: Dict[str, int],
    open_incidents_count: int,
    hours: int,
) -> str:
    """
    Intelligent heuristic & statistical NLP synthesizer that builds a structured,
    comprehensive security intelligence report even without an active LLM API key.
    """
    posture = _compute_posture_score(counts, open_incidents_count, 0)
    
    # 1. Analyze user anomalies
    user_blocks: Dict[str, int] = {}
    user_high_scores: Dict[str, List[int]] = {}
    dlp_patterns_detected: Dict[str, int] = {}
    off_hours_count = 0
    untrusted_device_count = 0

    for ev in events:
        uname = ev.user.username if ev.user else "unknown"
        if ev.outcome == "blocked":
            user_blocks[uname] = user_blocks.get(uname, 0) + 1
        if ev.risk_score and ev.risk_score >= 60:
            user_high_scores.setdefault(uname, []).append(ev.risk_score)
        
        for r in (ev.reasons or []):
            txt = r.get("text", "").lower()
            if "unverified" in txt or "untrusted" in txt:
                untrusted_device_count += 1
            if "unusual hour" in txt or "night" in txt or "off-hours" in txt:
                off_hours_count += 1

    # Inspect incidents for DLP and target assets
    high_value_targets = set()
    for inc in incidents:
        if inc.file:
            high_value_targets.add(f"{inc.file.original_name} ({inc.file.sensitivity.upper()})")
            if inc.file.dlp_json:
                try:
                    d = json.loads(inc.file.dlp_json)
                    for k, v in d.items():
                        dlp_patterns_detected[k] = dlp_patterns_detected.get(k, 0) + v
                except Exception:
                    pass

    # Top anomalous users
    sorted_threat_users = sorted(user_blocks.items(), key=lambda x: x[1], reverse=True)

    # Recommendations logic
    action_items = []
    if sorted_threat_users:
        top_u, b_cnt = sorted_threat_users[0]
        action_items.append(f"**Immediate Containment:** Investigate user `{top_u}` who triggered {b_cnt} blocked download attempts. Consider emergency privilege restriction if unrecognized.")
    if open_incidents_count > 0:
        action_items.append(f"**Incident Triage:** {open_incidents_count} security incident(s) are awaiting admin triage. Review flagged events in the Incidents portal.")
    if high_value_targets:
        targets_str = ", ".join(list(high_value_targets)[:3])
        action_items.append(f"**Data Asset Isolation:** High-risk confidential files ({targets_str}) were targeted. Verify per-file quarantine status.")
    if untrusted_device_count > 0:
        action_items.append(f"**Zero-Trust Device Verification:** {untrusted_device_count} operations originated from unverified hardware identifiers. Audit device fingerprints.")
    if not action_items:
        action_items.append("**Routine Hygiene:** Zero-trust parameters normal. Continue continuous logging and verify cryptographic audit hash chain.")

    recommendations_md = "\n".join([f"1. {item}" for item in action_items])

    report = f"""### 🛡️ Smart Cloud Shield Executive Threat Intelligence Report
* **Analysis Window:** Last {hours} Hours | **Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
* **Engine:** Smart Cloud Shield Security Intelligence Engine *(Local Deterministic Synthesizer)*
* **Security Posture Score:** **{posture['score']}/100** (Grade: **{posture['grade']}** — *{posture['status']}*)

---

#### 1. Executive Summary & Telemetry Overview
During this evaluation period, the Smart Cloud Shield zero-trust gateway processed access requests with the following disposition:
* **Allowed Downloads:** {counts.get('allowed', 0)} (Clean RBAC & ABAC compliance)
* **Suspicious Downloads (Warned):** {counts.get('warned', 0)} (Elevated risk, allowed with audit logging)
* **Blocked Exfiltrations:** {counts.get('blocked', 0)} (Automated policy intervention)
* **Permission Denials:** {counts.get('denied', 0)} (Clearance / Department boundary violations)
* **Active Open Incidents:** {open_incidents_count}

#### 2. Threat Detections & Insider Risk Patterns
* **Suspicious Off-Hour Access:** {off_hours_count} attempt(s) outside standard operational business hours (10:00 PM – 6:00 AM window).
* **Unrecognized Hardware:** {untrusted_device_count} event(s) initiated from untrusted or unverified device identifiers.
* **Top Anomalous Actors:**
{(''.join([f'  * User `{u}`: **{cnt} blocked attempts**' + (' (Risk Scores: ' + ', '.join(map(str, user_high_scores.get(u, []))) + ')' if u in user_high_scores else '') + '\\n' for u, cnt in sorted_threat_users[:4]]) if sorted_threat_users else '  * *No persistent malicious actors detected in this time window.*\\n')}
#### 3. DLP Pattern Exposure Assessment
Sensitive data patterns targeted in classified documents:
{(''.join([f'  * **{k.replace("_", " ").title()}:** {v} pattern occurrences protected\\n' for k, v in dlp_patterns_detected.items() if v > 0]) if dlp_patterns_detected else '  * *No raw PII or financial credentials exposed in intercepted requests.*\\n')}

#### 4. Actionable Security Recommendations
{recommendations_md}

---
*Tip: Configure `GEMINI_API_KEY` in your environment or `.env` file to enable continuous live GenAI LLM threat synthesis.*
"""
    return report


def summarize_security_logs(
    events: List[Any],
    incidents: List[Any],
    audit_rows: List[Any],
    counts: Dict[str, int],
    open_incidents_count: int,
    hours: int = 24,
) -> Dict[str, Any]:
    """
    Generates an executive threat intelligence summary of security telemetry.
    Attempts Google Gemini Generative AI first; falls back gracefully to the local NLP synthesizer.
    """
    posture = _compute_posture_score(counts, open_incidents_count, 0)

    # Prepare structured summary for LLM prompt
    recent_events_summary = []
    for e in events[:35]:
        recent_events_summary.append({
            "time": e.ts.strftime("%H:%M:%S") if e.ts else "?",
            "user": e.user.username if e.user else "?",
            "dept": e.user.department if e.user else "?",
            "file": e.file.original_name if e.file else "(none)",
            "sensitivity": e.file.sensitivity if e.file else "unknown",
            "action": e.action,
            "outcome": e.outcome,
            "risk_score": e.risk_score,
            "reasons": [r.get("text") for r in (e.reasons or [])],
        })

    recent_incidents_summary = []
    for inc in incidents[:15]:
        recent_incidents_summary.append({
            "id": inc.id,
            "time": inc.ts.strftime("%H:%M:%S") if inc.ts else "?",
            "user": inc.user.username if inc.user else "?",
            "file": inc.file.original_name if inc.file else "?",
            "level": inc.level,
            "risk_score": inc.risk_score,
            "status": inc.status,
            "reasons": [r.get("text") for r in inc.reasons],
        })

    system_instruction = (
        "You are the Chief Information Security Officer (CISO) and AI Threat Analyst for Smart Cloud Shield, "
        "an enterprise zero-trust cloud data loss prevention (DLP) and insider threat defense platform. "
        "Your task is to analyze telemetry logs and produce an authoritative, crisp, markdown-formatted executive threat summary."
    )

    prompt = f"""Analyze the following Smart Cloud Shield security telemetry from the past {hours} hours:

METRICS:
- Allowed Downloads: {counts.get('allowed', 0)}
- Warned Suspicious Downloads: {counts.get('warned', 0)}
- Blocked Exfiltrations: {counts.get('blocked', 0)}
- Denied Access Attempts: {counts.get('denied', 0)}
- Active Open Incidents: {open_incidents_count}

RECENT SECURITY EVENTS (Sample of last {len(recent_events_summary)} events):
{json.dumps(recent_events_summary, indent=2)}

ACTIVE INCIDENTS:
{json.dumps(recent_incidents_summary, indent=2)}

Please generate an Executive AI Threat Intelligence Summary with these exact sections:
1. 🛡️ Executive Posture & Threat Overview (High-level summary, threat posture grade, and primary risk drivers).
2. 🚨 High-Priority Threat Detections & Insider Anomalies (Specific users, files, odd hours, untrusted devices).
3. 🔍 Data Loss Prevention (DLP) & Exfiltration Analysis (Classified files targeted, potential blast radius).
4. 📋 Actionable Administrator Remediation Steps (Numbered, specific containment and policy recommendations).

Be concise, technical, and objective. Use markdown formatting with bolding and bullet points.
"""

    gemini_output = _call_gemini_api(prompt, system_instruction)

    if gemini_output:
        formatted = f"### 🛡️ Executive Threat Intelligence Report\n\n" + gemini_output
        return {
            "source": "gemini",
            "model": get_gemini_model(),
            "content": formatted,
            "posture": posture,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }

    # Fallback to local synthesizer
    local_output = _generate_local_threat_summary(
        events, incidents, audit_rows, counts, open_incidents_count, hours
    )
    return {
        "source": "local",
        "model": "Smart Cloud Shield Local NLP Engine",
        "content": local_output,
        "posture": posture,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


def analyze_single_incident(incident: Any) -> Dict[str, Any]:
    """
    Performs forensic deep-dive analysis on a single specific Incident.
    Explains the exact multi-pillar risk factors and recommends remediation.
    """
    user_name = incident.user.username if incident.user else "Unknown"
    user_dept = incident.user.department if incident.user else "Unknown"
    user_role = incident.user.role if incident.user else "Unknown"
    user_status = incident.user.status if incident.user else "active"
    file_name = incident.file.original_name if incident.file else "Unknown"
    file_sens = incident.file.sensitivity if incident.file else "unknown"
    score = incident.risk_score
    level = incident.level
    reasons = incident.reasons

    dlp_counts = {}
    if incident.file and incident.file.dlp_json:
        try:
            dlp_counts = json.loads(incident.file.dlp_json)
        except Exception:
            pass

    event = incident.event
    device_id = event.device_id if event else "Unknown"
    ip = event.ip if event else "Unknown"
    hour = event.ts.hour if event and event.ts else "Unknown"

    system_instruction = (
        "You are an expert Digital Forensics and Incident Response (DFIR) analyst for Smart Cloud Shield. "
        "Analyze this specific security incident and provide a concise, structured forensic breakdown."
    )

    prompt = f"""Investigate Security Incident #{incident.id}:
- User: {user_name} (Role: {user_role}, Department: {user_dept}, Account Status: {user_status})
- File: {file_name} (Sensitivity: {file_sens})
- Risk Score: {score}/100 | Enforced Level: {level.upper()} | Status: {incident.status}
- Client IP: {ip} | Device ID: {device_id} | Hour of Request: {hour}
- DLP Detected Patterns: {json.dumps(dlp_counts)}
- Triggered Risk Engine Reasons:
{json.dumps(reasons, indent=2)}

Provide a forensic assessment in markdown format:
1. **Root Cause Analysis:** Why was this specific download intercepted?
2. **Threat Assessment:** Likelihood of deliberate insider exfiltration vs accidental misuse.
3. **Blast Radius:** Sensitivity of data at risk if downloaded.
4. **Recommended Containment Action:** (e.g., Quarantine File, Trust Device, Lock User Account, or Mark False Alarm).
"""

    gemini_output = _call_gemini_api(prompt, system_instruction)

    if gemini_output:
        formatted = f"#### 🔍 Forensic DFIR Incident Breakdown — #{incident.id}\n\n" + gemini_output
        return {
            "source": "gemini",
            "model": get_gemini_model(),
            "incident_id": incident.id,
            "analysis": formatted,
        }

    # Deterministic forensic analysis fallback
    reasons_bullets = "\n".join([f"- **+{r.get('points', 0)} pts:** {r.get('text', '')}" for r in reasons])
    dlp_items = [f"{k.replace('_', ' ').title()}: {v}" for k, v in dlp_counts.items() if v > 0]
    dlp_str = ", ".join(dlp_items) if dlp_items else "None (Protected via metadata/classification)"

    recommended_action = "Investigate session"
    if score >= 70:
        recommended_action = "Isolate file via Quarantine and temporarily restrict user credentials."
    elif score >= 35:
        recommended_action = "Review user business justification. If hardware is legitimate, promote to Trusted Device."
    else:
        recommended_action = "Resolve incident and keep routine monitoring."

    local_analysis = f"""#### 🔍 Forensic DFIR Incident Breakdown — #{incident.id}
* **Subject:** `{user_name}` ({user_dept} dept, `{user_role}` role)
* **Target Resource:** `{file_name}` [{file_sens.upper()}]
* **Intervention Level:** `{level.upper()}` (**Risk Score: {score}/100**)
* **Device ID:** `{device_id[:16]}...` | **Client IP:** `{ip}`
* **Sensitive DLP Findings:** {dlp_str}

##### 1. Triggered Risk Heuristics
{reasons_bullets or '- Threshold anomaly'}

##### 2. Threat Vector Assessment
{'🚨 **Critical Exfiltration Risk:** Multiple compounding risk factors (high sensitivity + anomalous context). High probability of unauthorized data extraction attempt.' if score >= 70 else '⚠️ **Elevated Context Anomaly:** Legitimate user attempting off-hours or unverified device access. Potential accidental policy infringement or traveling employee.'}

##### 3. Recommended Remediation
* **Primary Recommendation:** {recommended_action}
* **Quarantine Assessment:** {'File contains critical credentials/PII and should remain QUARANTINED.' if file_sens in ('confidential', 'highly_confidential') else 'File can remain active pending user verification.'}
* **Device Handling:** If user `{user_name}` confirms this hardware is their company laptop, use the **Trust Device** action in the Incidents console to suppress future false positives.
"""
    return {
        "source": "local",
        "model": "Smart Cloud Shield Local DFIR Engine",
        "incident_id": incident.id,
        "analysis": local_analysis,
    }
