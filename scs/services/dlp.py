"""Content-aware DLP: find sensitive data in files and classify the file.

Only COUNTS are kept. Raw matches are never stored (privacy by design).
Checksums (Verhoeff for Aadhaar, Luhn for cards) cut false positives, so a
random 12-digit number is not flagged as an Aadhaar.
"""
import csv
import io
import math
import re

# ---------------------------------------------------------------- validators
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(number: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(number: str) -> str:
    """Used only to generate valid sample Aadhaar-like numbers for testing."""
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


def luhn_valid(number: str) -> bool:
    total, alt = 0, False
    for ch in reversed(number):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _entropy(s: str) -> float:
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


# ------------------------------------------------------------------ detectors
RE_AADHAAR = re.compile(r"(?<!\d)[2-9]\d{3} ?\d{4} ?\d{4}(?!\d)")
RE_CARDS = [
    re.compile(r"(?<!\d)\d{4}([ -]?)\d{4}\1\d{4}\1\d{4}(?!\d)"),  # 16 digits, grouped 4-4-4-4
    re.compile(r"(?<!\d)3[47]\d{2}([ -]?)\d{6}\1\d{5}(?!\d)"),    # Amex 4-6-5
    re.compile(r"(?<!\d)\d{13,19}(?!\d)"),                          # unseparated
]
RE_PAN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
RE_PHONE = re.compile(r"(?<!\d)(?:\+91[ -]?)?[6-9]\d{4}[ -]?\d{5}(?!\d)")
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_IFSC = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
RE_APIKEY = re.compile(
    r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,}|"
    r"(?i:api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"
)
RE_PASSWORD = re.compile(r"(?i)password\s*[:=]\s*\S{6,}")
RE_PRIVKEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
RE_KEYWORD = re.compile(r"(?i)\b(confidential|payroll|salary|internal use only|do not distribute)\b")
PAN_HOLDER_CHARS = set("ABCFGHLJPT")

# name: (weight per match, max matches counted)
WEIGHTS = {
    "aadhaar": (15, 5),
    "pan": (12, 5),
    "credit_card": (20, 5),
    "bank_ifsc": (10, 3),
    "api_key": (25, 3),
    "password": (20, 3),
    "private_key": (80, 1),
    "phone": (3, 5),
    "email": (2, 5),
    "keyword": (5, 4),
}
FILENAME_HINTS = ("salary", "payroll", "passwd", "password", "backup", "secret", "confidential")


def _find_cards(text):
    """Return spans of Luhn-valid card numbers."""
    spans = []
    for rx in RE_CARDS:
        for m in rx.finditer(text):
            digits = re.sub(r"[ -]", "", m.group())
            if 13 <= len(digits) <= 19 and luhn_valid(digits):
                spans.append(m.span())
    return spans


def _count_aadhaar(text):
    n = 0
    for m in RE_AADHAAR.finditer(text):
        digits = m.group().replace(" ", "")
        if len(digits) == 12 and verhoeff_valid(digits):
            n += 1
    return n


def scan_text(text: str) -> dict:
    card_spans = _find_cards(text)
    masked = list(text)  # hide cards so they are not re-read as Aadhaar
    for a, b in card_spans:
        masked[a:b] = "#" * (b - a)
    return {
        "aadhaar": _count_aadhaar("".join(masked)),
        "pan": sum(1 for m in RE_PAN.finditer(text) if m.group()[3] in PAN_HOLDER_CHARS),
        "credit_card": len({sp for sp in card_spans}),
        "bank_ifsc": len(RE_IFSC.findall(text)),
        "api_key": len(RE_APIKEY.findall(text)),
        "password": len(RE_PASSWORD.findall(text)),
        "private_key": len(RE_PRIVKEY.findall(text)),
        "phone": len(RE_PHONE.findall(text)),
        "email": len(RE_EMAIL.findall(text)),
        "keyword": len(RE_KEYWORD.findall(text)),
    }


def redact_text(text: str) -> str:
    """Mask sensitive PII, financial data, and credentials, returning a safe redacted copy."""
    # 1. Mask private keys
    text = RE_PRIVKEY.sub("-----BEGIN [REDACTED PRIVATE KEY]-----", text)
    # 2. Mask API keys
    text = RE_APIKEY.sub("[REDACTED_API_KEY]", text)
    # 3. Mask passwords
    text = RE_PASSWORD.sub("password: [REDACTED_PASSWORD]", text)
    # 4. Mask Credit Cards (keeping only last 4 digits)
    card_spans = _find_cards(text)
    for a, b in sorted(card_spans, reverse=True):
        raw = text[a:b]
        digits = re.sub(r"[ -]", "", raw)
        last4 = digits[-4:] if len(digits) >= 4 else "XXXX"
        text = text[:a] + f"****-****-****-{last4}" + text[b:]
    # 5. Mask Aadhaar (keeping only last 4 digits)
    def _mask_aadhaar(m):
        digits = m.group().replace(" ", "")
        if len(digits) == 12 and verhoeff_valid(digits):
            return f"********{digits[-4:]}"
        return m.group()
    text = RE_AADHAAR.sub(_mask_aadhaar, text)
    # 6. Mask PAN cards (keep 5 letter prefix and check letter)
    text = RE_PAN.sub(lambda m: f"{m.group()[:5]}****{m.group()[-1]}", text)
    return text


LEVELS = [(70, "highly_confidential"), (40, "confidential"), (15, "internal"), (0, "public")]


def classify(counts: dict, filename: str = "") -> tuple:
    score = 0
    for name, (weight, cap) in WEIGHTS.items():
        score += min(counts.get(name, 0), cap) * weight
    if any(h in filename.lower() for h in FILENAME_HINTS):
        score += 10
    score = min(score, 100)
    for floor, label in LEVELS:
        if score >= floor:
            return score, label
    return score, "public"


# ------------------------------------------------------------ text extraction
MAX_SCAN_BYTES = 20 * 1024 * 1024
ALLOWED_EXT = {
    "txt", "csv", "xlsx", "docx", "pdf", "json", "log", "md",
    "png", "jpg", "jpeg", "tiff", "bmp",
}


def is_ocr_available() -> bool:
    """Check if Tesseract OCR engine and PIL are available."""
    try:
        import shutil
        from pathlib import Path
        import pytesseract

        tess_env = os.environ.get("TESSERACT_CMD")
        if tess_env and Path(tess_env).exists():
            pytesseract.pytesseract.tesseract_cmd = tess_env
            return True
        if shutil.which("tesseract"):
            return True
        win_candidates = [
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
            str(Path.home() / "AppData" / "Local" / "Programs" / "Tesseract-OCR" / "tesseract.exe"),
        ]
        for wp in win_candidates:
            if Path(wp).exists():
                pytesseract.pytesseract.tesseract_cmd = wp
                return True
        return False
    except Exception:
        return False


def extract_text(data: bytes, filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    data = data[:MAX_SCAN_BYTES]
    try:
        if ext in ("txt", "csv", "json", "log", "md"):
            return data.decode("utf-8", errors="ignore")

        # 1. OCR for Image files (.png, .jpg, .jpeg, .tiff, .bmp)
        if ext in ("png", "jpg", "jpeg", "tiff", "bmp"):
            if is_ocr_available():
                import pytesseract
                from PIL import Image

                img = Image.open(io.BytesIO(data))
                return pytesseract.image_to_string(img)
            else:
                # Graceful heuristic fallback: extract readable ASCII strings from binary
                printable = re.findall(rb"[\x20-\x7E]{4,}", data)
                return " ".join(s.decode("ascii", errors="ignore") for s in printable)

        if ext == "xlsx":
            import openpyxl

            wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
            rows = []
            for ws in wb.worksheets:
                for row in ws.iter_rows(values_only=True):
                    rows.append(" ".join(str(c) for c in row if c is not None))
            return "\n".join(rows)

        if ext == "docx":
            import docx

            d = docx.Document(io.BytesIO(data))
            parts = [p.text for p in d.paragraphs]
            for t in d.tables:
                for r in t.rows:
                    parts.extend(c.text for c in r.cells)
            return "\n".join(parts)

        # 2. PDF extraction with Scanned PDF OCR Fallback
        if ext == "pdf":
            import pypdf

            reader = pypdf.PdfReader(io.BytesIO(data))
            text = "\n".join((p.extract_text() or "") for p in reader.pages)

            # If digital text is missing/empty, attempt OCR on embedded page images
            if len(text.strip()) < 30 and is_ocr_available():
                import pytesseract
                from PIL import Image

                ocr_parts = []
                for page in reader.pages:
                    for img_obj in page.images:
                        try:
                            pil_img = Image.open(io.BytesIO(img_obj.data))
                            ocr_parts.append(pytesseract.image_to_string(pil_img))
                        except Exception:
                            continue
                if ocr_parts:
                    return "\n".join(ocr_parts)

            return text
    except Exception:
        return ""
    return ""


def scan_file(data: bytes, filename: str) -> dict:
    text = extract_text(data, filename)
    counts = scan_text(text)
    score, level = classify(counts, filename)
    return {"counts": counts, "score": score, "level": level, "scanned_chars": len(text)}
