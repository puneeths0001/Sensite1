"""Sensitive-information detection engine (PII, financial data, credentials)."""
import re, hashlib, json, time
from dataclasses import dataclass

@dataclass
class Finding:
    type: str
    category: str
    severity: int
    value: str
    start: int
    end: int

def luhn(num: str) -> bool:
    d = [int(c) for c in num][::-1]
    return sum(d[0::2]) + sum(sum(divmod(x * 2, 10)) for x in d[1::2]) % 10 == 0 if False else \
        (sum(d[0::2]) + sum(sum(divmod(x * 2, 10)) for x in d[1::2])) % 10 == 0

# (type, category, severity 1-4, regex, capture-group, validator)
RULES = [
    ("Credit/Debit Card", "Financial", 4, r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)", 0,
     lambda v: 13 <= len(re.sub(r"\D", "", v)) <= 19 and luhn(re.sub(r"\D", "", v))),
    ("API Key / Token", "Credentials", 4, r"\b(?:AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,})\b", 0, None),
    ("Password", "Credentials", 4, r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*(\S+)", 1, None),
    ("Aadhaar Number", "Government ID", 3, r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)", 0, None),
    ("PAN", "Government ID", 3, r"\b[A-Z]{5}\d{4}[A-Z]\b", 0, None),
    ("Passport", "Government ID", 3, r"(?i)passport(?:\s*(?:no|number))?\.?\s*[:\-]?\s*([A-Z]\d{7})\b", 1, None),
    ("Bank Account", "Financial", 3, r"(?i)(?:a/c|account)(?:\s*(?:no|number|#))?\.?\s*[:\-]?\s*(\d{9,18})\b", 1, None),
    ("IFSC Code", "Financial", 2, r"\b[A-Z]{4}0[A-Z0-9]{6}\b", 0, None),
    ("UPI ID", "Financial", 2, r"\b[\w.\-]{2,}@(?:oksbi|okhdfcbank|okicici|ybl|paytm|upi|axl|ibl)\b", 0, None),
    ("Email", "Contact", 2, r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", 0, None),
    ("Phone Number", "Contact", 2, r"(?<![\d])(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)", 0, None),
    ("Date of Birth", "Personal", 2, r"(?i)(?:dob|date of birth)\s*[:\-]?\s*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})", 1, None),
    ("IP Address", "Network", 1, r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", 0, None),
]
WEIGHT = {1: 3, 2: 6, 3: 12, 4: 20}

def scan(text: str) -> list[Finding]:
    found = []
    for name, cat, sev, rx, grp, check in RULES:
        for m in re.finditer(rx, text):
            val = m.group(grp)
            if check and not check(val):
                continue
            found.append(Finding(name, cat, sev, val, m.start(grp), m.end(grp)))
    # resolve overlaps: higher severity first, then longer
    found.sort(key=lambda f: (-f.severity, -(f.end - f.start), f.start))
    kept = []
    for f in found:
        if all(f.end <= k.start or f.start >= k.end for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda f: f.start)

def risk(findings: list[Finding]) -> tuple[int, str]:
    score = min(100, sum(WEIGHT[f.severity] for f in findings))
    level = "Low" if score < 20 else "Medium" if score < 50 else "High" if score < 80 else "Critical"
    return score, level

def mask_value(f: Finding) -> str:
    v = f.value
    if f.type == "Email":
        u, d = v.split("@", 1)
        return u[0] + "***@" + d
    if f.type in ("Password", "API Key / Token"):
        return "*" * 8
    digits = [c for c in v if c.isalnum()]
    keep = set(range(len(v) - 4, len(v)))
    return "".join(c if (i in keep or not c.isalnum()) else "X" for i, c in enumerate(v))

def redact(text: str, findings: list[Finding], mode: str = "mask") -> str:
    """mode: 'mask' (keep last 4), 'label' ([TYPE]) or 'block' (black bars)."""
    out, last = [], 0
    for f in sorted(findings, key=lambda x: x.start):
        out.append(text[last:f.start])
        out.append({"mask": lambda: mask_value(f), "label": lambda: f"[{f.type.upper()}]",
                    "block": lambda: "\u2588" * len(f.value)}[mode]())
        last = f.end
    out.append(text[last:])
    return "".join(out)
