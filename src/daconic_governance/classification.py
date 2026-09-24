"""Structural restriction first; deterministic heuristics are not a universal DLP guarantee."""
import copy
import ipaddress
import re
from .common import digest, flatten, get_path

PATTERNS = [
    ("private_key", "CREDENTIAL", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?(?:-----END [^-]+-----|$)"),
    ("database_uri", "CREDENTIAL", r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s]+"),
    ("aws_key", "CREDENTIAL", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ("api_key", "CREDENTIAL", r"\bsk[-_][A-Za-z0-9_-]{16,}\b"),
    ("jwt", "CREDENTIAL", r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    ("password_context", "CREDENTIAL", r"\b(?:password|secret|token|api_key)\s*[:=]\s*[^\s,;]+"),
    ("iban", "FINANCIAL_PII", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b"),
    ("pan", "PAYMENT_CARD", r"(?<![\w])\d(?:[ -]?\d){12,18}(?![\w])"),
    ("private_ip", "INFRASTRUCTURE", r"\b(?:\d{1,3}\.){3}\d{1,3}\b|(?<!\w)::1(?!\w)"),
    ("email", "PII", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ("phone", "PII", r"(?<!\w)\+[1-9]\d{7,14}(?!\w)"),
    ("internal_host", "INFRASTRUCTURE", r"\b[A-Za-z0-9][A-Za-z0-9.-]*\.(?:internal|local)\b"),
]
DETECTOR_HASH = digest({"version": "v2-luhn-iban-context", "patterns": [list(x) for x in PATTERNS]})


def luhn(text):
    digits = [int(x) for x in text if x.isdigit() and x.isascii()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    return sum((n * 2 - 9 if n * 2 > 9 else n * 2) if i % 2 else n for i, n in enumerate(reversed(digits))) % 10 == 0


def valid_iban(text):
    text = text.replace(" ", "")
    if not 15 <= len(text) <= 34:
        return False
    moved = text[4:] + text[:4]
    return int("".join(str(ord(c) - 55) if c.isalpha() else c for c in moved)) % 97 == 1


def classify(payload):
    findings = []
    for path, scalar in flatten(payload):
        if scalar is None or type(scalar) is bool or isinstance(scalar, (dict, list)):
            continue
        text = str(scalar)
        name = path.rsplit("/", 1)[-1].lower()
        if name in {"password", "token", "secret", "api_key", "authorization"} and text:
            findings.append({"category": "CREDENTIAL", "path": path, "detector": "credential_field", "count": 1, "detector_hash": DETECTOR_HASH})
            continue
        if name in {"cvv", "cvc", "security_code"} and re.fullmatch(r"\d{3,4}", text):
            findings.append({"category": "PAYMENT_CARD", "path": path, "detector": "cvv_context", "count": 1, "detector_hash": DETECTOR_HASH})
            continue
        claimed = []
        for detector, category, pattern in PATTERNS:
            count = 0
            for match in re.finditer(pattern, text):
                start, end = match.span()
                if any(start < b and a < end for a, b in claimed):
                    continue
                candidate = match.group()
                if detector == "pan" and not luhn(candidate):
                    continue
                if detector == "iban" and not valid_iban(candidate):
                    continue
                if detector == "private_ip":
                    try:
                        addr = ipaddress.ip_address(candidate)
                        networks = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128")]
                        if not any(addr in n for n in networks):
                            continue
                    except ValueError:
                        continue
                claimed.append((start, end))
                count += 1
            if count:
                findings.append({"category": category, "path": path, "detector": detector, "count": count, "detector_hash": DETECTOR_HASH})
    return findings


def strip_restricted(payload, paths):
    value = copy.deepcopy(payload)
    count = 0
    # Lists retain length with null placeholders, preventing shifted-path mistakes.
    for path in sorted(set(paths), key=lambda p: p.count("/"), reverse=True):
        if path == "":
            return None, 1
        parent_path, _, last = path.rpartition("/")
        last = last.replace("~1", "/").replace("~0", "~")
        try:
            parent = get_path(value, parent_path)
            if isinstance(parent, list):
                parent[int(last)] = None
            else:
                del parent[last]
            count += 1
        except (KeyError, IndexError, TypeError, ValueError):
            continue
    return value, count
