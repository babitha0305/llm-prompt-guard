from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List


@dataclass
class PiiMatch:
    label: str
    kind: str      # "pii" or "secret"
    start: int
    end: int


def luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# (label, kind, regex) — order matters: earlier patterns claim spans first.
_PATTERNS = [
    ("PRIVATE_KEY", "secret", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("API_KEY", "secret", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("AWS_KEY", "secret", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", "secret", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("CREDIT_CARD", "pii", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("US_SSN", "pii", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("UK_NI_NUMBER", "pii", re.compile(r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b")),
    ("EMAIL", "pii", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("PHONE", "pii", re.compile(r"(?<![\w])\+\d{1,3}[\s.\-]?\d{2,5}[\s.\-]?\d{3,4}[\s.\-]?\d{3,4}(?![\w])")),
    ("PHONE", "pii", re.compile(r"(?<![\w])\(?\d{3,5}\)?[\s.\-]\d{3}[\s.\-]?\d{3,4}(?![\w])")),
]


def find_pii(text: str) -> List[PiiMatch]:
    claimed: List[PiiMatch] = []
    for label, kind, rx in _PATTERNS:
        for m in rx.finditer(text):
            if label == "CREDIT_CARD" and not luhn_ok(m.group()):
                continue
            if any(m.start() < c.end and c.start < m.end() for c in claimed):
                continue
            claimed.append(PiiMatch(label, kind, m.start(), m.end()))
    return sorted(claimed, key=lambda x: x.start)


def redact(text: str, matches: List[PiiMatch]) -> str:
    for m in sorted(matches, key=lambda x: x.start, reverse=True):
        text = text[: m.start] + f"[{m.label}_REDACTED]" + text[m.end:]
    return text
