from __future__ import annotations

import base64
import re
from typing import List, Tuple

_I = re.IGNORECASE

# (regex, weight, label) — weight is the detector's confidence that the text is an attack.
_RULES = [
    (re.compile(r"\bignore (?:all |any )?(?:the )?(?:previous|prior|above|earlier|preceding) (?:instructions?|prompts?|rules|messages|directions)", _I), 0.9, "override_instructions"),
    (re.compile(r"\bdisregard (?:all |any )?(?:the )?(?:previous|prior|above|earlier|system) (?:instructions?|prompts?|rules)", _I), 0.9, "override_instructions"),
    (re.compile(r"\b(?:reveal|show|print|repeat|display|output|leak) (?:me )?(?:your|the) (?:system|hidden|initial|original|secret) (?:prompt|instructions?|message)", _I), 0.85, "prompt_extraction"),
    (re.compile(r"\bwhat (?:is|are|were) your (?:system|initial|hidden) (?:prompt|instructions)", _I), 0.7, "prompt_extraction"),
    (re.compile(r"\byou are now (?:dan|in developer mode|an? (?:unrestricted|unfiltered|uncensored))", _I), 0.85, "persona_hijack"),
    (re.compile(r"\b(?:dan|do anything now)\b", _I), 0.5, "persona_hijack"),
    (re.compile(r"\b(?:developer mode|jailbreak(?:ed)?)\b", _I), 0.6, "jailbreak_keyword"),
    (re.compile(r"\bpretend (?:you have|there are) no (?:rules|restrictions|guidelines|filters|limits)", _I), 0.8, "persona_hijack"),
    (re.compile(r"\bact as (?:an? )?(?:unfiltered|unrestricted|uncensored)", _I), 0.8, "persona_hijack"),
    (re.compile(r"\bbypass (?:the |your )?(?:safety|content|security)? ?(?:filters?|policy|policies|guardrails?|restrictions)", _I), 0.85, "guardrail_bypass"),
    (re.compile(r"\bdo not (?:follow|obey) (?:your|the) (?:rules|guidelines|policies|instructions)", _I), 0.75, "override_instructions"),
    (re.compile(r"(?:^|\n)\s*(?:system|assistant)\s*:", _I), 0.5, "role_spoofing"),
    (re.compile(r"<\|(?:im_start|im_end|system|endoftext)\|>|\[/?INST\]|<<SYS>>", _I), 0.8, "chat_template_tokens"),
    (re.compile(r"<\s*/?\s*(?:system|instructions?)\s*>", _I), 0.6, "role_spoofing"),
    (re.compile(r"\bnew instructions?\s*:", _I), 0.5, "override_instructions"),
]

_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def scan_injection(text: str) -> Tuple[float, List[str]]:
    """Return (score in 0..1, matched labels). Weights combine as noisy-OR."""
    remaining = 1.0
    labels: List[str] = []
    for rx, weight, label in _RULES:
        if rx.search(text):
            remaining *= 1.0 - weight
            labels.append(label)
    return round(1.0 - remaining, 3), labels


def scan_encoded_injection(text: str) -> Tuple[float, List[str]]:
    """Decode base64-looking tokens and scan the decoded payload."""
    best, labels = 0.0, []
    for token in _B64.findall(text):
        try:
            decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode("utf-8")
        except Exception:
            continue
        if not decoded.isprintable():
            continue
        score, found = scan_injection(decoded)
        if score > best:
            best, labels = score, found
    return best, labels
