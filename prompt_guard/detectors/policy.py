from __future__ import annotations

import re
from typing import List, Tuple

_I = re.IGNORECASE

# (regex, severity, category)
_RULES = [
    (re.compile(r"\b(?:how (?:to|do i|can i)|steps? to|instructions? (?:for|to)|teach me (?:to|how to)) (?:make|build|synthesi[sz]e|create|assemble) (?:an? )?(?:pipe bomb|bomb|explosives?|nerve agent|bioweapon|molotov cocktail)", _I), 0.95, "weapons"),
    (re.compile(r"\b(?:write|create|build|code|develop) (?:me )?(?:an? )?(?:working )?(?:ransomware|keylogger|computer virus|malware|botnet|ddos script)", _I), 0.9, "malware"),
    (re.compile(r"\b(?:write|create|draft|build) (?:an? )?(?:convincing )?(?:phishing (?:email|page|site)|fake login page)", _I), 0.85, "fraud"),
    (re.compile(r"\bhow (?:to|do i|can i) (?:kill myself|commit suicide|end my life)", _I), 0.9, "self_harm"),
]


def scan_policy(text: str) -> List[Tuple[str, float]]:
    """Return a list of (category, severity) for each policy rule that matches."""
    return [(cat, sev) for rx, sev, cat in _RULES if rx.search(text)]
