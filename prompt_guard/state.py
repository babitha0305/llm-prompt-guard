from __future__ import annotations

import operator
from typing import Annotated, List, Literal, TypedDict


class Finding(TypedDict):
    detector: str
    category: str      # prompt_injection | harmful_request | self_harm | pii | secret | obfuscation | ...
    severity: float    # 0..1
    detail: str        # never contains the raw sensitive value


class GuardState(TypedDict, total=False):
    raw_input: str
    clean_input: str
    findings: Annotated[List[Finding], operator.add]   # parallel nodes append safely
    trace: Annotated[List[str], operator.add]
    risk_score: float
    decision: Literal["allow", "sanitize", "block"]
    llm_output: str
    output_blocked: bool
    final_output: str
