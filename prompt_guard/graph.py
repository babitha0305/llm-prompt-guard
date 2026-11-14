from __future__ import annotations

from typing import Any, Dict, Optional

from langgraph.graph import END, START, StateGraph

from .config import GuardConfig
from .llm import LLMClient, get_llm
from .nodes import make_nodes
from .state import GuardState


def build_graph(config: Optional[GuardConfig] = None, llm: Optional[LLMClient] = None):
    """Compile the guard pipeline.

    START -> sanitize -> pii -> [injection | policy | judge] (parallel) -> risk
          -> block -> END                       (risk too high)
          -> generate -> output_guard -> END    (allow / sanitize)
    """
    config = config or GuardConfig()
    llm = llm or get_llm(config.provider, config.model)
    judge_llm = llm if (config.use_llm_judge and config.provider != "mock") else None
    n = make_nodes(config, llm, judge_llm)

    g = StateGraph(GuardState)
    for name, fn in n.items():
        g.add_node(name, fn)

    g.add_edge(START, "sanitize")
    g.add_edge("sanitize", "pii")
    for detector in ("injection", "policy", "judge"):
        g.add_edge("pii", detector)
    g.add_edge(["injection", "policy", "judge"], "risk")   # fan-in: wait for all detectors
    g.add_conditional_edges(
        "risk",
        lambda s: "block" if s["decision"] == "block" else "generate",
        {"block": "block", "generate": "generate"},
    )
    g.add_edge("generate", "output_guard")
    g.add_edge("block", END)
    g.add_edge("output_guard", END)
    return g.compile()


class PromptGuard:
    """Convenience wrapper: guard = PromptGuard(); result = guard.invoke("...")."""

    def __init__(self, config: Optional[GuardConfig] = None, llm: Optional[LLMClient] = None):
        self.config = config or GuardConfig()
        self.graph = build_graph(self.config, llm)

    def invoke(self, prompt: str) -> Dict[str, Any]:
        state = self.graph.invoke({"raw_input": prompt})
        return {
            "decision": state["decision"],
            "risk_score": state["risk_score"],
            "output": state["final_output"],
            "output_blocked": state.get("output_blocked", False),
            "findings": state.get("findings", []),
            "trace": state.get("trace", []),
        }

    def mermaid(self) -> str:
        return self.graph.get_graph().draw_mermaid()
