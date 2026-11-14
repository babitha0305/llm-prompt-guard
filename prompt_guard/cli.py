from __future__ import annotations

import argparse
import json

from .config import GuardConfig
from .graph import PromptGuard


def main() -> None:
    p = argparse.ArgumentParser(prog="prompt-guard", description="LangGraph LLM prompt protection pipeline")
    p.add_argument("prompt", nargs="?", help="prompt to check (omit for interactive mode)")
    p.add_argument("--json", action="store_true", help="print the full result as JSON")
    p.add_argument("--judge", action="store_true", help="enable the LLM-as-judge node")
    p.add_argument("--show-graph", action="store_true", help="print the graph as Mermaid and exit")
    args = p.parse_args()

    config = GuardConfig.from_env()
    if args.judge:
        config.use_llm_judge = True
    guard = PromptGuard(config)

    if args.show_graph:
        print(guard.mermaid())
        return

    def run(text: str) -> None:
        r = guard.invoke(text)
        if args.json:
            print(json.dumps(r, indent=2))
        else:
            print(f"[{r['decision'].upper()}] risk={r['risk_score']}  trace={' > '.join(r['trace'])}")
            for f in r["findings"]:
                print(f"  - {f['category']} ({f['severity']:.2f}): {f['detail']}")
            print(f"\n{r['output']}\n")

    if args.prompt:
        run(args.prompt)
        return
    print("Prompt guard - type a prompt, empty line to quit.")
    while True:
        try:
            text = input("> ").strip()
        except EOFError:
            break
        if not text:
            break
        run(text)
