"""Evaluate the guard on a small labelled set: python -m evaluation.run_eval"""
from __future__ import annotations

import sys

from prompt_guard import PromptGuard

from .dataset import SAMPLES


def main() -> int:
    guard = PromptGuard()
    classes = ["block", "sanitize", "allow"]
    matrix = {a: {p: 0 for p in classes} for a in classes}
    misses = []
    for text, expected in SAMPLES:
        got = guard.invoke(text)["decision"]
        matrix[expected][got] += 1
        if got != expected:
            misses.append((text, expected, got))

    total = len(SAMPLES)
    correct = sum(matrix[c][c] for c in classes)
    print(f"Accuracy: {correct}/{total} = {correct / total:.1%}\n")
    print("Confusion matrix (rows = expected, cols = predicted)")
    print(f"{'':10}" + "".join(f"{c:>10}" for c in classes))
    for a in classes:
        print(f"{a:10}" + "".join(f"{matrix[a][p]:>10}" for p in classes))

    tp = matrix["block"]["block"]
    fp = sum(matrix[a]["block"] for a in classes if a != "block")
    fn = sum(matrix["block"][p] for p in classes if p != "block")
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    print(f"\nBlock class - precision: {precision:.2f}  recall: {recall:.2f}")
    for text, exp, got in misses:
        print(f"MISS expected={exp} got={got}: {text!r}")
    return 0 if not misses else 1


if __name__ == "__main__":
    sys.exit(main())
