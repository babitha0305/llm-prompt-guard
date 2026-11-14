from __future__ import annotations

from typing import Protocol


class LLMClient(Protocol):
    def complete(self, system: str, user: str) -> str: ...


class MockLLM:
    """Offline stand-in so the whole pipeline runs and tests without an API key."""

    def complete(self, system: str, user: str) -> str:
        body = user.replace("<user_input>", "").replace("</user_input>", "").strip()
        return f"[mock-llm] You asked: {body[:300]}"


class AnthropicLLM:
    def __init__(self, model: str, max_tokens: int = 800):
        import anthropic  # optional dependency

        self.client = anthropic.Anthropic()
        self.model = model
        self.max_tokens = max_tokens

    def complete(self, system: str, user: str) -> str:
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")


def get_llm(provider: str, model: str) -> LLMClient:
    if provider == "anthropic":
        return AnthropicLLM(model)
    return MockLLM()
