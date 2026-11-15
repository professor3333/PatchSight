"""Exact token counts with the model's own tokenizer.

Budgets are hard limits on Groq (8,000 tokens a minute, 7,000 input tokens a minute), and
a character-based estimate was off by up to a third on code-heavy prompts. Counting with
the real tokenizer makes the budget exact, and the same count serves the self-hosted
model, which shares the tokenizer.

The tokenizer file is downloaded once from Hugging Face at a pinned revision and refused
unless its SHA-256 matches the pin.
"""

import hashlib
from pathlib import Path
from typing import Protocol

import httpx
from pydantic import BaseModel, ConfigDict

# Chat formatting adds a few tokens per message (role markers, separators).
MESSAGE_OVERHEAD = 8


class TokenizerConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo: str
    revision: str
    sha256: str


class TokenCounter(Protocol):
    def count(self, text: str) -> int: ...


class CharEstimate:
    """A rough estimate for tests and offline use; never used to enforce real budgets."""

    def __init__(self, chars_per_token: float = 3.0) -> None:
        self.chars_per_token = chars_per_token

    def count(self, text: str) -> int:
        return int(len(text) / self.chars_per_token) + 1


class TokenizerMismatchError(RuntimeError):
    """The downloaded tokenizer file does not match the pinned SHA-256."""


class HfTokenizer:
    def __init__(self, config: TokenizerConfig, cache_dir: Path) -> None:
        from tokenizers import Tokenizer  # pipeline extra; imported lazily

        path = cache_dir / config.repo.replace("/", "__") / config.revision / "tokenizer.json"
        if not path.exists():
            url = f"https://huggingface.co/{config.repo}/resolve/{config.revision}/tokenizer.json"
            response = httpx.get(url, follow_redirects=True, timeout=120.0)
            response.raise_for_status()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(response.content)
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != config.sha256:
            raise TokenizerMismatchError(
                f"{path} has SHA-256 {actual}, but the config pins {config.sha256}"
            )
        self._tokenizer = Tokenizer.from_file(str(path))

    def count(self, text: str) -> int:
        return len(self._tokenizer.encode(text, add_special_tokens=False).ids)


def count_messages(
    counter: TokenCounter, messages: list[dict[str, str]] | tuple[dict[str, str], ...]
) -> int:
    return sum(counter.count(m["content"]) + MESSAGE_OVERHEAD for m in messages)
