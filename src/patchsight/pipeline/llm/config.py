"""Load provider, model and budget settings from ``configs/llm.toml``."""

import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict


class ProviderConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    base_url: str
    api_key_env: str
    tokens_per_minute: int
    requests_per_day: int
    tokens_per_day: int | None = None


class ModelConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: str
    model: str
    max_output_tokens: int
    seed: int
    extra: dict[str, Any] = {}


class BudgetConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_prompt_tokens: int
    chars_per_token: float
    max_hunk_lines: int


class LLMConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    providers: dict[str, ProviderConfig]
    models: dict[str, ModelConfig]
    budget: BudgetConfig

    def prompt_budget(self, role: str) -> int:
        """Largest prompt for this model that still fits one request under the TPM cap."""
        model = self.models[role]
        provider = self.providers[model.provider]
        headroom = provider.tokens_per_minute - model.max_output_tokens - 500
        return max(0, min(self.budget.max_prompt_tokens, headroom))


def load_config(path: Path) -> LLMConfig:
    return LLMConfig.model_validate(tomllib.loads(path.read_text(encoding="utf-8")))
