"""Load provider, model and budget settings from ``configs/llm.toml``."""

import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from patchsight.pipeline.llm.tokens import TokenizerConfig


class ProviderConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    base_url: str
    api_key_env: str
    tokens_per_minute: int
    requests_per_day: int
    tokens_per_day: int | None = None
    # A separate cap on input tokens per minute, which one request must also fit under.
    input_tokens_per_minute: int | None = None


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
    max_hunk_lines: int


class LLMConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    providers: dict[str, ProviderConfig]
    models: dict[str, ModelConfig]
    budget: BudgetConfig
    tokenizer: TokenizerConfig

    def prompt_budget(self, role: str) -> int:
        """Largest prompt, in exact tokens, that still fits the repair round under the caps.

        A repair round sends the prompt, the previous answer (up to ``max_output_tokens``)
        and a short repair note, and asks for another ``max_output_tokens``.
        """
        model = self.models[role]
        provider = self.providers[model.provider]
        repair_note = 400
        limits = [
            self.budget.max_prompt_tokens,
            provider.tokens_per_minute - 2 * model.max_output_tokens - repair_note,
        ]
        if provider.input_tokens_per_minute is not None:
            limits.append(provider.input_tokens_per_minute - model.max_output_tokens - repair_note)
        return max(0, min(limits))


def load_config(path: Path) -> LLMConfig:
    return LLMConfig.model_validate(tomllib.loads(path.read_text(encoding="utf-8")))
