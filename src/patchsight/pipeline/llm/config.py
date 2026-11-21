"""Load provider, model and budget settings from ``configs/llm.toml``."""

import tomllib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, model_validator

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
    # Output tokens per minute the provider allows this model, when it enforces a limit of
    # its own. A request whose output allowance exceeds it is refused outright, so
    # max_output_tokens must fit; the client also paces requests to stay under it.
    output_tokens_per_minute: int | None = None
    # This role's own output-capacity cap, in place of budget.output_tokens_per_candidate:
    # a prompt holds at most max_output_tokens // this many candidates.
    output_tokens_per_candidate: int | None = None

    @model_validator(mode="after")
    def _output_fits(self) -> "ModelConfig":
        limit = self.output_tokens_per_minute
        if limit is not None and self.max_output_tokens > limit:
            raise ValueError(
                f"{self.model}: max_output_tokens {self.max_output_tokens} exceeds the "
                f"provider's {limit} output tokens per minute, so every request would be refused"
            )
        return self


class BudgetConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_prompt_tokens: int
    max_hunk_lines: int
    # Output tokens one answered candidate needs (verdict, rationale, citations, and for
    # reasoning models their reasoning). When set, a prompt holds at most
    # max_output_tokens // this many candidates, so the answer fits the output limit.
    output_tokens_per_candidate: int | None = None
    # How candidates are ordered when a prompt must be cut to its budget (experiment E10):
    # BM25 against the advisory, or the smallest first, which kept more true functions.
    candidate_order: Literal["bm25", "smallest_first"] = "bm25"


class ValidationConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    # Accept an entry point that matches no definition exactly but exactly one on a dotted
    # boundary (``SetValue`` for ``Paved.SetValue``), kept as that definition's name.
    dotted_entry_points: bool = False


class LLMConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    providers: dict[str, ProviderConfig]
    models: dict[str, ModelConfig]
    budget: BudgetConfig
    tokenizer: TokenizerConfig
    validation: ValidationConfig = ValidationConfig()

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

    def candidate_limit(self, role: str) -> int | None:
        """Most candidates whose answers fit the role's output limit, or None for no limit.
        A role's own ``output_tokens_per_candidate`` takes the place of the budget's."""
        model = self.models[role]
        per_candidate = model.output_tokens_per_candidate or self.budget.output_tokens_per_candidate
        if per_candidate is None:
            return None
        return max(1, model.max_output_tokens // per_candidate)


def load_config(path: Path) -> LLMConfig:
    return LLMConfig.model_validate(tomllib.loads(path.read_text(encoding="utf-8")))
