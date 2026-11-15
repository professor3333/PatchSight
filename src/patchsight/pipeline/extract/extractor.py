"""One extraction: render, call the model, validate, repair once, or dead-letter."""

from collections.abc import Sequence, Set
from typing import Literal

from pydantic import BaseModel, ConfigDict

from patchsight.pipeline.extract.prompt import (
    AdvisoryText,
    CandidateInput,
    PromptTemplate,
    RenderedPrompt,
    render,
)
from patchsight.pipeline.extract.schema import SCHEMA_NAME, response_schema
from patchsight.pipeline.extract.validate import (
    ValidatedExtraction,
    ValidationFailedError,
    validate,
)
from patchsight.pipeline.llm.client import (
    LLMClient,
    LLMRequest,
    LLMResponse,
    ProviderRejectedError,
)
from patchsight.pipeline.llm.config import ModelConfig

Status = Literal["ok", "repaired", "dead_letter", "no_candidates"]

REPAIR_MESSAGE = (
    "Your answer failed validation:\n{errors}\n\n"
    "Return corrected JSON for the same candidates. Use only the candidate and hunk IDs "
    "shown above, and give exactly one item per candidate."
)


class ExtractionOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    advisory_id: str
    status: Status
    model: str
    prompt_version: str
    candidates: int
    vulnerable: tuple[str, ...]
    entry_points: tuple[str, ...]
    entry_points_dropped: int
    invented_ids_first_attempt: int
    errors: tuple[str, ...]
    truncated: bool
    dropped_candidates: tuple[str, ...]
    estimated_prompt_tokens: int
    prompt_tokens: int
    completion_tokens: int
    calls: int
    cached_calls: int
    provider_rejections: int


def _request(
    model: ModelConfig, prompt: RenderedPrompt, messages: Sequence[dict[str, str]]
) -> LLMRequest:
    return LLMRequest(
        model=model.model,
        prompt_version=prompt.version,
        messages=tuple(messages),
        schema_name=SCHEMA_NAME,
        response_schema=response_schema(),
        max_tokens=model.max_output_tokens,
        seed=model.seed,
        extra=model.extra,
    )


def extract(
    llm: LLMClient,
    model: ModelConfig,
    template: PromptTemplate,
    advisory: AdvisoryText,
    inputs: Sequence[CandidateInput],
    known_names: Set[str],
    budget_tokens: int,
    chars_per_token: float,
    max_hunk_lines: int,
) -> ExtractionOutcome:
    prompt = render(template, advisory, inputs, budget_tokens, chars_per_token, max_hunk_lines)
    base = {
        "advisory_id": advisory.id,
        "model": model.model,
        "prompt_version": prompt.version,
        "candidates": len(prompt.candidates),
        "truncated": prompt.truncated,
        "dropped_candidates": prompt.dropped,
        "estimated_prompt_tokens": prompt.estimated_tokens,
    }
    if not prompt.candidates:
        return ExtractionOutcome(
            **base, status="no_candidates", vulnerable=(), entry_points=(), entry_points_dropped=0,
            invented_ids_first_attempt=0, errors=(), prompt_tokens=0, completion_tokens=0,
            calls=0, cached_calls=0, provider_rejections=0,
        )  # fmt: skip

    responses: list[LLMResponse] = []
    messages = list(prompt.messages)
    first_invented = 0
    errors: list[str] = []
    result: ValidatedExtraction | None = None
    rejections = 0
    for attempt in range(2):
        try:
            response = llm.complete(_request(model, prompt, messages))
        except ProviderRejectedError as rejected:
            rejections += 1
            errors = [f"the provider rejected the generation: {rejected}"]
            messages.append(
                {"role": "user", "content": REPAIR_MESSAGE.format(errors="\n".join(errors))}
            )
            continue
        responses.append(response)
        try:
            result = validate(response.content, prompt, known_names)
            break
        except ValidationFailedError as failure:
            if attempt == 0:
                first_invented = failure.invented_ids
            errors = failure.errors
            messages += [
                {"role": "assistant", "content": response.content},
                {"role": "user", "content": REPAIR_MESSAGE.format(errors="\n".join(errors))},
            ]

    names = {c.id: c.name for c in prompt.candidates}
    usage = {
        "prompt_tokens": sum(r.prompt_tokens for r in responses),
        "completion_tokens": sum(r.completion_tokens for r in responses),
        "calls": len(responses) + rejections,
        "cached_calls": sum(r.cached for r in responses),
        "provider_rejections": rejections,
        "invented_ids_first_attempt": first_invented,
    }
    if result is None:
        return ExtractionOutcome(
            **base, **usage, status="dead_letter", vulnerable=(), entry_points=(),
            entry_points_dropped=0, errors=tuple(errors),
        )  # fmt: skip
    return ExtractionOutcome(
        **base,
        **usage,
        status="ok" if len(responses) == 1 and not rejections else "repaired",
        vulnerable=tuple(sorted({names[cid] for cid in result.vulnerable_ids})),
        entry_points=result.entry_points,
        entry_points_dropped=len(result.entry_points_dropped),
        errors=tuple(errors) if len(responses) > 1 or rejections else (),
    )
