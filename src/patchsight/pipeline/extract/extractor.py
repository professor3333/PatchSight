"""One extraction: render, call the model, validate, repair once, or dead-letter."""

from collections.abc import Sequence, Set
from typing import Literal

from pydantic import BaseModel, ConfigDict

from patchsight.pipeline.extract.prompt import (
    AdvisoryText,
    CandidateInput,
    CandidateOrder,
    HunkRef,
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
from patchsight.pipeline.llm.tokens import TokenCounter

Status = Literal["ok", "repaired", "dead_letter", "no_candidates"]

REPAIR_MESSAGE = (
    "Your answer failed validation:\n{errors}\n\n"
    "Return corrected JSON for the same candidates. Use only the candidate and hunk IDs "
    "shown above, and give exactly one item per candidate."
)


# A rationale is one sentence; anything longer is cut, so stored text stays short.
MAX_RATIONALE = 300


class CandidateEvidence(BaseModel):
    """Why one candidate was judged vulnerable, and the hunks the answer cited."""

    model_config = ConfigDict(frozen=True)

    path: str
    name: str
    rationale: str
    hunks: tuple[HunkRef, ...]


class ExtractionOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    advisory_id: str
    status: Status
    model: str
    prompt_version: str
    candidates: int
    vulnerable: tuple[str, ...]
    # (path, name) of each vulnerable candidate: a name can occur in several files.
    vulnerable_locations: tuple[tuple[str, str], ...] = ()
    evidence: tuple[CandidateEvidence, ...] = ()
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


def _evidence(prompt: RenderedPrompt, result: ValidatedExtraction) -> tuple[CandidateEvidence, ...]:
    refs = {r.id: r for r in prompt.hunks}
    by_id = {c.id: c for c in prompt.candidates}
    return tuple(
        CandidateEvidence(
            path=by_id[cid].path,
            name=by_id[cid].name,
            rationale=" ".join(result.rationales[cid].split())[:MAX_RATIONALE],
            hunks=tuple(refs[h] for h in result.evidence[cid] if h in refs),
        )
        for cid in result.vulnerable_ids
    )


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
    counter: TokenCounter,
    max_hunk_lines: int,
    max_candidates: int | None = None,
    dotted_entry_points: bool = False,
    candidate_order: CandidateOrder = "bm25",
) -> ExtractionOutcome:
    """Extract one advisory; its model calls and its outcome go to the client's trace."""
    prompt = render(
        template, advisory, inputs, budget_tokens, counter, max_hunk_lines, max_candidates,
        candidate_order,
    )  # fmt: skip
    return extract_prompt(llm, model, advisory.id, prompt, known_names, dotted_entry_points)


def extract_prompt(
    llm: LLMClient,
    model: ModelConfig,
    advisory_id: str,
    prompt: RenderedPrompt,
    known_names: Set[str],
    dotted_entry_points: bool = False,
) -> ExtractionOutcome:
    """Ask the model about one rendered prompt, validate, repair once, or dead-letter.

    Split from ``extract`` so a stored prompt's metadata can be replayed through the same
    loop: the regression suite does that with the recorded answers."""
    with llm.tracer.advisory(advisory_id):
        outcome = _extract(llm, model, advisory_id, prompt, known_names, dotted_entry_points)
        llm.tracer.emit(
            "extraction", status=outcome.status, model=outcome.model,
            prompt_version=outcome.prompt_version, candidates=outcome.candidates,
            truncated=outcome.truncated, dropped_candidates=len(outcome.dropped_candidates),
            calls=outcome.calls, cached_calls=outcome.cached_calls,
            provider_rejections=outcome.provider_rejections,
            invented_ids_first_attempt=outcome.invented_ids_first_attempt,
            entry_points_dropped=outcome.entry_points_dropped,
            prompt_tokens=outcome.prompt_tokens, completion_tokens=outcome.completion_tokens,
        )  # fmt: skip
    return outcome


def _extract(
    llm: LLMClient,
    model: ModelConfig,
    advisory_id: str,
    prompt: RenderedPrompt,
    known_names: Set[str],
    dotted_entry_points: bool,
) -> ExtractionOutcome:
    base = {
        "advisory_id": advisory_id,
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
            result = validate(response.content, prompt, known_names, dotted_entry_points)
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
    locations = {c.id: (c.path, c.name) for c in prompt.candidates}
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
        vulnerable_locations=tuple(sorted({locations[cid] for cid in result.vulnerable_ids})),
        evidence=_evidence(prompt, result),
        entry_points=result.entry_points,
        entry_points_dropped=len(result.entry_points_dropped),
        errors=tuple(errors) if len(responses) > 1 or rejections else (),
    )
