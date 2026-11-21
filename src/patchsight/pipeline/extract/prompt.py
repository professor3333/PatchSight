"""Render an extraction prompt: the advisory plus numbered candidates with their hunks.

* Candidates are numbered ``F1..Fn`` and hunks ``H1..Hm``. The model answers with these
  IDs, so validation is a set lookup and invented names cannot get through.
* Untrusted text (the advisory and the code) goes inside tags. Any closing-tag sequence
  inside it is neutralised, so data cannot break out of its tag.
* When the candidates exceed the token budget, or the number of answers that fit the
  output limit, they are ranked by BM25 against the advisory text and kept in rank order
  until either limit is reached. The result records which candidates were dropped, so
  truncation is never silent.
"""

import math
import re
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from patchsight.pipeline.diffs.hunks import Hunk
from patchsight.pipeline.llm.tokens import MESSAGE_OVERHEAD, TokenCounter

_VERSION = re.compile(r"^version:\s*(\S+)\s*$", re.MULTILINE)
_SECTION = re.compile(r"^## (system|user)\s*$", re.MULTILINE)
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9]*")
_CAMEL = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")


class PromptTemplate(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: str
    system: str
    user: str


class AdvisoryText(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    summary: str
    details: str


class CandidateInput(BaseModel):
    """A changed function and the hunks of its file that touch it."""

    model_config = ConfigDict(frozen=True)

    path: str
    name: str
    kind: str
    hunks: tuple[Hunk, ...]
    # Which commit the hunks come from, so two commits touching one file never collide.
    source: str = ""


class Candidate(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    path: str
    name: str
    hunk_ids: tuple[str, ...]


class HunkRef(BaseModel):
    """Where a numbered hunk comes from: the commit, the file and both line ranges."""

    model_config = ConfigDict(frozen=True)

    id: str
    source: str
    path: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int


class RenderedPrompt(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: str
    messages: tuple[dict[str, str], ...]
    candidates: tuple[Candidate, ...]
    hunk_ids: tuple[str, ...]
    hunks: tuple[HunkRef, ...] = ()
    estimated_tokens: int
    truncated: bool
    dropped: tuple[str, ...]


def load_template(path: Path) -> PromptTemplate:
    text = path.read_text(encoding="utf-8")
    version = _VERSION.search(text)
    if version is None:
        raise ValueError(f"{path} has no 'version:' line")
    parts = _SECTION.split(text)
    sections = {parts[i]: parts[i + 1].strip() for i in range(1, len(parts) - 1, 2)}
    if set(sections) != {"system", "user"}:
        raise ValueError(f"{path} needs exactly a '## system' and a '## user' section")
    return PromptTemplate(
        version=version.group(1), system=sections["system"], user=sections["user"]
    )


def neutralise(text: str) -> str:
    """Stop untrusted text from closing the tag it sits in, and drop control characters."""
    cleaned = "".join(ch for ch in text if ch in "\n\t" or ch.isprintable())
    return cleaned.replace("</", "<\\/")


def terms(text: str) -> list[str]:
    """Lower-cased word pieces, splitting camelCase and snake_case."""
    found: list[str] = []
    for word in _WORD.findall(text):
        found.extend(piece.lower() for piece in _CAMEL.findall(word) if len(piece) > 1)
    return found


# Scores are compared at this many decimal places, far below any meaningful difference.
SCORE_DECIMALS = 9


def bm25_scores(
    query: str, documents: Sequence[str], k1: float = 1.5, b: float = 0.75
) -> list[float]:
    """Each document's BM25 score against ``query``, rounded so it is the same everywhere.

    The ranking must not depend on the process or the platform (rule 12): it decides which
    candidates a truncated prompt keeps, and so the prompt's cache key. Query terms are
    visited in sorted order, each score is summed exactly (``math.fsum``), and scores are
    rounded, so a last-bit difference between platforms' ``math.log`` cannot reorder a tie.
    """
    tokenised = [terms(doc) for doc in documents]
    count = len(tokenised)
    if not count:
        return []
    average = sum(len(t) for t in tokenised) / count or 1.0
    frequency = Counter(term for t in tokenised for term in set(t))
    query_terms = sorted(set(terms(query)))
    scores = []
    for tokens in tokenised:
        counts = Counter(tokens)
        parts = []
        for term in query_terms:
            tf = counts.get(term, 0)
            if not tf:
                continue
            idf = math.log(1 + (count - frequency[term] + 0.5) / (frequency[term] + 0.5))
            parts.append(idf * tf * (k1 + 1) / (tf + k1 * (1 - b + b * len(tokens) / average)))
        scores.append(round(math.fsum(parts), SCORE_DECIMALS))
    return scores


def bm25_rank(query: str, documents: Sequence[str], k1: float = 1.5, b: float = 0.75) -> list[int]:
    """Document indices, best match first. Ties keep the original order."""
    scores = bm25_scores(query, documents, k1, b)
    return [index for _, index in sorted((-score, index) for index, score in enumerate(scores))]


def _hunk_block(hunk_id: str, hunk: Hunk, max_lines: int) -> str:
    header = f"@@ -{hunk.old_start},{hunk.old_count} +{hunk.new_start},{hunk.new_count} @@"
    lines = list(hunk.lines[:max_lines])
    if len(hunk.lines) > max_lines:
        lines.append(f"[... {len(hunk.lines) - max_lines} more lines not shown]")
    body = neutralise("\n".join([header, *lines]))
    return f'<hunk id="{hunk_id}">\n{body}\n</hunk>'


def _advisory_text(advisory: AdvisoryText) -> str:
    return neutralise(f"{advisory.summary}\n\n{advisory.details}".strip())


def _hunk_ids(inputs: Sequence[CandidateInput]) -> dict[tuple[str, str, int], str]:
    # Hunk IDs are global, in file and hunk order, so a hunk shared by two candidates has
    # one ID that both can cite.
    keys = sorted({(c.source, c.path, h.index) for c in inputs for h in c.hunks})
    return {key: f"H{n}" for n, key in enumerate(keys, 1)}


def _block(
    cid: str, item: CandidateInput, hunk_id: dict[tuple[str, str, int], str], max_lines: int
) -> str:
    hunks = "\n".join(
        _hunk_block(hunk_id[(item.source, item.path, h.index)], h, max_lines)
        for h in sorted(item.hunks, key=lambda h: h.index)
    )
    attributes = f'id="{cid}" file="{neutralise(item.path)}" name="{neutralise(item.name)}"'
    return f'<candidate {attributes} kind="{item.kind}">\n{hunks}\n</candidate>'


class BudgetPlan(BaseModel):
    """What fitting a prompt to its budget works from: the tokens every prompt spends on the
    instructions and the advisory, each candidate's own tokens, and the BM25 rank order."""

    model_config = ConfigDict(frozen=True)

    base_tokens: int
    costs: tuple[int, ...]
    order: tuple[int, ...]  # candidate indices, best match first
    scores: tuple[float, ...]  # each candidate's BM25 score, as ranked


def budget_plan(
    template: PromptTemplate,
    advisory: AdvisoryText,
    inputs: Sequence[CandidateInput],
    counter: TokenCounter,
    max_hunk_lines: int,
) -> BudgetPlan:
    advisory_text = _advisory_text(advisory)
    hunk_id = _hunk_ids(inputs)
    base = template.system + template.user.replace("{{advisory}}", advisory_text)
    documents = [f"{i.name} {' '.join(h for x in i.hunks for h in x.lines)}" for i in inputs]
    return BudgetPlan(
        base_tokens=counter.count(base) + 2 * MESSAGE_OVERHEAD,
        costs=tuple(counter.count(_block("F0000", i, hunk_id, max_hunk_lines)) for i in inputs),
        order=tuple(bm25_rank(advisory_text, documents)),
        scores=tuple(bm25_scores(advisory_text, documents)),
    )


def fit(
    order: Sequence[int],
    costs: Sequence[int],
    base_tokens: int,
    budget_tokens: int,
    max_candidates: int | None = None,
) -> set[int]:
    """The candidates a prompt keeps, taken in ``order``: the first always, the others
    while they fit the budget (and, with ``max_candidates``, the output limit)."""
    kept: set[int] = set()
    used = base_tokens
    for index in order:
        full = max_candidates is not None and len(kept) >= max_candidates
        if kept and (full or used + costs[index] > budget_tokens):
            continue
        kept.add(index)
        used += costs[index]
    return kept


def render(
    template: PromptTemplate,
    advisory: AdvisoryText,
    inputs: Sequence[CandidateInput],
    budget_tokens: int,
    counter: TokenCounter,
    max_hunk_lines: int,
    max_candidates: int | None = None,
) -> RenderedPrompt:
    """Render the prompt, keeping as many candidates as fit within ``budget_tokens``.

    ``max_candidates`` caps the count as well, so the model's answer fits its output limit.
    """

    def estimate(text: str) -> int:
        return counter.count(text)

    advisory_text = _advisory_text(advisory)
    hunk_id = _hunk_ids(inputs)

    def block(cid: str, item: CandidateInput) -> str:
        return _block(cid, item, hunk_id, max_hunk_lines)

    plan = budget_plan(template, advisory, inputs, counter, max_hunk_lines)
    kept = fit(plan.order, plan.costs, plan.base_tokens, budget_tokens, max_candidates)
    kept_in_order = [i for i in range(len(inputs)) if i in kept]

    candidates: list[Candidate] = []
    blocks: list[str] = []
    refs: dict[str, HunkRef] = {}
    for number, index in enumerate(kept_in_order, 1):
        item = inputs[index]
        cid = f"F{number}"
        for h in item.hunks:
            hid = hunk_id[(item.source, item.path, h.index)]
            refs.setdefault(
                hid,
                HunkRef(
                    id=hid, source=item.source, path=item.path, old_start=h.old_start,
                    old_count=h.old_count, new_start=h.new_start, new_count=h.new_count,
                ),
            )  # fmt: skip
        candidates.append(
            Candidate(
                id=cid,
                path=item.path,
                name=item.name,
                hunk_ids=tuple(
                    hunk_id[(item.source, item.path, h.index)]
                    for h in sorted(item.hunks, key=lambda h: h.index)
                ),
            )
        )
        blocks.append(block(cid, item))

    user = (
        template.user.replace("{{advisory_id}}", neutralise(advisory.id))
        .replace("{{advisory}}", advisory_text)
        .replace("{{candidates}}", "\n".join(blocks))
    )
    messages = ({"role": "system", "content": template.system}, {"role": "user", "content": user})
    dropped = tuple(inputs[i].name for i in range(len(inputs)) if i not in kept)
    return RenderedPrompt(
        version=template.version,
        messages=messages,
        candidates=tuple(candidates),
        hunk_ids=tuple(
            sorted({h for c in candidates for h in c.hunk_ids}, key=lambda x: int(x[1:]))
        ),
        estimated_tokens=estimate(template.system) + estimate(user) + 2 * MESSAGE_OVERHEAD,
        truncated=bool(dropped),
        dropped=dropped,
        hunks=tuple(sorted(refs.values(), key=lambda r: int(r.id[1:]))),
    )
