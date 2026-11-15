"""Render an extraction prompt: the advisory plus numbered candidates with their hunks.

* Candidates are numbered ``F1..Fn`` and hunks ``H1..Hm``. The model answers with these
  IDs, so validation is a set lookup and invented names cannot get through.
* Untrusted text (the advisory and the code) goes inside tags. Any closing-tag sequence
  inside it is neutralised, so data cannot break out of its tag.
* When the candidates exceed the token budget, they are ranked by BM25 against the
  advisory text and kept in rank order until the budget is full. The result records
  which candidates were dropped, so truncation is never silent.
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


class RenderedPrompt(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: str
    messages: tuple[dict[str, str], ...]
    candidates: tuple[Candidate, ...]
    hunk_ids: tuple[str, ...]
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


def bm25_rank(query: str, documents: Sequence[str], k1: float = 1.5, b: float = 0.75) -> list[int]:
    """Document indices, best match first. Ties keep the original order."""
    tokenised = [terms(doc) for doc in documents]
    count = len(tokenised)
    if not count:
        return []
    average = sum(len(t) for t in tokenised) / count or 1.0
    frequency = Counter(term for t in tokenised for term in set(t))
    query_terms = set(terms(query))
    scores = []
    for index, tokens in enumerate(tokenised):
        counts = Counter(tokens)
        score = 0.0
        for term in query_terms:
            tf = counts.get(term, 0)
            if not tf:
                continue
            idf = math.log(1 + (count - frequency[term] + 0.5) / (frequency[term] + 0.5))
            score += idf * tf * (k1 + 1) / (tf + k1 * (1 - b + b * len(tokens) / average))
        scores.append((-score, index))
    return [index for _, index in sorted(scores)]


def _hunk_block(hunk_id: str, hunk: Hunk, max_lines: int) -> str:
    header = f"@@ -{hunk.old_start},{hunk.old_count} +{hunk.new_start},{hunk.new_count} @@"
    lines = list(hunk.lines[:max_lines])
    if len(hunk.lines) > max_lines:
        lines.append(f"[... {len(hunk.lines) - max_lines} more lines not shown]")
    body = neutralise("\n".join([header, *lines]))
    return f'<hunk id="{hunk_id}">\n{body}\n</hunk>'


def render(
    template: PromptTemplate,
    advisory: AdvisoryText,
    inputs: Sequence[CandidateInput],
    budget_tokens: int,
    counter: TokenCounter,
    max_hunk_lines: int,
) -> RenderedPrompt:
    """Render the prompt, keeping as many candidates as fit within ``budget_tokens``."""

    def estimate(text: str) -> int:
        return counter.count(text)

    advisory_text = neutralise(f"{advisory.summary}\n\n{advisory.details}".strip())

    # Hunk IDs are global, in file and hunk order, so a hunk shared by two candidates has
    # one ID that both can cite.
    hunk_key = sorted({(c.source, c.path, h.index) for c in inputs for h in c.hunks})
    hunk_id = {key: f"H{n}" for n, key in enumerate(hunk_key, 1)}

    def block(cid: str, item: CandidateInput) -> str:
        hunks = "\n".join(
            _hunk_block(hunk_id[(item.source, item.path, h.index)], h, max_hunk_lines)
            for h in sorted(item.hunks, key=lambda h: h.index)
        )
        attributes = f'id="{cid}" file="{neutralise(item.path)}" name="{neutralise(item.name)}"'
        return f'<candidate {attributes} kind="{item.kind}">\n{hunks}\n</candidate>'

    base = template.system + template.user.replace("{{advisory}}", advisory_text)
    base_tokens = estimate(base) + 2 * MESSAGE_OVERHEAD
    costs = [estimate(block("F0000", item)) for item in inputs]
    order = bm25_rank(
        advisory_text, [f"{i.name} {' '.join(h for x in i.hunks for h in x.lines)}" for i in inputs]
    )

    kept: set[int] = set()
    used = base_tokens
    for index in order:
        # The best-ranked candidate is always kept; others only while they fit.
        if kept and used + costs[index] > budget_tokens:
            continue
        kept.add(index)
        used += costs[index]
    kept_in_order = [i for i in range(len(inputs)) if i in kept]

    candidates: list[Candidate] = []
    blocks: list[str] = []
    for number, index in enumerate(kept_in_order, 1):
        item = inputs[index]
        cid = f"F{number}"
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
    )
