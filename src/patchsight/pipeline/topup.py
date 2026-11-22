"""The prompts a configuration change alters, so a top-up run re-extracts only those.

Shadow-then-promote (``docs/architecture.md``) re-extracts the affected prompts and replays
the rest from the cache. A prompt is affected when its rendered messages differ between the
two configurations, because those messages are what a cached answer is keyed on. A change to
validation alone (such as dotted entry points) alters no prompt: its effect comes from
replaying the cached answers through the new validator, at no cost.

``plan`` compares two configurations on the PyPI backfill and on the Dunlap benchmark,
offline from the HTTP cache, and records the IDs and counts only: no prompt text.
"""

from collections import Counter
from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict

from patchsight.pipeline.extract.prompt import RenderedPrompt


class Change(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    candidates: int  # candidates the fix has
    kept_before: int
    kept_after: int
    truncated_before: bool
    truncated_after: bool

    @property
    def reason(self) -> str:
        if self.truncated_after and not self.truncated_before:
            return "newly cut by the candidate cap"
        if self.truncated_before and self.truncated_after:
            return "cut either way, other candidates kept"
        if self.truncated_before:
            return "no longer cut"
        return "other"


class Part(BaseModel):
    model_config = ConfigDict(frozen=True)

    benchmark: str
    considered: int  # prompts rendered under both configurations
    skipped: dict[str, int]  # vulnerabilities with no prompt, by build status
    changed: tuple[Change, ...]

    def reasons(self) -> dict[str, int]:
        return dict(sorted(Counter(c.reason for c in self.changed).items()))

    def ids(self) -> tuple[str, ...]:
        return tuple(c.id for c in self.changed)


class Plan(BaseModel):
    model_config = ConfigDict(frozen=True)

    role: str
    prompt_version: str
    before: str  # config path
    before_sha256: str
    after: str
    after_sha256: str
    parts: tuple[Part, ...]

    def part(self, benchmark: str) -> Part:
        return next(p for p in self.parts if p.benchmark == benchmark)


def compare(identifier: str, before: RenderedPrompt, after: RenderedPrompt) -> Change | None:
    """The change, or None when the prompt is the same, so its cached answer still holds."""
    if before.messages == after.messages:
        return None
    return Change(
        id=identifier, candidates=len(before.candidates) + len(before.dropped),
        kept_before=len(before.candidates),
        kept_after=len(after.candidates), truncated_before=before.truncated,
        truncated_after=after.truncated,
    )  # fmt: skip


def part(benchmark: str, considered: int, skipped: Iterable[str],
         changes: Iterable[Change | None]) -> Part:  # fmt: skip
    return Part(
        benchmark=benchmark, considered=considered,
        skipped=dict(sorted(Counter(skipped).items())),
        changed=tuple(sorted((c for c in changes if c is not None), key=lambda c: c.id)),
    )  # fmt: skip
