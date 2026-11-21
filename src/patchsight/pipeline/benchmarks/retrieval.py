"""Retrieval at the prompt budget (proposal §10, ADR 0003): which candidates a cut prompt keeps.

When a fix's candidates do not fit the token budget, they are ranked and kept in rank order
while they fit (``extract/prompt.py``). A true vulnerable function that is cut cannot be
picked by the model; only the low-confidence fallback still lists it. On the reports whose
prompts are cut, this measures how many of the true vulnerable functions among the
candidates each order keeps, with exactly the extractor's token costs:

* ``bm25``: BM25 against the advisory text, as the extractor ranks;
* ``file_order``: no ranking, in the order the path filter and the mapping produce them;
* ``oracle``: true functions first, cheapest first, the most any order can keep at this
  budget.

``freeze`` writes a bundle with, per report, each candidate's name, path, token cost and
label, the BM25 order and the prompt's fixed cost: no code and no advisory text (rule 13).
``score`` and ``render_markdown`` work from the bundle alone, so CI can regenerate the
committed report.
"""

import random
from collections.abc import Callable, Sequence
from functools import partial
from typing import Literal

from pydantic import BaseModel, ConfigDict

from patchsight.eval.metrics import Interval
from patchsight.pipeline.extract.prompt import fit

Ranking = Literal["bm25", "file_order", "oracle"]
RANKINGS: tuple[Ranking, ...] = ("bm25", "file_order", "oracle")
TOP_K = (1, 2, 3, 5, 10)
BOOTSTRAP = 2000
SEED = 20261121


class Item(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    path: str
    tokens: int
    vulnerable: bool


class Case(BaseModel):
    model_config = ConfigDict(frozen=True)

    report: str
    split: str
    base_tokens: int
    items: tuple[Item, ...]  # in the mapping's order
    bm25: tuple[int, ...]  # item indices, best match first


class Bundle(BaseModel):
    model_config = ConfigDict(frozen=True)

    benchmark: str
    split_sha256: str
    prompt_version: str
    tokenizer: str
    budget_tokens: int
    max_candidates: int | None
    cases: tuple[Case, ...]

    def truncated(self) -> list[Case]:
        """The cases whose prompt is cut: their candidates do not all fit, in any order."""
        return [c for c in self.cases if len(_kept(self, c, "bm25")) < len(c.items)]


def order(case: Case, ranking: Ranking) -> list[int]:
    indices = list(range(len(case.items)))
    if ranking == "bm25":
        return list(case.bm25)
    if ranking == "file_order":
        return indices
    # The cheapest candidate of each true name first, cheapest first: the most true names any
    # order can keep (each name counts once, so a second candidate of a name would waste room).
    first: dict[str, int] = {}
    for i in sorted(indices, key=lambda i: (case.items[i].tokens, i)):
        if case.items[i].vulnerable:
            first.setdefault(case.items[i].name, i)
    best = sorted(first.values(), key=lambda i: (case.items[i].tokens, i))
    return best + [i for i in indices if i not in set(best)]


def _true_names(case: Case, indices: Sequence[int]) -> set[str]:
    return {case.items[i].name for i in indices if case.items[i].vulnerable}


def _kept(bundle: Bundle, case: Case, ranking: Ranking) -> set[int]:
    costs = [i.tokens for i in case.items]
    return fit(order(case, ranking), costs, case.base_tokens, bundle.budget_tokens,
               bundle.max_candidates)  # fmt: skip


def kept_true(bundle: Bundle, case: Case, ranking: Ranking) -> tuple[int, int]:
    """True function names kept at the budget, and true names among all candidates."""
    kept = _kept(bundle, case, ranking)
    return len(_true_names(case, sorted(kept))), len(_true_names(case, range(len(case.items))))


def top_k_true(case: Case, ranking: Ranking, k: int) -> int:
    return len(_true_names(case, order(case, ranking)[:k]))


class RankingScore(BaseModel):
    model_config = ConfigDict(frozen=True)

    ranking: Ranking
    kept_true: int
    recall: float
    recall_ci95: Interval | None
    reports_with_none_kept: int  # reports with a true candidate, none of them kept
    candidates_kept: int
    recall_at_k: dict[int, float]  # by count of candidates, ignoring tokens


class Difference(BaseModel):
    """Recall of ``first`` minus recall of ``second``, paired by report."""

    model_config = ConfigDict(frozen=True)

    first: Ranking
    second: Ranking
    recall_difference: float
    ci95: Interval
    first_keeps_more: int  # cut reports where ``first`` keeps more true functions
    second_keeps_more: int
    tied: int


class SplitScore(BaseModel):
    model_config = ConfigDict(frozen=True)

    split: str
    reports: int
    truncated: int
    truncated_with_truth: int  # cut reports with a true function among their candidates
    true_functions: int  # in cut reports, among their candidates
    candidates: int  # in cut reports
    rankings: tuple[RankingScore, ...]
    bm25_vs_file_order: Difference | None


def _ci(values: list[float]) -> Interval:
    ordered = sorted(values)

    def at(q: float) -> float:
        position = q * (len(ordered) - 1)
        low = int(position)
        high = min(low + 1, len(ordered) - 1)
        return ordered[low] + (ordered[high] - ordered[low]) * (position - low)

    return Interval(low=at(0.025), high=at(0.975))


def _bootstrap(
    count: int, statistic: Callable[[Sequence[int]], float], seed: int
) -> Interval | None:
    """A 95% interval for ``statistic`` over ``count`` reports, resampling report indices."""
    if not count:
        return None
    rng = random.Random(seed)  # noqa: S311 - statistical resampling, not security
    return _ci([statistic([rng.randrange(count) for _ in range(count)]) for _ in range(BOOTSTRAP)])


def score_split(bundle: Bundle, split: str) -> SplitScore:
    chosen = [c for c in bundle.cases if split == "all" or c.split == split]
    cut = [c for c in bundle.truncated() if split == "all" or c.split == split]
    with_truth = [c for c in cut if any(i.vulnerable for i in c.items)]
    # Each report's (kept, true) once per order; the bootstrap resamples these.
    pairs = {r: [kept_true(bundle, c, r) for c in with_truth] for r in RANKINGS}
    total_true = sum(t for _, t in pairs["file_order"])

    def recall(ranking: Ranking, draw: Sequence[int]) -> float:
        true = sum(pairs[ranking][i][1] for i in draw)
        return sum(pairs[ranking][i][0] for i in draw) / true if true else 0.0

    everyone = range(len(with_truth))
    scores = []
    for ranking in RANKINGS:
        kept = sum(k for k, _ in pairs[ranking])
        at_k = {k: sum(top_k_true(c, ranking, k) for c in with_truth) for k in TOP_K}
        scores.append(
            RankingScore(
                ranking=ranking,
                kept_true=kept,
                recall=kept / total_true if total_true else 0.0,
                recall_ci95=_bootstrap(len(with_truth), partial(recall, ranking), SEED),
                reports_with_none_kept=sum(1 for k, _ in pairs[ranking] if k == 0),
                candidates_kept=sum(len(_kept(bundle, c, ranking)) for c in cut),
                recall_at_k={k: n / total_true if total_true else 0.0 for k, n in at_k.items()},
            )
        )
    difference = None
    if with_truth:
        sides = [(b, f) for (b, _), (f, _) in zip(pairs["bm25"], pairs["file_order"], strict=True)]

        def gap(draw: Sequence[int]) -> float:
            return recall("bm25", draw) - recall("file_order", draw)

        difference = Difference(
            first="bm25", second="file_order",
            first_keeps_more=sum(a > b for a, b in sides),
            second_keeps_more=sum(a < b for a, b in sides), tied=sum(a == b for a, b in sides),
            recall_difference=gap(everyone),
            ci95=_bootstrap(len(with_truth), gap, SEED) or Interval(low=0.0, high=0.0),
        )  # fmt: skip
    return SplitScore(
        split=split, reports=len(chosen), truncated=len(cut), truncated_with_truth=len(with_truth),
        true_functions=total_true, candidates=sum(len(c.items) for c in cut),
        rankings=tuple(scores), bm25_vs_file_order=difference,
    )  # fmt: skip


class Report(BaseModel):
    model_config = ConfigDict(frozen=True)

    benchmark: str
    split_sha256: str
    prompt_version: str
    tokenizer: str
    budget_tokens: int
    max_candidates: int | None
    splits: tuple[SplitScore, ...]


def score(bundle: Bundle) -> Report:
    return Report(
        benchmark=bundle.benchmark, split_sha256=bundle.split_sha256,
        prompt_version=bundle.prompt_version, tokenizer=bundle.tokenizer,
        budget_tokens=bundle.budget_tokens, max_candidates=bundle.max_candidates,
        splits=tuple(score_split(bundle, s) for s in ("all", "dev", "test")),
    )  # fmt: skip


LABELS = {
    "bm25": "BM25 against the advisory (as built)",
    "file_order": "No ranking: path filter and file order",
    "oracle": "Oracle: true functions first (ceiling)",
}


def _reports(n: int) -> str:
    return f"{n} report" if n == 1 else f"{n} reports"


def _interval(i: Interval | None) -> str:
    return "—" if i is None else f"{i.low:.3f} to {i.high:.3f}"


def render_markdown(report: Report, source: str) -> str:
    r = report
    cap = "none" if r.max_candidates is None else str(r.max_candidates)
    lines = [
        f"# Retrieval at the prompt budget: {r.benchmark}",
        "",
        "Generated by `python -m patchsight.pipeline retrieval-report`; do not edit by hand.",
        "",
        "When a fix's candidate functions do not fit the prompt's token budget, the extractor "
        "keeps them in BM25 order while they fit; a true vulnerable function that is cut "
        "cannot be picked by the model. On the reports whose prompts are cut, this counts the "
        "true vulnerable functions among the candidates that each order keeps, with the "
        "extractor's own token costs (ADR 0003). No model is called.",
        "",
        f"- {source}",
        f"- Split SHA-256 `{r.split_sha256}`; prompt `{r.prompt_version}`; tokenizer "
        f"`{r.tokenizer}`",
        f"- Budget {r.budget_tokens:,} prompt tokens; candidate cap {cap}",
        "- Recall = true functions kept / true functions among the candidates, over cut "
        "reports with at least one; CIs resample reports (2,000 draws). True functions the fix "
        "does not change are outside retrieval's reach and are not counted.",
        "",
    ]
    for s in r.splits:
        lines += [
            f"## {s.split}: {s.truncated} of {s.reports} prompts cut",
            "",
            f"{s.truncated_with_truth} cut reports have a true function among their "
            f"{s.candidates:,} candidates ({s.true_functions:,} true functions).",
            "",
            "| Order | Kept true | Recall (95% CI) | Reports with none kept | Candidates kept | "
            + " | ".join(f"Recall@{k}" for k in TOP_K) + " |",
            "|---|---:|---|---:|---:|" + "---:|" * len(TOP_K),
        ]  # fmt: skip
        for g in s.rankings:
            lines.append(
                f"| {LABELS[g.ranking]} | {g.kept_true} | {g.recall:.3f} "
                f"({_interval(g.recall_ci95)}) | {g.reports_with_none_kept} | "
                f"{g.candidates_kept} | "
                + " | ".join(f"{g.recall_at_k[k]:.3f}" for k in TOP_K) + " |"
            )  # fmt: skip
        if s.bm25_vs_file_order is not None:
            d = s.bm25_vs_file_order
            lines += [
                "",
                f"BM25 minus file order, paired by report: {d.recall_difference:+.3f} "
                f"(95% CI {d.ci95.low:+.3f} to {d.ci95.high:+.3f}). BM25 keeps more true "
                f"functions in {_reports(d.first_keeps_more)}, file order in "
                f"{_reports(d.second_keeps_more)}; they tie in {_reports(d.tied)}.",
            ]
        lines.append("")
    lines += [
        "Recall@k ranks by count of candidates and ignores tokens: how often a true function "
        "is among the first k.",
        "",
    ]
    return "\n".join(lines)
