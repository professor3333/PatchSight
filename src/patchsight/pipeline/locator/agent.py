"""The fix-commit locator agent: a bounded loop over four read-only tools (rule 8).

* **Tools:** list the advisory's references, compare two tags, search a repository's
  commits, get a commit. Each reads through the cached GitHub client, whose host is fixed to
  ``api.github.com``; package metadata comes from ``pypi.org``. No tool takes a URL, so no
  other host can be reached.
* **Bounds:** at most ``MAX_STEPS`` actions; only the repositories the package's PyPI
  metadata declares.
* **Actions** are strict-schema JSON, not native tool calls (ADR 0011): one client and
  schema for every provider, no tool outside the list, and every step cached by its request.
* **Verifier:** an answer stands only if the commit exists, sits between the last vulnerable
  and the first fixed tag, and touches non-test Python source. Otherwise it is discarded.
* **State** is the plain list of messages. Responses are cached, so a run replays exactly.

Everything the tools return is untrusted (advisory text, commit messages, code) and goes
back to the model inside ``<observation>`` tags, neutralised so it cannot close them.
"""

import json
import re
from collections.abc import Sequence
from typing import Any, Literal

from packaging.version import Version
from pydantic import BaseModel, ConfigDict, ValidationError

from patchsight.pipeline.diffs.github import GitHubClient
from patchsight.pipeline.diffs.paths import classify_path
from patchsight.pipeline.extract.prompt import PromptTemplate, neutralise
from patchsight.pipeline.extract.schema import _inline
from patchsight.pipeline.http import HttpError, NotFoundError
from patchsight.pipeline.llm.client import LLMClient, LLMRequest, ProviderRejectedError
from patchsight.pipeline.llm.config import ModelConfig
from patchsight.pipeline.locator.baseline import bracket, fixed_versions, tag_version, tags
from patchsight.pipeline.pypi import PyPIClient

SCHEMA_NAME = "patchsight_locator_step"
MAX_STEPS = 8
MAX_COMMITS_SHOWN = 80
MAX_PATCH_LINES = 40
Action = Literal[
    "list_references", "compare_tags", "search_commits", "get_commit", "answer", "abstain"
]
# In the masked evaluation, links and SHAs that would give the answer away are hidden.
_FIX_LINK = re.compile(r"https?://github\.com/[^\s/]+/[^\s/]+/(?:commit|pull|compare)/\S+", re.I)
_SHA = re.compile(r"\b[0-9a-f]{7,40}\b")


class Step(BaseModel):
    """One action the model takes. Unused arguments are null (strict schemas need them)."""

    model_config = ConfigDict(extra="forbid")

    action: Action
    repo: str | None
    base: str | None
    head: str | None
    query: str | None
    sha: str | None
    reason: str


def step_schema() -> dict[str, Any]:
    raw = Step.model_json_schema()
    result: dict[str, Any] = _inline(raw, raw.get("$defs", {}))
    return result


class Task(BaseModel):
    """What the agent is told about one vulnerability."""

    model_config = ConfigDict(frozen=True)

    vulnerability: str
    package: str
    summary: str
    details: str
    references: tuple[tuple[str, str], ...]  # (type, url)
    fixed: tuple[str, ...]
    repos: tuple[str, ...]
    comparisons: tuple[tuple[str, str, str], ...]  # (repo, base tag, head tag)


def mask(text: str) -> str:
    """Advisory text without fix links or commit SHAs, for the masked evaluation."""
    return _SHA.sub("[sha]", _FIX_LINK.sub("[fix link]", text))


def build_task(
    vulnerability: str, advisories: Sequence[Any], package: str, github: GitHubClient,
    pypi: PyPIClient, masked: bool = True,
) -> Task:  # fmt: skip
    """The task, from PyPI metadata, the repositories' tags and the advisories."""
    repos: list[str] = []
    for repo in pypi.declared_github_repos(package) or ():
        try:
            repos.append(github.canonical_repo(repo))
        except NotFoundError:
            continue
    fixed = sorted({v for a in advisories for v in fixed_versions(a, package)}, reverse=True)
    comparisons: list[tuple[str, str, str]] = []
    for repo in sorted(set(repos)):
        try:
            by_version: dict[Version, str] = {}
            for name in tags(github, repo):
                if (version := tag_version(name, package)) is not None:
                    by_version.setdefault(version, name)
        except (NotFoundError, HttpError):
            continue
        for version in fixed:
            if (pair := bracket(by_version, version)) is not None:
                comparisons.append((repo, *pair))
    references: list[tuple[str, str]] = []
    for advisory in advisories:
        for ref in advisory.references:
            hidden = masked and (ref.type == "FIX" or _FIX_LINK.search(ref.url))
            if not hidden and (ref.type, ref.url) not in references:
                references.append((ref.type, ref.url))
    text = "\n\n".join(f"{a.summary}\n{a.details}".strip() for a in advisories)
    summary = advisories[0].summary if advisories else ""
    return Task(
        vulnerability=vulnerability, package=package,
        summary=mask(summary) if masked else summary,
        details=mask(text) if masked else text,
        references=tuple(references[:30]), fixed=tuple(str(v) for v in fixed),
        repos=tuple(sorted(set(repos))), comparisons=tuple(comparisons),
    )  # fmt: skip


def _first_line(message: str) -> str:
    return message.strip().splitlines()[0][:120] if message.strip() else ""


class Tools:
    """The four read-only tools, and the verifier."""

    def __init__(self, task: Task, github: GitHubClient) -> None:
        self.task = task
        self.github = github
        self.calls = 0

    def _allowed(self, repo: str | None) -> str:
        if not repo or repo.lower() not in self.task.repos:
            raise PermissionError(f"repository {repo!r} is not one of {list(self.task.repos)}")
        return repo.lower()

    def run(self, step: Step) -> str:
        self.calls += 1
        try:
            if step.action == "list_references":
                rows = [f"{kind}: {url}" for kind, url in self.task.references]
                return "\n".join(rows) or "(no references)"
            if step.action == "compare_tags":
                return self.compare(self._allowed(step.repo), step.base or "", step.head or "")
            if step.action == "search_commits":
                return self.search(self._allowed(step.repo), step.query or "")
            if step.action == "get_commit":
                return self.commit(self._allowed(step.repo), step.sha or "")
        except PermissionError as refused:
            return f"error: {refused}"
        except NotFoundError:
            return "error: not found"
        except HttpError as error:
            return f"error: {error}"[:300]
        return f"error: {step.action} is not a tool"

    def compare(self, repo: str, base: str, head: str) -> str:
        data = self.github.http.get_json(f"/repos/{repo}/compare/{base}...{head}")
        commits = data.get("commits") or []
        rows = [
            f"{c['sha']} {(c['commit'].get('author') or {}).get('date', '')[:10]} "
            f"{_first_line(str(c['commit']['message']))}"
            for c in commits[:MAX_COMMITS_SHOWN]
        ]
        more = len(commits) - MAX_COMMITS_SHOWN
        return "\n".join(rows) + (f"\n({more} more not shown)" if more > 0 else "") or "(none)"

    def search(self, repo: str, query: str) -> str:
        data = self.github.http.get_json(
            "/search/commits", {"q": f"repo:{repo} {query}", "per_page": 10}
        )
        rows = [f"{i['sha']} {_first_line(str(i['commit']['message']))}" for i in data["items"]]
        return "\n".join(rows) or "(no matches)"

    def commit(self, repo: str, sha: str) -> str:
        data = self.github.http.get_json(f"/repos/{repo}/commits/{sha}")
        message = "\n".join(str(data["commit"]["message"]).strip().splitlines()[:8])
        files = data.get("files") or []
        listing = [
            f"{f['status']} {f['filename']} +{f.get('additions', 0)} -{f.get('deletions', 0)}"
            for f in files[:40]
        ]
        patch: list[str] = []
        for f in files:
            if classify_path(f["filename"]) == "python" and f.get("patch"):
                patch += [f"--- {f['filename']}", *str(f["patch"]).splitlines()]
            if len(patch) >= MAX_PATCH_LINES:
                break
        return "\n".join([
            f"commit {data['sha']}", message, "", "files:", *listing, "",
            "python changes (start):", *patch[:MAX_PATCH_LINES],
        ])  # fmt: skip

    def verify(self, repo: str | None, sha: str | None) -> tuple[str | None, str]:
        """(the full SHA, "verified"), or (None, why it is discarded)."""
        try:
            name = self._allowed(repo)
        except PermissionError:
            return None, "discarded: not one of the package's repositories"
        if not sha or not re.fullmatch(r"[0-9a-f]{7,40}", sha.lower()):
            return None, "discarded: not a commit SHA"
        try:
            change = self.github.commit(name, sha.lower())
        except (NotFoundError, HttpError):
            return None, "discarded: the commit does not exist"
        full = change.commits[0]
        between = False
        for compared_repo, base, head in self.task.comparisons:
            if compared_repo != name:
                continue
            data = self.github.http.get_json(f"/repos/{name}/compare/{base}...{head}")
            if any(str(c["sha"]) == full for c in data.get("commits") or []):
                between = True
                break
        if not between:
            return None, "discarded: not between the last vulnerable and the first fixed release"
        if not any(classify_path(f.filename) == "python" for f in change.files):
            return None, "discarded: touches no non-test Python source"
        return full, "verified"


class AgentRun(BaseModel):
    model_config = ConfigDict(frozen=True)

    vulnerability: str
    outcome: str  # found, discarded, abstained, step cap, invalid, error
    commit: str | None
    reason: str
    steps: int
    tool_calls: int
    actions: tuple[str, ...]
    prompt_tokens: int
    completion_tokens: int
    calls: int
    cached_calls: int


def render_task(template: PromptTemplate, task: Task, steps: int) -> str:
    comparisons = "\n".join(f"- `{r}`: `{b}` ... `{h}`" for r, b, h in task.comparisons)
    fields = {
        "advisory_id": task.vulnerability,
        "advisory": neutralise(f"{task.summary}\n\n{task.details}".strip()),
        "package": task.package,
        "repositories": ", ".join(f"`{r}`" for r in task.repos) or "none found",
        "fixed": ", ".join(task.fixed) or "unknown",
        "comparisons": comparisons or "- none: no tags match the fixed versions",
        "steps": str(steps),
    }
    text = template.user
    for key, value in fields.items():
        text = text.replace("{{" + key + "}}", value)
    return text


def locate(
    task: Task, llm: LLMClient, model: ModelConfig, template: PromptTemplate,
    github: GitHubClient, max_steps: int = MAX_STEPS,
) -> tuple[AgentRun, list[dict[str, str]]]:  # fmt: skip
    """Run the agent on one task: the result, and the full message list."""
    tools = Tools(task, github)
    messages: list[dict[str, str]] = [
        {"role": "system", "content": template.system},
        {"role": "user", "content": render_task(template, task, max_steps)},
    ]
    actions: list[str] = []
    usage = {"prompt": 0, "completion": 0, "calls": 0, "cached": 0}

    def finish(outcome: str, reason: str, commit: str | None = None) -> AgentRun:
        return AgentRun(
            vulnerability=task.vulnerability, outcome=outcome, commit=commit, reason=reason,
            steps=len(actions), tool_calls=tools.calls, actions=tuple(actions),
            prompt_tokens=usage["prompt"], completion_tokens=usage["completion"],
            calls=usage["calls"], cached_calls=usage["cached"],
        )  # fmt: skip

    for number in range(1, max_steps + 1):
        request = LLMRequest(
            model=model.model, prompt_version=template.version, messages=tuple(messages),
            schema_name=SCHEMA_NAME, response_schema=step_schema(),
            max_tokens=model.max_output_tokens, seed=model.seed, extra=model.extra,
        )  # fmt: skip
        try:
            response = llm.complete(request)
        except ProviderRejectedError as rejected:
            return finish(
                "error", f"the provider rejected step {number}: {rejected}"[:200]
            ), messages
        usage["calls"] += 1
        usage["cached"] += response.cached
        usage["prompt"] += response.prompt_tokens
        usage["completion"] += response.completion_tokens
        messages.append({"role": "assistant", "content": response.content})
        try:
            step = Step.model_validate(json.loads(response.content))
        except (ValueError, ValidationError):
            actions.append("invalid")
            observation = "error: the answer was not a valid action; answer with the schema"
        else:
            actions.append(step.action)
            if step.action == "answer":
                commit, why = tools.verify(step.repo, step.sha)
                return finish("found" if commit else "discarded", why, commit), messages
            if step.action == "abstain":
                return finish("abstained", step.reason[:200]), messages
            observation = tools.run(step)
        left = max_steps - number
        messages.append({
            "role": "user",
            "content": f"<observation>\n{neutralise(observation)}\n</observation>\n"
            f"Steps left: {left}." + (" Answer or abstain now." if left == 1 else ""),
        })  # fmt: skip
    return finish("step cap", f"no answer within {max_steps} steps"), messages
