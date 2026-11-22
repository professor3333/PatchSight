# ADR 0011: The fix-commit locator agent, and why its tools are JSON actions

- **Status:** accepted
- **Date:** 2026-11-19

## Context

2,306 PyPI vulnerabilities link no fix commit on GitHub, so their alerts get no symbol data. The proposal's answer is a bounded agent (rule 8). The masked evaluation of [E7](../experiments.md#e7-locating-a-fix-commit-the-advisory-does-not-link) showed that deterministic heuristics are far from its targets:

| Variant | Exact commit | Wrong commit |
|---|---:|---:|
| The best heuristic | 25.0% | 47.0% |
| Target | 70% or more | 5% or less |

Of the heuristic's wrong commits, 64 of 94 were wrong choices within a correct release comparison, and 30 needed a wider search. So the agent needs to choose better, by reading candidate diffs, and to search further, through commit search.

The proposal describes the agent as "our own code over native tool calling".

## Decision

`pipeline/locator/agent.py`: a loop of at most **8 steps** over four read-only tools.

- **The tools:**
  - **list references:** the advisory's references, with fix links hidden in the masked evaluation;
  - **compare two tags:** commits between two releases, with the first line of each message;
  - **search commits:** GitHub commit search within one repository;
  - **get a commit:** its message, its files, and the start of its Python changes.

  The task also states the package's repositories, its fixed versions, and the release comparisons computed from its tags.
- **Bounds (rule 8):**
  - **Hosts.** Every tool reads through the cached GitHub client, whose host is fixed to `api.github.com`; package metadata comes from `pypi.org`. No action takes a URL.
  - **Repositories.** Only those the package's PyPI metadata declares; any other is refused.
  - **Steps.** At most 8; then the run ends as *step cap*.
- **The verifier.** An answer stands only if the commit exists, sits between the last vulnerable and the first fixed tag, and touches non-test Python source. Otherwise it is *discarded*, which counts like an abstention, never as a found commit.
- **Untrusted text.** Advisory text, commit messages and code reach the model inside `<observation>` tags, neutralised so they cannot close them. The prompt (`prompts/locate_v1.md`, version `locate-v1`) says to treat them as data.
- **Actions are strict-schema JSON, not native tool calls.** At each step the model returns one object: the action, its arguments (null when unused), and a one-sentence reason. Three reasons:
  - **One path for every provider.** The extractor's client, limiter and strict-schema output already work on Groq and on llama.cpp (grammar-constrained). Native tool-call formats differ between them, and between models' chat templates.
  - **The grammar is the tool list.** The model cannot call a tool, or pass a field, that is not offered.
  - **Replay comes free.** Every step is a cached request over the plain message list, so a run replays exactly, which rule 8 asks for. A Kaggle run ships the GitHub answers it fetched, so a local replay sees the same data.

## Evaluation

The agent is scored on the frozen masked sample of E7 (`locator-agent-eval`), by the same harness as the heuristics, with the same targets: exact-commit accuracy of 70% or more and a wrong-commit rate of 5% or less. Its evaluation runs on Kaggle (`MODE = "locator"`), because 200 vulnerabilities of up to 8 steps exceed Groq's free daily quota.

It builds no records until it meets both targets. A wrong commit becomes a record of the wrong functions, and abstaining only costs coverage.

## Consequences

- **The proposal's "native tool calling" is not used.** The loop is still our own code with four tools and a step cap.
- **Commit search has its own rate limit** on GitHub (30 requests a minute). The client waits it out.
- **The Kaggle evaluation fits a session or resumes.** The notebook gives `locator-agent-eval` the session's remaining time (`--max-minutes`); no case starts after it, the results are always packaged, and a run that did not finish writes no report. Adding its zip as input to a second session replays the finished cases from the cache and continues.
- **The prompt is versioned and cached like the extractor's.** Changing it, or the tools' output format, misses the cache and is a new evaluated run.

## The first Kaggle run, 2026-11-22: not a result

The first evaluation on Kaggle (PatchSight `ccbf47a`) ran all 200 vulnerabilities, but GitHub refused the notebook's token: every tool call, and every tag listing behind the release comparisons, answered HTTP 401. The agent saw no repository and abstained on all 200. The run measures nothing about the agent, so it is not reported as a result; the evaluation is run again with a valid token.

The pipeline let it run for hours because a 401 was handled like any other HTTP error: the tools turned it into an observation for the model. Now a refused token is an error of its own (`AuthError`) that the tools let through, `locator-agent-eval` asks GitHub whether it accepts the token before the first case, and the notebook does the same at setup for every mode that reads GitHub.
