"""The contract between the LLM and the database: what the model must return."""

from typing import Any

from pydantic import BaseModel, ConfigDict

SCHEMA_NAME = "patchsight_extraction"


class ItemJudgement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_id: str
    is_vulnerable: bool
    rationale: str
    evidence_hunk_ids: list[str]


class Extraction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ItemJudgement]
    public_entry_points: list[str]


def _inline(node: Any, definitions: dict[str, Any]) -> Any:
    if isinstance(node, dict):
        if "$ref" in node:
            return _inline(definitions[node["$ref"].rsplit("/", 1)[-1]], definitions)
        return {k: _inline(v, definitions) for k, v in node.items() if k not in ("$defs", "title")}
    if isinstance(node, list):
        return [_inline(item, definitions) for item in node]
    return node


def response_schema() -> dict[str, Any]:
    """The JSON schema sent to the provider, with references inlined for strict mode."""
    raw = Extraction.model_json_schema()
    result: dict[str, Any] = _inline(raw, raw.get("$defs", {}))
    return result
