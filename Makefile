.PHONY: install lint format typecheck test check reproduce

install:
	uv sync --all-extras

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff check --fix .
	uv run ruff format .

typecheck:
	uv run mypy src/

test:
	uv run pytest -m "not live and not slow"

check: lint typecheck test

# Recompute the benchmark tables from committed files: no network, no API key.
reproduce:
	uv run python -m patchsight.pipeline reproduce
