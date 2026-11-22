"""Cost against quality on the Dunlap dev split, and the proposal's selection rule."""

from pathlib import Path

from patchsight.pipeline.benchmarks import cost_quality

REPO = Path(__file__).resolve().parents[1]


def test_the_rule_takes_the_cheapest_within_two_points_of_the_best() -> None:
    def point(label: str, f1: float, tokens: float) -> cost_quality.Point:
        return cost_quality.Point(label=label, tag=label, model="m", f1=f1, precision=0.0,
                                  recall=0.0, prompt_tokens=tokens, completion_tokens=0.0,
                                  usd_per_1000=None)  # fmt: skip

    points = [point("best", 0.680, 2000), point("close, cheaper", 0.665, 1500),
              point("far, cheapest", 0.600, 900)]  # fmt: skip
    best = max(points, key=lambda p: p.f1)
    close = [p for p in points if p.f1 >= best.f1 - cost_quality.WITHIN]
    assert min(close, key=lambda p: (p.tokens, p.label)).label == "close, cheaper"


def test_the_committed_report_and_chart_regenerate_exactly(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from patchsight.pipeline.__main__ import app

    reports = tmp_path / "docs" / "reports"
    reports.mkdir(parents=True)
    for _, tag in cost_quality.CONFIGURATIONS:
        name = f"extraction-dunlap-dev-{tag}.json"
        (reports / name).symlink_to(REPO / "docs" / "reports" / name)
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs" / "pricing.toml").symlink_to(REPO / "configs" / "pricing.toml")
    result = CliRunner().invoke(app, ["cost-quality", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "chosen: Qwen3.8-27B 4-bit, Kaggle" in result.output
    for suffix in (".md", ".json", ".svg"):
        name = f"cost-quality-dunlap-dev{suffix}"
        assert (reports / name).read_text() == (REPO / "docs" / "reports" / name).read_text()
