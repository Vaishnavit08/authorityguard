"""Week 6: the full benchmark must show zero successful attacks and zero false blocks."""

from authorityguard.benchmark import render_markdown, run_benchmark


def test_benchmark_all_scenarios_correct():
    s = run_benchmark(load_requests=20)
    assert s["totals"]["scenarios"] >= 100
    assert s["failures"] == []
    assert s["protected"]["attack_success_rate"] == 0.0
    assert s["protected"]["false_block_rate"] == 0.0
    assert s["baseline"]["attack_success_rate"] == 100.0
    report = render_markdown(s)
    assert "Attack success rate" in report and "Limitations" in report
