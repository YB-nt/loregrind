"""예산 상한이 코드에서 강제되는지 고정한다 (불변식 8).

프롬프트에 "아껴 써라"라고 쓰는 것은 게이트가 아니다. 여기서 검사하는 것은
**초과가 실제로 멈추는가**이다.
"""

from __future__ import annotations

import pytest

from loregrind.analyze.budget import Budget, BudgetExceeded, BudgetTracker


def test_cost_ceiling_stops_the_run() -> None:
    tracker = BudgetTracker(budget=Budget(max_cost_usd_per_run=0.10))
    tracker.begin_function()
    tracker.charge_llm(1000, 500, 0.06)
    with pytest.raises(BudgetExceeded, match="max_cost_usd_per_run"):
        tracker.charge_llm(1000, 500, 0.06)
    # 초과분도 누적에 남는다 — 계측이 지워지면 §6 비용 지표가 틀린다
    assert tracker.cost_usd == pytest.approx(0.12)


def test_token_ceiling_is_per_function_not_per_run() -> None:
    """함수별 카운터가 초기화되지 않으면 두 번째 함수가 첫 번째를 물려받는다."""
    tracker = BudgetTracker(budget=Budget(max_tokens_per_function=1000))
    tracker.begin_function()
    tracker.charge_llm(600, 300, 0.0)
    tracker.end_function()

    tracker.begin_function()
    tracker.charge_llm(600, 300, 0.0)  # 물려받았다면 여기서 터진다
    assert tracker.total_tokens == 1800


def test_tool_calls_are_counted_separately_from_tokens() -> None:
    """토큰만 세면 싼 도구를 무한히 부르는 탐색이 빠져나간다."""
    tracker = BudgetTracker(budget=Budget(max_tool_calls_per_function=3))
    tracker.begin_function()
    for _ in range(3):
        tracker.charge_tool_call()
    with pytest.raises(BudgetExceeded, match="max_tool_calls_per_function"):
        tracker.charge_tool_call()


def test_function_ceiling_checked_before_work_starts() -> None:
    tracker = BudgetTracker(budget=Budget(max_functions_per_run=2))
    for _ in range(2):
        tracker.begin_function()
        tracker.end_function()
    with pytest.raises(BudgetExceeded, match="max_functions_per_run"):
        tracker.begin_function()


def test_budget_is_serialisable_into_run_config() -> None:
    """계측되지 않은 상한은 상한이 아니다 — 어블레이션 축이 되려면 config 에 있어야 한다."""
    config = Budget().as_config()
    assert set(config) == {
        "max_tokens_per_function",
        "max_tool_calls_per_function",
        "max_cost_usd_per_run",
        "max_functions_per_run",
    }


def test_snapshot_carries_cost_for_finish_run() -> None:
    tracker = BudgetTracker()
    tracker.begin_function()
    tracker.charge_llm(100, 50, 0.01)
    tracker.end_function()
    snap = tracker.snapshot()
    assert snap["tokens_in"] == 100
    assert snap["tokens_out"] == 50
    assert snap["cost_usd"] == pytest.approx(0.01)
    assert snap["functions_done"] == 1
