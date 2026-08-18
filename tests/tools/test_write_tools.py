"""쓰기 도구와 전략 축 (§7 3주차).

**`allow_writes` 는 §6 어블레이션 1축의 조작 지점이다.** 꺼진 상태에서 쓰기가
새어 나가면 "쓰기 없음" 조건이 실제로는 쓰기 있음이 되고, 두 조건의 차이를 잰
숫자가 무의미해진다. 여기서 고정하는 것이 그것이다.
"""

from __future__ import annotations

import pytest

from loregrind.db.models import Binary, CallEdge, Function
from loregrind.db.repo import Repo
from loregrind.tools import api
from loregrind.tools.api import ToolContext
from loregrind.tools.protocol import ErrorCode

SHA = "2" * 64


def _ctx(*, allow_writes: bool, seed: int | None = None) -> ToolContext:
    repo = Repo.open(":memory:")
    binary_id = repo.insert_binary(
        Binary(
            sha256=SHA,
            arch="x86:LE:32:default",
            extract_schema_version=2,
            function_count=2,
            analyzed_at="2026-08-18T00:00:00Z",
        )
    )
    repo.insert_functions(
        [
            Function(binary_id=binary_id, addr="0x401000", original_name="FUN_00401000"),
            Function(binary_id=binary_id, addr="0x401100", original_name="FUN_00401100"),
        ]
    )
    repo.insert_call_edges(
        [CallEdge(binary_id=binary_id, caller_addr="0x401000", callee_addr="0x401100")]
    )
    run = repo.create_run("m", "v1", {"rename_writes": allow_writes}, seed=seed)
    return ToolContext(
        repo=repo,
        binary_id=binary_id,
        extract_schema_version=2,
        run_id=run.run_id,
        allow_writes=allow_writes,
    )


# -- 어블레이션 1축 -----------------------------------------------------------


def test_all_write_tools_refuse_when_writes_disabled() -> None:
    ctx = _ctx(allow_writes=False)
    calls = (
        lambda: api.record_analysis(ctx, "0x401000", "n", "s"),
        lambda: api.record_hypothesis(ctx, "가설"),
        lambda: api.rename_function(ctx, "0x401000", "decrypt"),
        lambda: api.set_comment(ctx, "0x401000", "주석"),
    )
    for call in calls:
        response = call()
        assert response["ok"] is False
        assert response["error"]["code"] == ErrorCode.WRITE_DISABLED
    # 판단이 하나도 안 들어갔다
    assert ctx.repo.readonly_query("SELECT COUNT(*) AS n FROM function_analyses")[0]["n"] == 0


def test_writes_land_in_db_when_enabled() -> None:
    ctx = _ctx(allow_writes=True)
    response = api.record_analysis(
        ctx,
        "0x401000",
        "decrypt_config",
        "설정을 복호화한다",
        [{"kind": "api", "ref": "CryptDecrypt"}],
        0.8,
    )
    assert response["ok"] is True
    assert response["provenance"]["source"] == "agent"

    func = ctx.repo.get_function(ctx.binary_id, "0x401000")
    stored = ctx.repo.current_analysis(func.id)  # type: ignore[arg-type,union-attr]
    assert stored is not None
    assert stored.proposed_name == "decrypt_config"
    assert stored.run_id == ctx.run_id  # 불변식 5


def test_agent_cannot_raise_its_own_trust_level() -> None:
    """`source='agent'` 고정 — human/emulation 은 에이전트가 쓸 수 없다."""
    ctx = _ctx(allow_writes=True)
    api.record_analysis(ctx, "0x401000", "n", "s")
    rows = ctx.repo.readonly_query("SELECT DISTINCT source FROM function_analyses")
    assert [r["source"] for r in rows] == ["agent"]


def test_rename_writes_db_only_not_ghidra() -> None:
    """불변식 2 — Ghidra 반영은 L5 의 단방향 배치다."""
    ctx = _ctx(allow_writes=True)
    response = api.rename_function(ctx, "0x401000", "install_persistence")
    assert response["data"]["applied_to_ghidra"] is False


def test_rename_rejects_non_identifier_names() -> None:
    """Ghidra apply(L5)에서 깨지기 전에 여기서 막는다."""
    ctx = _ctx(allow_writes=True)
    for bad in ("2bad", "has space", "hyphen-name", "", "x" * 200):
        assert api.rename_function(ctx, "0x401000", bad)["ok"] is False


def test_rename_propagates_to_neighbour_context() -> None:
    """리네임이 이후 컨텍스트에 전파된다 — 이것이 어블레이션 1축이 재는 효과다."""
    ctx = _ctx(allow_writes=True)
    api.rename_function(ctx, "0x401100", "write_payload")
    callees = api.get_callees(ctx, "0x401000")["data"]["callees"]
    assert callees[0]["current_name"] == "write_payload"


def test_hypothesis_starts_open_only() -> None:
    """에이전트가 자기 가설을 확정하면 검증 루프가 자기 확인으로 무너진다."""
    ctx = _ctx(allow_writes=True)
    response = api.record_hypothesis(ctx, "RC4 로 보인다", addr="0x401000", experiment="키 복원")
    assert response["data"]["status"] == "open"
    rows = ctx.repo.readonly_query("SELECT status FROM hypotheses")
    assert [r["status"] for r in rows] == ["open"]


def test_write_tools_are_listed_separately() -> None:
    """읽기/쓰기 목록이 갈라져 있어야 어블레이션 조건을 구성할 수 있다."""
    read_names = {fn.__name__ for fn in api.READ_TOOLS}
    write_names = {fn.__name__ for fn in api.WRITE_TOOLS}
    assert write_names == {"record_analysis", "record_hypothesis", "rename_function", "set_comment"}
    assert not (read_names & write_names)


# -- 어블레이션 2축 (전략) ----------------------------------------------------


def test_rank_strategy_refuses_without_scores() -> None:
    """없는 랭킹을 순차로 대신하면 기준선이 오염된다."""
    ctx = _ctx(allow_writes=False)
    response = api.list_candidates(ctx, strategy="rank")
    assert response["ok"] is False
    assert response["error"]["code"] == ErrorCode.NOT_EXTRACTED


def test_random_strategy_requires_a_seed() -> None:
    """시드 없는 무작위와 비교한 개선폭은 숫자가 아니다."""
    ctx = _ctx(allow_writes=False, seed=None)
    assert api.list_candidates(ctx, strategy="random")["ok"] is False

    seeded = _ctx(allow_writes=False, seed=42)
    assert api.list_candidates(seeded, strategy="random")["ok"] is True


def test_random_strategy_is_reproducible_from_the_seed() -> None:
    first = api.list_candidates(_ctx(allow_writes=False, seed=7), strategy="random")
    second = api.list_candidates(_ctx(allow_writes=False, seed=7), strategy="random")
    assert [c["addr"] for c in first["data"]["candidates"]] == [
        c["addr"] for c in second["data"]["candidates"]
    ]


def test_all_strategies_share_one_response_shape() -> None:
    """전략마다 shape 이 다르면 비교 대상이 '전략 + 소비 코드'가 된다."""
    ctx = _ctx(allow_writes=False, seed=1)
    for strategy in ("sequential", "random"):
        data = api.list_candidates(ctx, strategy=strategy)["data"]
        assert set(data) == {"candidates", "next_cursor", "strategy"}
        assert set(data["candidates"][0]) == {"addr", "original_name", "score", "reasons"}


def test_unknown_strategy_is_rejected() -> None:
    ctx = _ctx(allow_writes=False)
    response = api.list_candidates(ctx, strategy="vibes")
    assert response["ok"] is False
    assert "vibes" in response["error"]["message"]


def test_write_tools_still_charge_budget() -> None:
    """쓰기 도구도 예산을 지난다 (불변식 8)."""
    from loregrind.analyze.budget import Budget, BudgetTracker

    ctx = _ctx(allow_writes=True)
    ctx.budget = BudgetTracker(budget=Budget(max_tool_calls_per_function=1))
    ctx.budget.begin_function()
    assert api.record_analysis(ctx, "0x401000", "a", "b")["ok"] is True
    denied = api.record_analysis(ctx, "0x401000", "c", "d")
    assert denied["error"]["code"] == ErrorCode.BUDGET_EXCEEDED


@pytest.mark.parametrize("tool", ["record_analysis", "rename_function", "set_comment"])
def test_write_tools_reject_missing_functions(tool: str) -> None:
    ctx = _ctx(allow_writes=True)
    fn = getattr(api, tool)
    args = ("0x409999", "name") if tool != "record_analysis" else ("0x409999", "n", "s")
    assert fn(ctx, *args)["ok"] is False
