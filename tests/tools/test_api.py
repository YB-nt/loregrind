"""L2 도구 계약 (docs/SPEC.md §4).

전송 계층(MCP SDK)을 띄우지 않고 계약을 고정한다. 여기서 검사하는 것은
"도구가 동작하는가"가 아니라 **"약속한 형태로 실패하는가"**다 — 성공 경로보다
실패 경로가 에이전트 행동을 더 많이 결정한다.
"""

from __future__ import annotations

import pytest

from loregrind.analyze.budget import Budget, BudgetTracker
from loregrind.db.models import (
    ApiCall,
    Binary,
    CallEdge,
    Function,
    FunctionAnalysis,
    Import,
    StringLiteral,
    StringXref,
)
from loregrind.db.repo import Repo
from loregrind.tools import api
from loregrind.tools.api import ToolContext
from loregrind.tools.protocol import ErrorCode

SHA = "e" * 64


def _seed(repo: Repo, *, schema_version: int = 2) -> int:
    binary_id = repo.insert_binary(
        Binary(
            sha256=SHA,
            arch="x86:LE:32:default",
            extract_schema_version=schema_version,
            function_count=2,
            analyzed_at="2026-08-18T00:00:00Z",
            family_label="suspected-dropper",
        )
    )
    repo.insert_functions(
        [
            Function(
                binary_id=binary_id,
                addr="0x401000",
                original_name="FUN_00401000",
                signature="void FUN_00401000(void)",
                decompiled="void FUN_00401000(void) { FUN_00401230(); }",
                code_hash="hash-a",
                size=64,
                cyclomatic=3,
            ),
            Function(
                binary_id=binary_id,
                addr="0x401230",
                original_name="FUN_00401230",
                decompiled=None,
                decompile_error="decompile did not complete",
            ),
        ]
    )
    repo.insert_call_edges(
        [CallEdge(binary_id=binary_id, caller_addr="0x401000", callee_addr="0x401230")]
    )
    if schema_version >= 2:
        repo.insert_strings(
            [
                StringLiteral(
                    binary_id=binary_id,
                    addr="0x403000",
                    value="CurrentVersion\\Run",
                    encoding="ascii",
                    length=18,
                )
            ]
        )
        repo.insert_string_xrefs(
            [StringXref(binary_id=binary_id, function_addr="0x401000", string_addr="0x403000")]
        )
        index = repo.insert_imports(
            [Import(binary_id=binary_id, module="kernel32.dll", api_name="VirtualAlloc")]
        )
        repo.insert_api_calls(
            [
                ApiCall(
                    binary_id=binary_id,
                    function_addr="0x401000",
                    import_id=index[("kernel32.dll", "VirtualAlloc")],
                    call_addr="0x401010",
                )
            ]
        )
    return binary_id


@pytest.fixture
def ctx() -> ToolContext:
    repo = Repo.open(":memory:")
    binary_id = _seed(repo)
    return ToolContext(repo=repo, binary_id=binary_id, extract_schema_version=2)


@pytest.fixture
def ctx_v1() -> ToolContext:
    repo = Repo.open(":memory:")
    binary_id = _seed(repo, schema_version=1)
    return ToolContext(repo=repo, binary_id=binary_id, extract_schema_version=1)


# -- 공통 응답 형식 ----------------------------------------------------------


def test_every_success_carries_provenance(ctx: ToolContext) -> None:
    """사실인지 판단인지 구별할 수 없으면 이전 run 의 추측이 사실처럼 읽힌다."""
    for response in (
        api.get_function(ctx, "0x401000"),
        api.get_callees(ctx, "0x401000"),
        api.get_apis_used(ctx, "0x401000"),
        api.search_strings(ctx, "Current"),
        api.list_candidates(ctx),
    ):
        assert response["ok"] is True
        assert response["provenance"]["source"] == "extraction"
        assert "truncated" in response["provenance"]


def test_tools_return_errors_instead_of_raising(ctx: ToolContext) -> None:
    """예외는 전송 계층 오류가 되어 '고장'과 '없음'이 구별되지 않는다."""
    response = api.get_function(ctx, "0x409999")
    assert response["ok"] is False
    assert response["error"]["code"] == ErrorCode.NOT_FOUND


def test_invalid_address_format_is_rejected(ctx: ToolContext) -> None:
    """대문자 16진을 조용히 고치지 않는다 — 표기가 갈리면 캐시가 갈린다."""
    for bad in ("401000", "0X401000", "0x401ZZZ", ""):
        response = api.get_function(ctx, bad)
        assert response["ok"] is False
        assert response["error"]["code"] == ErrorCode.INVALID_ADDR


# -- 개별 도구 ---------------------------------------------------------------


def test_get_function_truncates_loudly(ctx: ToolContext) -> None:
    response = api.get_function(ctx, "0x401000", max_chars=10)
    assert response["provenance"]["truncated"] is True
    assert len(response["data"]["decompiled"]) == 10


def test_get_function_keeps_failed_decompile_visible(ctx: ToolContext) -> None:
    data = api.get_function(ctx, "0x401230")["data"]
    assert data["decompiled"] is None
    assert data["decompile_error"] == "decompile did not complete"


def test_callers_and_callees_include_current_names(ctx: ToolContext) -> None:
    run_id = ctx.repo.create_run("m", "v1", {}).run_id
    callee = ctx.repo.get_function(ctx.binary_id, "0x401230")
    assert callee is not None and callee.id is not None
    ctx.repo.insert_analysis(
        FunctionAnalysis(
            run_id=run_id, function_id=callee.id, source="agent", proposed_name="write_config"
        )
    )
    callees = api.get_callees(ctx, "0x401000")["data"]["callees"]
    assert callees == [
        {"addr": "0x401230", "original_name": "FUN_00401230", "current_name": "write_config"}
    ]
    assert api.get_callers(ctx, "0x401230")["data"]["callers"][0]["addr"] == "0x401000"


def test_search_strings_rejects_empty_query(ctx: ToolContext) -> None:
    response = api.search_strings(ctx, "")
    assert response["ok"] is False
    assert response["error"]["code"] == ErrorCode.TOO_MANY


def test_limit_ceiling_is_enforced(ctx: ToolContext) -> None:
    for response in (
        api.search_strings(ctx, "a", limit=10_000),
        api.get_callers(ctx, "0x401000", limit=0),
        api.list_candidates(ctx, limit=10_000),
    ):
        assert response["ok"] is False
        assert response["error"]["code"] == ErrorCode.TOO_MANY


def test_known_analysis_marks_stale_judgements(ctx: ToolContext) -> None:
    """판단 시점의 code_hash 가 현재와 다르면 그 판단은 낡았다."""
    run_id = ctx.repo.create_run("m", "v1", {}).run_id
    func = ctx.repo.get_function(ctx.binary_id, "0x401000")
    assert func is not None and func.id is not None
    ctx.repo.insert_analysis(
        FunctionAnalysis(
            run_id=run_id,
            function_id=func.id,
            source="agent",
            proposed_name="alloc_buffer",
            code_hash="hash-OLD",
        )
    )
    response = api.get_known_analysis(ctx, "0x401000")
    assert response["data"]["analysis"]["stale"] is True
    # 판단을 돌려줄 때는 provenance 가 extraction 이 아니다
    assert response["provenance"]["source"] == "agent"
    assert response["provenance"]["run_id"] == run_id


def test_known_analysis_absent_is_not_an_error(ctx: ToolContext) -> None:
    response = api.get_known_analysis(ctx, "0x401000")
    assert response["ok"] is True
    assert response["data"]["analysis"] is None


def test_list_candidates_paginates_deterministically(ctx: ToolContext) -> None:
    first = api.list_candidates(ctx, limit=1)["data"]
    assert [c["addr"] for c in first["candidates"]] == ["0x401000"]
    assert first["next_cursor"] == "0x401000"
    second = api.list_candidates(ctx, limit=1, cursor=first["next_cursor"])["data"]
    assert [c["addr"] for c in second["candidates"]] == ["0x401230"]
    assert second["next_cursor"] is None


def test_rank_strategy_is_refused_until_l3_exists(ctx: ToolContext) -> None:
    """없는 랭킹을 순차 순서로 대신하면 어블레이션 2축 기준선이 오염된다."""
    response = api.list_candidates(ctx, strategy="rank")
    assert response["ok"] is False
    assert response["error"]["code"] == ErrorCode.NOT_EXTRACTED


def test_sequential_strategy_reports_no_score(ctx: ToolContext) -> None:
    """0.0 을 넣으면 점수가 있는 척이 된다."""
    candidates = api.list_candidates(ctx)["data"]["candidates"]
    assert all(c["score"] is None for c in candidates)


# -- 추출되지 않음 vs 비어 있음 ----------------------------------------------


def test_v1_binary_reports_not_extracted_not_empty(ctx_v1: ToolContext) -> None:
    """빈 배열을 주면 에이전트가 '문자열이 없는 바이너리'로 오독한다."""
    for response in (api.search_strings(ctx_v1, "Current"), api.get_apis_used(ctx_v1, "0x401000")):
        assert response["ok"] is False
        assert response["error"]["code"] == ErrorCode.NOT_EXTRACTED
        assert "재추출" in response["error"]["message"]

    # 함수 조회는 v1 에서도 동작한다 — 사실이 있는 범위는 계속 쓸 수 있다
    assert api.get_function(ctx_v1, "0x401000")["ok"] is True


# -- 예산 (불변식 8) ---------------------------------------------------------


def test_budget_stops_tools_not_the_prompt(ctx: ToolContext) -> None:
    ctx.budget = BudgetTracker(budget=Budget(max_tool_calls_per_function=2))
    ctx.budget.begin_function()
    assert api.get_function(ctx, "0x401000")["ok"] is True
    assert api.get_function(ctx, "0x401000")["ok"] is True
    response = api.get_function(ctx, "0x401000")
    assert response["ok"] is False
    assert response["error"]["code"] == ErrorCode.BUDGET_EXCEEDED


def test_budget_error_precedes_argument_validation(ctx: ToolContext) -> None:
    """예산이 다 떨어졌으면 인자가 무엇이든 일한다는 신호를 주지 않는다."""
    ctx.budget = BudgetTracker(budget=Budget(max_tool_calls_per_function=1))
    ctx.budget.begin_function()
    api.get_function(ctx, "0x401000")
    assert api.get_function(ctx, "not-an-addr")["error"]["code"] == ErrorCode.BUDGET_EXCEEDED


# -- 범위 격리 ---------------------------------------------------------------


def test_no_raw_sql_tool_is_exported() -> None:
    """만능 도구가 생기면 어블레이션 전체가 무의미해진다."""
    names = {fn.__name__ for fn in api.READ_TOOLS}
    assert names == {
        "get_function",
        "get_callers",
        "get_callees",
        "get_apis_used",
        "search_strings",
        "get_known_analysis",
        "list_candidates",
    }
    assert not hasattr(api, "query")
    assert not hasattr(api, "readonly_query")


def test_tools_do_not_take_a_binary_argument() -> None:
    """바이너리는 서버 시작 시 고정된다 — 다른 샘플을 헤집는 경로를 막는다."""
    import inspect

    for fn in api.READ_TOOLS:
        params = set(inspect.signature(fn).parameters) - {"ctx"}
        assert "binary_id" not in params
        assert "sha256" not in params
