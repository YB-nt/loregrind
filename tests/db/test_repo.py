"""append-only 규율이 실제로 강제되는지 고정한다.

이 테스트가 없으면 규율은 문서일 뿐이다. §11 불변식 3·5 를 코드가 지키는지
확인하는 것이 목적이므로, "성공한다"가 아니라 **"위반이 거부된다"**를 검사한다.
"""

from __future__ import annotations

import sqlite3

import pytest

from loregrind.db.models import Binary, CallEdge, Function, FunctionAnalysis, Hypothesis
from loregrind.db.repo import AppendOnlyViolation, Repo, redact_config


@pytest.fixture
def repo() -> Repo:
    return Repo.open(":memory:")


@pytest.fixture
def function_id(repo: Repo) -> int:
    binary_id = repo.insert_binary(
        Binary(
            sha256="a" * 64,
            arch="x86:LE:32:default",
            extract_schema_version=1,
            function_count=1,
            analyzed_at="2026-08-17T00:00:00Z",
        )
    )
    repo.insert_functions(
        [
            Function(
                binary_id=binary_id,
                addr="0x401000",
                original_name="FUN_00401000",
                decompiled="void FUN_00401000(void) { return; }",
                code_hash="deadbeef",
            )
        ]
    )
    func = repo.get_function(binary_id, "0x401000")
    assert func is not None and func.id is not None
    return func.id


@pytest.fixture
def run_id(repo: Repo) -> str:
    return repo.create_run("test-model", "v1", {"strategy": "bottom-up"}).run_id


def test_supersede_hides_old_row(repo: Repo, function_id: int, run_id: str) -> None:
    """판단을 두 번 쓰면 이전 행은 조회에서 사라진다 — append-only 의 핵심 계약."""
    first = repo.insert_analysis(
        FunctionAnalysis(
            run_id=run_id, function_id=function_id, source="agent", proposed_name="maybe_init"
        )
    )
    second = repo.supersede_analysis(
        first,
        FunctionAnalysis(
            run_id=run_id, function_id=function_id, source="human", proposed_name="rc4_init"
        ),
    )

    current = repo.current_analysis(function_id)
    assert current is not None
    assert current.id == second
    assert current.proposed_name == "rc4_init"

    # 이전 행은 지워지지 않고 남아 있다 — 이력이므로
    rows = repo.readonly_query("SELECT id, superseded_by FROM function_analyses ORDER BY id")
    assert len(rows) == 2
    assert rows[0]["superseded_by"] == second


def test_cannot_supersede_twice(repo: Repo, function_id: int, run_id: str) -> None:
    """이미 가려진 행을 다시 가리면 이력이 갈라진다. 코드에서 먼저 막는다."""
    first = repo.insert_analysis(
        FunctionAnalysis(run_id=run_id, function_id=function_id, source="agent")
    )
    repo.supersede_analysis(
        first, FunctionAnalysis(run_id=run_id, function_id=function_id, source="agent")
    )
    with pytest.raises(AppendOnlyViolation):
        repo.supersede_analysis(
            first, FunctionAnalysis(run_id=run_id, function_id=function_id, source="human")
        )


def test_db_trigger_rejects_judgment_update(repo: Repo, function_id: int, run_id: str) -> None:
    """repo 를 우회해 직접 UPDATE 해도 DB 가 거부한다.

    규칙을 코드에만 두면 우회 경로가 생긴다. 트리거가 마지막 방어선이다.
    """
    analysis_id = repo.insert_analysis(
        FunctionAnalysis(
            run_id=run_id, function_id=function_id, source="agent", proposed_name="orig"
        )
    )
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        repo._conn.execute(
            "UPDATE function_analyses SET proposed_name = 'hacked' WHERE id = ?",
            (analysis_id,),
        )


def test_db_trigger_rejects_delete(repo: Repo, function_id: int, run_id: str) -> None:
    analysis_id = repo.insert_analysis(
        FunctionAnalysis(run_id=run_id, function_id=function_id, source="agent")
    )
    with pytest.raises(sqlite3.IntegrityError, match="never deleted"):
        repo._conn.execute("DELETE FROM function_analyses WHERE id = ?", (analysis_id,))


def test_analysis_requires_existing_run(repo: Repo, function_id: int) -> None:
    """run_id 없는 산출물은 존재할 수 없다 (불변식 5).

    이것이 깨지면 어블레이션이 SQL 한 줄로 안 되고 §6 평가 설계가 무너진다.
    """
    with pytest.raises(sqlite3.IntegrityError):
        repo.insert_analysis(
            FunctionAnalysis(run_id="does-not-exist", function_id=function_id, source="agent")
        )


def test_insert_analysis_rejects_presupplied_superseded_by(
    repo: Repo, function_id: int, run_id: str
) -> None:
    with pytest.raises(AppendOnlyViolation):
        repo.insert_analysis(
            FunctionAnalysis(
                run_id=run_id, function_id=function_id, source="agent", superseded_by=1
            )
        )


def test_confidence_range_enforced(repo: Repo, function_id: int, run_id: str) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        repo.insert_analysis(
            FunctionAnalysis(run_id=run_id, function_id=function_id, source="agent", confidence=1.5)
        )


def test_source_restricted_to_known_values(repo: Repo, function_id: int, run_id: str) -> None:
    """신뢰도 계층은 세 값뿐이다. 임의 문자열이 들어오면 계층이 무의미해진다."""
    with pytest.raises(sqlite3.IntegrityError):
        repo._conn.execute(
            "INSERT INTO function_analyses (run_id, function_id, source) VALUES (?, ?, ?)",
            (run_id, function_id, "guess"),
        )


def test_hypothesis_status_transition_is_new_row(repo: Repo, function_id: int, run_id: str) -> None:
    """상태 전이는 UPDATE 가 아니다."""
    hid = repo.insert_hypothesis(
        Hypothesis(run_id=run_id, function_id=function_id, statement="RC4 키 스케줄", status="open")
    )
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        repo._conn.execute("UPDATE hypotheses SET status = 'confirmed' WHERE id = ?", (hid,))


def test_call_graph_roundtrip(repo: Repo, function_id: int) -> None:
    func_binary = repo.readonly_query("SELECT binary_id FROM functions LIMIT 1")
    binary_id = int(func_binary[0]["binary_id"])
    repo.insert_call_edges(
        [
            CallEdge(binary_id=binary_id, caller_addr="0x401000", callee_addr="0x401230"),
            CallEdge(binary_id=binary_id, caller_addr="0x401000", callee_addr="0x401100"),
            # 중복 간선은 무해하게 무시된다
            CallEdge(binary_id=binary_id, caller_addr="0x401000", callee_addr="0x401230"),
        ]
    )
    assert repo.get_callees(binary_id, "0x401000") == ["0x401100", "0x401230"]
    assert repo.get_callers(binary_id, "0x401230") == ["0x401000"]


def test_readonly_query_rejects_writes(repo: Repo) -> None:
    with pytest.raises(ValueError, match="읽기 전용"):
        repo.readonly_query("DELETE FROM functions")
    with pytest.raises(ValueError):
        repo.readonly_query("UPDATE runs SET model = 'x'")


def test_create_run_redacts_secrets(repo: Repo) -> None:
    """설정에 키가 섞여 들어와도 DB 에 남지 않는다 (§10)."""
    repo.create_run(
        "m", "v1", {"anthropic_api_key": "sk-should-not-persist", "nested": {"token": "t"}}
    )
    rows = repo.readonly_query("SELECT config_json FROM runs")
    stored = str(rows[0]["config_json"])
    assert "sk-should-not-persist" not in stored
    assert "<redacted>" in stored


def test_redact_config_is_recursive() -> None:
    out = redact_config({"a": 1, "api_key": "x", "deep": {"secret_token": "y", "ok": 2}})
    assert out == {"a": 1, "api_key": "<redacted>", "deep": {"secret_token": "<redacted>", "ok": 2}}
