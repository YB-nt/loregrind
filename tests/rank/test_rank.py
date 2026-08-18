"""L3 랭킹 (§7 3주차).

여기서 고정하는 것 셋:

1. **결정론** — 같은 입력이 같은 순서를 만든다. 동점도 마찬가지다 (불변식 4)
2. **신호 분리** — 신호별 점수가 따로 남는다. 합계만 남기면 어블레이션 불가
3. **판정 근거** — 왜 걸러졌는지가 `library_verdicts` 에 남는다
"""

from __future__ import annotations

import json

import pytest

from loregrind.db.models import (
    ApiCall,
    Binary,
    CallEdge,
    Function,
    Import,
    StringLiteral,
    StringXref,
)
from loregrind.db.repo import Repo
from loregrind.rank.library_filter import FILTER_VERSION, classify
from loregrind.rank.pipeline import score_binary
from loregrind.rank.score import (
    Corpus,
    FunctionFacts,
    Score,
    Weights,
    api_signal,
    complexity_signal,
    rank,
    score_function,
    string_signal,
)

SHA = "1" * 64


@pytest.fixture
def repo() -> Repo:
    return Repo.open(":memory:")


@pytest.fixture
def binary_id(repo: Repo) -> int:
    bid = repo.insert_binary(
        Binary(
            sha256=SHA,
            arch="x86:LE:32:default",
            extract_schema_version=2,
            function_count=4,
            analyzed_at="2026-08-18T00:00:00Z",
        )
    )
    repo.insert_functions(
        [
            # 의심 함수 — 여러 카테고리 API + 희귀 문자열
            Function(binary_id=bid, addr="0x401000", original_name="FUN_00401000", cyclomatic=20),
            # 평범한 함수
            Function(binary_id=bid, addr="0x401100", original_name="FUN_00401100", cyclomatic=3),
            # 썽크 — 필터에 걸려야 한다
            Function(binary_id=bid, addr="0x401200", original_name="FUN_00401200", is_thunk=True),
            # 이름이 복원된 CRT 함수
            Function(binary_id=bid, addr="0x401300", original_name="memcpy", cyclomatic=4),
        ]
    )
    repo.insert_call_edges(
        [
            CallEdge(binary_id=bid, caller_addr="0x401000", callee_addr="0x401100"),
            CallEdge(binary_id=bid, caller_addr="0x401000", callee_addr="0x401200"),
            CallEdge(binary_id=bid, caller_addr="0x401000", callee_addr="0x401300"),
        ]
    )
    index = repo.insert_imports(
        [
            Import(binary_id=bid, module="advapi32.dll", api_name="CryptEncrypt"),
            Import(binary_id=bid, module="ws2_32.dll", api_name="connect"),
        ]
    )
    repo.insert_api_calls(
        [
            ApiCall(
                binary_id=bid,
                function_addr="0x401000",
                import_id=index[("advapi32.dll", "CryptEncrypt")],
                call_addr="0x401010",
            ),
            ApiCall(
                binary_id=bid,
                function_addr="0x401000",
                import_id=index[("ws2_32.dll", "connect")],
                call_addr="0x401020",
            ),
        ]
    )
    repo.insert_strings(
        [
            StringLiteral(
                binary_id=bid,
                addr="0x403000",
                value="http://c2.example.invalid/gate.php?id=",
                encoding="ascii",
                length=37,
            )
        ]
    )
    repo.insert_string_xrefs(
        [StringXref(binary_id=bid, function_addr="0x401000", string_addr="0x403000")]
    )
    return bid


# -- 라이브러리 필터 ---------------------------------------------------------


def test_thunk_and_named_library_are_filtered() -> None:
    thunk = Function(binary_id=1, addr="0x1", original_name="FUN_1", is_thunk=True)
    crt = Function(binary_id=1, addr="0x2", original_name="memcpy")
    assert classify(thunk) is not None and classify(thunk).is_library  # type: ignore[union-attr]
    assert classify(crt) is not None and classify(crt).is_library  # type: ignore[union-attr]


def test_stripped_function_is_left_unjudged() -> None:
    """확신 없으면 판정하지 않는다 — 잘못 걸러낸 함수는 영영 안 읽힌다."""
    assert classify(Function(binary_id=1, addr="0x1", original_name="FUN_00401000")) is None


def test_decompile_failure_is_not_folded_into_library() -> None:
    """실패를 라이브러리로 접으면 실패율이 필터 뒤로 숨는다."""
    failed = Function(binary_id=1, addr="0x1", original_name="FUN_1", decompile_error="timeout")
    assert classify(failed) is None


def test_verdict_history_records_why(repo: Repo, binary_id: int) -> None:
    """근거 없이 컬럼만 바뀌면 왜 걸러졌는지 복원할 수 없다."""
    run = repo.create_run("none", "ranker-v1", {})
    score_binary(repo, run.run_id, binary_id, Weights())

    thunk = repo.get_function(binary_id, "0x401200")
    assert thunk is not None and thunk.id is not None
    history = repo.library_verdict_history(thunk.id)
    assert len(history) == 1
    assert history[0]["is_library"] == 1
    assert history[0]["method"] == "thunk"
    assert history[0]["method_version"] == FILTER_VERSION
    # 캐시도 갱신됐다
    assert repo.get_function(binary_id, "0x401200").is_library is True  # type: ignore[union-attr]


# -- 신호 ---------------------------------------------------------------------


def test_multi_category_apis_outrank_single(repo: Repo) -> None:
    single, _ = api_signal(("CryptEncrypt",))
    multi, reasons = api_signal(("CryptEncrypt", "connect", "CreateProcessA"))
    assert multi > single
    assert any("crypto" in r for r in reasons)


def test_rare_strings_outrank_common_ones() -> None:
    """50개 함수가 참조하는 문자열은 정보량이 낮다 (IDF)."""
    rare, _ = string_signal((("http://c2.example.invalid/gate.php", 1),), total_functions=100)
    common, _ = string_signal((("http://c2.example.invalid/gate.php", 90),), total_functions=100)
    assert rare > common


def test_complexity_is_relative_not_absolute() -> None:
    """복잡도 30 이 큰지 작은지는 분포가 정한다."""
    tight = Corpus(total_functions=50, cyclomatic_mean=5.0, cyclomatic_stdev=2.0)
    loose = Corpus(total_functions=50, cyclomatic_mean=28.0, cyclomatic_stdev=10.0)
    assert complexity_signal(30, tight)[0] > complexity_signal(30, loose)[0]


def test_capa_absence_is_none_not_zero() -> None:
    """capa 미설치와 '규칙에 안 걸림'은 다르다."""
    facts = FunctionFacts(function_id=1, addr="0x1", capa_rules=None)
    assert score_function(facts, Corpus(total_functions=1), Weights()).s_capa is None
    facts_with = FunctionFacts(function_id=1, addr="0x1", capa_rules=())
    assert score_function(facts_with, Corpus(total_functions=1), Weights()).s_capa == 0.0


# -- 결정론 -------------------------------------------------------------------


def test_ties_break_on_address_not_insertion_order() -> None:
    """동점을 dict 순서에 맡기면 재현이 깨진다 (불변식 4)."""
    made = [
        Score(2, "0x402000", 1.0, 0, 0, 0, 0, None),
        Score(1, "0x401000", 1.0, 0, 0, 0, 0, None),
        Score(3, "0x400000", 1.0, 0, 0, 0, 0, None),
    ]
    assert [s.addr for s in rank(made)] == ["0x400000", "0x401000", "0x402000"]


def test_ranking_is_reproducible(repo: Repo, binary_id: int) -> None:
    run_a = repo.create_run("none", "ranker-v1", {})
    run_b = repo.create_run("none", "ranker-v1", {})
    a = score_binary(repo, run_a.run_id, binary_id, Weights())
    b = score_binary(repo, run_b.run_id, binary_id, Weights())
    assert [s.addr for s in a.top] == [s.addr for s in b.top]
    assert [round(s.score, 9) for s in a.top] == [round(s.score, 9) for s in b.top]


def test_suspicious_function_ranks_first(repo: Repo, binary_id: int) -> None:
    run = repo.create_run("none", "ranker-v1", {})
    result = score_binary(repo, run.run_id, binary_id, Weights())
    assert result.top[0].addr == "0x401000"
    # 신호가 개별로 남아 있다 — 합계만 남기면 어블레이션 불가
    assert result.top[0].s_api > 0
    assert result.top[0].s_strings > 0
    assert result.top[0].s_callgraph > 0


def test_scores_are_stored_per_signal(repo: Repo, binary_id: int) -> None:
    run = repo.create_run("none", "ranker-v1", {})
    score_binary(repo, run.run_id, binary_id, Weights())
    rows = repo.ranked_functions(run.run_id, binary_id, limit=10)
    assert rows[0]["addr"] == "0x401000"
    assert rows[0]["s_api"] > 0
    assert json.loads(rows[0]["reasons_json"])  # 근거가 비어 있지 않다
    # 라이브러리로 판정된 함수는 후보에서 빠진다
    assert "0x401200" not in [r["addr"] for r in rows]
    assert "0x401300" not in [r["addr"] for r in rows]


# -- 가중치 -------------------------------------------------------------------


def test_unknown_weight_key_is_rejected(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """오타난 가중치가 조용히 무시되면 어블레이션이 거짓말을 한다."""
    path = tmp_path / "ranking.json"
    path.write_text(json.dumps({"apis": 2.0}), encoding="utf-8")
    with pytest.raises(ValueError, match="알 수 없는 가중치"):
        Weights.load(path)


def test_missing_weight_file_falls_back_to_defaults(tmp_path) -> None:  # type: ignore[no-untyped-def]
    assert Weights.load(tmp_path / "nope.json") == Weights()


def test_weights_land_in_run_config() -> None:
    config = Weights(api=2.0).as_config()
    assert config["w_api"] == 2.0
    assert set(config) == {"w_api", "w_strings", "w_callgraph", "w_complexity", "w_capa"}


def test_no_llm_in_rank_layer() -> None:
    """불변식 4 — 이 계층은 결정론적 코드다."""
    import pathlib

    for path in pathlib.Path("src/loregrind/rank").glob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "anthropic" not in source
        assert "messages.create" not in source
