"""지표 계산 테스트.

이 코드가 틀리면 평가 숫자 전체가 무의미해지는데 **틀렸다는 신호가 눈에 보이지 않는다.**
그래서 "값이 나온다"가 아니라 **"측정 불가를 0 으로 내지 않는다"**를 주로 검사한다.
"""

from __future__ import annotations

import pytest

from eval.metrics import (
    LOWER_IS_BETTER,
    Citation,
    MetricValue,
    PriorCase,
    ProposedName,
    contradiction_rate,
    exploration_efficiency,
    hallucination_rate,
    is_auto_generated,
    is_regression,
    name_tokens,
    naming_accuracy,
    precision_at_1,
    recall_at_k,
)
from eval.truthset import EquivalencePair, GroundTruth, TruthBinary, TruthFunction

SHA_A = "a" * 64
SHA_B = "b" * 64


def make_gt() -> GroundTruth:
    return GroundTruth(
        version="test-1",
        binaries=(
            TruthBinary(
                sha256=SHA_A,
                source_project="demo",
                compiler="gcc",
                opt_level="-O2",
                functions=(
                    TruthFunction(
                        addr="0x401000",
                        true_name="rc4_init",
                        aliases=("rc4_key_schedule",),
                        is_key_function=True,
                        wrong_prior="string_compare",
                    ),
                    TruthFunction(addr="0x401100", true_name="parse_header"),
                ),
            ),
            TruthBinary(
                sha256=SHA_B,
                source_project="demo",
                compiler="clang",
                opt_level="-O2",
                is_holdout=True,
                functions=(TruthFunction(addr="0x8000", true_name="rc4_init"),),
            ),
        ),
        pairs=(
            EquivalencePair(
                source_symbol="rc4_init", left=(SHA_A, "0x401000"), right=(SHA_B, "0x8000")
            ),
        ),
    )


# -- 이름 정규화 --------------------------------------------------------------


def test_name_tokens_ignores_style_and_order() -> None:
    assert name_tokens("RC4Init") == name_tokens("rc4_init")
    assert name_tokens("init_rc4") == name_tokens("rc4_init")
    assert name_tokens("rc4_init") != name_tokens("rc4_encrypt")


@pytest.mark.parametrize(
    "name", ["FUN_00401000", "sub_401000", "thunk_FUN_00401000", "fun_401000", None]
)
def test_auto_generated_names_are_not_successes(name: str | None) -> None:
    assert is_auto_generated(name)


def test_real_name_is_not_auto_generated() -> None:
    assert not is_auto_generated("rc4_init")


# -- 명명 정확도 --------------------------------------------------------------


def test_naming_accuracy_counts_alias_as_hit() -> None:
    gt = make_gt()
    result = naming_accuracy(
        [
            ProposedName(SHA_A, "0x401000", "rc4_key_schedule"),  # alias → hit
            ProposedName(SHA_A, "0x401100", "FUN_00401100"),  # 자동 이름 → miss
        ],
        gt,
        stratum="gcc:-O2",
    )
    assert result.value == 0.5
    assert result.n == 2
    assert result.method == "token"


def test_naming_accuracy_excludes_functions_absent_from_groundtruth() -> None:
    gt = make_gt()
    result = naming_accuracy(
        [
            ProposedName(SHA_A, "0x401000", "rc4_init"),
            ProposedName(SHA_A, "0xdeadbeef", "whatever"),  # 정답셋에 없음 → 분모 제외
        ],
        gt,
    )
    assert result.value == 1.0
    assert result.n == 1


def test_naming_accuracy_without_overlap_is_unmeasured_not_zero() -> None:
    """겹치는 함수가 없으면 0% 가 아니라 측정 불가다. 이 구분이 리포트의 정직함이다."""
    result = naming_accuracy([ProposedName("f" * 64, "0x1", "x")], make_gt())
    assert result.value is None
    assert result.n == 0
    assert result.unmeasured_reason


def test_metric_value_rejects_none_without_reason() -> None:
    with pytest.raises(ValueError, match="unmeasured_reason"):
        MetricValue(metric="x", value=None, n=0)


def test_metric_value_rejects_value_with_zero_n() -> None:
    """n=0 인데 값이 있으면 그 숫자는 어디서 왔는지 설명할 수 없다."""
    with pytest.raises(ValueError, match="n=0"):
        MetricValue(metric="x", value=0.9, n=0)


# -- 환각률 ------------------------------------------------------------------


def test_hallucination_rate_is_string_verification() -> None:
    corpus = ["GetProcAddress", "software\\microsoft\\windows"]
    result = hallucination_rate(
        [
            Citation("f1", "GetProcAddress"),
            Citation("f2", "CreateRemoteThread"),  # 존재하지 않음 → 환각
        ],
        corpus,
    )
    assert result.rate.value == 0.5
    assert result.rate.n == 2
    assert [c.finding_id for c in result.unverifiable] == ["f2"]


def test_processed_citations_are_reported_as_defect() -> None:
    """인용이 가공돼 저장되면 대조가 성립하지 않는다. 낮은 환각률이 착시일 수 있다."""
    result = hallucination_rate([Citation("f1", "GetProc...")], ["GetProcAddress"])
    assert [c.finding_id for c in result.processed] == ["f1"]


def test_no_citations_is_a_defect_not_zero_hallucination() -> None:
    result = hallucination_rate([], ["anything"])
    assert result.rate.value is None
    assert "결함" in (result.rate.unmeasured_reason or "")


# -- 탐색 효율 ---------------------------------------------------------------


def test_exploration_efficiency_counts_reads_until_all_key_functions() -> None:
    result = exploration_efficiency(
        read_order=["0x1", "0x2", "0x401000"], key_functions=["0x401000"], total_functions=100
    )
    assert result.value == pytest.approx(0.03)
    assert result.n == 1


def test_exploration_efficiency_unmeasured_when_key_function_never_found() -> None:
    """끝까지 못 찾은 것과 비효율적으로 찾은 것은 다른 결과다."""
    result = exploration_efficiency(
        read_order=["0x1", "0x2"], key_functions=["0x401000"], total_functions=100
    )
    assert result.value is None
    assert "찾지 못했다" in (result.unmeasured_reason or "")


# -- 반대율 ------------------------------------------------------------------


def test_contradiction_rate_counts_overturned_priors() -> None:
    gt = make_gt()
    result = contradiction_rate(
        [
            # 틀린 사전정보를 뒤집고 정답에 도달 → 반대 성공
            PriorCase(SHA_A, "0x401000", "string_compare", "rc4_init"),
        ],
        gt,
    )
    assert result.value == 1.0
    assert result.n == 1


def test_contradiction_rate_zero_when_agent_copies_prior() -> None:
    """반대율 0 은 에이전트가 분석이 아니라 복사를 하고 있다는 신호다."""
    gt = make_gt()
    result = contradiction_rate(
        [PriorCase(SHA_A, "0x401000", "string_compare", "string_compare")], gt
    )
    assert result.value == 0.0


def test_contradiction_rate_unmeasured_without_cases() -> None:
    result = contradiction_rate([], make_gt())
    assert result.value is None


# -- 검색 ---------------------------------------------------------------------


def test_recall_at_k_uses_equivalence_pairs() -> None:
    gt = make_gt()
    ranked = {(SHA_A, "0x401000"): [("x" * 64, "0x1"), (SHA_B, "0x8000")]}
    assert recall_at_k(ranked, gt, 2).value == 1.0
    assert recall_at_k(ranked, gt, 1).value == 0.0
    assert precision_at_1(ranked, gt).value == 0.0


def test_recall_unmeasured_when_no_query_overlaps_pairs() -> None:
    result = recall_at_k({("z" * 64, "0x1"): [("y" * 64, "0x2")]}, make_gt(), 5)
    assert result.value is None
    assert result.k == 5


# -- 지표의 방향 --------------------------------------------------------------


def test_regression_direction_respects_lower_is_better() -> None:
    """방향을 틀리면 "개선"과 "하락"이 뒤집힌 채 리포트에 실린다.

    실제로 이 버그가 있었다 — exploration_efficiency 는 낮을수록 좋은데
    하락 판정에서 빠져 있었고, 홀드아웃 게이트가 악화를 통과시켰다.
    """
    # 높을수록 좋은 지표
    assert is_regression("naming_accuracy", 0.72, 0.68)
    assert not is_regression("naming_accuracy", 0.68, 0.72)
    # 낮을수록 좋은 지표
    for metric in ("hallucination_rate", "exploration_efficiency"):
        assert metric in LOWER_IS_BETTER
        assert is_regression(metric, 0.10, 0.12)
        assert not is_regression(metric, 0.12, 0.10)
