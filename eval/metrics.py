"""지표 계산 — 전부 결정론적이다.

§6 의 지표 6종을 계산한다. 규칙 셋:

1. **모든 결과에 `n` 이 붙는다.** `MetricValue` 가 `n` 을 필수 필드로 갖는다.
2. **LLM 을 호출하지 않는다** (불변식 4). 의미 동등 판정은 정답셋의 `aliases` 로
   미리 결정돼 있고, 계산은 문자열 대조다.
3. **환각률은 자동 검증이다.** 모델에게 "환각했니"라고 묻지 않는다. 인용 문자열이
   실제로 존재하는지 대조한다.

n=0 일 때 값을 0.0 으로 내지 않고 `None` 을 낸다. 0% 와 "측정 불가"는 다른 진술이고,
섞으면 리포트가 거짓말을 한다.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from eval.truthset import GroundTruth, TruthFunction

# Ghidra 자동 명명과 컴파일러 접두사. 이름 비교 전에 떼어낸다
_AUTO_NAME = re.compile(r"^(FUN|SUB|thunk_FUN|sub)_[0-9a-fA-F]+$", re.IGNORECASE)
_SPLIT = re.compile(r"[^a-z0-9]+")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
# 인용이 원문 그대로가 아님을 드러내는 흔적. 있으면 결함으로 보고한다
_PROCESSED_MARKERS = ("...", "…", "[truncated]", "(생략)")

# **낮을수록 좋은 지표.** 이 집합을 한 곳에 두는 이유: 방향을 호출부마다 판단하면
# 한 곳은 반드시 틀리고, 틀리면 "하락"과 "개선"이 뒤집힌 채로 리포트에 실린다.
# 새 지표를 추가할 때 방향을 여기에 등록할지 반드시 판단한다.
LOWER_IS_BETTER = frozenset({"hallucination_rate", "exploration_efficiency"})


def is_regression(metric: str, baseline: float, candidate: float) -> bool:
    """`candidate` 가 `baseline` 보다 나쁜가. 지표의 방향을 반영한다."""
    if metric in LOWER_IS_BETTER:
        return candidate > baseline
    return candidate < baseline


@dataclass(frozen=True, slots=True)
class MetricValue:
    """지표 하나. `n` 없이 존재할 수 없다."""

    metric: str
    value: float | None
    n: int
    stratum: str = "all"
    corpus_state: str = "cold"
    method: str | None = None
    k: int | None = None
    # 측정 불가 사유. value 가 None 이면 반드시 채운다
    unmeasured_reason: str | None = None

    def __post_init__(self) -> None:
        if self.value is None and not self.unmeasured_reason:
            raise ValueError(f"{self.metric}: value 가 None 이면 unmeasured_reason 이 필요하다")
        if self.value is not None and self.n == 0:
            raise ValueError(f"{self.metric}: n=0 인데 값이 있다. 어디서 나온 숫자인가")


def _unmeasured(metric: str, reason: str, **kw: object) -> MetricValue:
    return MetricValue(metric=metric, value=None, n=0, unmeasured_reason=reason, **kw)  # type: ignore[arg-type]


# -- 이름 정규화 --------------------------------------------------------------


def name_tokens(name: str) -> frozenset[str]:
    """이름을 토큰 집합으로. `RC4Init` / `rc4_init` / `init_rc4` 가 같아진다."""
    spaced = _CAMEL.sub(" ", name)
    return frozenset(t for t in _SPLIT.split(spaced.lower()) if t)


def is_auto_generated(name: str | None) -> bool:
    """`FUN_00401000` 같은 자동 이름. 명명 성공으로 세지 않는다."""
    return name is None or bool(_AUTO_NAME.match(name.strip()))


def names_match(proposed: str | None, truth: TruthFunction, method: str = "token") -> bool:
    """제안된 이름이 정답과 일치하는가.

    `method` 를 리포트에 명시해야 한다 — 판정 방법이 숫자를 바꾸기 때문이다.
    - `exact`: 소문자화 후 문자열 완전 일치
    - `token`: 토큰 집합 일치 (어순·구분자 무시)
    - `alias`: 정답셋에 미리 넣어 둔 의미 동등 목록 포함
    """
    # None 과 자동 생성 이름은 성공이 아니다. 여기서 걸러 이후 코드가 str 만 다루게 한다
    if proposed is None or is_auto_generated(proposed):
        return False
    candidates = (truth.true_name, *truth.aliases)
    if method == "exact":
        return proposed.strip().lower() in {c.strip().lower() for c in candidates}
    if method == "alias":
        return proposed.strip().lower() in {c.strip().lower() for c in candidates}
    if method == "token":
        return name_tokens(proposed) in {name_tokens(c) for c in candidates}
    raise ValueError(f"알 수 없는 판정 방법: {method}")


# -- 지표 --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProposedName:
    """에이전트가 낸 명명 하나."""

    sha256: str
    addr: str
    proposed_name: str | None


def naming_accuracy(
    proposals: Sequence[ProposedName],
    gt: GroundTruth,
    *,
    stratum: str = "all",
    corpus_state: str = "cold",
    method: str = "token",
) -> MetricValue:
    """명명 정확도. 정답셋에 없는 함수는 분모에서 제외한다."""
    scored = [(p, gt.function(p.sha256, p.addr)) for p in proposals]
    matched = [(p, t) for p, t in scored if t is not None]
    if not matched:
        return _unmeasured(
            "naming_accuracy",
            "정답셋과 겹치는 함수가 없다",
            stratum=stratum,
            corpus_state=corpus_state,
            method=method,
        )
    hits = sum(1 for p, t in matched if names_match(p.proposed_name, t, method))
    return MetricValue(
        metric="naming_accuracy",
        value=hits / len(matched),
        n=len(matched),
        stratum=stratum,
        corpus_state=corpus_state,
        method=method,
    )


@dataclass(frozen=True, slots=True)
class Citation:
    """findings 가 인용한 근거 하나."""

    finding_id: str
    quoted: str


@dataclass(frozen=True, slots=True)
class HallucinationResult:
    rate: MetricValue
    # 존재하지 않는 인용
    unverifiable: tuple[Citation, ...]
    # 원문 그대로가 아니라 가공된 흔적이 있는 인용. **이것 자체가 결함이다**
    processed: tuple[Citation, ...]


def hallucination_rate(
    citations: Sequence[Citation],
    corpus_strings: Sequence[str],
    *,
    stratum: str = "all",
    corpus_state: str = "cold",
) -> HallucinationResult:
    """환각률 — 인용한 근거가 실제로 존재하는가. **자동 검증이다.**

    `corpus_strings` 는 바이너리·DB 에서 실제로 뽑은 문자열이다. 인용이 그 안에
    부분 문자열로 존재하지 않으면 환각으로 센다.

    인용이 요약·가공되어 저장되고 있으면 대조가 성립하지 않으므로 그것을 결함으로
    함께 보고한다 — 환각률이 낮게 나오는 이유가 "인용이 느슨해서"일 수 있다.
    """
    if not citations:
        return HallucinationResult(
            rate=_unmeasured(
                "hallucination_rate",
                "인용이 하나도 없다. findings 에 근거가 저장되지 않는 것 자체가 결함이다",
                stratum=stratum,
                corpus_state=corpus_state,
            ),
            unverifiable=(),
            processed=(),
        )
    haystack = "\n".join(corpus_strings)
    unverifiable = tuple(c for c in citations if c.quoted and c.quoted not in haystack)
    processed = tuple(c for c in citations if any(m in c.quoted for m in _PROCESSED_MARKERS))
    return HallucinationResult(
        rate=MetricValue(
            metric="hallucination_rate",
            value=len(unverifiable) / len(citations),
            n=len(citations),
            stratum=stratum,
            corpus_state=corpus_state,
            method="substring",
        ),
        unverifiable=unverifiable,
        processed=processed,
    )


def exploration_efficiency(
    read_order: Sequence[str],
    key_functions: Sequence[str],
    total_functions: int,
    *,
    stratum: str = "all",
    corpus_state: str = "cold",
) -> MetricValue:
    """핵심 함수를 모두 찾기까지 읽은 함수 수 / 전체.

    낮을수록 좋다. 핵심 함수를 끝까지 못 찾으면 측정 불가로 낸다 — 전체를 읽은 것처럼
    1.0 을 내면 "비효율적이었다"와 "실패했다"가 구분되지 않는다.
    """
    if not key_functions or total_functions <= 0:
        return _unmeasured(
            "exploration_efficiency",
            "핵심 함수가 지정되지 않았거나 전체 함수 수가 0 이다",
            stratum=stratum,
            corpus_state=corpus_state,
        )
    remaining = set(key_functions)
    for i, addr in enumerate(read_order, start=1):
        remaining.discard(addr)
        if not remaining:
            return MetricValue(
                metric="exploration_efficiency",
                value=i / total_functions,
                n=len(key_functions),
                stratum=stratum,
                corpus_state=corpus_state,
            )
    return _unmeasured(
        "exploration_efficiency",
        f"핵심 함수 {len(remaining)}개를 끝까지 찾지 못했다",
        stratum=stratum,
        corpus_state=corpus_state,
    )


@dataclass(frozen=True, slots=True)
class PriorCase:
    """반대율 진단 케이스 하나 — 일부러 틀린 사전정보를 준 함수."""

    sha256: str
    addr: str
    wrong_prior: str
    final_name: str | None


def contradiction_rate(
    cases: Sequence[PriorCase],
    gt: GroundTruth,
    *,
    stratum: str = "all",
    corpus_state: str = "cold",
    method: str = "token",
) -> MetricValue:
    """반대율 — 주입된 틀린 사전정보를 에이전트가 뒤집는 비율.

    **0 에 가까우면 에이전트는 분석이 아니라 복사를 하고 있다.** 이 신호는 리포트에서
    묻지 않고 전면에 낸다. 불변식 7(사전정보는 결론이 아니라 가설)이 실제로 지켜지는지를
    직접 재는 지표다.
    """
    scored = [(c, gt.function(c.sha256, c.addr)) for c in cases]
    usable = [(c, t) for c, t in scored if t is not None]
    if not usable:
        return _unmeasured(
            "contradiction_rate",
            "반대율 케이스가 없다. 진단 테스트를 돌리지 않았다",
            stratum=stratum,
            corpus_state=corpus_state,
            method=method,
        )
    overturned = sum(
        1
        for c, t in usable
        if names_match(c.final_name, t, method)
        and name_tokens(c.final_name or "") != name_tokens(c.wrong_prior)
    )
    return MetricValue(
        metric="contradiction_rate",
        value=overturned / len(usable),
        n=len(usable),
        stratum=stratum,
        corpus_state=corpus_state,
        method=method,
    )


def recall_at_k(
    ranked_results: dict[tuple[str, str], Sequence[tuple[str, str]]],
    gt: GroundTruth,
    k: int,
    *,
    stratum: str = "all",
    corpus_state: str = "cold",
) -> MetricValue:
    """Recall@k — 등가 함수를 상위 k 에 회수하는가.

    `ranked_results`: 질의 함수 (sha256, addr) → 순위대로의 후보 목록.
    정답 쌍은 정답셋의 `pairs` 다.
    """
    expected: dict[tuple[str, str], set[tuple[str, str]]] = {}
    for pair in gt.pairs:
        expected.setdefault(pair.left, set()).add(pair.right)
        expected.setdefault(pair.right, set()).add(pair.left)

    queries = [q for q in ranked_results if q in expected]
    if not queries:
        return _unmeasured(
            "recall_at_k",
            "정답 쌍과 겹치는 질의가 없다",
            stratum=stratum,
            corpus_state=corpus_state,
            k=k,
        )
    hits = sum(1 for q in queries if expected[q] & set(ranked_results[q][:k]))
    return MetricValue(
        metric="recall_at_k",
        value=hits / len(queries),
        n=len(queries),
        stratum=stratum,
        corpus_state=corpus_state,
        k=k,
    )


def precision_at_1(
    ranked_results: dict[tuple[str, str], Sequence[tuple[str, str]]],
    gt: GroundTruth,
    *,
    stratum: str = "all",
    corpus_state: str = "cold",
) -> MetricValue:
    result = recall_at_k(ranked_results, gt, 1, stratum=stratum, corpus_state=corpus_state)
    if result.value is None:
        return _unmeasured(
            "precision_at_1",
            result.unmeasured_reason or "측정 불가",
            stratum=stratum,
            corpus_state=corpus_state,
        )
    return MetricValue(
        metric="precision_at_1",
        value=result.value,
        n=result.n,
        stratum=stratum,
        corpus_state=corpus_state,
        k=1,
    )
