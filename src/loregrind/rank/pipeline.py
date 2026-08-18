"""랭킹 파이프라인 — 사실을 모아 점수를 매기고 저장한다 (§3 L3).

순서가 고정되어 있다: **라이브러리 필터 → 점수 → 저장.** 필터를 나중에 돌리면
걸러질 함수까지 점수를 계산하느라 대형 바이너리에서 시간을 버린다.

이 모듈은 LLM 을 부르지 않는다 (불변식 4). `rank/` 전체가 그렇다.
"""

from __future__ import annotations

from dataclasses import dataclass

from loregrind.db.repo import Repo
from loregrind.rank.library_filter import FILTER_VERSION, FilterResult, classify
from loregrind.rank.score import (
    Corpus,
    FunctionFacts,
    Score,
    Weights,
    rank,
    score_function,
    to_row,
)


@dataclass(frozen=True, slots=True)
class RankResult:
    scored: int
    filtered: FilterResult
    top: tuple[Score, ...]


def apply_library_filter(repo: Repo, run_id: str, binary_id: int) -> FilterResult:
    """라이브러리 판정을 기록하고 캐시를 갱신한다."""
    judged: list[tuple[int, bool, str, str, float]] = []
    skipped = 0
    for func in repo.all_functions(binary_id):
        if func.id is None:
            continue
        verdict = classify(func)
        if verdict is None:
            # 미판정이다. 라이브러리가 아니라는 판정이 아니라 판정하지 않은 것 —
            # 이 함수는 분석 대상으로 남는다
            skipped += 1
            continue
        judged.append(
            (func.id, verdict.is_library, verdict.method, FILTER_VERSION, verdict.confidence)
        )

    if judged:
        repo.record_library_verdicts(run_id, judged)
    return FilterResult(
        judged=len(judged),
        library=sum(1 for _f, is_lib, _m, _v, _c in judged if is_lib),
        skipped=skipped,
    )


def score_binary(
    repo: Repo, run_id: str, binary_id: int, weights: Weights, *, top_n: int = 20
) -> RankResult:
    """바이너리 하나를 랭킹한다."""
    filtered = apply_library_filter(repo, run_id, binary_id)

    apis = repo.apis_by_function(binary_id)
    strings = repo.strings_by_function(binary_id)
    mean, stdev = repo.cyclomatic_stats(binary_id)
    rows = repo.ranking_facts(binary_id)
    corpus = Corpus(total_functions=len(rows), cyclomatic_mean=mean, cyclomatic_stdev=stdev)

    scores = [
        score_function(
            FunctionFacts(
                function_id=int(row["function_id"]),
                addr=str(row["addr"]),
                apis=tuple(apis.get(str(row["addr"]), ())),
                strings=tuple(strings.get(str(row["addr"]), ())),
                fan_in=int(row["fan_in"]),
                fan_out=int(row["fan_out"]),
                cyclomatic=row["cyclomatic"],
                # capa 미설치. None 을 유지해 "규칙에 안 걸림"과 구별한다
                capa_rules=None,
            ),
            corpus,
            weights,
        )
        for row in rows
    ]

    ordered = rank(scores)
    if ordered:
        repo.insert_scores(run_id, [to_row(s) for s in ordered])
    return RankResult(scored=len(ordered), filtered=filtered, top=tuple(ordered[:top_n]))
