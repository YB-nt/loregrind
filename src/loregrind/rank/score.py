"""결정론적 랭킹 — 무엇을 먼저 읽을지 정한다 (§3 L3).

## 이 계층에서 LLM 을 호출하지 않는다 (불변식 4)

LLM 은 **무엇을 읽을지 고르지 않는다.** 상위 N 개를 받아서 무엇을 할지만 정한다.
순서를 모델이 정하면 (a) 같은 run 을 두 번 돌린 결과가 달라지고, (b) §6 어블레이션
2축(랭킹 vs 순차 vs 랜덤)에서 무엇을 비교하는지 알 수 없게 된다.

## 가중합을 쓴다 — 여기서는 허용된다

§5 가 RRF 를 요구하는 것은 **검색 채널 융합**이다. 여기는 채널이 아니라 신호이고,
전부 같은 스케일(0..1)로 정규화되므로 가중합이 성립한다. 대신 **신호별 점수를 따로
저장한다** — 합계만 남기면 "어느 신호가 값을 했는가"를 물을 수 없다.

## 동점 처리

동점은 주소 오름차순으로 깬다. dict/set 순서에 맡기면 재현이 깨지는데, 증상이
"가끔 순서가 다르다"라서 눈에 잘 띄지 않는다.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

RANKER_VERSION = "ranker-v1"

# 의심 API 카테고리. 이름 부분 일치로 본다 — Ghidra 가 주는 이름이 정확히 무엇인지
# 실측 전이므로 접미사(A/W/Ex)를 흡수해야 한다
API_CATEGORIES: dict[str, tuple[str, ...]] = {
    "crypto": ("crypt", "hash", "bcrypt", "rc4", "aes", "md5", "sha"),
    "net": ("socket", "connect", "send", "recv", "internet", "winhttp", "wsa", "url"),
    "proc": (
        "createprocess",
        "createremotethread",
        "openprocess",
        "writeprocessmemory",
        "virtualalloc",
        "loadlibrary",
        "getprocaddress",
        "shellexecute",
    ),
    "fs": ("createfile", "writefile", "readfile", "deletefile", "movefile", "findfirstfile"),
    "reg": ("regopen", "regset", "regcreate", "regquery", "regdelete"),
    "persist": ("createservice", "startservice", "schtask", "setwindowshook"),
}

# 여러 카테고리에 걸친 함수가 더 의심스럽다 — 암호화 + 네트워크는 단독보다 강한 신호
_CATEGORY_BONUS = 0.15


@dataclass(frozen=True, slots=True)
class Weights:
    """신호 가중치. `runs.config_json` 에 그대로 실려 어블레이션 축이 된다."""

    api: float = 1.0
    strings: float = 0.8
    callgraph: float = 0.5
    complexity: float = 0.4
    capa: float = 1.2

    @classmethod
    def load(cls, path: Path | str = "config/ranking.json") -> Weights:
        """설정 파일이 있으면 읽고, 없으면 기본값. **없다고 실패하지 않는다.**"""
        p = Path(path)
        if not p.is_file():
            return cls()
        raw = json.loads(p.read_text(encoding="utf-8"))
        known = {f for f in cls.__dataclass_fields__}
        unknown = set(raw) - known
        if unknown:
            # 오타난 가중치가 조용히 무시되면 어블레이션이 거짓말을 한다
            raise ValueError(f"알 수 없는 가중치 키: {sorted(unknown)} (허용: {sorted(known)})")
        return cls(**{k: float(v) for k, v in raw.items()})

    def as_config(self) -> dict[str, float]:
        # `slots=True` 라 `__dict__` 가 없다. 필드 목록에서 직접 읽는다
        return {f"w_{name}": float(getattr(self, name)) for name in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class FunctionFacts:
    """점수 계산에 필요한 사실. 전부 추출 사실이며 판단이 아니다."""

    function_id: int
    addr: str
    apis: tuple[str, ...] = ()
    # (문자열, 이 바이너리에서 그 문자열을 참조하는 함수 수)
    strings: tuple[tuple[str, int], ...] = ()
    fan_in: int = 0
    fan_out: int = 0
    cyclomatic: int | None = None
    capa_rules: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class Score:
    function_id: int
    addr: str
    score: float
    s_api: float
    s_strings: float
    s_callgraph: float
    s_complexity: float
    # capa 미설치면 None. 0 으로 채우면 "규칙에 안 걸림"과 구별되지 않는다
    s_capa: float | None
    reasons: tuple[str, ...] = ()
    ranker_version: str = RANKER_VERSION


@dataclass(slots=True)
class Corpus:
    """바이너리 하나의 분포 통계. IDF 와 복잡도 이상치가 여기에 의존한다."""

    total_functions: int
    # 문자열 → 참조 함수 수. 흔한 문자열은 정보량이 낮다
    cyclomatic_mean: float = 0.0
    cyclomatic_stdev: float = 0.0
    reasons: list[str] = field(default_factory=list)


def api_signal(apis: tuple[str, ...]) -> tuple[float, list[str]]:
    """의심 API 클러스터. 카테고리가 여러 개면 가산점."""
    if not apis:
        return 0.0, []
    hit: dict[str, list[str]] = {}
    for api in apis:
        low = api.lower()
        for category, needles in API_CATEGORIES.items():
            if any(n in low for n in needles):
                hit.setdefault(category, []).append(api)
    if not hit:
        return 0.0, []
    # 카테고리 수로 포화시킨다. API 100개를 부르는 함수가 100배 의심스럽지는 않다
    base = min(1.0, len(hit) / 3.0)
    bonus = _CATEGORY_BONUS * max(0, len(hit) - 1)
    reasons = [f"{c}: {', '.join(sorted(v)[:3])}" for c, v in sorted(hit.items())]
    return min(1.0, base + bonus), reasons


def string_signal(
    strings: tuple[tuple[str, int], ...], total_functions: int
) -> tuple[float, list[str]]:
    """고신호 문자열 참조 — IDF 가중.

    50개 함수가 참조하는 문자열은 정보량이 낮다. 한 함수만 참조하는 긴 문자열이
    가장 강한 신호다 (§5 축적 정책의 IDF 와 같은 발상).
    """
    if not strings or total_functions <= 0:
        return 0.0, []
    best = 0.0
    reasons: list[str] = []
    for value, refs in strings:
        idf = math.log((total_functions + 1) / (max(refs, 1) + 0.5))
        # 길이 가중: 아주 짧은 문자열은 우연히 일치할 수 있다
        length_factor = min(1.0, len(value) / 24.0)
        weight = max(0.0, idf) * length_factor
        if weight > best:
            best = weight
            reasons = [f"희귀 문자열({refs}회 참조): {value[:40]}"]
    # log 스케일을 0..1 로 접는다
    return min(1.0, best / 3.0), reasons


def callgraph_signal(fan_in: int, fan_out: int) -> tuple[float, list[str]]:
    """콜그래프 위치. **많이 부르지만 적게 불리는** 함수가 오케스트레이터다."""
    if fan_in == 0 and fan_out == 0:
        return 0.0, []
    orchestration = min(1.0, fan_out / 8.0)
    # 아무도 안 부르는데 많이 부르는 함수 = 진입점 후보
    entry_like = 0.3 if fan_in == 0 and fan_out >= 3 else 0.0
    reasons = [f"fan_in={fan_in} fan_out={fan_out}"]
    return min(1.0, orchestration + entry_like), reasons


def complexity_signal(cyclomatic: int | None, corpus: Corpus) -> tuple[float, list[str]]:
    """복잡도 이상치. 분포 대비 편차이지 절대값이 아니다."""
    if cyclomatic is None or corpus.cyclomatic_stdev <= 0:
        return 0.0, []
    z = (cyclomatic - corpus.cyclomatic_mean) / corpus.cyclomatic_stdev
    if z <= 1.0:
        return 0.0, []
    return min(1.0, (z - 1.0) / 2.0), [f"복잡도 이상치 z={z:.1f} (cyclomatic={cyclomatic})"]


def score_function(facts: FunctionFacts, corpus: Corpus, weights: Weights) -> Score:
    s_api, r_api = api_signal(facts.apis)
    s_str, r_str = string_signal(facts.strings, corpus.total_functions)
    s_cg, r_cg = callgraph_signal(facts.fan_in, facts.fan_out)
    s_cx, r_cx = complexity_signal(facts.cyclomatic, corpus)

    s_capa: float | None = None
    r_capa: list[str] = []
    if facts.capa_rules is not None:
        s_capa = min(1.0, len(facts.capa_rules) / 3.0)
        r_capa = [f"capa: {', '.join(facts.capa_rules[:3])}"] if facts.capa_rules else []

    total = (
        s_api * weights.api
        + s_str * weights.strings
        + s_cg * weights.callgraph
        + s_cx * weights.complexity
        + (s_capa * weights.capa if s_capa is not None else 0.0)
    )
    return Score(
        function_id=facts.function_id,
        addr=facts.addr,
        score=total,
        s_api=s_api,
        s_strings=s_str,
        s_callgraph=s_cg,
        s_complexity=s_cx,
        s_capa=s_capa,
        reasons=tuple(r_api + r_str + r_cg + r_cx + r_capa),
    )


def rank(scores: list[Score]) -> list[Score]:
    """점수 내림차순. **동점은 주소 오름차순으로 깬다** — 재현성 (불변식 4)."""
    return sorted(scores, key=lambda s: (-s.score, s.addr))


def to_row(score: Score) -> dict[str, Any]:
    """DB 행으로. 신호별 점수를 따로 남긴다 — 합계만 남기면 어블레이션 불가."""
    return {
        "function_id": score.function_id,
        "score": score.score,
        "s_api": score.s_api,
        "s_strings": score.s_strings,
        "s_callgraph": score.s_callgraph,
        "s_complexity": score.s_complexity,
        "s_capa": score.s_capa,
        "reasons_json": json.dumps(list(score.reasons), ensure_ascii=False),
        "ranker_version": score.ranker_version,
    }
