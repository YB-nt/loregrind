"""정답셋 스키마와 적재.

합성 정답셋: 오픈소스를 컴파일 → 심볼 스트립 → 원본 함수명과 대조.
난이도 격자는 **컴파일러 x 최적화**이고, 결과는 셀 단위로 보고한다 — 평균만 내면
`-O0` 의 쉬운 성공이 `-O3` 의 실패를 가린다.

정답셋은 JSON 파일로 둔다. 에이전트가 읽는 SQLite(`loregrind.db`)에 넣지 않는다
(§6 정답 누출 차단). 이 분리는 `eval/leakage.py` 가 검사한다.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# 난이도 격자. 셀 문자열은 run_metrics.stratum 에 그대로 들어간다
COMPILERS = ("gcc", "clang", "msvc")
OPT_LEVELS = ("-O0", "-O1", "-O2", "-O3")


def stratum(compiler: str, opt: str) -> str:
    """`'gcc:-O2'` 형태. 지표 저장·리포트에서 동일한 표기를 쓴다."""
    return f"{compiler}:{opt}"


@dataclass(frozen=True, slots=True)
class TruthFunction:
    """정답 함수 하나."""

    # 스트립된 바이너리에서의 주소. 에이전트가 보는 식별자
    addr: str
    # 원본 심볼명. **에이전트 컨텍스트로 절대 흘러가면 안 되는 값**
    true_name: str
    # 의미 동등으로 인정할 이름들. 판정에 LLM 을 쓰지 않기 위해 미리 넣어 둔다
    aliases: tuple[str, ...] = ()
    # 탐색 효율 측정용. 정답셋에서 미리 지정한다
    is_key_function: bool = False
    # 반대율 진단용: 일부러 주입할 틀린 사전정보
    wrong_prior: str | None = None


@dataclass(frozen=True, slots=True)
class TruthBinary:
    """정답셋의 빌드 하나 = 격자의 한 셀."""

    sha256: str
    source_project: str
    compiler: str
    opt_level: str
    # 미학습 패밀리 홀드아웃 대상인가. 홀드아웃만 따로 보고해야 과적합을 잡는다
    is_holdout: bool = False
    functions: tuple[TruthFunction, ...] = ()

    @property
    def stratum(self) -> str:
        return stratum(self.compiler, self.opt_level)


@dataclass(frozen=True, slots=True)
class EquivalencePair:
    """같은 소스 함수의 서로 다른 빌드 = 검색 평가의 정답 쌍.

    정답셋을 만들 때 함께 산출한다. 나중에 만들려면 전체 빌드를 반복해야 한다.
    """

    source_symbol: str
    left: tuple[str, str]  # (sha256, addr)
    right: tuple[str, str]


@dataclass(frozen=True, slots=True)
class GroundTruth:
    version: str
    binaries: tuple[TruthBinary, ...] = ()
    pairs: tuple[EquivalencePair, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)

    def binary(self, sha256: str) -> TruthBinary | None:
        return next((b for b in self.binaries if b.sha256 == sha256), None)

    def function(self, sha256: str, addr: str) -> TruthFunction | None:
        b = self.binary(sha256)
        if b is None:
            return None
        return next((f for f in b.functions if f.addr == addr), None)

    def all_true_names(self) -> set[str]:
        """누출 점검이 쓰는, 절대 노출되면 안 되는 문자열 집합."""
        return {f.true_name for b in self.binaries for f in b.functions}

    def strata(self) -> list[str]:
        return sorted({b.stratum for b in self.binaries})

    def key_functions(self, sha256: str) -> list[str]:
        b = self.binary(sha256)
        return [] if b is None else [f.addr for f in b.functions if f.is_key_function]


def load(path: Path) -> GroundTruth:
    """정답셋 JSON 을 읽는다.

    파일이 없으면 에러를 낸다. **빈 정답셋으로 조용히 진행하지 않는다** — 그러면
    모든 지표가 n=0 으로 계산되고 "측정했다"는 착시가 생긴다.
    """
    if not path.is_file():
        raise FileNotFoundError(
            f"정답셋 {path} 가 없다. 합성 정답셋을 먼저 만들어야 한다 (§6). "
            "지표를 n=0 으로 내지 않는다"
        )
    raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    binaries = tuple(
        TruthBinary(
            sha256=str(b["sha256"]),
            source_project=str(b["source_project"]),
            compiler=str(b["compiler"]),
            opt_level=str(b["opt_level"]),
            is_holdout=bool(b.get("is_holdout", False)),
            functions=tuple(
                TruthFunction(
                    addr=str(f["addr"]),
                    true_name=str(f["true_name"]),
                    aliases=tuple(f.get("aliases", ())),
                    is_key_function=bool(f.get("is_key_function", False)),
                    wrong_prior=f.get("wrong_prior"),
                )
                for f in b.get("functions", ())
            ),
        )
        for b in raw.get("binaries", ())
    )
    pairs = tuple(
        EquivalencePair(
            source_symbol=str(p["source_symbol"]),
            left=(str(p["left"][0]), str(p["left"][1])),
            right=(str(p["right"][0]), str(p["right"][1])),
        )
        for p in raw.get("pairs", ())
    )
    return GroundTruth(
        version=str(raw["version"]),
        binaries=binaries,
        pairs=pairs,
        notes=tuple(raw.get("notes", ())),
    )
