"""라이브러리 함수 필터 — 분석 대상을 줄이는 단일 최대 효과의 최적화 (§3 L3).

## 왜 여기가 첫 번째 최적화인가

스트립된 바이너리에서 함수의 상당수는 CRT·STL·컴파일러 런타임이다. 그것들을
LLM 에게 읽히는 것은 순수한 낭비이고, 요약 카드에 섞이면 상위 함수의 컨텍스트까지
오염시킨다. 비용과 정확도가 **같은 방향으로** 개선되는 드문 지점이다.

## 판정은 근거와 함께 남긴다

`functions.is_library` 만 갱신하면 "왜 걸러졌는가"를 복원할 수 없다. 판정은
`library_verdicts` 에 method·version·confidence 와 함께 append 되고, 컬럼은
**파생 캐시**로만 다룬다 (docs/SPEC.md §7).

## 지금은 FID 가 없다

Ghidra FID 나 시그니처 DB 없이 도는 휴리스틱이다. **거짓 양성이 곧 분석 누락**
이므로 확신이 낮은 규칙은 라이브러리로 판정하지 않는다 — 판정하지 않은 함수는
그냥 분석 대상으로 남을 뿐이지만, 잘못 걸러낸 함수는 영영 안 읽힌다.
비대칭 비용이므로 규칙을 보수적으로 잡는다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from loregrind.db.models import Function

# 규칙을 고치면 올린다. 버전 없이 고치면 이전 판정과 비교할 수 없다
FILTER_VERSION = "libfilter-v1"

Method = Literal["thunk", "external", "name", "signature", "heuristic"]

# 컴파일러가 붙이는 이름들. Ghidra 가 심볼을 복원했을 때만 잡힌다
_LIBRARY_NAME_PATTERNS = (
    re.compile(r"^_+(std|CRT|RTC|Init|Tls|onexit|amsg)", re.IGNORECASE),
    re.compile(r"^(std::|__std|__scrt|__security|__report|_chk)", re.IGNORECASE),
    re.compile(r"^(mem(cpy|set|move|cmp)|str(len|cpy|cmp|cat|chr)|wcs[a-z]+)$", re.IGNORECASE),
    re.compile(r"^operator (new|delete)"),
    re.compile(r"^(malloc|free|calloc|realloc|printf|sprintf|fprintf|scanf)$", re.IGNORECASE),
)

# Ghidra 가 이름을 복원하지 못한 함수. 이름 규칙을 적용할 근거가 없다
_STRIPPED_NAME = re.compile(r"^(FUN|SUB|LAB)_[0-9a-fA-F]+$")


@dataclass(frozen=True, slots=True)
class Verdict:
    """판정 1건. `is_library=None` 은 **미판정**이며 라이브러리가 아니라는 뜻이 아니다."""

    is_library: bool
    method: Method
    confidence: float
    reason: str


def classify(func: Function) -> Verdict | None:
    """함수 하나를 판정한다. 확신이 없으면 `None` — 미판정으로 남긴다.

    반환이 `None` 이면 그 함수는 분석 대상에 남는다. 잘못 걸러내는 것보다
    한 번 더 읽는 편이 싸다 (거짓 양성 = 영구 누락).
    """
    if func.is_thunk:
        # 썽크는 정의상 다른 함수로 넘기는 코드다. 분석 가치가 없다
        return Verdict(True, "thunk", 1.0, "thunk")
    if func.is_external:
        return Verdict(True, "external", 1.0, "external symbol")

    name = func.original_name
    if not _STRIPPED_NAME.match(name):
        for pattern in _LIBRARY_NAME_PATTERNS:
            if pattern.search(name):
                # 이름이 복원된 경우에만 쓴다. 스트립된 바이너리에서는 대개 안 걸린다
                return Verdict(True, "name", 0.9, f"library name pattern: {name}")

    # **디컴파일 실패를 라이브러리로 판정하지 않는다.** 실패는 실패일 뿐이고,
    # 라이브러리로 접으면 실패율이 필터 뒤로 숨는다
    return None


@dataclass(frozen=True, slots=True)
class FilterResult:
    judged: int
    library: int
    skipped: int

    @property
    def coverage(self) -> float:
        """판정한 비율. 낮으면 필터가 사실상 일을 안 한 것이다."""
        total = self.judged + self.skipped
        return self.judged / total if total else 0.0
