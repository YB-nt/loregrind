"""심볼 추출 — 정답 이름과 주소의 근거 (§6).

## 왜 언스트립 빌드에서 읽는가

에이전트가 보는 것은 **스트립된** 바이너리다. 정답은 **언스트립** 빌드에서 읽는다.
둘이 같은 주소를 가리킬 수 있는 근거는 하나다 — `strip --strip-all` 은 심볼
테이블만 지우고 코드 섹션을 재배치하지 않는다. 재배치하는 도구를 쓰면 이 전제가
깨지고 정답이 통째로 어긋난다 (`toolchain.strip_command` 참조).

## 이름 장식을 벗긴다

같은 소스 함수가 툴체인마다 다른 이름으로 나온다 — Mach-O/32비트 PE 는 `_rc4_init`,
stdcall 은 `_rc4_init@12`. 벗기지 않으면 **같은 함수의 서로 다른 빌드가 다른
`source_symbol` 로 갈라져** `pairs` 가 비고, 검색 Recall@k 의 정답이 사라진다.

## 주소 표기

`functions.addr` 와 같은 소문자 16진 문자열(`"0x401000"`)로 맞춘다. 표기가 갈리면
정답셋과 DB 를 조인할 수 없고, 그 실패는 "정확도 0%" 로 보인다.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

# `nm` 출력 한 줄: "0000000000401000 T rc4_init"
# 주소가 없는 심볼(undefined)은 공백으로 시작하므로 매치되지 않는다
_NM_LINE = re.compile(r"^(?P<addr>[0-9a-fA-F]+)\s+(?P<type>[A-Za-z])\s+(?P<name>\S+)$")

# 코드 심볼만 본다. T/t = text, 나머지(D/B/R…)는 데이터다
_CODE_TYPES = frozenset({"T", "t"})

# stdcall/fastcall 장식: `@12`, `@@GLIBCXX_3.4`
_DECORATION = re.compile(r"[@].*$")


class SymbolReadError(RuntimeError):
    """심볼을 읽을 수 없다. 조용히 빈 정답셋을 만들지 않는다."""


@dataclass(frozen=True, slots=True)
class Symbol:
    addr: str
    name: str


def undecorate(raw: str) -> str:
    """툴체인이 붙인 장식을 벗긴다.

    선행 밑줄은 **하나만** 벗긴다. `__scrt_common_main` 같은 이름의 두 번째
    밑줄까지 벗기면 서로 다른 함수가 같은 이름으로 뭉친다.
    """
    name = _DECORATION.sub("", raw)
    if name.startswith("_") and not name.startswith("__"):
        name = name[1:]
    return name


def normalize_addr(raw: str) -> str:
    """`functions.addr` 와 같은 표기로. 앞의 0 을 지우되 최소 한 자리는 남긴다."""
    return f"0x{int(raw, 16):x}"


def parse_nm(output: str) -> list[Symbol]:
    """`nm` 출력을 파싱한다. 중복 이름은 첫 주소만 남긴다.

    같은 이름이 여러 주소에 나오면(썽크·ICF 병합) 어느 쪽이 정답인지 알 수 없다.
    **둘 다 넣으면 명명 정확도의 분모가 부풀고**, 하나를 고르면 임의 선택이다.
    첫 주소만 남기고 그 사실을 호출부가 알 수 있게 개수를 줄인다.
    """
    seen: dict[str, Symbol] = {}
    for line in output.splitlines():
        match = _NM_LINE.match(line.strip())
        if match is None or match.group("type") not in _CODE_TYPES:
            continue
        name = undecorate(match.group("name"))
        if name in seen:
            continue
        seen[name] = Symbol(addr=normalize_addr(match.group("addr")), name=name)
    return sorted(seen.values(), key=lambda s: s.addr)


def read_symbols(binary: Path, nm_path: str | None = None) -> list[Symbol]:
    """언스트립 빌드에서 코드 심볼을 읽는다."""
    tool = nm_path or shutil.which("nm")
    if tool is None:
        raise SymbolReadError("`nm` 이 없다. 정답 주소를 읽을 수 없다")
    if not binary.is_file():
        raise SymbolReadError(f"{binary} 가 없다")

    # S603: 인자는 여기서 조립했고 셸을 거치지 않는다. 대상은 컴파일 산출물이며
    # 실행되지 않는다 — nm 은 파일을 읽기만 한다 (§10)
    proc = subprocess.run(  # noqa: S603
        [tool, str(binary)], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise SymbolReadError(f"nm 실패 ({proc.returncode}): {proc.stderr.strip()[:200]}")

    symbols = parse_nm(proc.stdout)
    if not symbols:
        # 심볼이 0 개면 언스트립 빌드가 아니거나 nm 이 이 포맷을 못 읽는 것이다.
        # 빈 정답셋으로 진행하면 모든 지표가 n=0 이 되고 "측정했다"는 착시가 생긴다
        raise SymbolReadError(
            f"{binary} 에서 코드 심볼을 하나도 못 읽었다. "
            "언스트립 빌드가 맞는지, nm 이 이 포맷을 지원하는지 확인하라"
        )
    return symbols
