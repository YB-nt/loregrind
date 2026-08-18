"""툴체인 탐지 — **PE 를 못 만들면 코퍼스를 만들지 않는다** (§2).

## 왜 거부가 기본인가

`docs/PROJECT.md` §2 는 x86/x64 **PE** 정적 분석으로 범위를 못 박았다. 여기서
Mach-O 나 ELF 코퍼스를 조용히 만들면 두 가지가 동시에 망가진다 —

1. 범위 이탈. 안 하기로 한 것을 하게 된다
2. **숫자가 무의미해진다.** Mach-O 에서 잰 명명 정확도는 PE 분석기의 성능이 아니다

그래서 "PE 툴체인이 없다"는 경고가 아니라 실패다. 경고로 두면 누군가 그 코퍼스로
표를 채우고, 그 표는 무엇을 잰 것인지 알 수 없는 숫자가 된다.

## 툴체인의 주장을 믿지 않는다

컴파일러 이름이 `x86_64-w64-mingw32-gcc` 라고 PE 가 나온다는 보장은 없다 —
sysroot 가 깨져 있거나 래퍼가 다른 타깃을 가리킬 수 있다. 그래서 **실제 산출물의
매직바이트**로 판정한다 (`assert_pe`). 이것이 `extract/runner.py` 가 "종료 코드 0 을
믿지 않는다"고 한 것과 같은 규율이다.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

BinaryFormat = Literal["pe", "elf", "macho", "unknown"]

# EVAL-SPEC §2 의 격자 축. 셀 표기는 `<compiler>:<opt>` 로 고정된다
OPT_LEVELS = ("-O0", "-O1", "-O2", "-O3")

# 이름 → (격자에 쓸 compiler 이름, PE 를 낼 것으로 **기대되는가**).
# 기대일 뿐이고 판정은 산출물이 한다
_KNOWN = (
    ("x86_64-w64-mingw32-gcc", "mingw64", True),
    ("i686-w64-mingw32-gcc", "mingw32", True),
    ("cl.exe", "msvc", True),
    ("cl", "msvc", True),
    ("zig", "zig", True),
    # 아래는 PE 를 못 낸다. 탐지는 하되 코퍼스 생성에는 쓰지 않는다 —
    # "없다"와 "있지만 쓸 수 없다"를 구별해서 보고하기 위해서다
    ("gcc", "gcc", False),
    ("clang", "clang", False),
)


class NoPeToolchain(RuntimeError):
    """PE 를 만들 수 있는 컴파일러가 없다. 코퍼스 생성을 시작하지 않는다."""


class NotPeOutput(RuntimeError):
    """컴파일은 됐는데 PE 가 아니다. 툴체인의 주장과 산출물이 다르다."""


@dataclass(frozen=True, slots=True)
class Toolchain:
    """격자의 컴파일러 축 하나."""

    compiler: str
    path: str
    expects_pe: bool

    def command(self, source: Path, out: Path, opt: str) -> list[str]:
        """컴파일 명령. 즉석에서 조립하지 않는다 (`extract/runner.py` 와 같은 이유)."""
        if self.compiler == "msvc":
            return [self.path, str(source), f"/Fe{out}", "/O2" if opt != "-O0" else "/Od"]
        if self.compiler == "zig":
            return [
                self.path,
                "cc",
                "-target",
                "x86_64-windows-gnu",
                opt,
                str(source),
                "-o",
                str(out),
            ]
        return [self.path, opt, str(source), "-o", str(out)]

    def strip_command(self, path: Path) -> list[str] | None:
        """심볼 제거 명령. **주소를 옮기지 않는 방식만 쓴다.**

        `strip` 은 심볼 테이블만 지우고 코드 섹션을 재배치하지 않는다. 그래서
        언스트립 빌드에서 읽은 주소가 스트립 빌드에서도 그대로 유효하고,
        그것이 정답 주소의 근거다. 재배치하는 도구를 쓰면 정답이 어긋난다.
        """
        if self.compiler == "msvc":
            # MSVC 는 심볼을 PDB 로 분리한다. PDB 를 안 주면 그것이 곧 스트립이다
            return None
        strip = shutil.which(f"{self.path}-strip") or shutil.which("strip")
        return [strip, "--strip-all", str(path)] if strip else None


def detect() -> list[Toolchain]:
    """PATH 에서 알려진 컴파일러를 찾는다. 순서는 `_KNOWN` 이 정한다."""
    found: list[Toolchain] = []
    seen: set[str] = set()
    for exe, compiler, expects_pe in _KNOWN:
        path = shutil.which(exe)
        if path is None or compiler in seen:
            continue
        seen.add(compiler)
        found.append(Toolchain(compiler=compiler, path=path, expects_pe=expects_pe))
    return found


def pe_toolchains(available: list[Toolchain] | None = None) -> list[Toolchain]:
    return [t for t in (available if available is not None else detect()) if t.expects_pe]


def require_pe(available: list[Toolchain] | None = None) -> list[Toolchain]:
    """PE 툴체인을 요구한다. 없으면 **세운다.**

    메시지가 길다. "없다"만 알려주면 다음 사람이 무엇을 설치해야 하는지 몰라
    Mach-O 로 우회할 유혹이 생긴다.
    """
    found = available if available is not None else detect()
    usable = pe_toolchains(found)
    if usable:
        return usable
    others = ", ".join(f"{t.compiler}({t.path})" for t in found) or "없음"
    raise NoPeToolchain(
        "PE 를 만들 수 있는 컴파일러가 없다. §2 범위가 PE 전용이므로 "
        "다른 포맷으로 코퍼스를 만들면 지표가 무엇을 잰 것인지 알 수 없어진다.\n"
        f"  탐지된 컴파일러: {others}\n"
        "  설치 후보: mingw-w64 (`brew install mingw-w64`), zig, MSVC"
    )


def detect_format(path: Path) -> BinaryFormat:
    """**매직바이트로 판정한다.** 툴체인의 주장이 아니라 산출물이 근거다."""
    with path.open("rb") as fh:
        head = fh.read(4)
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macho"
    return "unknown"


def assert_pe(path: Path) -> None:
    """산출물이 PE 가 아니면 세운다. 코퍼스에 섞이기 전에 잡는다."""
    fmt = detect_format(path)
    if fmt != "pe":
        raise NotPeOutput(
            f"{path} 는 PE 가 아니다 (판정: {fmt}). 툴체인이 PE 를 낸다고 했지만 "
            "실제 산출물이 다르다 — sysroot 나 타깃 설정을 확인하라"
        )
