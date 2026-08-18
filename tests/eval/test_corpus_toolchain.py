"""툴체인 게이트 (§2 범위 + §6).

여기서 고정하는 것 하나: **PE 를 못 만들면 코퍼스 생성이 실패한다.**
경고로 두면 누군가 그 코퍼스로 표를 채우고, 그 표는 무엇을 잰 것인지
알 수 없는 숫자가 된다.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from eval.corpus.toolchain import (
    NoPeToolchain,
    NotPeOutput,
    Toolchain,
    assert_pe,
    detect,
    detect_format,
    pe_toolchains,
    require_pe,
)

CLANG = Toolchain(compiler="clang", path="/usr/bin/clang", expects_pe=False)
MINGW = Toolchain(compiler="mingw64", path="/opt/bin/x86_64-w64-mingw32-gcc", expects_pe=True)


def test_non_pe_toolchain_is_refused_not_warned() -> None:
    with pytest.raises(NoPeToolchain) as exc:
        require_pe([CLANG])
    # 무엇을 설치해야 하는지 알려준다 — 모르면 Mach-O 로 우회할 유혹이 생긴다
    assert "mingw-w64" in str(exc.value)
    assert "clang" in str(exc.value)


def test_empty_toolchain_list_is_refused() -> None:
    with pytest.raises(NoPeToolchain):
        require_pe([])


def test_pe_toolchain_passes_the_gate() -> None:
    assert require_pe([CLANG, MINGW]) == [MINGW]
    assert pe_toolchains([CLANG, MINGW]) == [MINGW]


def test_format_is_judged_by_magic_bytes_not_the_toolchain(tmp_path: Path) -> None:
    """툴체인의 주장이 아니라 산출물이 근거다."""
    pe = tmp_path / "a.exe"
    pe.write_bytes(b"MZ\x90\x00rest")
    macho = tmp_path / "b"
    macho.write_bytes(b"\xcf\xfa\xed\xfe rest")
    elf = tmp_path / "c"
    elf.write_bytes(b"\x7fELF rest")

    other = tmp_path / "d"
    other.write_bytes(b"??rest")

    assert detect_format(pe) == "pe"
    assert detect_format(macho) == "macho"
    assert detect_format(elf) == "elf"
    # 모르는 포맷을 PE 로 봐주지 않는다
    assert detect_format(other) == "unknown"


def test_assert_pe_catches_a_lying_toolchain(tmp_path: Path) -> None:
    """`mingw` 이름을 달고도 Mach-O 를 낼 수 있다 — sysroot 가 깨지면."""
    out = tmp_path / "out"
    out.write_bytes(b"\xcf\xfa\xed\xfe")
    with pytest.raises(NotPeOutput, match="macho"):
        assert_pe(out)

    good = tmp_path / "good.exe"
    good.write_bytes(b"MZ\x90\x00")
    assert_pe(good)  # 세우지 않는다


def test_strip_never_relocates_code() -> None:
    """정답 주소는 '스트립이 코드를 옮기지 않는다'에 의존한다."""
    cmd = MINGW.strip_command(Path("x.exe"))
    # strip 이 없는 환경도 있으므로 None 허용. 있으면 --strip-all 이어야 한다
    assert cmd is None or "--strip-all" in cmd


def test_detect_returns_real_toolchains() -> None:
    """이 기계에 무엇이 있든 형태는 지켜야 한다."""
    for tc in detect():
        assert tc.path and Path(tc.path).name
        assert tc.compiler
