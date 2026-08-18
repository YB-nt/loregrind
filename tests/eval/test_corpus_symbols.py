"""심볼 추출 (§6) — 정답 이름과 주소의 근거.

여기서 고정하는 것 둘:
1. **장식을 벗긴다** — 안 벗기면 같은 함수의 빌드들이 다른 이름으로 갈라져
   `pairs` 가 비고 검색 Recall@k 의 정답이 사라진다
2. **빈 결과를 성공으로 치지 않는다** — 심볼 0개는 "함수 없음"이 아니라 결함이다
"""

from __future__ import annotations

from pathlib import Path

import pytest

from eval.corpus.symbols import (
    SymbolReadError,
    normalize_addr,
    parse_nm,
    read_symbols,
    undecorate,
)

NM_OUTPUT = """\
0000000000401000 T rc4_init
0000000000401108 T _rc4_crypt
000000000040120c T _xor_decode@12
0000000000403000 D kBase64Alphabet
                 U printf
0000000000401300 t helper_local
"""


def test_only_code_symbols_survive() -> None:
    names = {s.name for s in parse_nm(NM_OUTPUT)}
    assert names == {"rc4_init", "rc4_crypt", "xor_decode", "helper_local"}
    assert "kBase64Alphabet" not in names  # 데이터
    assert "printf" not in names  # undefined


def test_decoration_is_stripped_so_pairs_survive() -> None:
    assert undecorate("_rc4_init") == "rc4_init"
    assert undecorate("_xor_decode@12") == "xor_decode"
    assert undecorate("rc4_init") == "rc4_init"


def test_double_underscore_is_kept() -> None:
    """`__scrt_common_main` 의 두 번째 밑줄까지 벗기면 다른 함수가 뭉친다."""
    assert undecorate("__scrt_common_main") == "__scrt_common_main"


def test_addresses_match_the_functions_addr_convention() -> None:
    assert normalize_addr("0000000000401000") == "0x401000"
    assert normalize_addr("401000") == "0x401000"
    assert normalize_addr("0") == "0x0"
    assert all(s.addr.startswith("0x") for s in parse_nm(NM_OUTPUT))


def test_duplicate_names_keep_one_address() -> None:
    """둘 다 넣으면 명명 정확도의 분모가 부푼다."""
    dupes = "0000000000401000 T rc4_init\n0000000000402000 T _rc4_init\n"
    parsed = parse_nm(dupes)
    assert len(parsed) == 1
    assert parsed[0].addr == "0x401000"


def test_symbols_are_sorted_for_determinism() -> None:
    addrs = [s.addr for s in parse_nm(NM_OUTPUT)]
    assert addrs == sorted(addrs)


def test_missing_binary_is_reported(tmp_path: Path) -> None:
    with pytest.raises(SymbolReadError):
        read_symbols(tmp_path / "nope.exe")


def test_stripped_binary_yields_an_error_not_an_empty_truthset(tmp_path: Path) -> None:
    """심볼 0개로 정답셋을 만들면 모든 지표가 n=0 이 되고 '측정했다'는 착시가 생긴다."""
    empty = tmp_path / "stripped"
    empty.write_bytes(b"MZ\x90\x00")
    with pytest.raises(SymbolReadError, match="심볼"):
        read_symbols(empty, nm_path="/usr/bin/true")
