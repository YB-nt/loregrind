"""정규화와 해싱은 결정론적이어야 한다.

이 코드가 틀리면 검색 히트율과 증분 재분석이 함께 무너지는데, **틀렸다는 신호가
눈에 보이지 않는다.** 숫자는 그대로 나온다. 그래서 단위 테스트가 필수다.
"""

from __future__ import annotations

from loregrind.extract.normalize import (
    NORMALIZE_VERSION,
    code_hash,
    normalize_decompiled,
)

# 같은 함수가 두 바이너리에서 다른 주소·다른 변수 번호로 나온 경우
CODE_A = """
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00401000(int *param_1)
{
  uint uVar1;
  int local_28;

  uVar1 = 0x9e3779b9;
  local_28 = *param_1;
  FUN_00401230(local_28, DAT_00404010);
  return;
}
"""

CODE_B = """
// different address, different register allocation
void FUN_10021abc(int *param_1)
{
  uint uVar7;
  int local_44;

  uVar7 = 0x9e3779b9;
  local_44 = *param_1;
  FUN_10021def(local_44, DAT_10024ff0);
  return;
}
"""


def test_normalization_is_deterministic() -> None:
    assert normalize_decompiled(CODE_A) == normalize_decompiled(CODE_A)
    assert code_hash(CODE_A) == code_hash(CODE_A)


def test_same_function_different_addresses_hash_equal() -> None:
    """정규화의 존재 이유. 주소·변수 번호가 달라도 같은 코드로 판정돼야 한다."""
    assert code_hash(CODE_A) == code_hash(CODE_B)


def test_different_logic_hashes_differ() -> None:
    """정규화가 과해서 서로 다른 코드를 뭉개지 않는지 확인한다."""
    other = CODE_A.replace("*param_1", "param_1[3]")
    assert code_hash(CODE_A) != code_hash(other)


def test_addresses_and_symbols_are_removed() -> None:
    out = normalize_decompiled(CODE_A)
    assert "0x401000" not in out
    assert "FUN_00401000" not in out
    assert "DAT_00404010" not in out
    assert "uVar1" not in out
    assert "local_28" not in out
    # 구조는 남아 있어야 한다 — 전부 지워버리면 해시가 무의미해진다
    assert "param_1" in out
    assert "return" in out


def test_comments_are_stripped() -> None:
    assert "WARNING" not in normalize_decompiled(CODE_A)
    assert "different address" not in normalize_decompiled(CODE_B)


def test_no_hash_without_decompilation() -> None:
    """실패한 함수에 해시를 만들지 않는다.

    빈 문자열의 해시는 모든 실패 함수에서 같아서, 무관한 함수들이 "같은 코드"로
    뭉쳐버린다.
    """
    assert code_hash(None) is None
    assert code_hash("") is None
    assert code_hash("   \n  /* only a comment */  ") is None


def test_hash_is_versioned() -> None:
    """정규화 규칙을 바꾸면 해시가 달라져야 한다 — 낡은 해시를 재사용하면 안 된다."""
    import loregrind.extract.normalize as mod

    baseline = code_hash(CODE_A)
    original = mod.NORMALIZE_VERSION
    try:
        mod.NORMALIZE_VERSION = original + 1
        assert code_hash(CODE_A) != baseline
    finally:
        mod.NORMALIZE_VERSION = original
    assert code_hash(CODE_A) == baseline
    assert original == NORMALIZE_VERSION
