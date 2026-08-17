"""디컴파일 C 의 정규화와 해싱.

**정규화 없는 해시는 히트율이 사실상 0 이다** (docs/PROJECT.md §4). 같은 함수가 다른
바이너리에서 다른 주소에 놓이고, Ghidra 의 변수 명명(`uVar1`, `local_28`)이 레지스터
할당과 스택 레이아웃에 따라 달라지기 때문이다. 주소·변수 번호·스택 오프셋을 지운
뒤에야 "같은 코드"를 같다고 판정할 수 있다.

이 모듈은 **결정론적이어야 한다.** 같은 입력에 항상 같은 해시를 낸다. 정규화 규칙을
바꾸면 기존 `code_hash` 전부가 무효가 되므로 `NORMALIZE_VERSION` 을 올리고
재적재 계획을 함께 세운다.
"""

from __future__ import annotations

import hashlib
import re

# 정규화 규칙을 바꿀 때마다 올린다. 해시 호환성의 경계다
NORMALIZE_VERSION = 1

# 규칙 적용 순서가 결과를 바꾼다. 아래 순서를 유지한다 —
# 심볼 이름(FUN_00401000) 안에 16진 주소가 들어 있으므로 심볼을 먼저 지워야
# 주소 규칙이 심볼을 반쪽으로 자르지 않는다.
_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    # 1. 주석 — Ghidra 가 붙이는 /* WARNING: ... */ 등. 내용이 버전마다 달라진다
    (re.compile(r"/\*.*?\*/", re.DOTALL), " "),
    (re.compile(r"//[^\n]*"), " "),
    # 2. Ghidra 자동 생성 심볼. 뒤의 주소까지 통째로 치환한다
    (re.compile(r"\bFUN_[0-9a-fA-F]+\b"), "FUN"),
    (re.compile(r"\b(DAT|PTR|LAB|UNK|SUB|EXT|switchD)_[0-9a-fA-F_]+\b"), "SYM"),
    # 문자열 참조 심볼: s_hello_world_00401234 → STR
    (re.compile(r"\bs_[A-Za-z0-9_]*?_[0-9a-fA-F]{6,}\b"), "STR"),
    # 3. 지역 변수·스택 슬롯. 번호는 레지스터 할당 결과라 의미가 없다
    (
        re.compile(r"\b(local|auStack|acStack|aiStack|afStack|puStack|piStack)_[0-9a-fA-F]+\b"),
        "LOC",
    ),
    # uVar1, iVar12, cVar3, pcVar4, fVar5 ... Ghidra 의 타입접두사+Var+번호
    (re.compile(r"\b[a-z]{1,3}Var[0-9]+\b"), "VAR"),
    # unaff_EBX, in_EAX, extraout_ECX, register0x00000010
    (re.compile(r"\b(unaff|in|extraout|out)_[A-Za-z0-9_]+\b"), "REG"),
    (re.compile(r"\bregister0x[0-9a-fA-F]+\b"), "REG"),
    # 4. 남은 16진 리터럴. 상수 자체는 신호이지만 주소로 쓰인 것과 구분할 수 없다.
    #    §5 의 "희귀 상수" 채널은 정규화 전 원본에서 따로 뽑는다
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "HEX"),
    # 5. 공백 정리 — 마지막에 한 번
    (re.compile(r"\s+"), " "),
)


def normalize_decompiled(code: str) -> str:
    """디컴파일 C 를 정규화한다. 결정론적이다."""
    out = code
    for pattern, replacement in _RULES:
        out = pattern.sub(replacement, out)
    return out.strip()


def code_hash(code: str | None) -> str | None:
    """정규화 후 sha256. 디컴파일이 없으면 None 을 돌려준다.

    실패한 함수에 해시를 만들지 않는 이유: 빈 문자열의 해시는 모든 실패 함수에서
    동일해서, 서로 무관한 함수들이 "같은 코드"로 뭉쳐버린다.
    """
    if code is None:
        return None
    normalized = normalize_decompiled(code)
    if not normalized:
        return None
    payload = f"v{NORMALIZE_VERSION}\n{normalized}".encode()
    return hashlib.sha256(payload).hexdigest()


def file_sha256(path: str, chunk_size: int = 1 << 20) -> str:
    """파일 해시. 바이너리를 메모리에 통째로 올리지 않는다."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()
