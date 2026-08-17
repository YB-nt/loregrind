"""L2 도구의 공통 응답 규약 (docs/SPEC.md §4.1).

모든 도구가 같은 형태를 반환한다. 형태가 도구마다 다르면 에이전트가 각각을 따로
배워야 하고, 실패를 성공으로 오독하는 경로가 도구 수만큼 생긴다.

    성공: {"ok": true,  "data": {...}, "provenance": {...}}
    실패: {"ok": false, "error": {"code": "...", "message": "..."}}

**예외를 던지지 않는다.** MCP 도구에서 예외는 전송 계층 오류가 되어 에이전트가
"도구가 고장났다"와 "그 주소에 함수가 없다"를 구별하지 못한다.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any, Literal

# functions.addr 와 같은 표기. 정수를 받지도 반환하지도 않는다
ADDR_PATTERN = re.compile(r"^0x[0-9a-f]+$")

ProvenanceSource = Literal["extraction", "agent", "emulation", "human"]


class ErrorCode(StrEnum):
    """실패 사유. 에이전트가 분기할 수 있어야 하므로 문자열 코드를 준다."""

    NOT_FOUND = "NOT_FOUND"
    INVALID_ADDR = "INVALID_ADDR"
    # **빈 결과와 구별된다.** 빈 배열을 주면 "문자열이 없는 바이너리"로 오독한다
    NOT_EXTRACTED = "NOT_EXTRACTED"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    WRITE_DISABLED = "WRITE_DISABLED"
    TOO_MANY = "TOO_MANY"


def ok(data: dict[str, Any], **provenance: Any) -> dict[str, Any]:
    """성공 응답.

    `provenance.source` 의 기본값이 `extraction` 인 것이 중요하다 — 판단을 반환하는
    도구가 명시적으로 덮어써야 하고, 잊으면 사실로 표시되는 것이 아니라 잊었다는
    사실이 리뷰에 걸린다.
    """
    prov: dict[str, Any] = {"source": provenance.pop("source", "extraction")}
    prov.update(provenance)
    prov.setdefault("truncated", False)
    return {"ok": True, "data": data, "provenance": prov}


def fail(code: ErrorCode, message: str) -> dict[str, Any]:
    return {"ok": False, "error": {"code": str(code), "message": message}}


def validate_addr(addr: str) -> str | None:
    """주소 형식 검사. 통과하면 None, 아니면 오류 메시지.

    대문자 16진을 조용히 소문자로 고치지 않는다 — 표기가 흔들리면 같은 함수에 대한
    질의가 두 가지 형태로 갈라지고, 그중 하나만 캐시에 맞는다.
    """
    if not ADDR_PATTERN.match(addr):
        return f"주소는 소문자 16진 문자열이어야 한다 (예: 0x401000). 받은 값: {addr!r}"
    return None


def check_limit(limit: int, maximum: int) -> str | None:
    if limit < 1:
        return f"limit 은 1 이상이어야 한다. 받은 값: {limit}"
    if limit > maximum:
        return f"limit 상한은 {maximum} 이다. 받은 값: {limit}"
    return None
