"""행 dataclass — schema.sql 의 테이블과 1:1 대응.

`schema.sql` 이 DDL 단일 소스이므로 이 파일은 그것을 따라간다. 컬럼을 추가할 때는
schema.sql(또는 마이그레이션)을 먼저 고치고 여기를 맞춘다. 순서를 바꾸면 코드가
DB 에 없는 컬럼을 참조하게 된다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# 신뢰도 계층. human > emulation > agent (docs/PROJECT.md §4)
Source = Literal["agent", "emulation", "human"]
HypothesisStatus = Literal["open", "confirmed", "refuted"]


@dataclass(frozen=True, slots=True)
class Binary:
    """분석 대상 바이너리. 샘플 자체는 저장하지 않는다 (§10)."""

    sha256: str
    arch: str
    extract_schema_version: int
    function_count: int
    analyzed_at: str
    filename: str | None = None
    # 사전정보다. 결론이 아니라 가설로만 쓴다 (불변식 7)
    family_label: str | None = None
    ghidra_path: str | None = None
    ghidra_version: str | None = None
    decompile_failure_count: int = 0
    duration_sec: float | None = None
    id: int | None = None


@dataclass(frozen=True, slots=True)
class Function:
    """추출 사실. 적재 후 아무도 고치지 않는다 (불변식 1)."""

    binary_id: int
    # Ghidra 가 준 16진 문자열 그대로. 정수 변환하지 않는다
    addr: str
    original_name: str
    signature: str | None = None
    size: int | None = None
    cyclomatic: int | None = None
    is_thunk: bool = False
    is_external: bool = False
    # L3 라이브러리 필터가 채운다. None = 미판정
    is_library: bool | None = None
    decompiled: str | None = None
    # 실패는 레코드를 빼지 않고 사유를 남긴다
    decompile_error: str | None = None
    # 정규화 후 해시. 정규화 없는 해시는 히트율이 0 이다 (§4)
    code_hash: str | None = None
    cfg_hash: str | None = None
    id: int | None = None


@dataclass(frozen=True, slots=True)
class CallEdge:
    """콜 그래프 간선. 바텀업 순서와 무효화 역전파의 근거."""

    binary_id: int
    caller_addr: str
    callee_addr: str


@dataclass(frozen=True, slots=True)
class Run:
    """모든 산출물의 소속 (불변식 5).

    `config_json` 은 **API 키를 제거한 사본**이어야 한다 (§10). 설정 객체를
    통째로 직렬화하지 않는다.
    """

    run_id: str
    model: str
    prompt_version: str
    config_json: str
    seed: int | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0


@dataclass(frozen=True, slots=True)
class FunctionAnalysis:
    """에이전트 판단. append-only — 정정은 새 행 + superseded_by (불변식 3)."""

    run_id: str
    function_id: int
    source: Source
    proposed_name: str | None = None
    summary: str | None = None
    evidence_json: str | None = None
    confidence: float | None = None
    # 판단 시점의 code_hash. 이후 함수가 바뀌면 이 판단이 낡았음을 알 수 있다
    code_hash: str | None = None
    id: int | None = None
    superseded_by: int | None = None


@dataclass(frozen=True, slots=True)
class Hypothesis:
    """가설. 상태 전이도 UPDATE 가 아니라 새 행이다."""

    run_id: str
    statement: str
    status: HypothesisStatus
    function_id: int | None = None
    experiment_json: str | None = None
    result_json: str | None = None
    id: int | None = None
    superseded_by: int | None = None


@dataclass(frozen=True, slots=True)
class ExtractMeta:
    """`meta.json` 의 내용. 추출 1회분의 메타데이터."""

    sha256: str
    ghidra_version: str
    extract_schema_version: int
    analyzed_at: str
    function_count: int
    decompile_failure_count: int
    duration_sec: float | None = None
    warnings: list[str] = field(default_factory=list)
