"""L2 도구의 구현 (docs/SPEC.md §4.2).

**MCP SDK 에 의존하지 않는다.** SDK 바인딩은 `server.py` 가 한다. 둘을 나누는 이유:

- 도구 로직을 SDK 없이 테스트할 수 있다. 전송 계층을 띄우지 않고 계약을 고정한다
- SDK 버전이 바뀌어도 도구 계약은 그대로다

## 바이너리는 컨텍스트에 고정된다

도구 인자에 `binary_id` 를 넣지 않는다. 넣으면 (a) 에이전트가 다른 샘플을 헤집는
경로가 열리고, (b) run 하나가 바이너리 하나에 대응하지 않게 되어 §6 어블레이션의
귀속이 복잡해진다.

## 만능 도구를 만들지 않는다

`query(sql)` 같은 도구가 있으면 에이전트 행동을 귀속할 수 없고 채널·전략 어블레이션이
전부 무의미해진다. `repo.readonly_query` 는 사람이 CLI 에서 쓰는 경로이며 여기서
노출하지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from loregrind.analyze.budget import BudgetExceeded, BudgetTracker
from loregrind.db.models import FACTS_SCHEMA_VERSION
from loregrind.db.repo import Repo
from loregrind.tools.protocol import ErrorCode, check_limit, fail, ok, validate_addr

MAX_LIMIT = 200
DEFAULT_MAX_CHARS = 20_000


@dataclass(slots=True)
class ToolContext:
    """도구가 공유하는 상태. 서버 시작 시 한 번 만들어진다."""

    repo: Repo
    binary_id: int
    extract_schema_version: int
    run_id: str | None = None
    # 어블레이션 1축(리네임 쓰기 유무)의 조작 지점. 기본은 읽기 전용이다 —
    # 쓰기가 기본이면 "쓰기 없음" 조건을 만들 때마다 명시해야 하고 언젠가 빠뜨린다
    allow_writes: bool = False
    budget: BudgetTracker = field(default_factory=BudgetTracker)

    @property
    def has_facts(self) -> bool:
        """문자열·임포트가 추출되었는가. 없으면 빈 결과가 아니라 NOT_EXTRACTED 다."""
        return self.extract_schema_version >= FACTS_SCHEMA_VERSION


def _charge(ctx: ToolContext) -> dict[str, Any] | None:
    """도구 호출 1회를 예산에 계상한다. 초과면 실패 응답을 돌려준다 (불변식 8).

    예외를 여기서 흡수하는 이유는 §4.1 의 "예외를 던지지 않는다" 때문이다.
    루프는 `BUDGET_EXCEEDED` 응답을 보고 중단을 결정한다.
    """
    try:
        ctx.budget.charge_tool_call()
    except BudgetExceeded as exc:
        return fail(ErrorCode.BUDGET_EXCEEDED, str(exc))
    return None


def _resolve(ctx: ToolContext, addr: str) -> tuple[Any, dict[str, Any] | None]:
    """주소 검증 + 함수 조회. 반환은 (함수, 오류응답) — 한쪽은 항상 None."""
    problem = validate_addr(addr)
    if problem is not None:
        return None, fail(ErrorCode.INVALID_ADDR, problem)
    func = ctx.repo.get_function(ctx.binary_id, addr)
    if func is None:
        return None, fail(ErrorCode.NOT_FOUND, f"{addr} 에 함수가 없다")
    return func, None


def get_function(ctx: ToolContext, addr: str, max_chars: int = DEFAULT_MAX_CHARS) -> dict[str, Any]:
    """함수 하나의 추출 사실. 디컴파일 텍스트를 포함한다.

    `max_chars` 를 넘으면 자르고 `provenance.truncated=true` 를 세운다.
    **조용히 자르지 않는다** — 자른 줄 모르면 에이전트가 함수 후반부가 없다는 사실을
    모른 채 "이 함수는 아무것도 반환하지 않는다"고 쓴다.
    """
    if (budget_error := _charge(ctx)) is not None:
        return budget_error
    func, error = _resolve(ctx, addr)
    if error is not None:
        return error

    decompiled = func.decompiled
    truncated = False
    if decompiled is not None and len(decompiled) > max_chars:
        decompiled = decompiled[:max_chars]
        truncated = True

    return ok(
        {
            "addr": func.addr,
            "original_name": func.original_name,
            "signature": func.signature,
            "size": func.size,
            "cyclomatic": func.cyclomatic,
            "is_thunk": func.is_thunk,
            "is_external": func.is_external,
            "decompiled": decompiled,
            "decompile_error": func.decompile_error,
            "code_hash": func.code_hash,
        },
        code_hash=func.code_hash,
        truncated=truncated,
    )


def _neighbours(ctx: ToolContext, addrs: list[str]) -> list[dict[str, Any]]:
    """이웃 함수에 현재 이름을 붙인다. 없으면 None — 없는 것을 지어내지 않는다."""
    out: list[dict[str, Any]] = []
    for addr in addrs:
        func = ctx.repo.get_function(ctx.binary_id, addr)
        current = None
        if func is not None and func.id is not None:
            analysis = ctx.repo.current_analysis(func.id)
            current = analysis.proposed_name if analysis is not None else None
        out.append(
            {
                "addr": addr,
                "original_name": func.original_name if func is not None else None,
                "current_name": current,
            }
        )
    return out


def get_callers(ctx: ToolContext, addr: str, limit: int = 50) -> dict[str, Any]:
    if (budget_error := _charge(ctx)) is not None:
        return budget_error
    if (problem := check_limit(limit, MAX_LIMIT)) is not None:
        return fail(ErrorCode.TOO_MANY, problem)
    _, error = _resolve(ctx, addr)
    if error is not None:
        return error
    addrs = ctx.repo.get_callers(ctx.binary_id, addr)
    return ok(
        {"callers": _neighbours(ctx, addrs[:limit]), "total": len(addrs)},
        truncated=len(addrs) > limit,
    )


def get_callees(ctx: ToolContext, addr: str, limit: int = 50) -> dict[str, Any]:
    if (budget_error := _charge(ctx)) is not None:
        return budget_error
    if (problem := check_limit(limit, MAX_LIMIT)) is not None:
        return fail(ErrorCode.TOO_MANY, problem)
    _, error = _resolve(ctx, addr)
    if error is not None:
        return error
    addrs = ctx.repo.get_callees(ctx.binary_id, addr)
    return ok(
        {"callees": _neighbours(ctx, addrs[:limit]), "total": len(addrs)},
        truncated=len(addrs) > limit,
    )


def get_apis_used(ctx: ToolContext, addr: str) -> dict[str, Any]:
    """이 함수가 부르는 임포트 API. 추출되지 않았으면 빈 목록이 아니라 실패다."""
    if (budget_error := _charge(ctx)) is not None:
        return budget_error
    if not ctx.has_facts:
        return fail(
            ErrorCode.NOT_EXTRACTED,
            f"이 바이너리는 extract v{ctx.extract_schema_version} 로 적재되어 "
            f"임포트 정보가 없다 (필요: v{FACTS_SCHEMA_VERSION}). 재추출이 필요하다",
        )
    _, error = _resolve(ctx, addr)
    if error is not None:
        return error
    return ok({"apis": ctx.repo.get_apis_used(ctx.binary_id, addr)})


def search_strings(
    ctx: ToolContext, substring: str, limit: int = 50, min_length: int = 4
) -> dict[str, Any]:
    """부분 문자열 검색. **정규식이 아니다** (docs/SPEC.md §4.2).

    반환되는 `value` 는 신뢰 경계 밖의 텍스트다. 프롬프트로 나갈 때
    `analyze.context.wrap_untrusted` 를 반드시 거친다.
    """
    if (budget_error := _charge(ctx)) is not None:
        return budget_error
    if not ctx.has_facts:
        return fail(
            ErrorCode.NOT_EXTRACTED,
            f"이 바이너리는 extract v{ctx.extract_schema_version} 로 적재되어 "
            f"문자열이 없다 (필요: v{FACTS_SCHEMA_VERSION}). 재추출이 필요하다",
        )
    if (problem := check_limit(limit, MAX_LIMIT)) is not None:
        return fail(ErrorCode.TOO_MANY, problem)
    if not substring:
        return fail(ErrorCode.TOO_MANY, "빈 문자열로는 검색하지 않는다 — 전체 스캔이 된다")

    matches = ctx.repo.search_strings(ctx.binary_id, substring, limit=limit, min_length=min_length)
    return ok({"matches": matches, "returned": len(matches)}, truncated=len(matches) == limit)


def get_known_analysis(ctx: ToolContext, addr: str) -> dict[str, Any]:
    """이전 run 의 판단. **사실이 아니다** — provenance.source 가 그것을 밝힌다.

    `stale` 은 판단 이후 함수가 바뀌었다는 뜻이다 (§4 증분 재분석의 도구 층 노출점).
    """
    if (budget_error := _charge(ctx)) is not None:
        return budget_error
    func, error = _resolve(ctx, addr)
    if error is not None:
        return error
    if func.id is None:
        # DB 에서 읽은 행에는 항상 id 가 있다. 없다면 적재 경로가 깨진 것이므로
        # 조용히 "판단 없음"으로 답하지 않는다
        return fail(ErrorCode.NOT_FOUND, f"{addr} 의 함수 행에 id 가 없다 (적재 결함)")
    analysis = ctx.repo.current_analysis(func.id)
    if analysis is None:
        return ok({"analysis": None}, code_hash=func.code_hash)

    return ok(
        {
            "analysis": {
                "proposed_name": analysis.proposed_name,
                "summary": analysis.summary,
                "evidence": analysis.evidence_json,
                "confidence": analysis.confidence,
                "source": analysis.source,
                "code_hash": analysis.code_hash,
                # 판단 시점의 해시와 현재 해시가 다르면 이 판단은 낡았다
                "stale": analysis.code_hash != func.code_hash,
            }
        },
        source=analysis.source,
        run_id=analysis.run_id,
        code_hash=func.code_hash,
    )


def list_candidates(
    ctx: ToolContext, strategy: str = "sequential", limit: int = 20, cursor: str | None = None
) -> dict[str, Any]:
    """무엇을 먼저 읽을지. 2주차는 `sequential` 만 지원한다.

    `strategy="rank"` 를 흉내내지 않는 이유: 없는 랭킹을 순차 순서로 대신하면
    §6 어블레이션 2축의 기준선이 오염되고, 그 오염은 표에 드러나지 않는다.
    """
    if (budget_error := _charge(ctx)) is not None:
        return budget_error
    if (problem := check_limit(limit, MAX_LIMIT)) is not None:
        return fail(ErrorCode.TOO_MANY, problem)
    if strategy == "rank":
        return fail(
            ErrorCode.NOT_EXTRACTED,
            "strategy='rank' 는 L3 랭킹(§7 3주차)이 붙어야 동작한다. "
            "지금 순차 순서로 대신하면 어블레이션 기준선이 오염된다",
        )
    if strategy != "sequential":
        return fail(
            ErrorCode.NOT_EXTRACTED, f"지원하지 않는 strategy: {strategy!r} (지금은 'sequential')"
        )

    rows = ctx.repo.list_functions(ctx.binary_id, after_addr=cursor, limit=limit + 1)
    has_more = len(rows) > limit
    page = rows[:limit]
    return ok(
        {
            "candidates": [
                {
                    "addr": row["addr"],
                    "original_name": row["original_name"],
                    # 순차 전략에는 점수가 없다. 0.0 을 넣으면 점수가 있는 척이 된다
                    "score": None,
                    "reasons": ["sequential order"],
                }
                for row in page
            ],
            "next_cursor": page[-1]["addr"] if has_more and page else None,
            "strategy": strategy,
        },
        truncated=has_more,
    )


# 읽기 전용 도구 목록. server.py 와 테스트가 같은 목록을 본다
READ_TOOLS = (
    get_function,
    get_callers,
    get_callees,
    get_apis_used,
    search_strings,
    get_known_analysis,
    list_candidates,
)
