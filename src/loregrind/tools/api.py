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

import json
import random
import re
from dataclasses import dataclass, field
from typing import Any

from loregrind.analyze.budget import BudgetExceeded, BudgetTracker
from loregrind.db.models import FACTS_SCHEMA_VERSION, FunctionAnalysis, Hypothesis
from loregrind.db.repo import Repo
from loregrind.tools.protocol import ErrorCode, check_limit, fail, ok, validate_addr

MAX_LIMIT = 200
DEFAULT_MAX_CHARS = 20_000
# 제안 이름은 C 식별자여야 한다. Ghidra apply(L5)에서 깨지지 않게 여기서 막는다
_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


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


_STRATEGIES = frozenset({"rank", "sequential", "random"})


def _rank_candidates(ctx: ToolContext, limit: int, cursor: str | None) -> dict[str, Any]:
    """L3 점수 순. 점수가 없으면 **순차로 대신하지 않는다.**

    없는 랭킹을 순차 순서로 흉내내면 §6 어블레이션 2축의 기준선이 오염되고,
    그 오염은 지표 표에 드러나지 않는다.
    """
    if ctx.run_id is None or not ctx.repo.has_scores(ctx.run_id):
        return fail(
            ErrorCode.NOT_EXTRACTED,
            "이 run 에 랭킹 점수가 없다. `loregrind rank` 를 먼저 돌려라 — "
            "순차 순서로 대신하면 어블레이션 기준선이 오염된다",
        )
    offset = int(cursor) if cursor else 0
    rows = ctx.repo.ranked_functions(ctx.run_id, ctx.binary_id, limit=limit + 1, offset=offset)
    has_more = len(rows) > limit
    page = rows[:limit]
    return ok(
        {
            "candidates": [
                {
                    "addr": row["addr"],
                    "original_name": row["original_name"],
                    "score": row["score"],
                    "reasons": json.loads(row["reasons_json"]),
                }
                for row in page
            ],
            "next_cursor": str(offset + limit) if has_more else None,
            "strategy": "rank",
        },
        truncated=has_more,
    )


def _random_candidates(ctx: ToolContext, limit: int) -> dict[str, Any]:
    """무작위 순서 — 어블레이션의 바닥선.

    **`runs.seed` 를 쓴다.** 시드 없는 무작위는 재현되지 않고, 재현되지 않는
    바닥선과 비교한 개선폭은 숫자가 아니다.
    """
    if ctx.run_id is None:
        return fail(ErrorCode.NOT_EXTRACTED, "run 없이는 무작위 순서를 재현할 수 없다")
    run = ctx.repo.get_run(ctx.run_id)
    seed = (run or {}).get("seed")
    if seed is None:
        return fail(
            ErrorCode.NOT_EXTRACTED,
            "runs.seed 가 없다. 시드 없는 무작위는 재현되지 않으므로 "
            "어블레이션 바닥선으로 쓸 수 없다 (`--seed` 로 지정하라)",
        )
    rows = ctx.repo.list_functions(ctx.binary_id, limit=MAX_LIMIT)
    rng = random.Random(int(seed))  # noqa: S311 - 암호용이 아니라 어블레이션 바닥선이다
    rng.shuffle(rows)
    return ok(
        {
            "candidates": [
                {
                    "addr": row["addr"],
                    "original_name": row["original_name"],
                    "score": None,
                    "reasons": [f"random order (seed={seed})"],
                }
                for row in rows[:limit]
            ],
            "next_cursor": None,
            "strategy": "random",
        },
        truncated=len(rows) > limit,
    )


def list_candidates(
    ctx: ToolContext, strategy: str = "sequential", limit: int = 20, cursor: str | None = None
) -> dict[str, Any]:
    """무엇을 먼저 읽을지. `rank` | `sequential` | `random` — §6 어블레이션 2축.

    **세 전략이 같은 인터페이스로 교체 가능해야** 어블레이션이 성립한다. 어느
    하나가 다른 shape 을 돌려주면 소비측이 전략마다 갈라지고, 그 순간 비교 대상이
    "전략"이 아니라 "전략 + 소비 코드"가 된다.
    """
    if (budget_error := _charge(ctx)) is not None:
        return budget_error
    if (problem := check_limit(limit, MAX_LIMIT)) is not None:
        return fail(ErrorCode.TOO_MANY, problem)
    if strategy not in _STRATEGIES:
        return fail(
            ErrorCode.NOT_EXTRACTED,
            f"지원하지 않는 strategy: {strategy!r} (허용: {', '.join(sorted(_STRATEGIES))})",
        )

    if strategy == "rank":
        return _rank_candidates(ctx, limit, cursor)
    if strategy == "random":
        return _random_candidates(ctx, limit)

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


# -- 쓰기 도구 (§7 3주차) ----------------------------------------------------
#
# **어블레이션 1축의 조작 지점이다.** `ctx.allow_writes` 가 꺼져 있으면 전부
# `WRITE_DISABLED` 를 반환한다. 기본값이 꺼짐인 이유: 켜짐이 기본이면 "쓰기 없음"
# 조건을 만들 때마다 명시해야 하고 언젠가 빠뜨린다.


def _write_guard(ctx: ToolContext) -> dict[str, Any] | None:
    if not ctx.allow_writes:
        return fail(
            ErrorCode.WRITE_DISABLED,
            "이 run 은 읽기 전용이다 (어블레이션 1축: rename_writes=false)",
        )
    if ctx.run_id is None:
        return fail(ErrorCode.WRITE_DISABLED, "run 없이 판단을 남길 수 없다 (불변식 5)")
    return None


def record_analysis(
    ctx: ToolContext,
    addr: str,
    proposed_name: str,
    summary: str,
    evidence: list[dict[str, Any]] | None = None,
    confidence: float | None = None,
) -> dict[str, Any]:
    """판단을 남긴다. `source='agent'` 고정 — 자기 신뢰 등급을 올릴 수 없다."""
    if (budget_error := _charge(ctx)) is not None:
        return budget_error
    if (denied := _write_guard(ctx)) is not None:
        return denied
    func, error = _resolve(ctx, addr)
    if error is not None:
        return error
    if func.id is None:
        return fail(ErrorCode.NOT_FOUND, f"{addr} 의 함수 행에 id 가 없다 (적재 결함)")

    assert ctx.run_id is not None  # noqa: S101 - _write_guard 가 이미 확인했다
    analysis_id = ctx.repo.insert_analysis(
        FunctionAnalysis(
            run_id=ctx.run_id,
            function_id=func.id,
            source="agent",
            proposed_name=proposed_name or None,
            summary=summary or None,
            evidence_json=json.dumps(evidence or [], ensure_ascii=False),
            confidence=confidence,
            code_hash=func.code_hash,
        )
    )
    return ok({"analysis_id": analysis_id, "addr": addr}, source="agent", run_id=ctx.run_id)


def record_hypothesis(
    ctx: ToolContext, statement: str, addr: str | None = None, experiment: str | None = None
) -> dict[str, Any]:
    """가설을 남긴다. **`status='open'` 으로만 생성된다.**

    확정·반증은 에뮬레이션(§7 9-10주차)이 한다 — 에이전트가 자기 가설을 스스로
    확정할 수 있으면 검증 루프가 자기 확인으로 무너진다.
    """
    if (budget_error := _charge(ctx)) is not None:
        return budget_error
    if (denied := _write_guard(ctx)) is not None:
        return denied

    function_id = None
    if addr is not None:
        func, error = _resolve(ctx, addr)
        if error is not None:
            return error
        function_id = func.id

    assert ctx.run_id is not None  # noqa: S101 - _write_guard 가 이미 확인했다
    hypothesis_id = ctx.repo.insert_hypothesis(
        Hypothesis(
            run_id=ctx.run_id,
            function_id=function_id,
            statement=statement,
            status="open",
            experiment_json=json.dumps({"plan": experiment}, ensure_ascii=False)
            if experiment
            else None,
        )
    )
    return ok({"hypothesis_id": hypothesis_id, "status": "open"}, source="agent", run_id=ctx.run_id)


def rename_function(ctx: ToolContext, addr: str, name: str) -> dict[str, Any]:
    """함수 이름을 제안한다. **DB 에만 쓴다** (불변식 2).

    Ghidra 반영은 L5 의 단방향 배치 apply 다. 여기서 Ghidra 를 만지면 DB 가 단일
    진실 소스가 아니게 되고, 역방향 동기화 경로가 생긴다.
    """
    if (budget_error := _charge(ctx)) is not None:
        return budget_error
    if (denied := _write_guard(ctx)) is not None:
        return denied
    if not _NAME_PATTERN.match(name):
        return fail(
            ErrorCode.INVALID_ADDR,
            f"이름은 C 식별자여야 한다 (^[A-Za-z_][A-Za-z0-9_]{{0,127}}$). 받은 값: {name!r}",
        )
    func, error = _resolve(ctx, addr)
    if error is not None:
        return error
    if func.id is None:
        return fail(ErrorCode.NOT_FOUND, f"{addr} 의 함수 행에 id 가 없다 (적재 결함)")

    assert ctx.run_id is not None  # noqa: S101 - _write_guard 가 이미 확인했다
    analysis_id = ctx.repo.insert_analysis(
        FunctionAnalysis(
            run_id=ctx.run_id,
            function_id=func.id,
            source="agent",
            proposed_name=name,
            code_hash=func.code_hash,
        )
    )
    # 리네임이 이후 컨텍스트에 전파된다 — 이것이 어블레이션 1축이 재는 효과다
    return ok(
        {"addr": addr, "name": name, "analysis_id": analysis_id, "applied_to_ghidra": False},
        source="agent",
        run_id=ctx.run_id,
    )


def set_comment(ctx: ToolContext, addr: str, text: str) -> dict[str, Any]:
    """주석을 남긴다. `rename_function` 과 같이 DB 에만 쓴다."""
    if (budget_error := _charge(ctx)) is not None:
        return budget_error
    if (denied := _write_guard(ctx)) is not None:
        return denied
    func, error = _resolve(ctx, addr)
    if error is not None:
        return error
    if func.id is None:
        return fail(ErrorCode.NOT_FOUND, f"{addr} 의 함수 행에 id 가 없다 (적재 결함)")

    assert ctx.run_id is not None  # noqa: S101 - _write_guard 가 이미 확인했다
    analysis_id = ctx.repo.insert_analysis(
        FunctionAnalysis(
            run_id=ctx.run_id,
            function_id=func.id,
            source="agent",
            summary=text,
            code_hash=func.code_hash,
        )
    )
    return ok(
        {"addr": addr, "analysis_id": analysis_id, "applied_to_ghidra": False},
        source="agent",
        run_id=ctx.run_id,
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

# 쓰기 도구. `allow_writes` 가 꺼져 있으면 전부 WRITE_DISABLED 를 반환한다
WRITE_TOOLS = (
    record_analysis,
    record_hypothesis,
    rename_function,
    set_comment,
)
