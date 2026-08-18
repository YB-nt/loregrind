"""읽기 전용 분석 에이전트 (§7 2주차 완료 기준 — "함수 1개를 제대로 요약").

## 이 루프가 결정론적으로 하는 일

에이전트가 정하는 것은 **무엇을 읽고 무엇이라 판단할지**뿐이다. 나머지는 전부
코드가 한다 — 도구 디스패치, 예산 차단, 근거 검증, DB 기록, run 계측.
불변식 4("성공 판정은 결정론적 코드가 한다")가 여기에 걸린다.

## 쓰기 도구는 아직 없다

2주차는 읽기 전용이다. 그런데 판단을 DB 에 남기는 것은 불변식 5 가 요구한다 —
run 에 소속되지 않은 산출물은 어블레이션에서 볼 수 없다. 그래서 **에이전트가
쓰기 도구를 부르는 것이 아니라, 루프가 최종 결과를 기록한다.** 둘은 다르다:
어블레이션 1축이 조작하는 것은 "리네임이 이후 컨텍스트에 전파되는가"이고,
결과 기록은 계측이다.

## 근거는 저장 전에 검증한다

에이전트가 인용한 근거가 실제로 존재하는지 여기서 대조한다. 검증은 판단을
막지 않는다 — 존재하지 않는 근거도 그대로 저장하고 **표시만 한다.** 지우면
§6 환각률이 0 이 되고, 그 0 은 시스템이 좋아서가 아니라 증거를 없앴기 때문이다.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from loregrind.analyze.budget import Budget, BudgetExceeded, BudgetTracker
from loregrind.analyze.context import (
    PROMPT_VERSION,
    FunctionContext,
    build_function_prompt,
    build_system_prompt,
    wrap_tool_result,
)
from loregrind.analyze.llm import (
    DEFAULT_MAX_TOKENS,
    LLMClient,
    Usage,
    estimate_cost_usd,
)
from loregrind.db.models import FunctionAnalysis
from loregrind.tools import api
from loregrind.tools.api import ToolContext

DEFAULT_EFFORT = "high"
# 도구 호출이 끝나지 않는 대화를 코드가 끊는다. 예산과 별개의 2차 방어다
MAX_TURNS = 24

EVIDENCE_KINDS = frozenset({"string", "api", "callee", "constant"})

# 최종 답변의 형태를 고정한다. 자유 텍스트로 두면 §6 환각률을 잴 수 없다
ANALYSIS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "proposed_name": {"type": "string"},
        "summary": {"type": "string"},
        "confidence": {"type": "number"},
        "evidence": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "enum": sorted(EVIDENCE_KINDS)},
                    "ref": {"type": "string"},
                },
                "required": ["kind", "ref"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["proposed_name", "summary", "confidence", "evidence"],
    "additionalProperties": False,
}

# MCP 서버와 같은 도구 목록을 쓴다. 두 곳이 갈라지면 어블레이션 대상이 달라진다
_DISPATCH: dict[str, Callable[..., dict[str, Any]]] = {fn.__name__: fn for fn in api.READ_TOOLS}


class AgentError(RuntimeError):
    """루프를 진행할 수 없는 상태."""


@dataclass(frozen=True, slots=True)
class Evidence:
    kind: str
    ref: str
    # 사실 집합에 실제로 있는가. False 여도 지우지 않는다 (§6 환각률의 입력)
    verified: bool


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    addr: str
    proposed_name: str | None
    summary: str | None
    confidence: float | None
    evidence: tuple[Evidence, ...]
    usage: Usage
    cost_usd: float
    turns: int
    tool_calls: int
    stop_reason: str
    run_id: str
    analysis_id: int | None = None
    # 예산·거부로 중단됐으면 여기에 이유가 남는다. 성공한 척하지 않는다
    aborted: str | None = None

    @property
    def unverified_evidence(self) -> tuple[Evidence, ...]:
        return tuple(e for e in self.evidence if not e.verified)


def tool_schemas() -> list[dict[str, Any]]:
    """도구 정의. 이름·설명은 `tools/server.py` 와 같은 계약이다."""
    addr = {"type": "string", "description": "소문자 16진 함수 주소 (예: 0x401000)"}
    return [
        {
            "name": "get_function",
            "description": "함수 하나의 추출 사실과 디컴파일 텍스트를 돌려준다.",
            "input_schema": {
                "type": "object",
                "properties": {"addr": addr, "max_chars": {"type": "integer"}},
                "required": ["addr"],
            },
        },
        {
            "name": "get_callers",
            "description": "이 함수를 호출하는 함수들.",
            "input_schema": {
                "type": "object",
                "properties": {"addr": addr, "limit": {"type": "integer"}},
                "required": ["addr"],
            },
        },
        {
            "name": "get_callees",
            "description": "이 함수가 호출하는 함수들.",
            "input_schema": {
                "type": "object",
                "properties": {"addr": addr, "limit": {"type": "integer"}},
                "required": ["addr"],
            },
        },
        {
            "name": "get_apis_used",
            "description": "이 함수가 사용하는 임포트 API 목록.",
            "input_schema": {
                "type": "object",
                "properties": {"addr": addr},
                "required": ["addr"],
            },
        },
        {
            "name": "search_strings",
            "description": "문자열 부분 일치 검색. 정규식이 아니다.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "substring": {"type": "string"},
                    "limit": {"type": "integer"},
                    "min_length": {"type": "integer"},
                },
                "required": ["substring"],
            },
        },
        {
            "name": "get_known_analysis",
            "description": "이 함수에 대한 이전 run 의 판단. 사실이 아니라 추측이다.",
            "input_schema": {
                "type": "object",
                "properties": {"addr": addr},
                "required": ["addr"],
            },
        },
    ]


def dispatch(ctx: ToolContext, call_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """도구 호출 1건을 실행한다.

    모르는 도구 이름은 조용히 넘기지 않는다 — 모델이 존재하지 않는 도구를 부른
    사실 자체가 프롬프트·스키마 불일치의 신호다.
    """
    fn = _DISPATCH.get(call_name)
    if fn is None:
        known = ", ".join(sorted(_DISPATCH))
        return {
            "ok": False,
            "error": {"code": "NOT_FOUND", "message": f"{call_name!r} 도구는 없다 ({known})"},
        }
    try:
        return fn(ctx, **arguments)
    except TypeError as exc:
        return {"ok": False, "error": {"code": "INVALID_ADDR", "message": f"인자 오류: {exc}"}}


def collect_context(ctx: ToolContext, addr: str) -> FunctionContext:
    """프롬프트에 넣을 사실을 모은다. 전부 추출 사실이며 판단이 아니다."""
    response = api.get_function(ctx, addr)
    if not response["ok"]:
        raise AgentError(f"{addr}: {response['error']['message']}")
    data = response["data"]

    binary = ctx.repo.get_binary(ctx.binary_id)
    apis: list[dict[str, Any]] = []
    strings: list[dict[str, Any]] = []
    if ctx.has_facts:
        apis = ctx.repo.get_apis_used(ctx.binary_id, addr)
        strings = ctx.repo.get_strings_for_function(ctx.binary_id, addr)

    known = api.get_known_analysis(ctx, addr)
    return FunctionContext(
        addr=data["addr"],
        original_name=data["original_name"],
        signature=data["signature"],
        decompiled=data["decompiled"],
        decompile_error=data["decompile_error"],
        callers=ctx.repo.get_callers(ctx.binary_id, addr),
        callees=ctx.repo.get_callees(ctx.binary_id, addr),
        apis=apis,
        strings=strings,
        family_label=binary.family_label if binary is not None else None,
        known_analysis=known["data"]["analysis"] if known["ok"] else None,
    )


def known_facts(ctx: ToolContext, fn_ctx: FunctionContext) -> list[str]:
    """근거 대조에 쓸 사실 집합.

    §6 환각률과 **같은 방식**(부분 문자열 대조)으로 검증한다. 여기서 느슨하게
    보고 평가에서 엄격하게 보면 두 숫자가 어긋난다.
    """
    facts: list[str] = [fn_ctx.decompiled or ""]
    facts.extend(str(s["value"]) for s in fn_ctx.strings)
    for entry in fn_ctx.apis:
        facts.append(str(entry["api_name"]))
        facts.append(f"{entry['module']}!{entry['api_name']}")
    facts.extend(fn_ctx.callees)
    facts.extend(fn_ctx.callers)
    return [f for f in facts if f]


def verify_evidence(items: list[dict[str, Any]], facts: list[str]) -> tuple[Evidence, ...]:
    haystack = "\n".join(facts)
    out: list[Evidence] = []
    for item in items:
        kind = str(item.get("kind", "")) or "string"
        ref = str(item.get("ref", ""))
        out.append(Evidence(kind=kind, ref=ref, verified=bool(ref) and ref in haystack))
    return tuple(out)


@dataclass(slots=True)
class ReadOnlyAgent:
    """함수 1개를 요약한다. 쓰기 도구를 노출하지 않는다."""

    ctx: ToolContext
    client: LLMClient
    budget: Budget = field(default_factory=Budget)
    effort: str = DEFAULT_EFFORT
    max_tokens: int = DEFAULT_MAX_TOKENS
    # **run 하나에 트래커 하나.** 함수마다 새로 만들면 `max_cost_usd_per_run` 이
    # 매번 0 에서 시작해 run 상한이 영영 걸리지 않고, `runs` 의 비용도 마지막 함수
    # 것만 남는다. 지금은 CLI 가 함수 1개만 돌려서 증상이 보이지 않을 뿐이다
    tracker: BudgetTracker = field(init=False)
    # run 전체의 토큰 누적. `runs` 계측의 소스다
    run_usage: Usage = field(init=False, default_factory=Usage)

    def __post_init__(self) -> None:
        self.tracker = BudgetTracker(budget=self.budget)
        self.ctx.budget = self.tracker

    def summarize(self, addr: str) -> AnalysisResult:
        if self.ctx.run_id is None:
            # 계측 없는 run 은 §6 에서 존재하지 않는 것과 같다
            raise AgentError("run_id 없는 컨텍스트로는 분석하지 않는다 (불변식 5)")

        tracker = self.tracker
        # 함수별 카운터만 초기화한다. run 누적(비용·함수 수)은 이어진다
        tracker.begin_function()

        fn_ctx = collect_context(self.ctx, addr)
        facts = known_facts(self.ctx, fn_ctx)
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": build_function_prompt(fn_ctx)}
        ]

        usage = Usage()
        aborted: str | None = None
        stop_reason = "unknown"
        turns = 0
        tool_calls = 0
        payload: dict[str, Any] = {}

        while turns < MAX_TURNS:
            turns += 1
            result = self.client.create(
                system=build_system_prompt(),
                messages=messages,
                tools=tool_schemas(),
                max_tokens=self.max_tokens,
                effort=self.effort,
                output_schema=ANALYSIS_SCHEMA,
            )
            usage = usage + result.usage
            stop_reason = result.stop_reason

            try:
                tracker.charge_llm(
                    result.usage.input_tokens,
                    result.usage.output_tokens,
                    estimate_cost_usd(self.client.model, result.usage),
                )
            except BudgetExceeded as exc:
                # 부분 결과를 버리지 않는다 (§4 원칙 4). 여기까지의 계측은 남는다
                aborted = str(exc)
                break

            if result.stop_reason == "refusal":
                aborted = "모델이 응답을 거부했다 (stop_reason=refusal)"
                break
            if result.stop_reason == "max_tokens":
                aborted = "max_tokens 에서 잘렸다. 결과를 신뢰할 수 없다"
                break

            messages.append({"role": "assistant", "content": result.content})

            if result.stop_reason == "tool_use" and result.tool_calls:
                blocks: list[dict[str, Any]] = []
                for call in result.tool_calls:
                    tool_calls += 1
                    response = dispatch(self.ctx, call.name, call.arguments)
                    blocks.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": call.id,
                            # 도구 응답에도 격리가 필요하다 — 안에 디컴파일 텍스트와
                            # 문자열이 그대로 들어 있다 (§10)
                            "content": wrap_tool_result(
                                call.name, json.dumps(response, ensure_ascii=False)
                            ),
                            "is_error": not response["ok"],
                        }
                    )
                messages.append({"role": "user", "content": blocks})
                continue

            payload = _parse_final(result.text)
            break
        else:
            aborted = f"{MAX_TURNS}턴 안에 끝나지 않았다"

        evidence = verify_evidence(list(payload.get("evidence", [])), facts)
        cost = estimate_cost_usd(self.client.model, usage)
        tracker.end_function()
        self.run_usage = self.run_usage + usage

        analysis_id = None
        if payload:
            analysis_id = self._record(addr, payload, evidence)

        # `runs` 에는 **run 누적**을 쓴다. 이 함수 것만 쓰면 두 번째 함수가 첫 번째의
        # 비용을 덮어써 §6 비용 지표가 마지막 함수 값이 된다.
        # `finish_run` 이 절대값 UPDATE 이므로 함수마다 불러도 결과가 맞는다
        self.ctx.repo.finish_run(
            self.ctx.run_id,
            tokens_in=self.run_usage.input_tokens + self.run_usage.cache_read_input_tokens,
            tokens_out=self.run_usage.output_tokens,
            cost_usd=estimate_cost_usd(self.client.model, self.run_usage),
        )

        return AnalysisResult(
            addr=addr,
            proposed_name=payload.get("proposed_name"),
            summary=payload.get("summary"),
            confidence=_as_confidence(payload.get("confidence")),
            evidence=evidence,
            usage=usage,
            cost_usd=cost,
            turns=turns,
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            run_id=self.ctx.run_id,
            analysis_id=analysis_id,
            aborted=aborted,
        )

    def _record(
        self, addr: str, payload: dict[str, Any], evidence: tuple[Evidence, ...]
    ) -> int | None:
        func = self.ctx.repo.get_function(self.ctx.binary_id, addr)
        if func is None or func.id is None or self.ctx.run_id is None:
            return None
        return self.ctx.repo.insert_analysis(
            FunctionAnalysis(
                run_id=self.ctx.run_id,
                function_id=func.id,
                # 에이전트는 자기 판단의 신뢰 등급을 스스로 올릴 수 없다
                source="agent",
                proposed_name=str(payload.get("proposed_name") or "") or None,
                summary=str(payload.get("summary") or "") or None,
                evidence_json=json.dumps(
                    [{"kind": e.kind, "ref": e.ref, "verified": e.verified} for e in evidence],
                    ensure_ascii=False,
                ),
                confidence=_as_confidence(payload.get("confidence")),
                code_hash=func.code_hash,
            )
        )


def _parse_final(text: str) -> dict[str, Any]:
    """최종 응답을 파싱한다. 못 읽으면 빈 판단이다 — 지어내지 않는다."""
    if not text.strip():
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _as_confidence(value: Any) -> float | None:
    """0..1 밖의 값은 저장하지 않는다 — DB CHECK 에 걸리기 전에 잡는다."""
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if 0.0 <= number <= 1.0 else None


def make_config(model: str, effort: str, budget: Budget, *, allow_writes: bool) -> dict[str, Any]:
    """`create_run(config=...)` 에 넣을 형태. 어블레이션 축이 여기서 나온다."""
    return {
        "layer": "l4-readonly-agent",
        "prompt_version": PROMPT_VERSION,
        "model": model,
        "effort": effort,
        "rename_writes": allow_writes,
        "strategy": "single-function",
        **budget.as_config(),
    }
