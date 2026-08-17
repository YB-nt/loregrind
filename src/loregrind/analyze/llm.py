"""LLM 호출 경계 — 루프는 이 프로토콜에만 의존한다.

## 왜 프로토콜로 나누는가

`agent.py` 가 Anthropic SDK 를 직접 부르면 (a) API 키 없이는 루프를 테스트할 수
없고, (b) 예산 게이트·도구 디스패치·근거 검증 같은 **결정론적 부분이 비결정론적
부분과 섞인다.** 여기서 경계를 그으면 가짜 클라이언트로 루프 전체를 고정할 수 있다.

## 비용은 추정이 아니라 계측이다

`§6` 비용 지표가 필수이므로 토큰·비용이 run 에 남아야 한다. 가격표에 없는 모델로
돌리면 **0 을 기록하지 않고 세운다** — `EVAL-SPEC.md` 의 "측정 불가는 0% 가 아니다"
를 비용에도 적용한다. 0 이 기록되면 리포트에서 "비용이 들지 않았다"로 읽힌다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

# 기본 모델. docs/PROJECT.md §9 는 Anthropic API 를 스택으로 정하고 모델은 열어 뒀다
DEFAULT_MODEL = "claude-opus-5"
# 비스트리밍 요청의 상한. 이보다 크게 잡으려면 스트리밍으로 가야 한다
DEFAULT_MAX_TOKENS = 16_000

# 100만 토큰당 USD (input, output). 캐시는 입력가 기준 배수로 계산한다.
# **이 표에 없는 모델은 거부한다.** 추정치를 넣으면 그 추정이 지표가 된다
MODEL_PRICING: dict[str, tuple[float, float]] = {
    "claude-opus-5": (5.0, 25.0),
    "claude-opus-4-8": (5.0, 25.0),
    "claude-sonnet-5": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
}
CACHE_READ_MULTIPLIER = 0.1
CACHE_WRITE_MULTIPLIER = 1.25


class UnknownModelPricing(RuntimeError):
    """가격표에 없는 모델. 비용을 0 으로 기록하느니 시작을 거부한다."""


class MissingCredentials(RuntimeError):
    """API 키가 없다. SDK 의 TypeError 를 그대로 흘리지 않고 여기서 잡는다."""


@dataclass(frozen=True, slots=True)
class Usage:
    """호출 1회의 토큰 계측."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cache_read_input_tokens=self.cache_read_input_tokens + other.cache_read_input_tokens,
            cache_creation_input_tokens=(
                self.cache_creation_input_tokens + other.cache_creation_input_tokens
            ),
        )


@dataclass(frozen=True, slots=True)
class ToolCall:
    """모델이 요청한 도구 호출 1건."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True, slots=True)
class LLMResult:
    """호출 1회의 결과.

    `content` 를 그대로 보관하는 이유: 다음 턴에 **원형 그대로** 되돌려 보내야 한다.
    텍스트만 뽑아 재조립하면 도구 호출 블록이 사라져 대화가 깨진다.
    """

    stop_reason: str
    content: list[dict[str, Any]]
    usage: Usage
    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    model: str = ""


def price_of(model: str) -> tuple[float, float]:
    if model not in MODEL_PRICING:
        known = ", ".join(sorted(MODEL_PRICING))
        raise UnknownModelPricing(
            f"{model!r} 은 가격표에 없다. 비용을 0 으로 기록하면 §6 비용 지표가 "
            f"거짓이 된다. MODEL_PRICING 에 추가하라 (현재: {known})"
        )
    return MODEL_PRICING[model]


def estimate_cost_usd(model: str, usage: Usage) -> float:
    """토큰 계측을 비용으로 환산한다.

    캐시 읽기·쓰기를 입력가와 같은 값으로 세면 캐시가 절약한 비용이 지표에서
    사라진다 — §6 이 캐시 히트율과 비용 추이를 함께 보라고 요구하는 이유다.
    """
    input_price, output_price = price_of(model)
    million = 1_000_000
    return (
        usage.input_tokens * input_price
        + usage.cache_read_input_tokens * input_price * CACHE_READ_MULTIPLIER
        + usage.cache_creation_input_tokens * input_price * CACHE_WRITE_MULTIPLIER
        + usage.output_tokens * output_price
    ) / million


class LLMClient(Protocol):
    """루프가 아는 유일한 LLM 인터페이스."""

    model: str

    def create(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int,
        effort: str,
        output_schema: dict[str, Any] | None,
    ) -> LLMResult: ...


@dataclass
class AnthropicClient:
    """Anthropic Messages API 바인딩.

    **API 키를 인자로 받지 않는다** (§10). SDK 가 `.env`/환경변수에서 읽게 두고,
    이 객체는 키를 필드로 들고 있지 않으므로 직렬화되거나 로그에 찍힐 수 없다.

    `temperature`/`top_p` 를 보내지 않는다 — Claude Opus 5 에서는 400 이고,
    무엇보다 §6 이 요구하는 재현성은 샘플링 파라미터가 아니라 프롬프트 버전과
    `runs` 계측으로 확보한다.
    """

    model: str = DEFAULT_MODEL
    _client: Any = field(default=None, repr=False)

    def __post_init__(self) -> None:
        # 가격표 확인을 호출 시점이 아니라 생성 시점에 한다. 첫 호출 뒤에 터지면
        # 이미 돈을 쓴 뒤다
        price_of(self.model)
        if self._client is None:
            import anthropic

            # 키를 인자로 넘기지 않는다 (§10). SDK 가 환경에서 읽게 두면 이 객체는
            # 키를 필드로 들고 있지 않으므로 repr·직렬화·로그로 샐 수 없다
            self._client = anthropic.Anthropic()

    def create(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int,
        effort: str,
        output_schema: dict[str, Any] | None,
    ) -> LLMResult:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": messages,
            "output_config": {"effort": effort},
        }
        if tools:
            kwargs["tools"] = tools
        if output_schema is not None:
            kwargs["output_config"]["format"] = {
                "type": "json_schema",
                "schema": output_schema,
            }

        try:
            message = self._client.messages.create(**kwargs)
        except TypeError as exc:
            # SDK 는 인증 수단을 **요청 시점에** 확인하고 TypeError 를 던진다.
            # 생성 시점에 미리 막을 수도 있지만, 그러면 프로필 기반 인증
            # (`ant auth login`)을 키 없음으로 오판한다 — 실제로 못 보낼 때만 세운다
            if "authentication" not in str(exc).lower():
                raise
            raise MissingCredentials(
                "인증 수단을 찾지 못했다. ANTHROPIC_API_KEY 를 `.env` 에 넣고 환경에 실어라 — "
                "키를 코드·설정·DB 에 두지 않는다 (§10)"
            ) from exc
        return _result_from_message(message)


def _result_from_message(message: Any) -> LLMResult:
    """SDK 응답을 프로토콜 형태로 옮긴다. 여기서만 SDK 객체를 만진다."""
    content: list[dict[str, Any]] = []
    texts: list[str] = []
    calls: list[ToolCall] = []

    for block in message.content:
        block_dict = block.model_dump() if hasattr(block, "model_dump") else dict(block)
        content.append(block_dict)
        if block_dict.get("type") == "text":
            texts.append(str(block_dict.get("text", "")))
        elif block_dict.get("type") == "tool_use":
            calls.append(
                ToolCall(
                    id=str(block_dict["id"]),
                    name=str(block_dict["name"]),
                    arguments=dict(block_dict.get("input") or {}),
                )
            )

    raw = message.usage
    usage = Usage(
        input_tokens=int(getattr(raw, "input_tokens", 0) or 0),
        output_tokens=int(getattr(raw, "output_tokens", 0) or 0),
        cache_read_input_tokens=int(getattr(raw, "cache_read_input_tokens", 0) or 0),
        cache_creation_input_tokens=int(getattr(raw, "cache_creation_input_tokens", 0) or 0),
    )
    return LLMResult(
        stop_reason=str(message.stop_reason),
        content=content,
        usage=usage,
        text="\n".join(texts),
        tool_calls=tuple(calls),
        model=str(getattr(message, "model", "")),
    )
