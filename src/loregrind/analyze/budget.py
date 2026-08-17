"""예산 상한 — **프롬프트가 아니라 코드가 막는다** (불변식 8).

"토큰을 아껴 써라"라고 프롬프트에 쓰는 것은 게이트가 아니다. 모델이 그 문장을 지킬
확률이 얼마든, 지키지 않았을 때 멈추는 것이 없으면 상한이 아니다.

여기서 세는 것은 세 가지다.

1. **토큰** — 함수당, run 당
2. **비용** — run 당. 모델 계층화(강한 모델/저가 모델)를 섞으면 토큰만으로는 안 잡힌다
3. **도구 호출 횟수** — 토큰만 세면 싼 도구를 무한히 부르는 탐색이 빠져나간다

초과 시 `BudgetExceeded` 를 던지고, 루프는 **부분 결과를 커밋한 뒤** 중단한다
(§4 원칙 4 — 함수 단위 커밋). 중단이 곧 폐기가 되면 예산 게이트가 작업을 파괴한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# docs/SPEC.md §6 의 초기값. **근거 없는 값이다** — 4주차 대형 바이너리 완주에서
# 실측해 고쳐야 한다. 지금 이 숫자를 인용해 "예산 안에서 돈다"고 쓰지 않는다.
DEFAULT_MAX_TOKENS_PER_FUNCTION = 40_000
DEFAULT_MAX_TOOL_CALLS_PER_FUNCTION = 30
DEFAULT_MAX_COST_USD_PER_RUN = 5.0
DEFAULT_MAX_FUNCTIONS_PER_RUN = 200


class BudgetExceeded(RuntimeError):
    """상한에 걸렸다. 호출자는 부분 결과를 커밋한 뒤 중단한다."""

    def __init__(self, limit_name: str, used: float, limit: float) -> None:
        super().__init__(f"예산 초과: {limit_name} = {used} > {limit}")
        self.limit_name = limit_name
        self.used = used
        self.limit = limit


@dataclass(frozen=True, slots=True)
class Budget:
    """상한 묶음. `runs.config_json` 에 그대로 실려 어블레이션 축이 된다."""

    max_tokens_per_function: int = DEFAULT_MAX_TOKENS_PER_FUNCTION
    max_tool_calls_per_function: int = DEFAULT_MAX_TOOL_CALLS_PER_FUNCTION
    max_cost_usd_per_run: float = DEFAULT_MAX_COST_USD_PER_RUN
    max_functions_per_run: int = DEFAULT_MAX_FUNCTIONS_PER_RUN

    def as_config(self) -> dict[str, float]:
        """`create_run(config=...)` 에 넣을 형태. 계측되지 않은 상한은 상한이 아니다."""
        return {
            "max_tokens_per_function": self.max_tokens_per_function,
            "max_tool_calls_per_function": self.max_tool_calls_per_function,
            "max_cost_usd_per_run": self.max_cost_usd_per_run,
            "max_functions_per_run": self.max_functions_per_run,
        }


@dataclass(slots=True)
class BudgetTracker:
    """누적 사용량. run 하나에 하나.

    함수별 카운터는 `begin_function()` 에서 초기화된다. 초기화를 잊으면 두 번째
    함수가 첫 번째의 사용량을 물려받아 조기에 걸리므로, 루프는 반드시 함수 진입 시
    이것을 부른다.
    """

    budget: Budget = field(default_factory=Budget)
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    functions_done: int = 0
    _function_tokens: int = 0
    _function_tool_calls: int = 0

    @property
    def total_tokens(self) -> int:
        return self.tokens_in + self.tokens_out

    def begin_function(self) -> None:
        """새 함수 분석 시작. run 상한을 **먼저** 확인한다."""
        if self.functions_done >= self.budget.max_functions_per_run:
            raise BudgetExceeded(
                "max_functions_per_run", self.functions_done, self.budget.max_functions_per_run
            )
        self._function_tokens = 0
        self._function_tool_calls = 0

    def end_function(self) -> None:
        self.functions_done += 1

    def charge_llm(self, tokens_in: int, tokens_out: int, cost_usd: float) -> None:
        """LLM 호출 1회를 계상한다. **호출 후 즉시** 부른다.

        나중에 몰아서 더하면 상한을 넘긴 채로 여러 번 호출한 뒤에야 걸린다.
        """
        self.tokens_in += tokens_in
        self.tokens_out += tokens_out
        self.cost_usd += cost_usd
        self._function_tokens += tokens_in + tokens_out

        if self.cost_usd > self.budget.max_cost_usd_per_run:
            raise BudgetExceeded(
                "max_cost_usd_per_run", self.cost_usd, self.budget.max_cost_usd_per_run
            )
        if self._function_tokens > self.budget.max_tokens_per_function:
            raise BudgetExceeded(
                "max_tokens_per_function",
                self._function_tokens,
                self.budget.max_tokens_per_function,
            )

    def charge_tool_call(self) -> None:
        """도구 호출 1회. 상한을 넘으면 **도구를 실행하기 전에** 세운다."""
        self._function_tool_calls += 1
        if self._function_tool_calls > self.budget.max_tool_calls_per_function:
            raise BudgetExceeded(
                "max_tool_calls_per_function",
                self._function_tool_calls,
                self.budget.max_tool_calls_per_function,
            )

    def snapshot(self) -> dict[str, float]:
        """`finish_run` 에 넘길 계측값. 비용이 run 에 없으면 §6 비용 지표가 측정 불가다."""
        return {
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "cost_usd": self.cost_usd,
            "functions_done": self.functions_done,
        }
