"""비용 계측 (§6 비용 지표의 전제).

여기서 고정하는 것 하나: **모르는 모델의 비용을 0 으로 기록하지 않는다.**
0 이 기록되면 리포트에서 "비용이 들지 않았다"로 읽히고, 그것은 측정이 아니라 거짓이다.
"""

from __future__ import annotations

import pytest

from loregrind.analyze.llm import (
    MODEL_PRICING,
    UnknownModelPricing,
    Usage,
    estimate_cost_usd,
    price_of,
)


def test_unknown_model_is_refused_not_priced_at_zero() -> None:
    with pytest.raises(UnknownModelPricing, match="가격표에 없다"):
        price_of("claude-does-not-exist")
    with pytest.raises(UnknownModelPricing):
        estimate_cost_usd("claude-does-not-exist", Usage(input_tokens=1000))


def test_cost_uses_published_rates() -> None:
    # opus 5: $5 / $25 per MTok
    cost = estimate_cost_usd("claude-opus-5", Usage(input_tokens=1_000_000))
    assert cost == pytest.approx(5.0)
    cost = estimate_cost_usd("claude-opus-5", Usage(output_tokens=1_000_000))
    assert cost == pytest.approx(25.0)


def test_cache_reads_are_cheaper_than_fresh_input() -> None:
    """캐시가 절약한 비용이 지표에서 사라지면 §6 캐시 곡선을 그릴 수 없다."""
    fresh = estimate_cost_usd("claude-opus-5", Usage(input_tokens=1_000_000))
    cached = estimate_cost_usd("claude-opus-5", Usage(cache_read_input_tokens=1_000_000))
    written = estimate_cost_usd("claude-opus-5", Usage(cache_creation_input_tokens=1_000_000))
    assert cached < fresh < written
    assert cached == pytest.approx(fresh * 0.1)


def test_usage_accumulates() -> None:
    total = Usage(input_tokens=10, output_tokens=5) + Usage(
        input_tokens=1, cache_read_input_tokens=2
    )
    assert (total.input_tokens, total.output_tokens, total.cache_read_input_tokens) == (11, 5, 2)


def test_default_model_is_priced() -> None:
    """기본 모델이 가격표에 없으면 첫 실행이 무조건 실패한다."""
    from loregrind.analyze.llm import DEFAULT_MODEL

    assert DEFAULT_MODEL in MODEL_PRICING
