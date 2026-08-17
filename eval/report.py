"""리포트 생성 — 규율을 코드로 강제한다.

§6 리포트 규율:
- **지표에 반드시 `n` 을 붙인다.** 함수 12개에서 잰 92% 는 92% 가 아니다
- **컴파일러 x 최적화 셀별로 보고한다.** 평균은 그다음이다
- **실패한 셀은 채우지 말고 비워 두고 이유를 적는다**
- **콜드 vs 웜 vs 홀드아웃을 항상 함께 낸다.** 웜만 담은 표는 만들지 않는다

마지막 항목이 이 모듈의 핵심이다. `render_metric_table()` 은 홀드아웃 열을 **항상**
그린다. 데이터가 없으면 빈 셀에 "측정 안 함"을 적는다 — 열을 지우지 않는다. 열이
사라지면 홀드아웃을 재지 않았다는 사실도 함께 사라진다.
"""

from __future__ import annotations

from collections.abc import Sequence

from eval.metrics import MetricValue

CORPUS_STATES = ("cold", "warm", "holdout")
_NOT_MEASURED = "측정 안 함"


def _cell(value: MetricValue | None) -> str:
    if value is None:
        return _NOT_MEASURED
    if value.value is None:
        return f"측정 불가 ({value.unmeasured_reason})"
    return f"{value.value:.3f} (n={value.n})"


def render_metric_table(metric: str, values: Sequence[MetricValue]) -> str:
    """지표 하나를 셀 x 코퍼스상태 표로. 홀드아웃 열은 언제나 존재한다."""
    indexed = {(v.stratum, v.corpus_state): v for v in values if v.metric == metric}
    strata = sorted({s for s, _ in indexed} | {"all"})

    lines = [f"### {metric}", ""]
    methods = sorted({v.method for v in values if v.metric == metric and v.method})
    if methods:
        # 판정 방법이 숫자를 바꾼다. 명시하지 않은 표는 해석할 수 없다
        lines.append(f"판정 방법: {', '.join(methods)}")
        lines.append("")
    lines.append("| 셀 (컴파일러:최적화) | " + " | ".join(CORPUS_STATES) + " |")
    lines.append("|---" * (len(CORPUS_STATES) + 1) + "|")
    for s in strata:
        row = [s] + [_cell(indexed.get((s, state))) for state in CORPUS_STATES]
        lines.append("| " + " | ".join(row) + " |")

    holdout_present = any(state == "holdout" for _, state in indexed)
    if not holdout_present:
        lines.append("")
        lines.append(
            "> **홀드아웃 미측정.** 홀드아웃 없이 웜 성능만 보면 개선과 과적합을 "
            "구분할 수 없다 (§6)."
        )
    return "\n".join(lines)


def render_report(values: Sequence[MetricValue], *, title: str = "평가 리포트") -> str:
    metrics = sorted({v.metric for v in values})
    lines = [f"# {title}", ""]
    if not metrics:
        lines.append("측정된 지표가 없다. 이것은 0% 가 아니라 **미측정**이다.")
        return "\n".join(lines)
    unmeasured = [v for v in values if v.value is None]
    lines.append(f"- 지표 {len(metrics)}종, 측정 실패 {len(unmeasured)}건")
    lines.append("")
    for metric in metrics:
        lines.append(render_metric_table(metric, values))
        lines.append("")
    if unmeasured:
        lines.append("## 미측정 / 측정 불가")
        lines.append("")
        lines.append("| 지표 | 셀 | 코퍼스 | 사유 |")
        lines.append("|---|---|---|---|")
        for v in unmeasured:
            lines.append(f"| {v.metric} | {v.stratum} | {v.corpus_state} | {v.unmeasured_reason} |")
    return "\n".join(lines)


def cutline_verdict(values: Sequence[MetricValue]) -> tuple[bool, str]:
    """§7 5주차 컷라인 판정 근거.

    코어 지표 표가 나왔는가. 평가 담당의 일은 이 판정의 **근거를 제공하는 것**이며,
    숫자를 좋게 만드는 것이 아니다.
    """
    core = {"naming_accuracy", "hallucination_rate", "exploration_efficiency"}
    measured = {v.metric for v in values if v.value is not None}
    missing = sorted(core - measured)
    if missing:
        return False, f"코어 지표 미측정: {', '.join(missing)} — 6주차 이후를 잘라낼 근거"
    holdout = any(v.corpus_state == "holdout" and v.value is not None for v in values)
    if not holdout:
        return False, "코어 지표는 나왔으나 홀드아웃이 없다. 과적합 여부를 판정할 수 없다"
    return True, "코어 지표 + 홀드아웃 측정됨"
