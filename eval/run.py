"""평가 하네스 진입점 — `python -m eval.run <command>`.

`make verify` / `make verify-holdout` 이 이것을 호출한다.

**측정하지 못한 것을 통과로 만들지 않는다.** 정답셋이 없으면 `leakage` 와 `holdout` 은
0 이 아니라 **비정상 종료(exit 3)** 한다. 게이트가 조용히 초록이 되면 게이트가 아니다.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from eval import leakage, report
from eval.metrics import MetricValue, is_regression
from eval.truthset import GroundTruth, load
from loregrind.db.repo import Repo

# 정답셋 기본 경로. 에이전트가 읽는 artifacts/·.ghidra-projects/ 밖이다
DEFAULT_GROUNDTRUTH = Path("eval/groundtruth/groundtruth.json")
DEFAULT_DB = Path("loregrind.db")

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_UNMEASURED = 3


def _load_gt(path: Path) -> GroundTruth | None:
    try:
        return load(path)
    except FileNotFoundError as exc:
        print(f"[eval] {exc}", file=sys.stderr)
        return None


def _stored_metrics(repo: Repo) -> list[MetricValue]:
    """DB 에 기록된 지표를 리포트용 객체로 되돌린다."""
    rows = repo.readonly_query(
        "SELECT metric, value, n, stratum, corpus_state, method, k FROM run_metrics",
        limit=1_000_000,
    )
    return [
        MetricValue(
            metric=str(r["metric"]),
            value=float(r["value"]),
            n=int(r["n"]),
            stratum=str(r["stratum"]),
            corpus_state=str(r["corpus_state"]),
            method=r["method"],
            k=r["k"],
        )
        for r in rows
    ]


def cmd_leakage(args: argparse.Namespace) -> int:
    """정답 누출 점검. 지표를 재기 전에 통과해야 한다."""
    gt = _load_gt(Path(args.groundtruth))
    if gt is None:
        print("[eval] 정답셋이 없어 누출 점검을 수행할 수 없다 — 통과가 아니다", file=sys.stderr)
        return EXIT_UNMEASURED
    repo = Repo.open(args.db)
    try:
        result = leakage.audit(repo, gt, Path(args.groundtruth), Path(args.db))
    finally:
        repo.close()
    print(result.render())
    if not result.clean:
        print(f"\n[eval] 차단 발견 {len(result.blocking)}건 — 지표를 재지 않는다", file=sys.stderr)
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    """DB 에 기록된 지표로 리포트를 만든다."""
    repo = Repo.open(args.db)
    try:
        values = _stored_metrics(repo)
    finally:
        repo.close()
    print(report.render_report(values))
    ok, reason = report.cutline_verdict(values)
    print()
    print(f"## §7 5주차 컷라인 판정\n\n- {'충족' if ok else '미충족'} — {reason}")
    return EXIT_OK if ok else EXIT_UNMEASURED


def cmd_holdout(args: argparse.Namespace) -> int:
    """홀드아웃 검증 — 누출 점검 + 홀드아웃 측정 여부 + 콜드/웜 대비.

    **홀드아웃 성능이 떨어지면 개선이 아니라 과적합이다.** 홀드아웃이 측정되지
    않았다면 그 사실 자체를 실패로 낸다.
    """
    gt = _load_gt(Path(args.groundtruth))
    if gt is None:
        return EXIT_UNMEASURED

    holdout_binaries = [b for b in gt.binaries if b.is_holdout]
    if not holdout_binaries:
        print(
            "[eval] 정답셋에 홀드아웃(is_holdout=true) 빌드가 없다. "
            "미학습 패밀리 홀드아웃 없이는 과적합을 판정할 수 없다 (§6)",
            file=sys.stderr,
        )
        return EXIT_UNMEASURED

    repo = Repo.open(args.db)
    try:
        audit = leakage.audit(repo, gt, Path(args.groundtruth), Path(args.db))
        values = _stored_metrics(repo)
    finally:
        repo.close()

    print(audit.render())
    print()
    if not audit.clean:
        print(
            f"[eval] 누출 차단 {len(audit.blocking)}건 — 홀드아웃 숫자를 신뢰할 수 없다",
            file=sys.stderr,
        )
        return EXIT_FINDINGS

    warm = {v.metric: v for v in values if v.corpus_state == "warm" and v.value is not None}
    hold = {v.metric: v for v in values if v.corpus_state == "holdout" and v.value is not None}
    if not hold:
        print(
            f"[eval] 홀드아웃 빌드 {len(holdout_binaries)}개가 정답셋에 있으나 "
            "run_metrics 에 corpus_state='holdout' 지표가 없다 — 미측정",
            file=sys.stderr,
        )
        return EXIT_UNMEASURED

    print("## 웜 대비 홀드아웃\n")
    print("| 지표 | 웜 | 홀드아웃 | 차이 |")
    print("|---|---|---|---|")
    regressions = 0
    for metric in sorted(set(warm) | set(hold)):
        w, h = warm.get(metric), hold.get(metric)
        if w is None or h is None or w.value is None or h.value is None:
            print(
                f"| {metric} | {'—' if w is None else w.value:.3f} | "
                f"{'—' if h is None else h.value:.3f} | 비교 불가 |"
            )
            continue
        delta = h.value - w.value
        # 방향은 metrics.LOWER_IS_BETTER 가 정한다. 여기서 다시 판단하지 않는다 —
        # 방향 판정이 두 곳에 있으면 한 곳은 반드시 틀린다
        worse = is_regression(metric, w.value, h.value)
        if worse:
            regressions += 1
        print(
            f"| {metric} | {w.value:.3f} (n={w.n}) | {h.value:.3f} (n={h.n}) | "
            f"{delta:+.3f}{' ⚠ 하락' if worse else ''} |"
        )

    if regressions:
        print(
            f"\n[eval] 홀드아웃에서 {regressions}개 지표가 하락했다. "
            "개선이 아니라 과적합일 수 있다",
            file=sys.stderr,
        )
        return EXIT_FINDINGS
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="eval.run", description="Loregrind 평가 하네스")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--groundtruth", default=str(DEFAULT_GROUNDTRUTH))
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("leakage", help="정답 누출 점검").set_defaults(func=cmd_leakage)
    sub.add_parser("report", help="지표 리포트 + 컷라인 판정").set_defaults(func=cmd_report)
    sub.add_parser("holdout", help="홀드아웃 검증 (누출 + 과적합)").set_defaults(func=cmd_holdout)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
