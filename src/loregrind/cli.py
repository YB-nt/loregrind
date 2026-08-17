"""`loregrind` CLI — §8 산출물 1번.

1주차 범위는 `extract` / `load` / `query` 다. `analyze` / `eval` 은 아직 없으며,
있는 척하지 않고 명시적으로 거부한다 — 조용히 아무것도 하지 않는 서브커맨드는
"돌았는데 결과가 없다"는 오해를 만든다.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from loregrind.db.repo import Repo
from loregrind.extract.loader import ExtractLoadError, load_extract
from loregrind.extract.runner import ARTIFACTS_ROOT, GhidraError, run_extract

DEFAULT_DB = "loregrind.db"


def _cmd_extract(args: argparse.Namespace) -> int:
    """Ghidra headless 로 추출한다. 적재는 하지 않는다 (`load` 가 한다)."""
    try:
        result = run_extract(
            Path(args.binary),
            reanalyze=args.reanalyze,
            java_heap=args.heap,
            max_cpu=args.max_cpu,
        )
    except GhidraError as exc:
        print(f"추출 실패: {exc}", file=sys.stderr)
        return 1
    print(f"추출 완료: {result.extract_dir}")
    print(f"  sha256: {result.sha256}")
    print(f"  다음: loregrind load {result.extract_dir} --arch <arch>")
    return 0


def _cmd_load(args: argparse.Namespace) -> int:
    """추출 산출물을 DB 에 적재한다."""
    repo = Repo.open(args.db)
    try:
        result = load_extract(
            repo,
            Path(args.extract_dir),
            arch=args.arch,
            filename=args.filename,
            family_label=args.family_label,
        )
    except ExtractLoadError as exc:
        print(f"적재 실패: {exc}", file=sys.stderr)
        return 1
    finally:
        repo.close()

    print(f"적재 완료: binary_id={result.binary_id} (extract v{result.extract_schema_version})")
    print(f"  함수 {result.functions}개, 콜 간선 {result.call_edges}개")
    print(f"  디컴파일 실패 {result.decompile_failures}개 (레코드는 남아 있다)")
    print(
        f"  문자열 {result.strings}개 (참조 {result.string_xrefs}), "
        f"임포트 {result.imports}개, API 호출 {result.api_calls}개"
    )
    if result.without_code_hash:
        # 정규화가 코드를 통째로 지워버린 경우다. 규칙이 과한지 확인해야 한다
        print(f"  주의: 디컴파일은 됐으나 code_hash 를 못 만든 함수 {result.without_code_hash}개")
    for warning in result.warnings:
        print(f"  주의: {warning}")
    return 0


def _cmd_query(args: argparse.Namespace) -> int:
    """개발자용 읽기 전용 조회 — §7 1주차 완료 기준.

    이 경로를 MCP 도구로 노출하지 않는다. 만능 query 도구는 에이전트 행동 귀속을
    불가능하게 만든다.
    """
    repo = Repo.open(args.db)
    try:
        rows = repo.readonly_query(args.sql, limit=args.limit)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        repo.close()

    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2, default=str))
    elif not rows:
        print("(행 없음)")
    else:
        for row in rows:
            print(" | ".join(f"{k}={v}" for k, v in row.items()))
        print(f"-- {len(rows)}행")
    return 0


def _cmd_eval(args: argparse.Namespace) -> int:
    """어블레이션·지표 조회. 전체 평가 하네스는 `python -m eval.run` 이다.

    여기서 하는 일은 **어블레이션이 SQL 한 줄로 뽑히는지 확인**하는 것뿐이다.
    안 뽑히면 애플리케이션에서 우회 집계하지 않고 결함으로 보고한다 (§6).
    """
    repo = Repo.open(args.db)
    try:
        if args.run_id:
            rows = repo.metrics_for_run(args.run_id)
            if not rows:
                print(f"run {args.run_id} 에 기록된 지표가 없다 (0% 가 아니라 미측정)")
                return 3
            for row in rows:
                print(" | ".join(f"{k}={v}" for k, v in row.items()))
            return 0

        rows = repo.ablation(args.metric, args.ablation_axis)
    finally:
        repo.close()

    if not rows:
        print(
            f"어블레이션 결과가 비어 있다: metric={args.metric}, axis={args.ablation_axis}\n"
            "  run_metrics 에 지표가 없거나 runs.config_json 에 그 축이 없다.\n"
            "  → 우회 집계하지 말고 계측 결함으로 다룬다 (§6)",
            file=sys.stderr,
        )
        return 3
    print(f"# 어블레이션 — {args.metric} by {args.ablation_axis}")
    for row in rows:
        print(" | ".join(f"{k}={v}" for k, v in row.items()))
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    """L2 MCP 도구 서버 (§7 2주차).

    바이너리는 여기서 고정된다 — 도구 인자로 받지 않는다. 에이전트가 다른 샘플을
    헤집는 경로를 막고, run 하나가 바이너리 하나에 대응하게 하려는 것이다.
    """
    from loregrind.tools.server import BinaryNotLoaded, build_context, build_server

    try:
        ctx = build_context(args.db, args.binary, allow_writes=args.allow_writes, model=args.model)
    except BinaryNotLoaded as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(
        f"MCP 서버 시작 (stdio) — binary_id={ctx.binary_id}, run_id={ctx.run_id}, "
        f"쓰기={'허용' if ctx.allow_writes else '금지'}",
        file=sys.stderr,
    )
    build_server(ctx).run(transport="stdio")
    return 0


def _cmd_not_implemented(args: argparse.Namespace) -> int:
    print(
        f"{args.command} 는 아직 구현되지 않았다 (§7 {args.milestone}). "
        "지금 가능한 것: extract / load / query / serve / eval",
        file=sys.stderr,
    )
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="loregrind",
        description="스트립된 바이너리를 위한 에이전트 리버스 엔지니어링 지식 베이스",
    )
    parser.add_argument("--db", default=DEFAULT_DB, help=f"SQLite 경로 (기본: {DEFAULT_DB})")
    sub = parser.add_subparsers(dest="command", required=True)

    p_extract = sub.add_parser("extract", help="Ghidra headless 추출 (적재는 별도)")
    p_extract.add_argument("binary", help="대상 바이너리 경로")
    p_extract.add_argument(
        "--reanalyze", action="store_true", help="기존 Ghidra 프로젝트를 삭제하고 재생성"
    )
    p_extract.add_argument("--heap", default="8G", help="_JAVA_OPTIONS 힙 (기본: 8G)")
    p_extract.add_argument("--max-cpu", type=int, default=4)
    p_extract.set_defaults(func=_cmd_extract)

    p_load = sub.add_parser("load", help="추출 산출물을 DB 에 적재")
    p_load.add_argument("extract_dir", help=f"{ARTIFACTS_ROOT}/<sha256> 디렉터리")
    p_load.add_argument("--arch", required=True, help='예: "x86:LE:32:default"')
    p_load.add_argument("--filename", default=None, help="원본 파일명 (샘플은 저장하지 않는다)")
    p_load.add_argument(
        "--family-label",
        default=None,
        help="사전정보. 결론이 아니라 가설로만 쓰인다 (불변식 7)",
    )
    p_load.set_defaults(func=_cmd_load)

    p_query = sub.add_parser("query", help="읽기 전용 SQL 조회 (개발자용)")
    p_query.add_argument("sql", help="SELECT / WITH / EXPLAIN 만 허용")
    p_query.add_argument("--limit", type=int, default=100)
    p_query.add_argument("--json", action="store_true")
    p_query.set_defaults(func=_cmd_query)

    p_serve = sub.add_parser("serve", help="L2 MCP 도구 서버 (stdio)")
    p_serve.add_argument("--binary", required=True, help="대상 바이너리의 sha256")
    p_serve.add_argument("--model", default="unset", help="runs.model 에 기록된다")
    p_serve.add_argument(
        "--allow-writes",
        action="store_true",
        help="쓰기 도구 활성화 (§7 3주차 전까지 쓰기 도구 자체가 없다)",
    )
    p_serve.set_defaults(func=_cmd_serve)

    p_analyze = sub.add_parser("analyze", help="(미구현) 분석 루프")
    p_analyze.set_defaults(func=_cmd_not_implemented, milestone="3~4주차")

    p_eval = sub.add_parser("eval", help="어블레이션·지표 조회 (전체는 python -m eval.run)")
    p_eval.add_argument(
        "--ablation-axis",
        default="rename_writes",
        help="runs.config_json 의 키. 이 축으로 GROUP BY 한다",
    )
    p_eval.add_argument("--metric", default="naming_accuracy")
    p_eval.add_argument("--run-id", default=None, help="지정하면 그 run 의 지표를 나열한다")
    p_eval.set_defaults(func=_cmd_eval)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
