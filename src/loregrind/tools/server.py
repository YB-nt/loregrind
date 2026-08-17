"""MCP stdio 서버 — `api.py` 의 도구를 전송 계층에 붙인다 (docs/SPEC.md §4.1).

여기에는 **로직이 없다.** 도구 로직은 `api.py` 에 있고 이 파일은 바인딩만 한다.
그래야 SDK 버전이 바뀌어도 도구 계약이 흔들리지 않고, 테스트가 전송 계층을 띄우지
않고 계약을 고정할 수 있다.

바이너리는 서버 시작 시 고정된다. 도구 인자에 `binary_id` 가 없는 이유는
`api.py` 의 모듈 docstring 에 적혀 있다.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.server import MCPServer

from loregrind.analyze.budget import Budget, BudgetTracker
from loregrind.analyze.context import PROMPT_VERSION, build_system_prompt
from loregrind.db.repo import Repo
from loregrind.tools import api
from loregrind.tools.api import ToolContext

SERVER_NAME = "loregrind"


class BinaryNotLoaded(RuntimeError):
    """서버를 띄울 대상이 DB 에 없다. 조용히 빈 서버를 띄우지 않는다."""


def build_context(
    db_path: str | Path,
    sha256: str,
    *,
    allow_writes: bool = False,
    budget: Budget | None = None,
    model: str = "unset",
    extra_config: dict[str, Any] | None = None,
) -> ToolContext:
    """DB 를 열고 대상 바이너리를 고정한다.

    `create_run` 을 여기서 부른다 — **도구 호출도 run 에 소속되어야** 어블레이션이
    성립한다 (불변식 5). run 없이 도는 서버는 계측이 없는 서버다.
    """
    repo = Repo.open(db_path)
    binary = repo.get_binary_by_sha256(sha256)
    if binary is None or binary.id is None:
        raise BinaryNotLoaded(f"sha256 {sha256[:12]}… 가 DB 에 없다. 먼저 loregrind load 를 하라")

    effective = budget or Budget()
    config: dict[str, Any] = {
        "layer": "l2-readonly",
        "sha256": sha256,
        # 어블레이션 1축이 이 키로 GROUP BY 된다
        "rename_writes": allow_writes,
        **effective.as_config(),
    }
    # 호출자가 계층·전략을 덮어쓸 수 있게 한다. 같은 run 에 서로 다른 config 가
    # 두 벌 생기면 어블레이션이 어느 쪽으로 GROUP BY 되는지 알 수 없다
    config.update(extra_config or {})
    run = repo.create_run(model=model, prompt_version=PROMPT_VERSION, config=config)
    return ToolContext(
        repo=repo,
        binary_id=binary.id,
        extract_schema_version=binary.extract_schema_version,
        run_id=run.run_id,
        allow_writes=allow_writes,
        budget=BudgetTracker(budget=effective),
    )


def build_server(ctx: ToolContext) -> MCPServer:
    """도구를 등록한 서버. 쓰기 도구는 §7 3주차까지 존재하지 않는다."""
    server = MCPServer(
        name=SERVER_NAME,
        version="0.1.0",
        instructions=build_system_prompt(),
    )

    @server.tool(description="함수 하나의 추출 사실과 디컴파일 텍스트를 돌려준다")
    def get_function(addr: str, max_chars: int = api.DEFAULT_MAX_CHARS) -> dict[str, Any]:
        return api.get_function(ctx, addr, max_chars)

    @server.tool(description="이 함수를 호출하는 함수들")
    def get_callers(addr: str, limit: int = 50) -> dict[str, Any]:
        return api.get_callers(ctx, addr, limit)

    @server.tool(description="이 함수가 호출하는 함수들")
    def get_callees(addr: str, limit: int = 50) -> dict[str, Any]:
        return api.get_callees(ctx, addr, limit)

    @server.tool(description="이 함수가 사용하는 임포트 API 목록")
    def get_apis_used(addr: str) -> dict[str, Any]:
        return api.get_apis_used(ctx, addr)

    @server.tool(description="문자열 부분 일치 검색 (정규식이 아니다)")
    def search_strings(substring: str, limit: int = 50, min_length: int = 4) -> dict[str, Any]:
        return api.search_strings(ctx, substring, limit, min_length)

    @server.tool(description="이 함수에 대한 이전 run 의 판단 (사실이 아니라 추측이다)")
    def get_known_analysis(addr: str) -> dict[str, Any]:
        return api.get_known_analysis(ctx, addr)

    @server.tool(description="다음에 읽을 함수 후보. 2주차는 strategy='sequential' 만")
    def list_candidates(
        strategy: str = "sequential", limit: int = 20, cursor: str | None = None
    ) -> dict[str, Any]:
        return api.list_candidates(ctx, strategy, limit, cursor)

    return server


def main(argv: list[str] | None = None) -> int:
    """`loregrind serve` 가 부른다. stdio 로만 뜬다 — 네트워크로 열지 않는다 (§2)."""
    import argparse

    parser = argparse.ArgumentParser(prog="loregrind-serve")
    parser.add_argument("--db", default="loregrind.db")
    parser.add_argument("--binary", required=True, help="대상 바이너리의 sha256")
    parser.add_argument("--model", default="unset", help="runs.model 에 기록된다")
    parser.add_argument(
        "--allow-writes",
        action="store_true",
        help="쓰기 도구 활성화 (§7 3주차 전까지는 쓰기 도구 자체가 없다)",
    )
    args = parser.parse_args(argv)

    ctx = build_context(args.db, args.binary, allow_writes=args.allow_writes, model=args.model)
    build_server(ctx).run(transport="stdio")
    return 0
