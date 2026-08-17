"""모든 DB 접근이 지나는 유일한 층.

여기를 우회하는 SQL 을 코드베이스에 두지 않는다. 이유는 두 가지다.

1. **`superseded_by IS NULL` 필터를 호출부가 잊을 수 없게 한다.** 필터를 각 호출부에
   흩어 놓으면 반드시 빠뜨리는 곳이 생기고, 그 순간 가려진 판단이 되살아난다.
   조회 메서드는 뷰(`v_current_analyses`)를 통해서만 판단을 읽는다.
2. **`run_id` 없는 INSERT 를 불가능하게 한다** (불변식 5). 산출물 삽입 메서드는
   `run_id` 를 필수 인자로 받는다.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from importlib import resources
from pathlib import Path
from typing import Any

from loregrind.db.models import (
    ApiCall,
    Binary,
    CallEdge,
    Function,
    FunctionAnalysis,
    Hypothesis,
    Import,
    Run,
    StringLiteral,
    StringXref,
)

# 개발자용 조회에서 허용하는 접두사. 쓰기 문장을 CLI 로 흘려보내지 않는다
_READONLY_PREFIXES = ("select", "with", "explain", "pragma table_info")


class AppendOnlyViolation(RuntimeError):
    """append-only 규율을 코드에서 어긴 경우. DB 트리거보다 먼저 잡는다."""


def load_schema_sql() -> str:
    """`schema.sql` 을 읽는다. 설치된 패키지에서도 동작한다."""
    return resources.files("loregrind.db").joinpath("schema.sql").read_text(encoding="utf-8")


def migration_files() -> list[tuple[str, str]]:
    """`migrations/` 의 `NNNN__*.sql` 을 이름 순으로 돌려준다.

    이름 순 = 적용 순이다. `NNNN` 을 4자리 zero-pad 로 강제하는 이유가 이것이다.
    """
    root = resources.files("loregrind.db").joinpath("migrations")
    out: list[tuple[str, str]] = []
    for entry in sorted(p.name for p in root.iterdir() if p.name.endswith(".sql")):
        out.append((entry, root.joinpath(entry).read_text(encoding="utf-8")))
    return out


def apply_migrations(conn: sqlite3.Connection) -> list[str]:
    """아직 적용되지 않은 마이그레이션을 순서대로 적용한다.

    `schema_migrations` 는 `schema.sql` 이 아니라 여기서 만든다 — 커밋된 기반 스키마를
    나중에 고치지 않기 위함이다(`/db-change` 절대 규칙 1의 정신).
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "  filename TEXT PRIMARY KEY,"
        "  applied_at TEXT NOT NULL DEFAULT (datetime('now'))"
        ")"
    )
    applied = {str(r["filename"]) for r in conn.execute("SELECT filename FROM schema_migrations")}
    newly: list[str] = []
    for filename, sql in migration_files():
        if filename in applied:
            continue
        conn.executescript(sql)
        conn.execute("INSERT INTO schema_migrations (filename) VALUES (?)", (filename,))
        conn.commit()
        newly.append(filename)
    return newly


def connect(path: str | Path) -> sqlite3.Connection:
    """DB 연결을 만들고 스키마와 마이그레이션을 보장한다.

    `foreign_keys` 는 연결 단위 설정이라 여기서 매번 켠다 — schema.sql 안의
    PRAGMA 는 그 연결에만 적용되고 다음 연결로 이어지지 않는다.
    """
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(load_schema_sql())
    apply_migrations(conn)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


class Repo:
    """DB 접근의 단일 통로."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    @classmethod
    def open(cls, path: str | Path) -> Repo:
        return cls(connect(path))

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Cursor]:
        """트랜잭션. 함수 단위로 커밋한다 (§4 원칙 4)."""
        cur = self._conn.cursor()
        try:
            yield cur
        except Exception:
            self._conn.rollback()
            raise
        else:
            self._conn.commit()
        finally:
            cur.close()

    # -- 추출 사실 (immutable) ------------------------------------------------

    def insert_binary(self, b: Binary) -> int:
        with self.tx() as cur:
            cur.execute(
                """
                INSERT INTO binaries (
                    sha256, filename, arch, family_label, ghidra_path, ghidra_version,
                    extract_schema_version, function_count, decompile_failure_count,
                    analyzed_at, duration_sec
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    b.sha256,
                    b.filename,
                    b.arch,
                    b.family_label,
                    b.ghidra_path,
                    b.ghidra_version,
                    b.extract_schema_version,
                    b.function_count,
                    b.decompile_failure_count,
                    b.analyzed_at,
                    b.duration_sec,
                ),
            )
            return int(cur.lastrowid or 0)

    def get_binary_by_sha256(self, sha256: str) -> Binary | None:
        row = self._conn.execute("SELECT * FROM binaries WHERE sha256 = ?", (sha256,)).fetchone()
        return _binary_from_row(row) if row is not None else None

    def get_binary(self, binary_id: int) -> Binary | None:
        row = self._conn.execute("SELECT * FROM binaries WHERE id = ?", (binary_id,)).fetchone()
        return _binary_from_row(row) if row is not None else None

    def insert_functions(self, funcs: Iterable[Function]) -> int:
        """함수를 일괄 적재한다. 반환값은 삽입된 행 수."""
        rows = [
            (
                f.binary_id,
                f.addr,
                f.original_name,
                f.signature,
                f.size,
                f.cyclomatic,
                int(f.is_thunk),
                int(f.is_external),
                None if f.is_library is None else int(f.is_library),
                f.decompiled,
                f.decompile_error,
                f.code_hash,
                f.cfg_hash,
            )
            for f in funcs
        ]
        with self.tx() as cur:
            cur.executemany(
                """
                INSERT INTO functions (
                    binary_id, addr, original_name, signature, size, cyclomatic,
                    is_thunk, is_external, is_library, decompiled, decompile_error,
                    code_hash, cfg_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        return len(rows)

    def insert_call_edges(self, edges: Iterable[CallEdge]) -> int:
        rows = [(e.binary_id, e.caller_addr, e.callee_addr) for e in edges]
        with self.tx() as cur:
            # 같은 간선이 두 번 들어와도 실패시키지 않는다 — 추출 사실의 중복은 무해하다
            cur.executemany(
                "INSERT OR IGNORE INTO call_edges (binary_id, caller_addr, callee_addr) "
                "VALUES (?, ?, ?)",
                rows,
            )
        return len(rows)

    def get_function(self, binary_id: int, addr: str) -> Function | None:
        row = self._conn.execute(
            "SELECT * FROM functions WHERE binary_id = ? AND addr = ?", (binary_id, addr)
        ).fetchone()
        return _function_from_row(row) if row is not None else None

    def count_functions(self, binary_id: int) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM functions WHERE binary_id = ?", (binary_id,)
        ).fetchone()
        return int(row["n"])

    def list_functions(
        self, binary_id: int, *, after_addr: str | None = None, limit: int = 20
    ) -> list[dict[str, Any]]:
        """주소 순 함수 목록. L2 `list_candidates(strategy='sequential')` 의 뒷단.

        커서는 **주소 문자열 비교**다. `"0x401000" < "0x99"` 처럼 자릿수가 다르면
        사전순이 수치순과 어긋나지만, 한 바이너리 안의 주소는 자릿수가 같으므로
        실무상 일치한다. 정수 변환은 하지 않는다 — 추출 사실을 원형으로 보존한다.
        """
        if after_addr is None:
            rows = self._conn.execute(
                "SELECT addr, original_name, is_library FROM functions "
                "WHERE binary_id = ? ORDER BY addr LIMIT ?",
                (binary_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT addr, original_name, is_library FROM functions "
                "WHERE binary_id = ? AND addr > ? ORDER BY addr LIMIT ?",
                (binary_id, after_addr, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_callees(self, binary_id: int, addr: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT callee_addr FROM call_edges WHERE binary_id = ? AND caller_addr = ? "
            "ORDER BY callee_addr",
            (binary_id, addr),
        ).fetchall()
        return [str(r["callee_addr"]) for r in rows]

    def get_callers(self, binary_id: int, addr: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT caller_addr FROM call_edges WHERE binary_id = ? AND callee_addr = ? "
            "ORDER BY caller_addr",
            (binary_id, addr),
        ).fetchall()
        return [str(r["caller_addr"]) for r in rows]

    # -- 문자열·임포트 (추출 사실, 마이그레이션 0002) -------------------------

    def insert_strings(self, items: Iterable[StringLiteral]) -> int:
        rows = [
            (s.binary_id, s.addr, s.value, s.encoding, s.length, int(s.truncated)) for s in items
        ]
        with self.tx() as cur:
            cur.executemany(
                "INSERT INTO strings (binary_id, addr, value, encoding, length, truncated) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                rows,
            )
        return len(rows)

    def insert_string_xrefs(self, xrefs: Iterable[StringXref]) -> int:
        rows = [(x.binary_id, x.function_addr, x.string_addr) for x in xrefs]
        with self.tx() as cur:
            # 추출 사실의 중복은 무해하다. 같은 함수가 같은 문자열을 두 번 참조할 수 있다
            cur.executemany(
                "INSERT OR IGNORE INTO string_xrefs (binary_id, function_addr, string_addr) "
                "VALUES (?, ?, ?)",
                rows,
            )
        return len(rows)

    def insert_imports(self, items: Iterable[Import]) -> dict[tuple[str, str], int]:
        """임포트를 적재하고 `(module, api_name) → import_id` 지도를 돌려준다.

        `api_calls` 가 `import_id` 를 필요로 하므로 적재 순서가 강제된다 —
        imports 먼저, 그 다음 api_calls. 지도를 반환하지 않으면 호출부가 다시
        SELECT 해야 하고, 그 SELECT 가 repo 밖으로 새어 나간다.
        """
        index: dict[tuple[str, str], int] = {}
        with self.tx() as cur:
            for imp in items:
                cur.execute(
                    "INSERT INTO imports (binary_id, module, api_name, iat_addr, ordinal) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (imp.binary_id, imp.module, imp.api_name, imp.iat_addr, imp.ordinal),
                )
                index[(imp.module, imp.api_name)] = int(cur.lastrowid or 0)
        return index

    def insert_api_calls(self, calls: Iterable[ApiCall]) -> int:
        rows = [(c.binary_id, c.function_addr, c.import_id, c.call_addr) for c in calls]
        with self.tx() as cur:
            cur.executemany(
                "INSERT OR IGNORE INTO api_calls "
                "(binary_id, function_addr, import_id, call_addr) VALUES (?, ?, ?, ?)",
                rows,
            )
        return len(rows)

    def get_apis_used(self, binary_id: int, function_addr: str) -> list[dict[str, Any]]:
        """이 함수가 부르는 API 목록. L2 `get_apis_used` 의 뒷단.

        정렬을 고정한다 — 목록 순서가 흔들리면 같은 run 을 두 번 돌린 결과가 달라지고
        어블레이션 비교가 무의미해진다 (docs/SPEC.md §4.1).
        """
        rows = self._conn.execute(
            """
            SELECT i.module, i.api_name, COUNT(*) AS call_count
            FROM api_calls a JOIN imports i ON i.id = a.import_id
            WHERE a.binary_id = ? AND a.function_addr = ?
            GROUP BY i.module, i.api_name
            ORDER BY call_count DESC, i.module, i.api_name
            """,
            (binary_id, function_addr),
        ).fetchall()
        return [dict(r) for r in rows]

    def search_strings(
        self,
        binary_id: int,
        substring: str,
        *,
        limit: int = 50,
        min_length: int = 4,
    ) -> list[dict[str, Any]]:
        """부분 문자열 검색. **정규식은 받지 않는다** (docs/SPEC.md §4.2).

        ReDoS 표면이기도 하지만, 더 큰 이유는 질의 표현력이 가변이면 §6 탐색 효율을
        run 사이에서 비교할 수 없다는 것이다.
        """
        # LIKE 의 와일드카드를 사용자 입력으로 받지 않는다 — 부분 일치 고정이다.
        # 이스케이프 순서가 중요하다: 역슬래시를 먼저 하지 않으면 두 번 이스케이프된다
        escaped = substring.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        rows = self._conn.execute(
            """
            SELECT s.addr, s.value, s.encoding, s.length, s.truncated
            FROM strings s
            WHERE s.binary_id = ? AND s.length >= ? AND s.value LIKE ? ESCAPE '\\'
            ORDER BY s.addr
            LIMIT ?
            """,
            (binary_id, min_length, pattern, limit),
        ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["truncated"] = bool(item["truncated"])
            item["referenced_by"] = self.get_string_referrers(binary_id, str(row["addr"]))
            out.append(item)
        return out

    def get_string_referrers(self, binary_id: int, string_addr: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT function_addr FROM string_xrefs WHERE binary_id = ? AND string_addr = ? "
            "ORDER BY function_addr",
            (binary_id, string_addr),
        ).fetchall()
        return [str(r["function_addr"]) for r in rows]

    def get_strings_for_function(self, binary_id: int, function_addr: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT s.addr, s.value, s.encoding, s.length, s.truncated
            FROM string_xrefs x JOIN strings s
              ON s.binary_id = x.binary_id AND s.addr = x.string_addr
            WHERE x.binary_id = ? AND x.function_addr = ?
            ORDER BY s.addr
            """,
            (binary_id, function_addr),
        ).fetchall()
        return [dict(r) | {"truncated": bool(r["truncated"])} for r in rows]

    # -- run (불변식 5) -------------------------------------------------------

    def create_run(
        self,
        model: str,
        prompt_version: str,
        config: dict[str, Any],
        seed: int | None = None,
    ) -> Run:
        """run 을 시작한다.

        `config` 는 여기서 키를 제거한 사본으로 직렬화된다 (§10). 호출자가 잊어도
        비밀정보가 DB 에 남지 않게 하려는 것이다.
        """
        run_id = str(uuid.uuid4())
        safe = redact_config(config)
        run = Run(
            run_id=run_id,
            model=model,
            prompt_version=prompt_version,
            config_json=json.dumps(safe, sort_keys=True, ensure_ascii=False),
            seed=seed,
        )
        with self.tx() as cur:
            cur.execute(
                "INSERT INTO runs (run_id, model, prompt_version, config_json, seed) "
                "VALUES (?, ?, ?, ?, ?)",
                (run.run_id, run.model, run.prompt_version, run.config_json, run.seed),
            )
        return run

    def finish_run(self, run_id: str, tokens_in: int, tokens_out: int, cost_usd: float) -> None:
        """run 을 마감한다.

        `runs` 는 판단 테이블이 아니라 계측 테이블이므로 이 UPDATE 는
        append-only 규율의 대상이 아니다.
        """
        with self.tx() as cur:
            cur.execute(
                "UPDATE runs SET tokens_in = ?, tokens_out = ?, cost_usd = ?, "
                "finished_at = datetime('now') WHERE run_id = ?",
                (tokens_in, tokens_out, cost_usd, run_id),
            )

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        """run 의 계측값. 비용 지표가 실제로 기록됐는지 확인하는 경로."""
        row = self._conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return dict(row) if row is not None else None

    # -- 판단 (append-only) ---------------------------------------------------

    def insert_analysis(self, a: FunctionAnalysis) -> int:
        if a.superseded_by is not None:
            raise AppendOnlyViolation("새 판단은 superseded_by 를 채운 채로 삽입하지 않는다")
        with self.tx() as cur:
            return self._insert_analysis(cur, a)

    @staticmethod
    def _insert_analysis(cur: sqlite3.Cursor, a: FunctionAnalysis) -> int:
        cur.execute(
            """
            INSERT INTO function_analyses (
                run_id, function_id, proposed_name, summary, evidence_json,
                confidence, source, code_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                a.run_id,
                a.function_id,
                a.proposed_name,
                a.summary,
                a.evidence_json,
                a.confidence,
                a.source,
                a.code_hash,
            ),
        )
        return int(cur.lastrowid or 0)

    def supersede_analysis(self, old_id: int, new: FunctionAnalysis) -> int:
        """판단을 정정한다 — 판단 갱신의 유일한 경로.

        `superseded_by` 를 채우는 UPDATE 는 판단 내용의 변경이 아니라 링크 부착이므로
        허용된다. 판단 필드를 제자리에서 고치는 것은 DB 트리거가 거부한다.
        """
        with self.tx() as cur:
            new_id = self._insert_analysis(cur, replace(new, superseded_by=None))
            cur.execute(
                "UPDATE function_analyses SET superseded_by = ? "
                "WHERE id = ? AND superseded_by IS NULL",
                (new_id, old_id),
            )
            if cur.rowcount != 1:
                # 이미 가려진 행을 다시 가리려 한 경우. 이력이 갈라지므로 중단한다
                raise AppendOnlyViolation(f"analysis {old_id} 는 이미 가려졌거나 존재하지 않는다")
            return new_id

    def current_analysis(self, function_id: int) -> FunctionAnalysis | None:
        """현재 유효한 판단. 뷰를 통해 읽으므로 가려진 행은 보이지 않는다."""
        row = self._conn.execute(
            "SELECT * FROM v_current_analyses WHERE function_id = ? ORDER BY id DESC LIMIT 1",
            (function_id,),
        ).fetchone()
        return _analysis_from_row(row) if row is not None else None

    def current_analyses_by_run(self, run_id: str) -> list[FunctionAnalysis]:
        rows = self._conn.execute(
            "SELECT * FROM v_current_analyses WHERE run_id = ? ORDER BY id",
            (run_id,),
        ).fetchall()
        return [_analysis_from_row(r) for r in rows]

    def insert_hypothesis(self, h: Hypothesis) -> int:
        with self.tx() as cur:
            cur.execute(
                """
                INSERT INTO hypotheses (
                    run_id, function_id, statement, status, experiment_json, result_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    h.run_id,
                    h.function_id,
                    h.statement,
                    h.status,
                    h.experiment_json,
                    h.result_json,
                ),
            )
            return int(cur.lastrowid or 0)

    # -- 평가 지표 (§6) -------------------------------------------------------

    def insert_metric(
        self,
        run_id: str,
        metric: str,
        value: float,
        n: int,
        *,
        stratum: str = "all",
        corpus_state: str = "cold",
        groundtruth_version: str | None = None,
        method: str | None = None,
        k: int | None = None,
    ) -> int:
        """지표 하나를 기록한다.

        `n` 이 필수 인자인 것이 핵심이다 — 함수 12개에서 잰 92% 는 92% 가 아니다.
        기본값을 주면 호출자가 생략하고, 생략된 n 은 리포트에서 복원할 수 없다.
        """
        with self.tx() as cur:
            cur.execute(
                """
                INSERT INTO run_metrics (
                    run_id, metric, value, n, stratum, corpus_state,
                    groundtruth_version, method, k
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, metric, value, n, stratum, corpus_state, groundtruth_version, method, k),
            )
            return int(cur.lastrowid or 0)

    def ablation(self, metric: str, config_key: str) -> list[dict[str, Any]]:
        """어블레이션 — SQL 한 줄이어야 한다는 요구를 코드로 고정한다.

        애플리케이션에서 우회 집계하지 않는다. 이 질의가 안 되면 계측이 결함이므로
        집계를 우회하지 말고 결함으로 보고한다.
        """
        rows = self._conn.execute(
            """
            SELECT r.config_json ->> ('$.' || ?) AS condition,
                   m.stratum,
                   m.corpus_state,
                   AVG(m.value) AS mean_value,
                   SUM(m.n)     AS total_n,
                   COUNT(*)     AS runs
            FROM run_metrics m JOIN runs r USING (run_id)
            WHERE m.metric = ?
            GROUP BY condition, m.stratum, m.corpus_state
            ORDER BY m.stratum, m.corpus_state, condition
            """,
            (config_key, metric),
        ).fetchall()
        return [dict(r) for r in rows]

    def metrics_for_run(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT metric, value, n, stratum, corpus_state, method, k, computed_at "
            "FROM run_metrics WHERE run_id = ? ORDER BY metric, stratum",
            (run_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def table_names(self) -> set[str]:
        """이 DB 에 있는 테이블 이름. 정답 누출 점검이 사용한다."""
        rows = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')"
        ).fetchall()
        return {str(r["name"]) for r in rows}

    # -- 개발자용 조회 --------------------------------------------------------

    def readonly_query(self, sql: str, limit: int = 100) -> list[dict[str, Any]]:
        """개발자용 읽기 전용 조회 (§7 1주차 완료 기준: "SQL로 직접 질의 가능").

        **이것을 MCP 도구로 노출하지 않는다.** 만능 `query(sql)` 도구는 에이전트
        행동 귀속을 불가능하게 만들고 어블레이션을 무의미하게 한다. 사람이 CLI 에서
        쓰는 경로일 뿐이다.
        """
        stripped = sql.strip().rstrip(";").lower()
        if not stripped.startswith(_READONLY_PREFIXES):
            raise ValueError(
                f"읽기 전용 조회만 허용된다. 허용 접두사: {', '.join(_READONLY_PREFIXES)}"
            )
        rows = self._conn.execute(sql).fetchmany(limit)
        return [dict(r) for r in rows]


def redact_config(config: dict[str, Any]) -> dict[str, Any]:
    """설정에서 비밀정보로 보이는 값을 제거한다 (§10).

    키 이름 기반이라 완벽하지 않다. 그래서 이것에 의존하지 않고 **애초에 설정 객체에
    API 키를 담지 않는 것**이 1차 방어다. 이 함수는 2차 방어다.

    **문자열 값만 가린다.** 이 프로젝트에서 `token` 은 비밀정보만큼이나 자주
    토큰 수를 뜻한다 — `max_tokens_per_function` 같은 예산 상한이 `<redacted>` 로
    바뀌면 그 축으로 어블레이션을 할 수 없게 된다. 비밀정보는 문자열이고 예산은
    숫자이므로, 타입으로 가른다.
    """
    secret_markers = ("key", "token", "secret", "password", "credential")
    out: dict[str, Any] = {}
    for k, v in config.items():
        if isinstance(v, dict):
            out[k] = redact_config(v)
        elif isinstance(v, str) and any(m in k.lower() for m in secret_markers):
            out[k] = "<redacted>"
        else:
            out[k] = v
    return out


# -- 행 → dataclass 변환 -----------------------------------------------------


def _binary_from_row(row: sqlite3.Row) -> Binary:
    return Binary(
        id=int(row["id"]),
        sha256=str(row["sha256"]),
        filename=row["filename"],
        arch=str(row["arch"]),
        family_label=row["family_label"],
        ghidra_path=row["ghidra_path"],
        ghidra_version=row["ghidra_version"],
        extract_schema_version=int(row["extract_schema_version"]),
        function_count=int(row["function_count"]),
        decompile_failure_count=int(row["decompile_failure_count"]),
        analyzed_at=str(row["analyzed_at"]),
        duration_sec=row["duration_sec"],
    )


def _function_from_row(row: sqlite3.Row) -> Function:
    is_library = row["is_library"]
    return Function(
        id=int(row["id"]),
        binary_id=int(row["binary_id"]),
        addr=str(row["addr"]),
        original_name=str(row["original_name"]),
        signature=row["signature"],
        size=row["size"],
        cyclomatic=row["cyclomatic"],
        is_thunk=bool(row["is_thunk"]),
        is_external=bool(row["is_external"]),
        is_library=None if is_library is None else bool(is_library),
        decompiled=row["decompiled"],
        decompile_error=row["decompile_error"],
        code_hash=row["code_hash"],
        cfg_hash=row["cfg_hash"],
    )


def _analysis_from_row(row: sqlite3.Row) -> FunctionAnalysis:
    return FunctionAnalysis(
        id=int(row["id"]),
        run_id=str(row["run_id"]),
        function_id=int(row["function_id"]),
        proposed_name=row["proposed_name"],
        summary=row["summary"],
        evidence_json=row["evidence_json"],
        confidence=row["confidence"],
        source=row["source"],
        code_hash=row["code_hash"],
        superseded_by=row["superseded_by"],
    )
