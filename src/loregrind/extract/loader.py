"""L1 적재 — Ghidra 산출물(JSONL)을 읽어 DB 에 넣는다.

**추출과 적재는 분리되어 있다.** Ghidra 스크립트(`scripts/export_functions.py`)는
Ghidra 인터프리터에서 돌며 파일만 남기고, 이 모듈이 그 파일을 읽는다. 함수 호출로
잇지 않는 이유는 두 세계가 서로 다른 인터프리터·의존성에서 돌기 때문이다
(불변식 1도 같은 방향이다 — 에이전트 런타임은 Ghidra 를 호출하지 않는다).

여기서 다루는 값(`original_name`, `signature`, 디컴파일 텍스트)은 전부 **바이너리에서
나온 데이터**다. 프롬프트로 흘려보낼 때는 반드시 격리 래핑을 거쳐야 한다 (§10).
이 모듈은 DB 에만 쓰므로 래핑하지 않지만, 여기서 나간 값이 어디로 가는지는
호출자의 책임이다.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from loregrind.db.models import Binary, CallEdge, ExtractMeta, Function
from loregrind.db.repo import Repo
from loregrind.extract.normalize import code_hash

# scripts/export_functions.py 가 쓰는 스키마 버전. 맞지 않으면 적재를 거부한다
SUPPORTED_EXTRACT_SCHEMA_VERSION = 1

FUNCTIONS_FILE = "functions.jsonl"
META_FILE = "meta.json"


class ExtractLoadError(RuntimeError):
    """적재를 진행할 수 없는 상태. 조용히 넘기지 않고 세운다."""


@dataclass(frozen=True, slots=True)
class LoadResult:
    binary_id: int
    sha256: str
    functions: int
    call_edges: int
    decompile_failures: int
    # 디컴파일은 됐지만 정규화 결과가 비어 code_hash 를 못 만든 함수 수.
    # 0 이 아니면 정규화 규칙이 너무 공격적인지 확인해야 한다
    without_code_hash: int


def read_meta(extract_dir: Path) -> ExtractMeta:
    path = extract_dir / META_FILE
    if not path.is_file():
        raise ExtractLoadError(f"{path} 가 없다. 추출이 완주하지 않았을 수 있다")
    raw = json.loads(path.read_text(encoding="utf-8"))
    version = int(raw["extract_schema_version"])
    if version != SUPPORTED_EXTRACT_SCHEMA_VERSION:
        raise ExtractLoadError(
            f"extract_schema_version {version} 는 지원하지 않는다 "
            f"(지원: {SUPPORTED_EXTRACT_SCHEMA_VERSION}). 마이그레이션이 필요하다"
        )
    return ExtractMeta(
        sha256=str(raw["sha256"]),
        ghidra_version=str(raw["ghidra_version"]),
        extract_schema_version=version,
        analyzed_at=str(raw["analyzed_at"]),
        function_count=int(raw["function_count"]),
        decompile_failure_count=int(raw.get("decompile_failure_count", 0)),
        duration_sec=raw.get("duration_sec"),
        warnings=list(raw.get("warnings", [])),
    )


def load_extract(
    repo: Repo,
    extract_dir: Path,
    arch: str,
    *,
    filename: str | None = None,
    family_label: str | None = None,
    ghidra_path: str | None = None,
) -> LoadResult:
    """추출 디렉터리 하나를 적재한다.

    `family_label` 은 사전정보다. 결론이 아니라 가설로 쓰인다 (불변식 7) — 여기서는
    저장만 하고, 이 값을 근거로 판단을 내리는 것은 상위 계층에서 금지된다.
    """
    meta = read_meta(extract_dir)

    if repo.get_binary_by_sha256(meta.sha256) is not None:
        raise ExtractLoadError(
            f"sha256 {meta.sha256[:12]}… 는 이미 적재돼 있다. "
            "재적재는 증분 재분석 경로로 해야 한다 (§4) — 지금은 지원하지 않는다"
        )

    binary_id = repo.insert_binary(
        Binary(
            sha256=meta.sha256,
            arch=arch,
            filename=filename,
            family_label=family_label,
            ghidra_path=ghidra_path,
            ghidra_version=meta.ghidra_version,
            extract_schema_version=meta.extract_schema_version,
            function_count=meta.function_count,
            decompile_failure_count=meta.decompile_failure_count,
            analyzed_at=meta.analyzed_at,
            duration_sec=meta.duration_sec,
        )
    )

    functions: list[Function] = []
    edges: list[CallEdge] = []
    failures = 0
    without_hash = 0

    jsonl = extract_dir / FUNCTIONS_FILE
    if not jsonl.is_file():
        raise ExtractLoadError(f"{jsonl} 가 없다")

    with jsonl.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ExtractLoadError(f"{jsonl}:{lineno} JSON 파싱 실패: {exc}") from exc

            decompiled = rec.get("decompiled")
            error = rec.get("decompile_error")
            if error:
                failures += 1
            digest = code_hash(decompiled)
            if decompiled and digest is None:
                without_hash += 1

            addr = str(rec["address"])
            functions.append(
                Function(
                    binary_id=binary_id,
                    addr=addr,
                    original_name=str(rec["name"]),
                    signature=rec.get("signature"),
                    size=rec.get("size"),
                    cyclomatic=rec.get("cyclomatic"),
                    is_thunk=bool(rec.get("is_thunk", False)),
                    is_external=bool(rec.get("is_external", False)),
                    decompiled=decompiled,
                    decompile_error=error,
                    code_hash=digest,
                )
            )
            edges.extend(
                CallEdge(binary_id=binary_id, caller_addr=addr, callee_addr=str(callee))
                for callee in rec.get("callees", [])
            )

    inserted = repo.insert_functions(functions)
    edge_count = repo.insert_call_edges(edges)

    # meta.json 과 실제 레코드 수가 어긋나면 추출이 중간에 끊긴 것이다.
    # 종료 코드 0 을 믿지 않는다 — 산출물의 형태로 판정한다
    if inserted != meta.function_count:
        raise ExtractLoadError(
            f"function_count 불일치: meta.json={meta.function_count}, "
            f"functions.jsonl={inserted}. 추출이 중간에 끊겼을 수 있다"
        )
    if failures != meta.decompile_failure_count:
        raise ExtractLoadError(
            f"decompile_failure_count 불일치: meta.json={meta.decompile_failure_count}, "
            f"functions.jsonl={failures}"
        )

    return LoadResult(
        binary_id=binary_id,
        sha256=meta.sha256,
        functions=inserted,
        call_edges=edge_count,
        decompile_failures=failures,
        without_code_hash=without_hash,
    )
