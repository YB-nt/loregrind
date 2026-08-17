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
from typing import Any

from loregrind.db.models import (
    ApiCall,
    Binary,
    CallEdge,
    Encoding,
    ExtractMeta,
    Function,
    Import,
    StringLiteral,
    StringXref,
)
from loregrind.db.repo import Repo
from loregrind.extract.normalize import code_hash

# scripts/export_functions.py 가 쓰는 스키마 버전. 이 집합 밖이면 적재를 거부한다.
#   1 — functions.jsonl 만
#   2 — + strings.jsonl / imports.jsonl (docs/SPEC.md §3)
SUPPORTED_EXTRACT_SCHEMA_VERSIONS = frozenset({1, 2})
CURRENT_EXTRACT_SCHEMA_VERSION = 2
# 문자열·임포트를 요구하는 도구는 이 버전 이상을 요구한다
FACTS_SCHEMA_VERSION = 2

FUNCTIONS_FILE = "functions.jsonl"
STRINGS_FILE = "strings.jsonl"
IMPORTS_FILE = "imports.jsonl"
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
    extract_schema_version: int
    strings: int = 0
    string_xrefs: int = 0
    imports: int = 0
    api_calls: int = 0
    # 적재 중 발견한, 실패는 아니지만 알아야 할 것들
    warnings: tuple[str, ...] = ()


def read_meta(extract_dir: Path) -> ExtractMeta:
    path = extract_dir / META_FILE
    if not path.is_file():
        raise ExtractLoadError(f"{path} 가 없다. 추출이 완주하지 않았을 수 있다")
    raw = json.loads(path.read_text(encoding="utf-8"))
    version = int(raw["extract_schema_version"])
    if version not in SUPPORTED_EXTRACT_SCHEMA_VERSIONS:
        supported = ", ".join(str(v) for v in sorted(SUPPORTED_EXTRACT_SCHEMA_VERSIONS))
        raise ExtractLoadError(
            f"extract_schema_version {version} 는 지원하지 않는다 "
            f"(지원: {supported}). 마이그레이션이 필요하다"
        )

    def optional_count(key: str) -> int | None:
        """version 1 에는 없는 카운트. **없음과 0 을 구별한다.**

        0 으로 채우면 "문자열이 없는 바이너리"와 "문자열을 추출하지 않았다"가
        같아지고, L2 도구가 빈 결과를 사실로 반환하게 된다 (docs/SPEC.md §3).
        """
        value = raw.get(key)
        return None if value is None else int(value)

    return ExtractMeta(
        sha256=str(raw["sha256"]),
        ghidra_version=str(raw["ghidra_version"]),
        extract_schema_version=version,
        analyzed_at=str(raw["analyzed_at"]),
        function_count=int(raw["function_count"]),
        decompile_failure_count=int(raw.get("decompile_failure_count", 0)),
        duration_sec=raw.get("duration_sec"),
        warnings=list(raw.get("warnings", [])),
        string_count=optional_count("string_count"),
        import_count=optional_count("import_count"),
        api_call_count=optional_count("api_call_count"),
    )


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    """JSONL 을 통째로 읽는다. 파일이 없으면 세운다 — 조용히 빈 목록이 되지 않게."""
    if not path.is_file():
        raise ExtractLoadError(f"{path} 가 없다")
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ExtractLoadError(f"{path}:{lineno} JSON 파싱 실패: {exc}") from exc
    return records


def _coerce_encoding(raw: object) -> Encoding:
    """알 수 없는 인코딩 값을 'other' 로 접는다.

    Ghidra 데이터 타입 이름은 버전마다 늘어난다. 여기서 세우면 새 타입 하나 때문에
    추출 전체가 버려지는데, 인코딩은 그만한 값어치가 없는 부가 정보다.
    """
    text = str(raw)
    return "ascii" if text == "ascii" else "utf16le" if text == "utf16le" else "other"


def _load_strings(
    repo: Repo, extract_dir: Path, binary_id: int, meta: ExtractMeta
) -> tuple[int, int]:
    """`strings.jsonl` 적재. 반환은 (문자열 수, xref 수)."""
    records = _read_jsonl(extract_dir / STRINGS_FILE)

    literals: list[StringLiteral] = []
    xrefs: list[StringXref] = []
    seen: set[str] = set()
    for rec in records:
        addr = str(rec["address"])
        if addr in seen:
            # UNIQUE(binary_id, addr) 위반을 적재 전에 잡는다 — 어느 주소인지
            # 알려주는 편이 IntegrityError 보다 낫다
            raise ExtractLoadError(f"{STRINGS_FILE}: 문자열 주소 {addr} 가 중복된다")
        seen.add(addr)
        value = str(rec["value"])
        literals.append(
            StringLiteral(
                binary_id=binary_id,
                addr=addr,
                value=value,
                encoding=_coerce_encoding(rec.get("encoding", "other")),
                # length 는 잘리기 전 원본 길이다. 없으면 현재 길이로 둔다
                length=int(rec.get("length", len(value)) or 0),
                truncated=bool(rec.get("truncated", False)),
            )
        )
        referenced_by = rec.get("referenced_by") or []
        if not isinstance(referenced_by, list):
            raise ExtractLoadError(f"{STRINGS_FILE}: {addr} 의 referenced_by 가 리스트가 아니다")
        xrefs.extend(
            StringXref(binary_id=binary_id, function_addr=str(fn), string_addr=addr)
            for fn in referenced_by
        )

    inserted = repo.insert_strings(literals)
    if meta.string_count is not None and inserted != meta.string_count:
        raise ExtractLoadError(
            f"string_count 불일치: meta.json={meta.string_count}, "
            f"{STRINGS_FILE}={inserted}. 추출이 중간에 끊겼을 수 있다"
        )
    return inserted, repo.insert_string_xrefs(xrefs)


def _load_imports(
    repo: Repo, extract_dir: Path, binary_id: int, meta: ExtractMeta
) -> tuple[int, int]:
    """`imports.jsonl` 적재. 반환은 (임포트 수, API 호출 수).

    `api_calls` 가 `import_id` 를 참조하므로 순서가 강제된다 — imports 먼저다.
    """
    records = _read_jsonl(extract_dir / IMPORTS_FILE)

    imports: list[Import] = []
    seen: set[tuple[str, str]] = set()
    for rec in records:
        module = str(rec["module"]).lower()
        api_name = str(rec["api_name"])
        if (module, api_name) in seen:
            raise ExtractLoadError(f"{IMPORTS_FILE}: 임포트 {module}!{api_name} 가 중복된다")
        seen.add((module, api_name))
        ordinal = rec.get("ordinal")
        imports.append(
            Import(
                binary_id=binary_id,
                module=module,
                api_name=api_name,
                iat_addr=None if rec.get("iat_addr") is None else str(rec["iat_addr"]),
                ordinal=None if ordinal is None else int(ordinal),
            )
        )

    index = repo.insert_imports(imports)
    if meta.import_count is not None and len(index) != meta.import_count:
        raise ExtractLoadError(
            f"import_count 불일치: meta.json={meta.import_count}, {IMPORTS_FILE}={len(index)}"
        )

    calls: list[ApiCall] = []
    for rec in records:
        key = (str(rec["module"]).lower(), str(rec["api_name"]))
        import_id = index[key]
        entries = rec.get("calls") or []
        if not isinstance(entries, list):
            raise ExtractLoadError(f"{IMPORTS_FILE}: {key[1]} 의 calls 가 리스트가 아니다")
        for call in entries:
            calls.append(
                ApiCall(
                    binary_id=binary_id,
                    function_addr=str(call["function_addr"]),
                    import_id=import_id,
                    call_addr=str(call["call_addr"]),
                )
            )

    inserted_calls = repo.insert_api_calls(calls)
    if meta.api_call_count is not None and inserted_calls != meta.api_call_count:
        raise ExtractLoadError(
            f"api_call_count 불일치: meta.json={meta.api_call_count}, "
            f"{IMPORTS_FILE}={inserted_calls}"
        )
    return len(index), inserted_calls


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

    warnings: list[str] = []
    strings = xrefs = imports = api_calls = 0
    if meta.extract_schema_version >= FACTS_SCHEMA_VERSION:
        strings, xrefs = _load_strings(repo, extract_dir, binary_id, meta)
        imports, api_calls = _load_imports(repo, extract_dir, binary_id, meta)
    else:
        # 거부하지 않고 적재하되 흔적을 남긴다. 이 바이너리에 대해 문자열·API 도구는
        # 빈 결과가 아니라 NOT_EXTRACTED 를 반환해야 한다 (docs/SPEC.md §4.1)
        warnings.append(
            f"extract_schema_version={meta.extract_schema_version} 산출물이라 "
            "문자열·임포트가 없다. search_strings / get_apis_used 는 이 바이너리에서 "
            f"NOT_EXTRACTED 를 반환한다 (재추출하면 v{CURRENT_EXTRACT_SCHEMA_VERSION})"
        )

    return LoadResult(
        binary_id=binary_id,
        sha256=meta.sha256,
        functions=inserted,
        call_edges=edge_count,
        decompile_failures=failures,
        without_code_hash=without_hash,
        extract_schema_version=meta.extract_schema_version,
        strings=strings,
        string_xrefs=xrefs,
        imports=imports,
        api_calls=api_calls,
        warnings=tuple(warnings),
    )
