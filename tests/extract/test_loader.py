"""적재는 산출물의 형태로 성공을 판정한다.

`meta.json` 과 `functions.jsonl` 이 어긋나면 추출이 중간에 끊긴 것이다. 종료 코드가
0 이었어도 적재하지 않는다 — 빈 결과를 성공으로 넣으면 이후 모든 지표가 오염된다.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from loregrind.db.repo import Repo
from loregrind.extract.loader import ExtractLoadError, load_extract

ARCH = "x86:LE:32:default"
SHA = "b" * 64


def _write_jsonl(path: Path, records: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def write_extract(
    tmp_path: Path,
    records: list[dict[str, object]],
    *,
    function_count: int | None = None,
    decompile_failure_count: int | None = None,
    schema_version: int = 2,
    strings: list[dict[str, object]] | None = None,
    imports: list[dict[str, object]] | None = None,
    string_count: int | None = None,
    import_count: int | None = None,
    api_call_count: int | None = None,
) -> Path:
    out = tmp_path / SHA
    out.mkdir(parents=True, exist_ok=True)
    _write_jsonl(out / "functions.jsonl", records)
    failures = sum(1 for r in records if r.get("decompile_error"))
    meta: dict[str, object] = {
        "sha256": SHA,
        "ghidra_version": "11.1",
        "extract_schema_version": schema_version,
        "analyzed_at": "2026-08-17T00:00:00Z",
        "duration_sec": 1.5,
        "function_count": len(records) if function_count is None else function_count,
        "decompile_failure_count": (
            failures if decompile_failure_count is None else decompile_failure_count
        ),
        "warnings": [],
    }

    if schema_version >= 2:
        string_records = sample_strings() if strings is None else strings
        import_records = sample_imports() if imports is None else imports
        _write_jsonl(out / "strings.jsonl", string_records)
        _write_jsonl(out / "imports.jsonl", import_records)
        calls = sum(len(r.get("calls", []) or []) for r in import_records)  # type: ignore[arg-type]
        meta["string_count"] = len(string_records) if string_count is None else string_count
        meta["import_count"] = len(import_records) if import_count is None else import_count
        meta["api_call_count"] = calls if api_call_count is None else api_call_count

    (out / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return out


def sample_strings() -> list[dict[str, object]]:
    return [
        {
            "address": "0x403000",
            "value": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "encoding": "ascii",
            "length": 45,
            "truncated": False,
            "referenced_by": ["0x401000"],
        },
        {
            # 참조가 없는 문자열도 남긴다 — 버리면 정보가 사라진다
            "address": "0x403100",
            "value": "unreferenced",
            "encoding": "utf16le",
            "length": 12,
            "truncated": False,
            "referenced_by": [],
        },
    ]


def sample_imports() -> list[dict[str, object]]:
    return [
        {
            "module": "kernel32.dll",
            "api_name": "VirtualAlloc",
            "iat_addr": "0x402000",
            "ordinal": None,
            "calls": [{"function_addr": "0x401000", "call_addr": "0x401010"}],
        },
        {
            "module": "advapi32.dll",
            "api_name": "RegSetValueExA",
            "iat_addr": "0x402004",
            "ordinal": None,
            "calls": [
                {"function_addr": "0x401000", "call_addr": "0x401020"},
                {"function_addr": "0x401230", "call_addr": "0x401240"},
            ],
        },
    ]


def sample_records() -> list[dict[str, object]]:
    return [
        {
            "address": "0x401000",
            "name": "FUN_00401000",
            "is_thunk": False,
            "is_external": False,
            "signature": "void FUN_00401000(void)",
            "decompiled": "void FUN_00401000(void) { FUN_00401230(); return; }",
            "decompile_error": None,
            "callees": ["0x401230"],
            "size": 42,
            "cyclomatic": 3,
        },
        {
            "address": "0x401230",
            "name": "FUN_00401230",
            "is_thunk": False,
            "is_external": False,
            "signature": "void FUN_00401230(void)",
            # 디컴파일 실패도 레코드로 남는다
            "decompiled": None,
            "decompile_error": "decompile did not complete",
            "callees": [],
            "size": 7,
            "cyclomatic": None,
        },
    ]


@pytest.fixture
def repo() -> Repo:
    return Repo.open(":memory:")


def test_load_records_functions_and_edges(repo: Repo, tmp_path: Path) -> None:
    result = load_extract(repo, write_extract(tmp_path, sample_records()), arch=ARCH)
    assert result.functions == 2
    assert result.call_edges == 1
    assert result.decompile_failures == 1

    # 실패한 함수도 조회된다 — 레코드를 빼지 않았다는 증거
    failed = repo.get_function(result.binary_id, "0x401230")
    assert failed is not None
    assert failed.decompiled is None
    assert failed.decompile_error == "decompile did not complete"
    assert failed.code_hash is None

    ok = repo.get_function(result.binary_id, "0x401000")
    assert ok is not None and ok.code_hash is not None
    assert repo.get_callees(result.binary_id, "0x401000") == ["0x401230"]


def test_function_count_mismatch_is_rejected(repo: Repo, tmp_path: Path) -> None:
    extract_dir = write_extract(tmp_path, sample_records(), function_count=99)
    with pytest.raises(ExtractLoadError, match="function_count 불일치"):
        load_extract(repo, extract_dir, arch=ARCH)


def test_failure_count_mismatch_is_rejected(repo: Repo, tmp_path: Path) -> None:
    extract_dir = write_extract(tmp_path, sample_records(), decompile_failure_count=0)
    with pytest.raises(ExtractLoadError, match="decompile_failure_count 불일치"):
        load_extract(repo, extract_dir, arch=ARCH)


def test_unsupported_schema_version_is_rejected(repo: Repo, tmp_path: Path) -> None:
    """추출 스키마가 바뀌면 조용히 적재하지 않는다. 마이그레이션이 필요하다."""
    extract_dir = write_extract(tmp_path, sample_records(), schema_version=99)
    with pytest.raises(ExtractLoadError, match="extract_schema_version"):
        load_extract(repo, extract_dir, arch=ARCH)


def test_v1_extract_loads_without_facts_but_warns(repo: Repo, tmp_path: Path) -> None:
    """구버전 산출물은 거부하지 않되 흔적을 남긴다.

    문자열·임포트가 0 인 것이 아니라 **추출되지 않은** 것이므로, 이 사실이 사라지면
    L2 도구가 빈 결과를 사실로 반환하게 된다 (docs/SPEC.md §3).
    """
    result = load_extract(
        repo, write_extract(tmp_path, sample_records(), schema_version=1), arch=ARCH
    )
    assert result.extract_schema_version == 1
    assert result.strings == 0 and result.imports == 0
    assert any("NOT_EXTRACTED" in w for w in result.warnings)


def test_load_strings_and_imports(repo: Repo, tmp_path: Path) -> None:
    result = load_extract(repo, write_extract(tmp_path, sample_records()), arch=ARCH)
    assert result.extract_schema_version == 2
    assert (result.strings, result.string_xrefs) == (2, 1)
    assert (result.imports, result.api_calls) == (2, 3)

    apis = repo.get_apis_used(result.binary_id, "0x401000")
    assert [(a["module"], a["api_name"]) for a in apis] == [
        ("advapi32.dll", "RegSetValueExA"),
        ("kernel32.dll", "VirtualAlloc"),
    ]

    hits = repo.search_strings(result.binary_id, "CurrentVersion")
    assert len(hits) == 1
    assert hits[0]["referenced_by"] == ["0x401000"]
    assert repo.get_string_referrers(result.binary_id, "0x403100") == []


def test_string_count_mismatch_is_rejected(repo: Repo, tmp_path: Path) -> None:
    extract_dir = write_extract(tmp_path, sample_records(), string_count=99)
    with pytest.raises(ExtractLoadError, match="string_count 불일치"):
        load_extract(repo, extract_dir, arch=ARCH)


def test_api_call_count_mismatch_is_rejected(repo: Repo, tmp_path: Path) -> None:
    extract_dir = write_extract(tmp_path, sample_records(), api_call_count=1)
    with pytest.raises(ExtractLoadError, match="api_call_count 불일치"):
        load_extract(repo, extract_dir, arch=ARCH)


def test_duplicate_string_address_is_rejected(repo: Repo, tmp_path: Path) -> None:
    """UNIQUE 위반을 IntegrityError 가 아니라 어느 주소인지로 보고한다."""
    dupes = sample_strings()
    dupes[1]["address"] = dupes[0]["address"]
    extract_dir = write_extract(tmp_path, sample_records(), strings=dupes)
    with pytest.raises(ExtractLoadError, match="0x403000 가 중복"):
        load_extract(repo, extract_dir, arch=ARCH)


def test_missing_strings_file_is_rejected(repo: Repo, tmp_path: Path) -> None:
    """v2 를 선언했는데 파일이 없으면 빈 목록이 아니라 실패다."""
    extract_dir = write_extract(tmp_path, sample_records())
    (extract_dir / "strings.jsonl").unlink()
    with pytest.raises(ExtractLoadError, match=r"strings\.jsonl 가 없다"):
        load_extract(repo, extract_dir, arch=ARCH)


def test_import_module_is_lowercased(repo: Repo, tmp_path: Path) -> None:
    """KERNEL32.dll 과 kernel32.dll 이 갈라지면 API 집합 채널의 교집합이 비어간다."""
    imports = sample_imports()
    imports[0]["module"] = "KERNEL32.DLL"
    result = load_extract(
        repo, write_extract(tmp_path, sample_records(), imports=imports), arch=ARCH
    )
    apis = repo.get_apis_used(result.binary_id, "0x401000")
    assert ("kernel32.dll", "VirtualAlloc") in [(a["module"], a["api_name"]) for a in apis]


def test_duplicate_binary_is_rejected(repo: Repo, tmp_path: Path) -> None:
    extract_dir = write_extract(tmp_path, sample_records())
    load_extract(repo, extract_dir, arch=ARCH)
    with pytest.raises(ExtractLoadError, match="이미 적재"):
        load_extract(repo, extract_dir, arch=ARCH)


def test_missing_meta_is_rejected(repo: Repo, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ExtractLoadError, match=r"meta\.json"):
        load_extract(repo, empty, arch=ARCH)


def test_family_label_is_stored_but_not_a_verdict(repo: Repo, tmp_path: Path) -> None:
    """사전정보는 저장만 한다. 결론으로 쓰는 것은 상위 계층에서 금지된다 (불변식 7)."""
    result = load_extract(
        repo, write_extract(tmp_path, sample_records()), arch=ARCH, family_label="suspected-rc4"
    )
    binary = repo.get_binary_by_sha256(result.sha256)
    assert binary is not None
    assert binary.family_label == "suspected-rc4"
    # 라벨이 판단 테이블로 새어 들어가지 않았다
    assert repo.readonly_query("SELECT COUNT(*) AS n FROM function_analyses")[0]["n"] == 0
