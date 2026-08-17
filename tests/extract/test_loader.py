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


def write_extract(
    tmp_path: Path,
    records: list[dict[str, object]],
    *,
    function_count: int | None = None,
    decompile_failure_count: int | None = None,
    schema_version: int = 1,
) -> Path:
    out = tmp_path / SHA
    out.mkdir(parents=True, exist_ok=True)
    with (out / "functions.jsonl").open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    failures = sum(1 for r in records if r.get("decompile_error"))
    meta = {
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
    (out / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return out


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
    extract_dir = write_extract(tmp_path, sample_records(), schema_version=2)
    with pytest.raises(ExtractLoadError, match="extract_schema_version"):
        load_extract(repo, extract_dir, arch=ARCH)


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
