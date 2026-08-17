"""문자열·임포트 조회 계약 (마이그레이션 0002, docs/SPEC.md §3·§4.2).

여기서 고정하는 것은 두 가지다.

1. **질의 표현력이 고정되어 있다.** `search_strings` 는 부분 문자열만 받는다.
   사용자 입력의 `%` `_` 가 와일드카드로 작동하면 질의 표현력이 가변이 되고,
   §6 탐색 효율을 run 사이에서 비교할 수 없다.
2. **목록 순서가 결정론적이다.** 순서가 흔들리면 같은 run 을 두 번 돌린 결과가
   달라진다.
"""

from __future__ import annotations

import pytest

from loregrind.db.models import ApiCall, Binary, Import, StringLiteral, StringXref
from loregrind.db.repo import Repo


@pytest.fixture
def repo() -> Repo:
    return Repo.open(":memory:")


@pytest.fixture
def binary_id(repo: Repo) -> int:
    return repo.insert_binary(
        Binary(
            sha256="c" * 64,
            arch="x86:LE:32:default",
            extract_schema_version=2,
            function_count=0,
            analyzed_at="2026-08-18T00:00:00Z",
        )
    )


def _seed_strings(repo: Repo, binary_id: int) -> None:
    repo.insert_strings(
        [
            StringLiteral(
                binary_id=binary_id,
                addr="0x403000",
                value="100%_complete",
                encoding="ascii",
                length=13,
            ),
            StringLiteral(
                binary_id=binary_id,
                addr="0x403020",
                value="1000_complete",
                encoding="ascii",
                length=13,
            ),
            StringLiteral(
                binary_id=binary_id, addr="0x403040", value="abc", encoding="ascii", length=3
            ),
        ]
    )


def test_search_strings_treats_wildcards_literally(repo: Repo, binary_id: int) -> None:
    """`%` 는 와일드카드가 아니라 문자다. 아니면 질의 표현력이 가변이 된다."""
    _seed_strings(repo, binary_id)
    hits = repo.search_strings(binary_id, "100%_")
    assert [h["addr"] for h in hits] == ["0x403000"]

    # 와일드카드로 해석되면 "1000_complete"(0x403020) 도 걸린다.
    # 문자로 해석되므로 "100%_complete" 하나만 나온다
    assert [h["addr"] for h in repo.search_strings(binary_id, "0%_c")] == ["0x403000"]


def test_search_strings_honours_min_length(repo: Repo, binary_id: int) -> None:
    _seed_strings(repo, binary_id)
    assert [h["addr"] for h in repo.search_strings(binary_id, "abc", min_length=4)] == []
    assert [h["addr"] for h in repo.search_strings(binary_id, "abc", min_length=3)] == ["0x403040"]


def test_search_strings_is_ordered_and_limited(repo: Repo, binary_id: int) -> None:
    _seed_strings(repo, binary_id)
    hits = repo.search_strings(binary_id, "complete", limit=1)
    # 주소 오름차순 고정. limit 이 걸려도 어느 행이 나올지 정해져 있다
    assert [h["addr"] for h in hits] == ["0x403000"]


def test_string_xrefs_are_bidirectional(repo: Repo, binary_id: int) -> None:
    _seed_strings(repo, binary_id)
    repo.insert_string_xrefs(
        [
            StringXref(binary_id=binary_id, function_addr="0x401000", string_addr="0x403000"),
            StringXref(binary_id=binary_id, function_addr="0x401100", string_addr="0x403000"),
            # 같은 간선이 두 번 와도 실패하지 않는다 — 추출 사실의 중복은 무해하다
            StringXref(binary_id=binary_id, function_addr="0x401100", string_addr="0x403000"),
        ]
    )
    assert repo.get_string_referrers(binary_id, "0x403000") == ["0x401000", "0x401100"]
    for_function = repo.get_strings_for_function(binary_id, "0x401000")
    assert [s["addr"] for s in for_function] == ["0x403000"]


def test_get_apis_used_counts_call_sites(repo: Repo, binary_id: int) -> None:
    index = repo.insert_imports(
        [
            Import(binary_id=binary_id, module="kernel32.dll", api_name="VirtualAlloc"),
            Import(binary_id=binary_id, module="kernel32.dll", api_name="CreateFileA"),
        ]
    )
    virtual_alloc = index[("kernel32.dll", "VirtualAlloc")]
    create_file = index[("kernel32.dll", "CreateFileA")]
    repo.insert_api_calls(
        [
            ApiCall(
                binary_id=binary_id,
                function_addr="0x401000",
                import_id=virtual_alloc,
                call_addr="0x401010",
            ),
            ApiCall(
                binary_id=binary_id,
                function_addr="0x401000",
                import_id=virtual_alloc,
                call_addr="0x401030",
            ),
            ApiCall(
                binary_id=binary_id,
                function_addr="0x401000",
                import_id=create_file,
                call_addr="0x401050",
            ),
        ]
    )
    apis = repo.get_apis_used(binary_id, "0x401000")
    # 호출 수 내림차순 → 동수면 이름순. 결정론적이어야 한다
    assert [(a["api_name"], a["call_count"]) for a in apis] == [
        ("VirtualAlloc", 2),
        ("CreateFileA", 1),
    ]
    assert repo.get_apis_used(binary_id, "0x409999") == []


def test_facts_are_scoped_to_binary(repo: Repo, binary_id: int) -> None:
    """다른 바이너리의 사실이 새어 들어오지 않는다 — L2 는 바이너리 하나에 고정된다."""
    _seed_strings(repo, binary_id)
    other = repo.insert_binary(
        Binary(
            sha256="d" * 64,
            arch="x86:LE:32:default",
            extract_schema_version=2,
            function_count=0,
            analyzed_at="2026-08-18T00:00:00Z",
        )
    )
    assert repo.search_strings(other, "complete") == []
