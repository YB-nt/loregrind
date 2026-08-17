"""누출 점검과 리포트 규율 테스트.

누출은 조용하다 — 숫자가 좋아지고 에러는 안 난다. 그래서 게이트가 실제로 잡는지를
테스트로 고정한다. 리포트 쪽은 **홀드아웃 열이 사라지지 않는지**를 검사한다.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval import leakage
from eval.metrics import MetricValue
from eval.report import cutline_verdict, render_metric_table, render_report
from eval.truthset import GroundTruth, TruthBinary, TruthFunction, load, stratum
from loregrind.db.models import Binary, Function
from loregrind.db.repo import Repo

SHA = "a" * 64


@pytest.fixture
def repo() -> Repo:
    return Repo.open(":memory:")


def gt_with(true_name: str) -> GroundTruth:
    return GroundTruth(
        version="t1",
        binaries=(
            TruthBinary(
                sha256=SHA,
                source_project="demo",
                compiler="gcc",
                opt_level="-O0",
                functions=(TruthFunction(addr="0x401000", true_name=true_name),),
            ),
        ),
    )


def seed(repo: Repo, *, original_name: str, decompiled: str) -> None:
    binary_id = repo.insert_binary(
        Binary(
            sha256=SHA,
            arch="x86:LE:32:default",
            extract_schema_version=1,
            function_count=1,
            analyzed_at="2026-08-17T00:00:00Z",
        )
    )
    repo.insert_functions(
        [
            Function(
                binary_id=binary_id,
                addr="0x401000",
                original_name=original_name,
                decompiled=decompiled,
            )
        ]
    )


# -- 마이그레이션 ------------------------------------------------------------


def test_migration_applied_on_connect(repo: Repo) -> None:
    """0001 이 자동 적용된다 — run_metrics 가 없으면 지표를 저장할 수 없다."""
    assert "run_metrics" in repo.table_names()
    applied = repo.readonly_query("SELECT filename FROM schema_migrations")
    assert any("0001" in str(r["filename"]) for r in applied)


def test_metric_requires_n(repo: Repo) -> None:
    run = repo.create_run("m", "v1", {})
    repo.insert_metric(run.run_id, "naming_accuracy", 0.5, 2, stratum="gcc:-O0")
    rows = repo.metrics_for_run(run.run_id)
    assert rows[0]["n"] == 2


def test_run_metrics_cannot_be_deleted(repo: Repo) -> None:
    """나쁜 숫자를 지우면 5주차 컷라인 판단이 불가능해진다."""
    import sqlite3

    run = repo.create_run("m", "v1", {})
    repo.insert_metric(run.run_id, "naming_accuracy", 0.1, 5)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        repo._conn.execute("DELETE FROM run_metrics")


def test_ablation_is_one_sql_query(repo: Repo) -> None:
    """어블레이션이 SQL 로 뽑히지 않으면 계측 결함이다 (§6)."""
    on = repo.create_run("m", "v1", {"rename_writes": True})
    off = repo.create_run("m", "v1", {"rename_writes": False})
    repo.insert_metric(on.run_id, "naming_accuracy", 0.8, 10)
    repo.insert_metric(off.run_id, "naming_accuracy", 0.5, 10)

    rows = repo.ablation("naming_accuracy", "rename_writes")
    by_cond = {str(r["condition"]): r["mean_value"] for r in rows}
    assert by_cond["1"] == pytest.approx(0.8)
    assert by_cond["0"] == pytest.approx(0.5)


# -- 누출 점검 ---------------------------------------------------------------


def test_leaked_symbol_in_corpus_is_blocking(repo: Repo) -> None:
    seed(repo, original_name="FUN_00401000", decompiled="void rc4_init(void){return;}")
    report = leakage.audit(
        repo, gt_with("rc4_init"), Path("eval/groundtruth/gt.json"), Path("x.db")
    )
    assert not report.clean
    assert any(f.kind == "symbol-in-corpus" for f in report.blocking)


def test_clean_corpus_passes(repo: Repo) -> None:
    seed(repo, original_name="FUN_00401000", decompiled="void FUN_00401000(void){return;}")
    report = leakage.audit(
        repo, gt_with("rc4_init"), Path("eval/groundtruth/gt.json"), Path("x.db")
    )
    assert report.clean


def test_short_symbol_names_are_skipped_to_avoid_false_positives(repo: Repo) -> None:
    seed(repo, original_name="FUN_00401000", decompiled="int i = 0; xor(i);")
    report = leakage.audit(repo, gt_with("xor"), Path("eval/groundtruth/gt.json"), Path("x.db"))
    assert report.clean


def test_groundtruth_inside_agent_readable_dir_is_blocking(repo: Repo) -> None:
    """가장 흔한 누출 경로 — 정답셋이 에이전트가 읽는 디렉터리에 있는 경우."""
    findings = leakage.check_groundtruth_location(
        Path("artifacts/extract/gt.json"), Path("loregrind.db")
    )
    assert any(f.kind == "groundtruth-location" for f in findings)
    assert any(f.severity == leakage.SEVERITY_BLOCKING for f in findings)


def test_pdb_path_is_warned(repo: Repo) -> None:
    seed(repo, original_name="FUN_00401000", decompiled=r'x = "C:\build\demo\demo.pdb";')
    report = leakage.audit(
        repo, gt_with("rc4_init"), Path("eval/groundtruth/gt.json"), Path("x.db")
    )
    assert any(f.kind == "pdb-path" for f in report.findings)


def test_report_records_skipped_checks(repo: Repo) -> None:
    """건너뛴 검사를 통과로 읽지 않게 한다."""
    seed(repo, original_name="FUN_00401000", decompiled="void FUN_00401000(void){}")
    report = leakage.audit(
        repo, gt_with("rc4_init"), Path("eval/groundtruth/gt.json"), Path("x.db")
    )
    assert report.checks_skipped
    assert "건너뛴 검사" in report.render()


# -- 정답셋 로딩 -------------------------------------------------------------


def test_missing_groundtruth_raises_instead_of_empty(tmp_path: Path) -> None:
    """빈 정답셋으로 조용히 진행하면 모든 지표가 n=0 이 되고 '측정했다'는 착시가 생긴다."""
    with pytest.raises(FileNotFoundError, match="정답셋"):
        load(tmp_path / "nope.json")


def test_groundtruth_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "gt.json"
    path.write_text(
        json.dumps(
            {
                "version": "v1",
                "binaries": [
                    {
                        "sha256": SHA,
                        "source_project": "demo",
                        "compiler": "clang",
                        "opt_level": "-O3",
                        "is_holdout": True,
                        "functions": [
                            {"addr": "0x1", "true_name": "aes_encrypt", "is_key_function": True}
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    gt = load(path)
    assert gt.strata() == [stratum("clang", "-O3")]
    assert gt.key_functions(SHA) == ["0x1"]
    assert gt.binaries[0].is_holdout


# -- 리포트 규율 -------------------------------------------------------------


def test_holdout_column_always_rendered() -> None:
    """웜만 담은 표는 만들지 않는다. 열이 사라지면 미측정 사실도 사라진다."""
    table = render_metric_table(
        "naming_accuracy",
        [MetricValue("naming_accuracy", 0.8, 10, stratum="gcc:-O2", corpus_state="warm")],
    )
    assert "holdout" in table
    assert "측정 안 함" in table
    assert "홀드아웃 미측정" in table


def test_unmeasured_cells_are_left_empty_with_reason() -> None:
    values = [
        MetricValue("naming_accuracy", None, 0, stratum="msvc:-O2", unmeasured_reason="빌드 실패")
    ]
    out = render_report(values)
    assert "빌드 실패" in out
    assert "미측정 / 측정 불가" in out


def test_cutline_requires_core_metrics_and_holdout() -> None:
    ok, reason = cutline_verdict([])
    assert not ok
    assert "코어 지표 미측정" in reason

    core = [
        MetricValue("naming_accuracy", 0.7, 20, corpus_state="warm"),
        MetricValue("hallucination_rate", 0.1, 20, corpus_state="warm"),
        MetricValue("exploration_efficiency", 0.2, 20, corpus_state="warm"),
    ]
    ok, reason = cutline_verdict(core)
    assert not ok
    assert "홀드아웃" in reason

    ok, reason = cutline_verdict(
        [*core, MetricValue("naming_accuracy", 0.6, 8, corpus_state="holdout")]
    )
    assert ok
