"""정답 누출 차단 — 지표를 재기 전에 먼저 할 일.

원본 심볼명이 에이전트가 보는 컨텍스트로 흘러들면 **명명 정확도가 통째로 무의미해진다.**
누출은 조용하다. 숫자는 좋아지고 아무 에러도 나지 않는다. 그래서 자동 점검을 게이트로
둔다(`make verify-holdout`).

§6 이 지정한 점검 경로:
  1. 스트립 후에도 남는 디버그 섹션 / 익스포트 테이블 / RTTI
  2. PDB 경로 문자열
  3. 어서션·로그 문자열에 박힌 함수명 (`__func__`, `assert` 매크로 전개)
  4. **정답셋 파일이 에이전트가 접근 가능한 DB/디렉터리에 있는 경우** ← 가장 흔하다
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from eval.truthset import GroundTruth
from loregrind.db.repo import Repo

# 에이전트가 읽는 경로. 정답셋이 이 안에 있으면 누출이다
AGENT_READABLE_DIRS = ("artifacts", ".ghidra-projects")

_PDB_PATH = re.compile(r"[A-Za-z]:\\.{0,200}?\.pdb", re.IGNORECASE)
_FUNC_MACRO = re.compile(r"__func__|__FUNCTION__|__PRETTY_FUNCTION__")
# 스트립되지 않은 디버그 흔적
_DEBUG_SECTION = re.compile(r"\.debug_(info|line|str)|\.symtab|__DWARF", re.IGNORECASE)

SEVERITY_BLOCKING = "blocking"
SEVERITY_WARN = "warn"


@dataclass(frozen=True, slots=True)
class Finding:
    """누출 의심 1건."""

    path: str  # 어디서 발견했는가 (경로 / 테이블.컬럼)
    kind: str
    detail: str
    severity: str = SEVERITY_BLOCKING


@dataclass(frozen=True, slots=True)
class LeakageReport:
    findings: tuple[Finding, ...]
    # 실제로 무엇을 검사했는가. 검사하지 않은 것을 통과로 읽지 않게 하려는 기록
    checks_run: tuple[str, ...]
    checks_skipped: tuple[tuple[str, str], ...] = ()

    @property
    def blocking(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity == SEVERITY_BLOCKING)

    @property
    def clean(self) -> bool:
        return not self.blocking

    def render(self) -> str:
        lines = ["# 정답 누출 점검", ""]
        lines.append(f"- 실행한 검사: {len(self.checks_run)}개")
        for name in self.checks_run:
            lines.append(f"  - {name}")
        if self.checks_skipped:
            lines.append(f"- **건너뛴 검사: {len(self.checks_skipped)}개** (통과가 아니다)")
            for name, reason in self.checks_skipped:
                lines.append(f"  - {name} — {reason}")
        lines.append("")
        if not self.findings:
            lines.append("발견된 누출 없음.")
            return "\n".join(lines)
        lines.append(f"## 발견 {len(self.findings)}건 (차단 {len(self.blocking)}건)")
        lines.append("")
        lines.append("| 심각도 | 위치 | 종류 | 내용 |")
        lines.append("|---|---|---|---|")
        for f in self.findings:
            lines.append(f"| {f.severity} | `{f.path}` | {f.kind} | {f.detail} |")
        return "\n".join(lines)


def check_groundtruth_location(gt_path: Path, db_path: Path) -> list[Finding]:
    """정답셋이 에이전트가 읽는 곳에 있지 않은지. 가장 흔한 누출 경로다."""
    out: list[Finding] = []
    resolved = gt_path.resolve()
    parts = resolved.parts
    for agent_dir in AGENT_READABLE_DIRS:
        if agent_dir in parts:
            out.append(
                Finding(
                    path=str(gt_path),
                    kind="groundtruth-location",
                    detail=f"정답셋이 에이전트 접근 경로(`{agent_dir}/`) 안에 있다",
                )
            )
    if resolved.parent == db_path.resolve().parent and db_path.name != gt_path.name:
        out.append(
            Finding(
                path=str(gt_path),
                kind="groundtruth-location",
                detail=(
                    f"정답셋이 에이전트 DB(`{db_path.name}`)와 같은 디렉터리에 있다. "
                    "물리적으로 분리하라"
                ),
                severity=SEVERITY_WARN,
            )
        )
    return out


def check_db_has_no_truth_tables(repo: Repo) -> list[Finding]:
    """에이전트 DB 에 정답 테이블이 들어와 있지 않은지."""
    suspicious = {"groundtruth", "ground_truth", "truth", "labels", "answers"}
    present = {t for t in repo.table_names() if t.lower() in suspicious}
    return [
        Finding(
            path=f"db:{name}",
            kind="truth-table-in-agent-db",
            detail="정답 테이블이 에이전트 DB 안에 있다. 별 파일로 분리하라",
        )
        for name in sorted(present)
    ]


def check_symbols_not_in_corpus(repo: Repo, gt: GroundTruth) -> list[Finding]:
    """원본 심볼명이 에이전트가 읽는 값에 남아 있지 않은지.

    스트립이 제대로 됐다면 `functions.original_name` 은 `FUN_...` 형태여야 하고,
    디컴파일 텍스트·시그니처에도 원본 이름이 없어야 한다.

    짧은 이름(3자 이하)은 우연 일치가 많아 검사에서 뺀다 — 거짓 양성이 쌓이면
    이 게이트를 사람이 무시하기 시작한다.
    """
    truth_names = {n for n in gt.all_true_names() if len(n) > 3}
    if not truth_names:
        return []
    rows = repo.readonly_query(
        "SELECT b.sha256 AS sha256, f.addr AS addr, f.original_name AS original_name, "
        "f.signature AS signature, f.decompiled AS decompiled "
        "FROM functions f JOIN binaries b ON b.id = f.binary_id",
        limit=1_000_000,
    )
    out: list[Finding] = []
    for row in rows:
        haystack = "\n".join(
            str(row.get(col) or "") for col in ("original_name", "signature", "decompiled")
        )
        for name in truth_names:
            if name in haystack:
                out.append(
                    Finding(
                        path=f"db:functions[{str(row['sha256'])[:8]}…@{row['addr']}]",
                        kind="symbol-in-corpus",
                        detail=f"원본 심볼명 `{name}` 이 에이전트가 읽는 값에 남아 있다",
                    )
                )
    return out


def check_debug_artifacts(repo: Repo) -> list[Finding]:
    """PDB 경로·`__func__`·디버그 섹션 흔적. 스트립이 불완전하다는 신호다."""
    rows = repo.readonly_query(
        "SELECT b.sha256 AS sha256, f.addr AS addr, f.decompiled AS decompiled "
        "FROM functions f JOIN binaries b ON b.id = f.binary_id "
        "WHERE f.decompiled IS NOT NULL",
        limit=1_000_000,
    )
    checks = (
        ("pdb-path", _PDB_PATH),
        ("func-macro", _FUNC_MACRO),
        ("debug-section", _DEBUG_SECTION),
    )
    out: list[Finding] = []
    for row in rows:
        text = str(row["decompiled"])
        for kind, pattern in checks:
            match = pattern.search(text)
            if match:
                out.append(
                    Finding(
                        path=f"db:functions[{str(row['sha256'])[:8]}…@{row['addr']}]",
                        kind=kind,
                        detail=f"`{match.group(0)[:80]}` — 스트립이 불완전할 수 있다",
                        severity=SEVERITY_WARN,
                    )
                )
    return out


def audit(repo: Repo, gt: GroundTruth, gt_path: Path, db_path: Path) -> LeakageReport:
    """전체 누출 점검. `make verify-holdout` 의 첫 단계다."""
    findings: list[Finding] = []
    run: list[str] = []
    skipped: list[tuple[str, str]] = []

    findings += check_groundtruth_location(gt_path, db_path)
    run.append("정답셋 위치 (에이전트 접근 경로 밖인가)")

    findings += check_db_has_no_truth_tables(repo)
    run.append("에이전트 DB 에 정답 테이블 부재")

    if gt.all_true_names():
        findings += check_symbols_not_in_corpus(repo, gt)
        run.append("원본 심볼명이 코퍼스에 없음")
    else:
        skipped.append(("원본 심볼명 대조", "정답셋에 함수가 없다"))

    findings += check_debug_artifacts(repo)
    run.append("PDB 경로 / __func__ / 디버그 섹션 흔적")

    # 아직 구현되지 않은 검사를 통과로 읽지 않게 명시한다
    skipped.append(
        (
            "익스포트 테이블 / RTTI 잔여물",
            "L1 이 임포트·익스포트·RTTI 를 추출하지 않는다 (1주차 범위 밖)",
        )
    )
    return LeakageReport(
        findings=tuple(findings), checks_run=tuple(run), checks_skipped=tuple(skipped)
    )
