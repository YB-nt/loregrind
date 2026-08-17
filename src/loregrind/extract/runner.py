"""Ghidra headless 실행 — `/ghidra-extract` 의 정규 명령을 코드로 고정한다.

명령을 즉석에서 조립하지 않는다. 조립 지점이 여러 곳이 되면 힙 크기·스크립트 경로·
로그 위치가 조금씩 달라지고, 그 순간 추출 결과가 재현되지 않는다.

**샘플을 실행하지 않는다** (§10). Ghidra 에 정적 분석 입력으로 넘기는 것뿐이며,
이 모듈은 대상 바이너리를 프로세스로 띄우지 않는다.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from loregrind.extract.loader import CURRENT_EXTRACT_SCHEMA_VERSION
from loregrind.extract.normalize import file_sha256

# 종료 코드 0 으로도 조용히 실패한다. 로그에서 이 패턴을 찾아야 한다
_LOG_FAILURE_PATTERN = re.compile(r"ERROR|Script failed|OutOfMemory", re.IGNORECASE)

# 힙은 CLI 플래그로 줄 수 없다. _JAVA_OPTIONS 로만 전달된다
DEFAULT_JAVA_HEAP = "8G"
DEFAULT_MAX_CPU = 4

PROJECTS_ROOT = Path(".ghidra-projects")
ARTIFACTS_ROOT = Path("artifacts/extract")
GHIDRA_SCRIPT = "export_functions.py"
# scripts/ 는 Ghidra 인터프리터 전용이다. src/ 와 섞지 않는다
SCRIPT_PATH = Path("scripts")


class GhidraError(RuntimeError):
    """추출이 신뢰할 수 없는 상태로 끝났다."""


@dataclass(frozen=True, slots=True)
class ExtractRun:
    sha256: str
    extract_dir: Path
    log_path: Path
    returncode: int


def ghidra_home() -> Path:
    home = os.environ.get("GHIDRA_HOME")
    if not home:
        raise GhidraError("GHIDRA_HOME 이 설정되지 않았다. Ghidra 11.x 설치 경로를 지정하라")
    path = Path(home)
    if not (path / "support" / "analyzeHeadless").is_file():
        raise GhidraError(f"{path}/support/analyzeHeadless 가 없다. GHIDRA_HOME 을 확인하라")
    return path


def build_command(
    binary: Path,
    sha256: str,
    config_path: Path,
    *,
    max_cpu: int = DEFAULT_MAX_CPU,
) -> list[str]:
    """정규 명령. 이 형태에서 벗어나지 않는다.

    `-postScript` 인자는 **config JSON 경로 하나만** 넘긴다. 인자를 여러 개 넘기면
    공백·따옴표 처리가 Ghidra 버전마다 달라 조용히 어긋난다.
    """
    return [
        str(ghidra_home() / "support" / "analyzeHeadless"),
        str(PROJECTS_ROOT / sha256),
        "loregrind",
        "-import",
        str(binary),
        "-scriptPath",
        str(SCRIPT_PATH),
        "-postScript",
        GHIDRA_SCRIPT,
        str(config_path),
        "-log",
        str(ARTIFACTS_ROOT / sha256 / "ghidra.log"),
        "-max-cpu",
        str(max_cpu),
        "-deleteProject",
    ]


def run_extract(
    binary: Path,
    *,
    reanalyze: bool = False,
    java_heap: str = DEFAULT_JAVA_HEAP,
    max_cpu: int = DEFAULT_MAX_CPU,
    timeout_sec: int = 3600,
) -> ExtractRun:
    """바이너리 하나를 추출한다.

    프로젝트 디렉터리는 샘플당 하나(`.ghidra-projects/<sha256>/`)다. 기존 프로젝트에
    덮어쓰지 않는다 — 재분석은 `reanalyze=True` 로 디렉터리를 삭제한 뒤 재생성한다.
    """
    if not binary.is_file():
        raise GhidraError(f"{binary} 가 없다")

    sha256 = file_sha256(str(binary))
    project_dir = PROJECTS_ROOT / sha256
    extract_dir = ARTIFACTS_ROOT / sha256

    if project_dir.exists():
        if not reanalyze:
            raise GhidraError(f"{project_dir} 가 이미 있다. 재분석은 reanalyze=True 로만 한다")
        shutil.rmtree(project_dir)

    project_dir.mkdir(parents=True, exist_ok=True)
    extract_dir.mkdir(parents=True, exist_ok=True)

    config_path = extract_dir / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "out_dir": str(extract_dir.resolve()),
                "sha256": sha256,
                "extract_schema_version": CURRENT_EXTRACT_SCHEMA_VERSION,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    env = dict(os.environ)
    # 힙이 부족하면 큰 샘플에서 디컴파일러가 조용히 죽는다.
    # launch.properties 의 VMARGS 와 함께 쓰지 않는다 — 둘 중 하나만
    env["_JAVA_OPTIONS"] = f"-Xmx{java_heap}"

    cmd = build_command(binary, sha256, config_path, max_cpu=max_cpu)
    # S603: 인자는 build_command 가 조립한 것이고 셸을 거치지 않는다.
    # 대상 바이너리는 Ghidra 에 정적 분석 입력으로 넘어갈 뿐 실행되지 않는다 (§10)
    proc = subprocess.run(  # noqa: S603
        cmd,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        check=False,
    )

    log_path = extract_dir / "ghidra.log"
    verify_log(log_path, proc.returncode)
    return ExtractRun(
        sha256=sha256, extract_dir=extract_dir, log_path=log_path, returncode=proc.returncode
    )


def verify_log(log_path: Path, returncode: int) -> None:
    """**종료 코드 0 을 믿지 않는다.**

    OOM 은 로그에만 남고 종료 코드는 0 이다. 성공 판정을 도구의 종료 코드에
    위임하면 빈 결과를 성공으로 적재하게 된다.
    """
    if returncode != 0:
        raise GhidraError(f"analyzeHeadless 가 {returncode} 로 종료했다. 로그: {log_path}")
    if not log_path.is_file():
        raise GhidraError(f"로그 {log_path} 가 없다. 실행이 시작되지 않았을 수 있다")

    hits = [
        line.rstrip()
        for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if _LOG_FAILURE_PATTERN.search(line)
    ]
    if hits:
        preview = "\n  ".join(hits[:5])
        raise GhidraError(
            f"로그에 실패 흔적이 {len(hits)}건 있다 (종료 코드는 0이었다):\n  {preview}"
        )
