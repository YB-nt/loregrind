# 프로젝트 레이아웃 스캐폴딩과 워크트리 소유권 지도

- **날짜**: 2026-08-17
- **브랜치**: (미커밋) `feature/project-scaffold` 예정
- **계층**: infra
- **마일스톤**: §7 1주차 진입 준비

## 배경

`docs/PROJECT.md`와 하네스는 있는데 코드를 놓을 디렉터리가 없었다. `src/`가 없으니
스킬들이 참조하는 경로(`src/loregrind/retrieval/channels/`, `eval/retrieval/run.py`)가
전부 존재하지 않는 경로였고, 스킬을 호출해도 적용할 대상이 없었다.

동시에 계층별 병렬 작업을 워크트리로 하려면 **어느 브랜치가 어느 경로를 소유하는지**를
먼저 정해야 한다. 정하지 않고 워크트리를 띄우면 병합 때마다 같은 파일에서 충돌한다.

## 변경 내용

| 파일 | 변경 | 구분 |
|---|---|---|
| `pyproject.toml` | uv + ruff + mypy(strict) + pytest 설정, `src/` 레이아웃, `loregrind` 콘솔 스크립트 | 신규 |
| `uv.lock` | `uv sync` 산출 | 신규 |
| `src/loregrind/{,db,db/migrations,extract,tools,rank,analyze,emulate,retrieval,retrieval/channels,report}` | 10개 패키지. 각 `__init__.py`에 계층 책임과 관련 불변식 1줄 | 신규 |
| `scripts/README.md` | Ghidra 인터프리터 경계 명시 (`src/` 임포트 금지, 접점은 파일) | 신규 |
| `tests/{db,extract,tools,rank,analyze,emulate,retrieval,report}/` | 계층별 테스트 디렉터리 | 신규 |
| `eval/retrieval/`, `config/` | 스킬이 참조하는 경로 | 신규 |
| `docs/WORKTREE.md` | 워크트리 소유권 지도, 공유 파일 목록, 생성·정리 절차 | 신규 |
| `.gitignore` | `.ghidra-projects/`, `artifacts/` 추가 | 수정 |
| `.claude/skills/db-change/SKILL.md` | 경로를 `src/loregrind/db/**`로 정정 | 수정 |
| `.claude/skills/ghidra-extract/SKILL.md` | `-scriptPath`를 `scripts`로 정정 | 수정 |

## 설계 결정과 근거

### 레이아웃은 `loregrind-implementation` 스킬의 정의를 그대로 따랐다

새로 설계하지 않았다. 스킬이 이미 레이아웃을 정의하고 있었고, 그것이 `docs/PROJECT.md` §3
계층 구분과 일치했다. 두 번째 권위를 만들면 어느 쪽이 정본인지 다투게 된다.

### `scripts/`를 `src/`에서 분리하고 그 이유를 파일에 박았다

Ghidra 스크립트는 Ghidra의 Jython/PyGhidra 인터프리터에서 돌고 uv가 설치한 의존성을 쓸 수 없다.
경계가 문서에만 있으면 다음 사람이 `src/loregrind/extract/scripts/`에 넣는다 —
실제로 `ghidra-extract` 스킬이 그렇게 쓰고 있었다(아래 불일치 3번). 그래서 경계 이유를
`scripts/README.md`에 두고, 두 세계의 접점은 **함수 호출이 아니라 JSONL 파일**이라고 명시했다.

### `tests/`를 계층별로 쪼갰다

워크트리 병렬 작업의 실제 충돌 지점은 소스가 아니라 테스트다. 계층마다 다른 파일을 만지지만
테스트는 한 디렉터리에 모이기 때문이다. 소유권을 디렉터리 단위로 나눠 충돌 자체를 없앴다.

### 마이그레이션을 `src/loregrind/db/migrations/`에 뒀다

`db-change` 스킬은 저장소 루트 `db/migrations/` + `db/schema_base.sql`을 가정했는데,
그러면 DDL 소스가 `schema.sql`과 `schema_base.sql` 둘이 된다. `loregrind-implementation`이
"`schema.sql` — DDL 단일 소스"라고 못박았으므로 후자를 정본으로 두고 마이그레이션을
패키지 안으로 옮겼다. `src/` 레이아웃에서는 SQL이 패키지와 함께 배포되는 이점도 있다.

### 워크트리는 만들지 않았다

소유권 지도와 생성 절차만 문서화했다. 코드가 0행인 상태에서 9개 워크트리를 띄우면
각각이 `develop`에서 멀어진 채 잊히고, 다음에 열 때 리베이스 비용이 작업보다 커진다.
필요한 시점에 표를 보고 하나씩 만든다.

### 발견한 스킬 간 경로 불일치 4건

레이아웃을 만들면서 세 스킬이 서로 다른 레이아웃을 가정하고 있음이 드러났다.

| 불일치 | 판정 근거 | 수정 |
|---|---|---|
| `db-change`가 `src/loregrind/store/**` 참조 | 정본 레이아웃에 `store/`가 없다 | → `src/loregrind/db/**` |
| `db-change`의 `db/schema_base.sql` | DDL 소스가 둘이 된다 | → `src/loregrind/db/schema.sql` |
| `ghidra-extract`의 `-scriptPath "src/loregrind/extract/scripts"` | **`loregrind-implementation`의 "`scripts/`와 `src/`를 섞지 않는다"를 정면 위반** | → `-scriptPath "scripts"` |
| `.gitignore`는 `ghidra_projects/`, 스킬은 `.ghidra-projects/` | 표기 불일치로 Ghidra 프로젝트가 커밋될 수 있었다 | 둘 다 등록 + `artifacts/` 추가 |

3번이 가장 위험했다. 스킬을 그대로 따르면 Ghidra 스크립트가 `src/` 안에 생기고,
그 디렉터리의 코드가 어느 인터프리터에서 도는지 모호해진다.

## 기각한 대안

| 대안 | 기각 사유 |
|---|---|
| `models.py` / `repo.py` / `schema.sql` / `cli.py` 빈 스텁 생성 | 빈 파일은 "이미 있다"는 거짓 신호를 준다. 1주차 실제 구현 대상이므로 디렉터리만 만들고 파일은 비웠다 |
| 마이그레이션을 루트 `db/`에 두기 (스킬 원안) | DDL 소스가 둘이 된다. §4 "DB가 단일 진실 소스"와 어긋난다 |
| 지금 워크트리 9개 생성 | 위 "워크트리는 만들지 않았다" 참조 |
| `tests/`를 단일 디렉터리로 | 병합 충돌이 전부 여기로 몰린다 |
| `artifacts/`를 워크트리 간 공유 | Ghidra가 프로젝트 디렉터리에 락을 건다. 재추출 비용은 한 번이고 락 충돌 디버깅은 매번이다 |
| 런타임 의존성(pyghidra, capa, networkx…) 미리 선언 | 쓰지 않는 의존성을 락파일에 넣으면 첫 `uv sync`만 느려진다. 계층 착수 시 `uv add` |

## 불변식·안전 규칙 영향

| 항목 | 영향 | 판정 |
|---|---|---|
| 불변식 1 (추출/런타임 분리) | `extract/`와 `tools/`를 별 패키지로, Ghidra 스크립트는 `scripts/`로 3분할 | 강화 |
| 불변식 2 (DB 단일 진실 소스) | `db/schema.sql` 단일 DDL 소스 확정, 마이그레이션 경로 일원화 | 강화 |
| 불변식 4 (결정론) | `rank/`를 별 패키지로 분리해 LLM 호출 코드와 물리적으로 떨어뜨림 | 강화 |
| §10 (평문 PE 미커밋) | `.gitignore`에 `artifacts/`, `.ghidra-projects/` 추가 — 추출 산출물과 Ghidra 프로젝트가 커밋될 경로를 막았다 | 강화 |
| §10 (API 키) | `.env.example`이 아직 없다. 워크트리마다 `.env`를 복사해야 하는 구조인데 템플릿이 없다 | **미해결** |

`pyproject.toml`의 ruff `select`에 `S`(bandit)를 넣었다. §10 위반 중 정적으로 잡히는 것을
린트가 잡게 하려는 의도다. `S608`(SQL 문자열 조립)은 전역으로 끄지 않고 개별 `noqa`로 풀도록 했다.

## 검증

```
uv sync                    → 13 패키지 설치 성공
uv run ruff check .        → All checks passed!
uv run mypy                → Success: no issues found in 10 source files
uv run pytest              → collected 0 items (테스트 없음, 정상)
uv run python -c "import …" → 10개 패키지 임포트 OK
```

- **미검증** — `ghidra-extract`의 정규 `analyzeHeadless` 명령. Ghidra 미설치로 실행 못 했다.
  `-scriptPath "scripts"`로 고쳤지만 실제 완주는 확인하지 않았다
- **미검증** — 워크트리 병렬 시나리오. `docs/WORKTREE.md`의 소유권 지도는 설계이고,
  실제로 두 워크트리를 동시에 돌려 충돌이 없는지는 확인하지 않았다
- **미검증** — Python 3.12 요구. 시스템 python은 3.10이고 uv가 3.12를 별도로 받아 썼다.
  시스템 python으로 직접 돌리면 실패한다

## 미해결 / 후속

- `.env.example` 신설 필요 (`.gitignore`가 이미 예외 처리해뒀는데 파일이 없다)
- `docs/ablation.md` 없음 — `/add-retrieval-channel` 5단계가 이 파일을 요구한다.
  첫 채널 추가 전에 빈 표를 만들어 둔다
- Best-README-Template 잔여물(`README.md`, `BLANK_README.md`, `CHANGELOG.md`, `images/`) 미정리
- 1주차 실제 구현 대상: `db/schema.sql`, `db/models.py`, `db/repo.py`, `cli.py`, `scripts/`의 추출 스크립트
- 스킬 프론트매터·경로 참조를 자동 검증하는 린트 검토. 이번에 발견한 불일치 4건은 모두 정적으로 잡힌다
