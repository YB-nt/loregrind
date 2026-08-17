# 작업 명세 — 무엇을 만들었고 그 파일이 무엇을 하는가

이 문서는 **지금까지 저장소에 들어간 것의 전수 명세**다.

`docs/changes/`와 역할이 다르다. 그쪽은 작업 단위별로 **"왜 그렇게 했고 무엇을 기각했는가"**를
남긴다(§8 산출물 4번의 원재료). 이 문서는 **"현재 무엇이 존재하고 각 파일이 무슨 일을 하는가"**를
한 곳에서 읽게 한다. 새로 합류한 사람이나 오랜 뒤의 자신이 첫 번째로 읽는 문서다.

- **기준 커밋**: `2d0c22e` (`develop`, `origin/develop`에 푸시됨)
- **최종 갱신**: 2026-08-17

## 먼저 분명히 할 것 — 구현 코드는 아직 0행이다

지금까지의 작업은 **사양 · 하네스 · 프로젝트 골격**이다. 동작하는 Loregrind 기능은 없다.

| 있는 것 | 없는 것 |
|---|---|
| 사양 문서(§1~§11), 개발 하네스(에이전트 4 + 스킬 8) | `schema.sql`, `repo.py`, `cli.py` — 1주차 대상 |
| 패키지 골격 10개, 빌드·린트·타입·테스트 설정 | Ghidra 추출 스크립트, MCP 도구, 랭킹, 검색 채널 |
| 워크트리 소유권 지도, 변경 기록 4건 | 테스트 0건 (`pytest`가 수집하는 항목 없음) |

`__init__.py` 10개에 들어 있는 것은 docstring 한 줄씩이고, 함수·클래스는 하나도 없다.
빈 스텁을 만들지 않은 것은 의도적이다 — 빈 파일은 "이미 있다"는 거짓 신호를 준다.

---

## 커밋 이력

| 커밋 | 작업 | 규모 |
|---|---|---|
| `ddd9e26` | Best-README-Template 스캐폴드 (외부 템플릿, **정리 대상**) | 8 files |
| `103fd4c` | Git-Flow 전략 + 샘플 커밋 차단 | 3 files, +223 |
| `7314590` | `docs/PROJECT.md` 요청서 도입 | 1 file, +286 |
| `6a7c93f` | 개발 하네스 구성 (에이전트 4 + 스킬 5) | 13 files, +1572 |
| `cdf91dc` | 작업 스킬 3종 프론트매터 수정 | 4 files |
| `0b405af` | 프로젝트 레이아웃 스캐폴딩 + 워크트리 지도 | 29 files, +728 |

`master`는 `ddd9e26`에 그대로 있다. Git-Flow에 따라 `master`는 릴리스 병합만 받으며,
첫 릴리스는 §7 1주차 완료 기준("SQL로 직접 질의 가능") 충족 시점이다.

---

## 1. 사양과 규약 (`docs/`)

| 파일 | 내용 | 권위 |
|---|---|---|
| `PROJECT.md` (286행) | §1 문제 정의, §2 범위, §3 5계층 아키텍처, §4 데이터 모델, §5 검색 계층, §6 평가 설계, §7 12주 마일스톤, §8 산출물, §9 스택, §10 안전 규칙, §11 불변식 8개 | **최상위.** 다른 문서와 어긋나면 이것이 이긴다 |
| `GIT-FLOW.md` | 브랜치 5종, 명명 규칙, Conventional Commits + 계층 스코프, 커밋 전 확인 4항목 | 커밋·병합 |
| `WORKTREE.md` | 워크트리 9개의 경로 소유권, 공유 파일 7개, 생성·정리 절차, 워크트리별 분리 대상 | 병렬 작업 |
| `changes/README.md` | 변경 기록 템플릿과 4개 규칙 | 기록 형식 |
| `changes/*.md` (4건) | 작업별 "왜·무엇을 기각·무엇이 미검증" | 설계 근거 |
| `WORKLOG.md` | 이 문서 | 현재 상태 |
| `LEARNING.md` | 학습 경로 — 선행 지식, 읽는 순서, 일반화 가능한 교훈 8개, 주차별 자기검증 질문 | 학습 |

### `docs/WORKTREE.md`의 핵심 — 경로 소유권

한 경로는 한 브랜치만 만진다. 계층 9개(`db`, `l1-extract`, `l2-tools`, `l3-rank`,
`l4-analyze`, `l4-emulate`, `retrieval`, `l5-report`, `eval`)에 워크트리를 1:1로 붙인다.

**아무 계층도 소유하지 않는 공유 파일 7개**는 피처 워크트리에서 고치지 않는다:
`pyproject.toml`, `uv.lock`, `db/schema.sql`, `db/repo.py`, `cli.py`, `docs/PROJECT.md`, `.claude/`.
`develop`에서 단기 브랜치로 먼저 병합하고 각 워크트리가 리베이스로 받아간다.

워크트리마다 **따로** 갖는 것: `.venv/`, `loregrind.db`, `artifacts/`, `.ghidra-projects/`, `.env`.
마지막 두 개가 중요하다 — **Ghidra는 프로젝트 디렉터리에 락을 걸기 때문에** 두 워크트리가
같은 `.ghidra-projects/` 경로를 쓰면 두 번째 `analyzeHeadless`가 실패한다.

---

## 2. 개발 하네스 (`.claude/`)

코드가 아니라 **에이전트에게 주는 규약**이다. Loregrind 작업 시 자동으로 로드된다.

### 에이전트 4개 (`.claude/agents/`)

| 에이전트 | 역할 |
|---|---|
| `loregrind-architect` | 변경을 L1~L5 중 어디에 놓을지 결정, 스키마·도구 시그니처 설계, 구현 전 범위 이탈 차단 |
| `loregrind-implementer` | Python 구현 + 테스트 + ruff/mypy |
| `loregrind-invariant-auditor` | §11 불변식 8개 + §10 안전 규칙 감사, 경계면(스키마↔추출↔도구↔프롬프트) 교차 검증 |
| `loregrind-evaluator` | 정답셋 합성, 지표 계산, 어블레이션 6축, 진단 테스트 |

### 스킬 8개 (`.claude/skills/`)

**상시 5개** — `loregrind-architecture`(계층 배치 헌법) / `loregrind-implementation`(코드 규약,
**프로젝트 레이아웃 정본**) / `loregrind-invariant-audit`(감사 절차) / `loregrind-eval`(평가 설계) /
`loregrind-build`(오케스트레이터).

**작업 절차 3개** — `db-change`(스키마 변경 절차) / `ghidra-extract`(정규 `analyzeHeadless` 명령) /
`add-retrieval-channel`(채널 추가 5단계).

---

## 3. 스킬 3종 활성화 수정 (`cdf91dc`)

세 스킬이 **파일은 있으나 로드되지 않아 실제로 적용되지 않던** 상태를 고쳤다.
`Skill(db-change)` 실호출이 `Unknown skill: db-change`를 반환하는 것으로 미등록을 확인했다.

### 원인 1 — YAML 파싱 중단 (`ghidra-extract`)

```yaml
# before — 파싱 실패
argument-hint: [binary-path] [--reanalyze]
# after
argument-hint: "[binary-path] [--reanalyze]"
```

YAML이 `[binary-path]`를 플로우 시퀀스로 읽고 뒤의 `[--reanalyze]`에서
`expected <block end>, but found '['`로 중단한다. 프론트매터 전체가 무효화되므로
`name`·`description`도 읽히지 않는다.

### 원인 2 — 미지원 키가 로드를 막음 (3개 전부)

`paths:`(3개), `arguments:`(1개)를 제거했다. 정상 동작 중인 `loregrind-*` 5개가
`name`/`description`만 쓴다는 대조가 근거였고, 제거 시점에 세 스킬이 순차로 등록됐다.
`paths:`의 관할 디렉터리 정보는 버리지 않고 본문 `적용 범위:` 줄로 옮겼다.

### 부수적으로 고친 실질 버그 — 거짓 통과하던 검증 스크립트

```bash
# before — $channel 은 치환되지 않으므로 CH="" 가 된다
CH=$channel; MISS=0
rg -q "\b$CH\b" src/loregrind/retrieval/fusion.py || { echo "2 RRF 미등록"; MISS=1; }
# after
CH=<channel>   # ← 실제 채널명으로 치환해서 실행한다
MISS=0
```

`CH=""`이면 `rg -q "\b\b"`가 무엇이든 매치해 **5단계 검증이 아무것도 확인하지 않은 채
"채널 확인됨"을 출력한다.** 4·5번 누락을 막으려고 만든 스킬이 정확히 그 지점에서 거짓
통과하던 셈이다.

---

## 4. 프로젝트 레이아웃 (`0b405af`)

### 디렉터리 트리와 각 경로의 책임

```
pyproject.toml              빌드·린트·타입·테스트 설정 (아래 상세)
uv.lock                     dev 13패키지 고정
src/loregrind/              설치되는 패키지. src 레이아웃 → sys.path 사고 차단
├── __init__.py             패키지 루트
├── db/                     DB 접근 계층. 모든 접근이 repo.py 하나를 지난다 (불변식 2)
│   └── migrations/         NNNN__<verb>_<subject>.sql
├── extract/                L1 — Ghidra 산출물 적재. 런타임과 분리 (불변식 1)
├── tools/                  L2 — MCP 서버. raw SQL 도구 금지
├── rank/                   L3 — 결정론적 랭킹. LLM 호출 금지 (불변식 4)
├── analyze/                L4 — 바텀업 루프, 요약 카드, 예산 게이트
├── emulate/                L4 — 함수 단위 격리 에뮬레이션 (§10)
├── retrieval/channels/     검색 채널 + RRF 융합. 미검증 판단 미색인 (불변식 6)
└── report/                 L5 — 리포트, ATT&CK, IOC
scripts/                    Ghidra Jython/PyGhidra 전용. src/ 임포트 금지
tests/{8계층}/               계층별 분리 — 병합 충돌 방지
eval/retrieval/             정답셋·지표·어블레이션
config/                     retrieval.yaml 등 런타임 설정
artifacts/, .ghidra-projects/   런타임 생성. gitignore 대상
```

`__init__.py` 각각에 계층 책임과 **관련 불변식 번호**를 한 줄로 넣었다.
파일을 여는 사람이 규칙을 먼저 보게 하려는 의도다. 예:

```python
"""L3 우선순위 — 결정론적 랭킹과 라이브러리 필터. 이 계층에서 LLM을 호출하지 않는다 (불변식 4)."""
```

### `pyproject.toml` — 설정별 이유

| 설정 | 값 | 이유 |
|---|---|---|
| `requires-python` | `>=3.12` | §9 스택. 시스템 python은 3.10이라 uv가 3.12를 별도로 받아 쓴다 |
| `[project.scripts]` | `loregrind = "loregrind.cli:main"` | §8 산출물 1번의 `extract\|analyze\|query\|eval` CLI 진입점. `cli.py`는 아직 없다 |
| `[tool.hatch...wheel]` | `packages = ["src/loregrind"]` | src 레이아웃에서 설치 대상 지정 |
| `[dependency-groups] dev` | ruff, mypy, pytest | 런타임 의존성은 **비워 뒀다**. 쓰지 않는 패키지를 락파일에 넣으면 첫 `uv sync`만 느려진다. 계층 착수 시 `uv add` |
| `ruff.extend-exclude` | `["scripts"]` | `scripts/`는 Ghidra 인터프리터에서 돈다. 이 프로젝트의 파이썬 규칙을 적용하면 거짓 경고만 나온다 |
| `ruff.lint.select` | `E,F,I,UP,B,SIM,RUF,S` | **`S`(bandit)가 의도적 선택**이다. §10 위반 중 정적으로 잡히는 것을 린트가 잡게 한다 |
| `S608` | 전역으로 끄지 않음 | SQL 문자열 조립은 `repo.py`에서 파라미터 바인딩과 함께 의도적으로 쓴다. 개별 `noqa`로 풀어야 리뷰에 걸린다 |
| `per-file-ignores` | `tests/** = ["S101"]` | pytest는 `assert`를 쓴다 |
| `mypy` | `strict = true`, `warn_unreachable` | DB 행 shape이 코드 전체로 번지는 프로젝트라 타입이 실제로 버그를 잡는다 |
| `mypy.exclude` | `^scripts/` | 위와 같은 이유 |
| `pytest.markers` | `ghidra` | Ghidra 없이 못 도는 테스트 분리 |
| `pytest.addopts` | `-m 'not ghidra' -ra` | CI가 항상 초록이 되게 하되 **`-ra`로 스킵 사실을 숨기지 않는다** |

### `scripts/README.md` — 두 인터프리터의 경계

`scripts/`는 Ghidra의 Jython/PyGhidra에서 돌고 uv가 설치한 의존성을 쓸 수 없다.
경계가 문서에만 있으면 다음 사람이 `src/` 안에 넣는다 — 실제로 `ghidra-extract` 스킬이
그렇게 쓰고 있었다. README에 박은 규칙:

- `src/loregrind/`를 임포트하지 않는다. 표준 라이브러리 + Ghidra API만.
- **두 세계의 유일한 접점은 파일이다** — 스크립트가 JSONL을 쓰고 `extract/`가 읽어 적재한다.
  함수 호출로 잇지 않는다.
- 인자는 config JSON 경로 하나만. 여러 인자는 Ghidra 버전마다 따옴표 처리가 달라 조용히 어긋난다.

### `.gitignore` 변경 — §10 방어 강화

```diff
  ghidra_projects/
+ .ghidra-projects/
+ # artifacts/ 는 추출 산출물(JSONL·로그)의 출력 루트다. 코드가 런타임에 만든다.
+ artifacts/
```

기존 항목은 `ghidra_projects/`(언더스코어)였고 스킬은 `.ghidra-projects/`(하이픈)를 썼다.
**표기 불일치로 Ghidra 프로젝트와 추출 산출물이 커밋될 경로가 열려 있었다.**

### 스킬 경로 불일치 4건 정정

레이아웃을 만들면서 세 스킬이 서로 다른 레이아웃을 가정하고 있음이 드러났다.

| 불일치 | 수정 |
|---|---|
| `db-change`가 `src/loregrind/store/**` 참조 — 없는 경로 | → `src/loregrind/db/**` |
| `db-change`의 `db/schema_base.sql` — DDL 소스가 둘이 됨 | → `src/loregrind/db/schema.sql` 하나 |
| `ghidra-extract`의 `-scriptPath "src/loregrind/extract/scripts"` — **"scripts와 src를 섞지 않는다"를 정면 위반** | → `-scriptPath "scripts"` |
| `.gitignore` vs 스킬의 Ghidra 경로 표기 | 둘 다 등록 |

---

## 5. 검증된 것과 검증되지 않은 것

### 통과

```
uv sync                     13 패키지 설치
uv run ruff check .         All checks passed!
uv run mypy                 Success: no issues found in 10 source files
uv run pytest               collected 0 items  (테스트 없음 — 정상)
uv run python -c "import …" 10개 패키지 임포트 OK
```

### 미검증 (추측으로 채우지 않는다)

| 항목 | 이유 |
|---|---|
| `ghidra-extract`의 `analyzeHeadless` 명령 완주 | **Ghidra 미설치.** `-scriptPath`를 고쳤지만 실행은 확인하지 않았다. 스킬 자체가 "최초 1회 `-help`로 실측 후 갱신하라"를 요구한다 |
| 워크트리 병렬 시나리오 | 소유권 지도는 설계다. 두 워크트리를 동시에 돌려 충돌이 없는지는 확인하지 않았다 |
| 시스템 python 직접 실행 | 시스템은 3.10, uv가 3.12를 받아 썼다. `python3`로 직접 돌리면 실패한다 |
| 사양의 실현 가능성 | 코드 0행 시점의 문서다 |

---

## 6. 다음 작업 — §7 1주차

완료 기준은 **"SQL로 직접 질의 가능"**이다. 순서와 각 파일이 지켜야 할 것:

1. **`db/schema.sql`** — `binaries`, `functions`, `runs`, `function_analyses`, `hypotheses`,
   `entries`, `occurrences`. `function_analyses`에 `superseded_by`와 **`run_id` NOT NULL**을
   스키마 단계에서 못박는다. 여기서 옵셔널로 두면 이후 계층이 우회하고 어블레이션이 무너진다(§6).
2. **`db/models.py`** — 행 dataclass. `source` 컬럼은 `agent` | `emulation` | `human`.
3. **`db/repo.py`** — 모든 DB 접근의 유일한 통로. **조회 메서드 안에 `superseded_by IS NULL`
   필터를 넣는다** — 호출부에 흩어 놓으면 반드시 빠뜨리는 곳이 생긴다.
4. **`scripts/export_functions.py`** — Ghidra 인터프리터용. `artifacts/extract/<sha256>/`에
   `functions.jsonl` + `meta.json`. 디컴파일 실패는 레코드를 빼지 않고
   `decompiled: null` + `decompile_error`로 기록한다.
5. **`extract/`** — JSONL을 읽어 적재. 정규화(주소·레지스터·스택 오프셋 제거) 후 `code_hash`.
6. **`cli.py`** — `loregrind extract` 먼저.

스키마 작업은 `/db-change`, 추출은 `/ghidra-extract`를 통해서 한다. 두 스킬이 이제 실제
경로를 가리키므로 바로 적용 가능하다.

### 그 밖의 미해결

- **`.env.example` 없음** — `.gitignore`가 `!.env.example`로 예외 처리했는데 파일이 없다.
  워크트리마다 `.env`를 복사해야 하는 구조라 템플릿이 필요하다
- **`docs/ablation.md` 없음** — `/add-retrieval-channel` 5단계가 이 표를 요구한다
- **Best-README-Template 잔여물** — `README.md`, `BLANK_README.md`, `CHANGELOG.md`, `images/`.
  Loregrind와 무관하다
- **테스트 0건** — 결정론적 코드(랭킹·정규화·해시·RRF·예산)는 단위 테스트가 필수다.
  이 코드가 틀리면 평가 숫자 전체가 무의미해지는데 틀렸다는 신호가 눈에 보이지 않는다
