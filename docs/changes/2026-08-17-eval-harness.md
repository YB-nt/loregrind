# 평가 하네스와 검증 게이트 (§7 2주차 일부)

- **날짜**: 2026-08-17
- **브랜치**: `feature/eval-harness`
- **계층**: eval / db / infra
- **마일스톤**: §7 2주차 — "평가 하네스 뼈대"

## 배경

§6 은 "평가를 마지막에 붙이지 않는다. **2주차부터 함께 만든다**"고 못박았다. L1 이 끝난
지금이 그 지점이다.

더 중요한 이유가 있다. §6 의 규율(`n` 병기, 셀별 보고, 홀드아웃 병기, 누출 차단)은
전부 **사람이 지켜야 하는 규율**로 스킬 문서에 있었다. 문서에 쓴 규칙은 지켜지지 않는다
(`docs/LEARNING.md` §3-2). 측정을 시작하기 전에 이 규율들을 코드와 게이트로 옮겼다.

## 변경 내용

| 파일 | 변경 | 구분 |
|---|---|---|
| `src/loregrind/db/migrations/0001__create_run_metrics.sql` | 지표 저장 테이블 (첫 마이그레이션) | 신규 |
| `src/loregrind/db/repo.py` | 마이그레이션 러너, `insert_metric`, `ablation`, `table_names` | 수정 |
| `eval/__init__.py`, `truthset.py`, `metrics.py`, `leakage.py`, `report.py`, `run.py` | 평가 하네스 본체 | 신규 |
| `eval/groundtruth/README.md`, `groundtruth.example.json` | 정답셋 스키마 참조 + 누출 경고 | 신규 |
| `Makefile` | `verify` / `verify-holdout` 등 12개 타깃 | 신규 |
| `docs/EVAL-SPEC.md` | 평가 하네스 명세 (지표 공식·게이트 exit 코드·미강제 목록) | 신규 |
| `docs/ablation.md` | 6축 + 채널 표 (전부 "측정 전") | 신규 |
| `src/loregrind/cli.py` | `eval` 을 미구현 거부 → 어블레이션·지표 조회로 구현 | 수정 |
| `pyproject.toml` | mypy 대상에 `eval` 추가, pytest `pythonpath`, isort first-party | 수정 |
| `tests/eval/test_metrics.py`, `test_leakage_and_report.py` | 38건 | 신규 |
| `.claude/skills/loregrind-eval/SKILL.md` | "구현 위치" 표 추가 (규율 ↔ 코드 매핑) | 수정 |
| `docs/GIT-FLOW.md` | 커밋 전 확인을 `make verify` 로 교체 | 수정 |

## 설계 결정과 근거

### `n` 을 타입 수준에서 필수로 만들었다

`MetricValue.n` 은 기본값이 없고 `Repo.insert_metric(run_id, metric, value, n)` 도 `n` 을
위치 인자로 받는다. `run_metrics.n` 은 `NOT NULL CHECK (n >= 0)`.

기본값을 주면 호출자가 생략하고, 생략된 `n` 은 리포트에서 복원할 수 없다.
**함수 12개에서 잰 92% 는 92% 가 아니다.**

### "측정 불가"와 "0%"를 타입으로 분리했다

`value: float | None` + `unmeasured_reason`. `__post_init__` 이 두 위반을 거부한다:

- `value is None` 인데 사유가 없으면 → `ValueError`
- `value is not None` 인데 `n == 0` 이면 → `ValueError` ("어디서 나온 숫자인가")

이 구분이 리포트의 정직함을 지탱한다. 정답셋과 겹치는 함수가 없을 때 0.0 을 내면
"명명을 하나도 못 맞혔다"로 읽히지만 실제로는 **아무것도 재지 않은 것**이다.

### 지표의 방향을 한 곳에 모았다 — 실제로 버그였다

`LOWER_IS_BETTER = {"hallucination_rate", "exploration_efficiency"}` + `is_regression()`.

**처음 구현에서는 `cmd_holdout` 이 `hallucination_rate` 만 특별 처리했다.** 그 결과
합성 시나리오에서 `exploration_efficiency` 가 0.210 → 0.240 으로 **악화됐는데 게이트가
통과시켰다.** 탐색 효율은 "핵심 함수까지 읽은 비율"이라 낮을수록 좋다.

방향 판정이 두 곳에 있으면 한 곳은 반드시 틀리고, 틀리면 "개선"과 "하락"이 뒤집힌 채
리포트에 실린다. 테스트로 고정했다(`test_regression_direction_respects_lower_is_better`).

### 게이트를 둘로 나눴다

| 게이트 | 무엇을 보는가 | 데이터 없이 돌아가는가 |
|---|---|---|
| `make verify` | 코드 규율 (lint/types/test/schema/migration) | **예** — 항상 돌아야 한다 |
| `make verify-holdout` | 숫자 신뢰성 (누출/홀드아웃/과적합) | **아니오** — 없으면 exit 3 |

`verify-holdout` 의 exit 3(미측정)이 설계 핵심이다. 정답셋이 없을 때 0 을 반환하면
게이트가 아니다. 지금 저장소에는 정답셋이 없으므로 이 게이트는 **실패한다** —
그것이 올바른 현재 상태다.

### 정답셋을 파일로, 에이전트 DB 밖에 뒀다

`eval/groundtruth/*.json`. `loregrind.db` 에 넣지 않는다. `eval/leakage.py` 가 네 경로를
검사하고, **건너뛴 검사를 통과로 기록하지 않는다**(`checks_skipped` 에 사유와 함께 출력).

짧은 심볼명(3자 이하)은 대조에서 제외했다. 거짓 양성이 쌓이면 사람이 이 게이트를
무시하기 시작하는데, 무시되는 게이트는 없는 게이트보다 나쁘다.

### 홀드아웃 열을 지우지 않는다

`render_metric_table` 은 `cold`/`warm`/`holdout` 열을 **항상** 그리고, 데이터가 없으면
"측정 안 함" + 경고를 넣는다. 열이 사라지면 **홀드아웃을 재지 않았다는 사실도 함께
사라진다.** 웜만 담은 표는 만들지 않는다는 규율의 코드적 표현이다.

### `run_metrics` 를 long format 으로

지표명을 컬럼이 아니라 행으로 둔다. 컬럼으로 두면 지표를 추가할 때마다 마이그레이션이
쌓인다. §6 의 6종은 시작점이고 진단 테스트가 계속 늘어난다.

### 마이그레이션 러너를 코드에 뒀다

`schema_migrations` 테이블을 `schema.sql` 이 아니라 `apply_migrations()` 가 만든다.
커밋된 기반 스키마를 나중에 고치지 않기 위함이다(`/db-change` 절대 규칙 1의 정신).

### 모듈명을 `truthset.py` 로 바꿨다 (이름 충돌)

처음에는 모듈 `eval/groundtruth.py` 와 데이터 디렉터리 `eval/groundtruth/` 가 공존했다.
지금은 우연히 동작한다 — 정규 모듈이 네임스페이스 패키지보다 우선하기 때문이다. 그러나
그 디렉터리에 `__init__.py` 가 생기는 순간 **모듈이 가려지고** 임포트가 조용히 다른 것을
집는다. 모듈을 `truthset.py` 로 바꿔 충돌을 제거했다.

### `make` 는 종료 코드를 보존하지 못한다

`make` 는 레시피가 실패하면 실패 코드와 무관하게 **자기 종료 코드 2** 를 낸다.
그래서 `make verify-holdout` 의 종료 코드로는 1(발견)과 3(미측정)을 구분할 수 없다.

명세에 exit 3 을 적어두고 실제로는 2 가 나오면 그 명세는 거짓이다. 두 가지를 했다:

- Makefile 이 `[gate] holdout exit=3 (미측정)` 줄로 실제 코드를 출력한다
- `docs/EVAL-SPEC.md` §8 에 "CI 가 코드로 분기해야 하면 make 를 거치지 말고
  `eval.run` 을 직접 호출한다"를 명시했다

## 기각한 대안

| 대안 | 기각 사유 |
|---|---|
| 지표 모듈을 `src/loregrind/eval/` 에 두기 | 정답을 다루는 코드가 에이전트 런타임이 임포트할 수 있는 위치에 있으면 누출 경로가 하나 열린다. 레이아웃 정본도 `eval/` 을 루트에 둔다 |
| `eval/` 을 패키지로 만들지 않고 스크립트로 | 지표 계산은 결정론적 코드라 단위 테스트가 필수다. 임포트되지 않으면 테스트할 수 없다. `pytest pythonpath=["."]` 로 해결 |
| 지표를 CSV/노트북에 저장 | `runs` 와 조인이 안 되고 어블레이션이 애플리케이션 우회 집계가 된다 (§6 위반) |
| 지표별 컬럼 (wide format) | 지표 수만큼 마이그레이션이 쌓인다 |
| 의미 동등 판정을 LLM 으로 | 불변식 4 위반. 같은 입력에 같은 숫자가 안 나오면 어블레이션 비교가 무의미하다. `aliases` 로 사전 확정 |
| `verify-holdout` 이 데이터 없을 때 통과 | 조용히 초록이 되는 게이트는 게이트가 아니다 |
| 정답셋 없을 때 빈 `GroundTruth` 반환 | 모든 지표가 `n=0` 이 되고 "측정했다"는 착시가 생긴다. `FileNotFoundError` 를 던진다 |
| 누출 검사에서 짧은 이름도 대조 | 거짓 양성이 쌓여 게이트가 무시된다 |

## 불변식·안전 규칙 영향

| 항목 | 영향 | 판정 |
|---|---|---|
| 4 (결정론) | 지표 계산 전체가 문자열 대조. LLM 호출 없음. 테스트 38건이 고정 | PASS |
| 5 (run 소속) | `run_metrics.run_id NOT NULL REFERENCES runs` | PASS |
| 6 (미검증 판단 미색인) | 해당 없음 (색인 코드 없음) | 해당 없음 |
| 7 (사전정보는 가설) | 반대율(`contradiction_rate`)이 이 불변식의 준수 여부를 **직접 재는** 지표다 | 측정 경로 확보 |
| 3 (append-only) | `run_metrics` DELETE 를 트리거로 차단. 나쁜 숫자를 지우면 컷라인 판단이 불가능해진다 | PASS |
| §10 (API 키) | `insert_metric` 은 설정을 받지 않는다. `create_run` 의 마스킹 경로 그대로 | PASS |
| §6 (정답 누출) | `eval/leakage.py` 4검사 + 게이트. 익스포트/RTTI 검사는 **미구현으로 명시** | 부분 |

## 검증

```
make verify           PASS — lint / mypy strict(21 files) / pytest 65 / schema / migration
make verify-holdout   정답셋 없음 → exit 3 (설계된 실패)
```

게이트 3종 시나리오를 합성 데이터로 실증했다:

| 시나리오 | 기대 | 결과 |
|---|---|---|
| 정답셋 없음 | exit 3 (미측정) | exit 3 ✅ |
| 홀드아웃 하락 (naming ↓, hallucination ↑, exploration ↑) | exit 1, 3건 모두 하락 표시 | exit 1, 3건 ✅ |
| 홀드아웃 개선 | exit 0 | exit 0 ✅ |

두 번째 시나리오가 방향 버그를 잡아냈다 — 수정 전에는 `exploration_efficiency` 악화를
통과시켰다.

### 미검증

| 항목 | 이유 |
|---|---|
| **실제 지표 값** | 하나도 측정되지 않았다. LLM 호출 경로(L2~L4)가 없다 |
| 정답셋 생성 파이프라인 | **미구현.** 컴파일→스트립→대조 자동화 없음. 스키마와 소비 측만 있다 |
| 누출 검사의 실효성 | 합성 데이터로만 확인했다. 실제 스트립 바이너리에서 어떤 잔여물이 남는지는 미확인 |
| 익스포트 테이블 / RTTI 누출 | L1 이 추출하지 않아 검사 불가. `checks_skipped` 에 명시 |
| 어블레이션 두 run 의 축 외 동일성 | 코드로 검사하지 않는다. 사람이 확인해야 한다 |
| 캐시 히트율·비용 곡선 | `runs` 에 원천은 있으나 곡선 산출 코드 없음 |

## 미해결 / 후속

- **정답셋 생성 파이프라인이 다음 큰 조각이다.** 이것이 없으면 모든 지표가 exit 3 다
- 어블레이션 run 쌍의 `config` diff 검사를 코드로 옮길지 검토 (`docs/EVAL-SPEC.md` §9)
- `.env.example` 여전히 없음
- Ghidra 실측 1회 여전히 미수행 — L1 의 `export_functions.py`는 아직 확정이 아니다
- 2주차 남은 부분: L2 MCP 도구 층 + 프롬프트 인젝션 격리
