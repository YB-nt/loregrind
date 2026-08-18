# 감사 — 불변식 위반 1건과 잠복 결함 2건 수정

- **날짜**: 2026-08-18
- **브랜치**: feature/l2-tools
- **계층**: L4(격리·예산) + L2(계층 경계)
- **마일스톤**: §7 2주차 사후 감사

## 배경

`feature/spec` · `feature/l1-facts` · `feature/l2-tools` 세 브랜치를 `/loregrind-invariant-audit`
절차로 전수 감사했다. **테스트 143개가 전부 통과하는 상태에서 위반 1건과 잠복 결함
2건이 살아 있었다** — 통과하는 테스트 묶음이 규율 준수를 증명하지 않는다는 사례로
남긴다.

## 감사 결과

| 항목 | 판정 | 근거 |
|---|---|---|
| 불변식 1 (추출/런타임 분리) | **FAIL → 수정** | `tools/api.py:28` 이 `extract.loader` 임포트 |
| 불변식 2 (단방향 apply) | PASS | `extract/` 밖에 Ghidra 읽기 없음 |
| 불변식 3 (append-only) | PASS | 판단 조회가 전부 `v_current_analyses` 경유 (`repo.py:486,493`), 유일한 UPDATE 는 `superseded_by` 링크 부착 (`repo.py:474`) |
| 불변식 4 (결정론 랭킹) | N-A | L3 미구현 |
| 불변식 5 (run 소속) | PASS | `function_analyses`/`hypotheses`/`run_metrics` INSERT 전부 `run_id` 포함 |
| 불변식 6 (미검증 미색인) | N-A | 검색 계층 미구현 |
| 불변식 7 (사전정보=가설) | PASS | `context.py:131~` 전 경로가 `wrap_untrusted`/`frame_prior_as_hypothesis` |
| 불변식 8 (예산은 코드에) | **FAIL → 수정** | 트래커가 함수마다 초기화되어 run 상한이 무력 |
| §10 인젝션 격리 | **FAIL → 수정** | `agent.py:334` 도구 결과가 래퍼를 우회 |
| §10 샘플 미실행 | PASS | `extract/runner.py` 외 `subprocess` 없음 |
| §10 API 키 | PASS | 키를 인자로 받지 않음. `redact_config` 는 2차 방어 |
| 정규화 ↔ 해시 | PASS | `code_hash()` 가 내부에서 `normalize_decompiled` 를 거친다 (`normalize.py:67`) |
| §2 범위 | PASS | ELF/언패킹/웹 프레임워크 없음 |

## 수정 1 — §10 격리 우회 (가장 심각)

**증상**: 첫 프롬프트는 `wrap_untrusted` 로 감쌌지만, **도구 응답은 날것의 JSON 으로
대화에 들어갔다**(`agent.py:334`). 응답 안에는 `decompiled`·`strings[].value`·
`api_name`·`original_name` 이 그대로 있다.

**왜 심각한가**: 에이전트가 `get_function` 이나 `search_strings` 를 부르는 순간
격리가 풀리는데, **그 경로가 탐색의 주 경로다.** 첫 턴만 안전하고 나머지 전부가
무방비였다. §7 11주차 인젝션 성공률이 이 구멍 때문에 높게 나왔다면, 그것은 시스템의
성질이 아니라 버그를 잰 것이 된다.

**수정**: `context.py` 에 `wrap_tool_result()` 를 두고 응답 **전체**를
`<untrusted kind="tool_result" tool="...">` 로 감싼다. 안쪽 필드를 골라 감싸지 않는
이유는 새 필드가 추가될 때마다 누락이 생기기 때문이다.

## 수정 2 — 불변식 8: run 예산이 함수마다 초기화

**증상**: `summarize()` 가 호출될 때마다 `BudgetTracker` 를 새로 만들었다. 그래서
(a) `max_cost_usd_per_run` 이 매번 $0 에서 시작해 **run 상한이 영영 걸리지 않고**,
(b) `finish_run` 이 그 함수의 비용만 써서 `runs.cost_usd` 가 마지막 함수 값이 됐다.

**왜 지금 안 보였나**: CLI 가 함수 1개만 돌린다. §7 3주차에 루프가 여러 함수를 도는
순간 조용히 터졌을 것이고, 증상은 "예산이 안 걸린다"가 아니라 **"비용 지표가 틀렸다"**
로 나타났을 것이다.

**수정**: 트래커를 에이전트 필드로 올려 run 하나에 하나만 두고, `run_usage` 누적을
`finish_run` 에 쓴다. `finish_run` 은 절대값 UPDATE 이므로 함수마다 불러도 맞는다.

## 수정 3 — 불변식 1: 계층 경계

`tools/api.py`(L2)가 `extract/loader.py`(L1)에서 `FACTS_SCHEMA_VERSION` 을 가져오고
있었다. 실행 결합은 없지만 감사 grep 이 잡는 신호이고, 실제로 이 상수는 **추출 절차가
아니라 `binaries.extract_schema_version` 행의 의미**다. `db/models.py` 로 옮기고
loader 는 거기서 가져오게 했다.

## 기각한 대안

| 대안 | 기각 사유 |
|---|---|
| 도구 응답의 문자열 필드만 골라 격리 | 새 필드가 추가될 때마다 누락. 응답 전체를 감싸는 편이 잊을 수 없다 |
| 도구 층에서 응답을 미리 감싸기 | `SPEC.md` §4.1 의 "격리는 프롬프트 조립 지점 한 곳" 을 깬다. 도구 결과를 대화에 넣는 지점이 프롬프트 조립 지점이다 |
| 트래커를 `ToolContext` 소유로 | 컨텍스트는 도구용 상태다. run 예산은 루프의 것이고, 루프가 소유해야 수명이 맞는다 |
| `FACTS_SCHEMA_VERSION` 을 양쪽에 중복 정의 | 두 값이 갈라지면 도구가 `NOT_EXTRACTED` 를 잘못 반환한다 |
| 회귀 테스트 없이 수정만 | 143개가 통과하는 채로 세 결함이 살아 있었다. 수정만 하면 같은 일이 반복된다 |

## 검증

```
make verify → PASS
  ruff / ruff format   All checks passed
  mypy (strict)        Success: no issues found in 30 source files
  pytest               147 passed in 0.24s   (143 → +4 회귀 테스트)
```

추가한 회귀 테스트 4건 — **수정 전에는 전부 실패한다**:

| 테스트 | 무엇을 고정하나 |
|---|---|
| `test_tool_results_are_isolated_too` | 도구 응답이 `<untrusted kind="tool_result">` 로 감싸인다 |
| `test_injection_via_tool_result_cannot_escape` | 문자열에 심은 `</untrusted>` 가 도구 결과를 타고 와도 블록을 못 빠져나간다 |
| `test_run_cost_accumulates_across_functions` | 두 함수의 비용이 합산된다 (덮어쓰기 아님) |
| `test_run_cost_ceiling_survives_across_functions` | run 상한이 두 번째 함수에서 걸린다 |

### 미검증 항목

| 항목 | 이유 |
|---|---|
| 격리가 **모델에게** 효과가 있는지 | 문자열 수준에서만 확인했다. 모델이 실제로 따르지 않는지는 §7 11주차 인젝션 성공률이다 |
| 여러 함수 루프의 실제 동작 | 수정 2는 두 번 `summarize()` 호출로만 확인했다. L4 루프(3~4주차)는 아직 없다 |
| 감사 대상 밖 | L3·검색·에뮬레이션은 코드가 없어 N-A 다. 구현 시 같은 절차를 다시 돌려야 한다 |

## 미해결 / 후속

- **테스트가 통과해도 규율은 별개다.** 이번 세 건 전부 기존 테스트를 통과한 채로
  존재했다. 계층을 추가할 때마다 감사를 돌리는 것을 절차로 유지한다.
- 다음: §7 3주차 — L3 랭킹 + 쓰기 도구 + 첫 어블레이션.
- 이 브랜치는 사용자 요청에 따라 **`develop`에 병합하지 않고 푸시만 한다.**
