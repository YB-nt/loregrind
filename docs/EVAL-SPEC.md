# 평가 하네스 명세 (EVAL-SPEC)

이 문서는 **무엇을 어떻게 측정하는지의 계약**이다. `docs/PROJECT.md` §6 이 요구사항이고,
`.claude/skills/loregrind-eval/SKILL.md` 가 설계 규율이며, 이 문서가 그것의 **구현 명세**다.
어긋나면 `docs/PROJECT.md` §6 이 이긴다.

핵심 주장은 하나다 — "하네스를 만들었다"는 흔하고 **"성능을 측정했다"가 차별점이다.**
그래서 이 명세의 대부분은 "숫자를 어떻게 뽑는가"가 아니라
**"어떻게 거짓 숫자를 못 뽑게 하는가"**에 대한 것이다.

- 기준 커밋: `develop`
- 구현 위치: `eval/` (정답 취급 — 스키마는 `truthset.py`, 데이터는 `groundtruth/`), `src/loregrind/db/` (지표 저장)
- 게이트: `make verify` (코드 규율) / `make verify-holdout` (숫자 신뢰성)

---

## 1. 설계 원칙 — 이 4개가 나머지를 결정한다

| 원칙 | 구현으로 어떻게 강제되는가 |
|---|---|
| **`n` 없는 지표는 존재할 수 없다** | `MetricValue.n` 필수 필드, `run_metrics.n NOT NULL`, `Repo.insert_metric(n=...)` 위치 인자 |
| **측정 불가 ≠ 0%** | `value: float \| None` + `unmeasured_reason` 필수. `__post_init__` 이 위반을 거부 |
| **지표 계산에 LLM 을 쓰지 않는다** | 의미 동등 판정을 정답셋의 `aliases` 로 미리 확정. 계산은 전부 문자열 대조 (불변식 4) |
| **정답은 에이전트와 물리적으로 분리** | 정답셋은 `eval/groundtruth/*.json`. `loregrind.db` 에 넣지 않고 `eval/leakage.py` 가 검사 |

### `MetricValue` 계약

```python
MetricValue(metric="naming_accuracy", value=0.72, n=25, stratum="gcc:-O2",
            corpus_state="warm", method="token", k=None, unmeasured_reason=None)
```

- `value is None` → `unmeasured_reason` 필수 (없으면 `ValueError`)
- `value is not None and n == 0` → `ValueError` ("어디서 나온 숫자인가")

이 두 검사가 리포트의 정직함을 타입 수준에서 지탱한다.

---

## 2. 정답셋 명세

### 생성 절차

오픈소스를 컴파일 → 심볼 스트립 → 원본 함수명과 대조. 난이도 격자는
**컴파일러 × 최적화**이며, 셀 표기는 `<compiler>:<opt>` (예: `gcc:-O2`)로 고정한다.
이 문자열이 `run_metrics.stratum` 에 그대로 들어간다.

```
컴파일러: gcc | clang | msvc
최적화:   -O0 | -O1 | -O2 | -O3
```

### 파일 스키마 (`eval/groundtruth/groundtruth.json`)

```json
{
  "version": "gt-2026-08-17",
  "binaries": [
    {
      "sha256": "…", "source_project": "libdemo",
      "compiler": "gcc", "opt_level": "-O2",
      "is_holdout": false,
      "functions": [
        {"addr": "0x401000", "true_name": "rc4_init",
         "aliases": ["rc4_key_schedule"],
         "is_key_function": true,
         "wrong_prior": "string_compare"}
      ]
    }
  ],
  "pairs": [
    {"source_symbol": "rc4_init",
     "left": ["<sha256-A>", "0x401000"], "right": ["<sha256-B>", "0x8000"]}
  ],
  "notes": ["…"]
}
```

| 필드 | 왜 있는가 |
|---|---|
| `aliases` | 의미 동등 판정을 **미리** 확정해 계산에서 LLM 을 뺀다 |
| `is_key_function` | 탐색 효율의 분자 기준. 사후에 정하면 지표를 유리하게 조작할 수 있다 |
| `wrong_prior` | 반대율 진단에 주입할 틀린 사전정보 |
| `pairs` | 검색 Recall@k 의 정답. **정답셋 생성 시 함께 산출한다** — 나중에 만들려면 전체 빌드를 반복해야 한다 |
| `is_holdout` | 미학습 패밀리 홀드아웃. 이 플래그가 없으면 과적합을 판정할 수 없다 |

정답셋 파일이 없으면 `eval.truthset.load()` 는 **예외를 던진다.** 빈 정답셋으로
진행하면 모든 지표가 `n=0` 이 되고 "측정했다"는 착시가 생긴다.

### 실제 멀웨어

**정성 데모용이며 정량 지표를 뽑지 않는다.** 정답이 없으므로 숫자에 근거가 없다.
실 샘플은 `is_holdout` 이 아니라 정답셋 밖에 둔다.

---

## 3. 정답 누출 차단 (지표보다 먼저)

누출은 조용하다 — 숫자가 좋아지고 에러는 나지 않는다. 그래서 게이트로 만든다.

| 검사 | 구현 | 심각도 |
|---|---|---|
| 정답셋이 에이전트 접근 경로(`artifacts/`, `.ghidra-projects/`) 안에 있는가 | `check_groundtruth_location` | 차단 |
| 정답셋이 에이전트 DB 와 같은 디렉터리에 있는가 | 같음 | 경고 |
| 에이전트 DB 에 정답 테이블(`groundtruth`, `labels`, …)이 있는가 | `check_db_has_no_truth_tables` | 차단 |
| 원본 심볼명이 `functions.original_name` / `signature` / `decompiled` 에 남아 있는가 | `check_symbols_not_in_corpus` | 차단 |
| PDB 경로 / `__func__` / 디버그 섹션 흔적 | `check_debug_artifacts` | 경고 |
| 익스포트 테이블 / RTTI 잔여물 | **미구현** — L1 이 아직 추출하지 않는다 | 건너뜀 |

**건너뛴 검사는 통과로 기록되지 않는다.** `LeakageReport.checks_skipped` 가 사유와 함께
리포트에 출력된다. 3자 이하의 짧은 심볼명은 우연 일치가 많아 대조에서 제외한다 —
거짓 양성이 쌓이면 사람이 이 게이트를 무시하기 시작한다.

---

## 4. 지표 명세

### 4.1 명명 정확도 `naming_accuracy`

```
value = |{f : names_match(proposed(f), truth(f))}| / |{f : f ∈ groundtruth}|
```

- 분모는 **정답셋과 겹치는 함수만**. 정답셋에 없는 함수는 제외한다
- `FUN_00401000`, `sub_401000`, `thunk_FUN_*` 는 성공으로 세지 않는다 (`is_auto_generated`)
- 판정 방법 3종 — 리포트에 **반드시 명시**한다 (`method` 컬럼)

| method | 규칙 |
|---|---|
| `exact` | 소문자화 후 문자열 완전 일치 |
| `token` | 토큰 집합 일치. `RC4Init` = `rc4_init` = `init_rc4` (기본값) |
| `alias` | 정답셋 `aliases` 포함 여부 |

### 4.2 환각률 `hallucination_rate`

```
value = |{c : c.quoted ∉ corpus_strings}| / |citations|
```

**자동 검증이다.** 모델에게 "환각했니"라고 묻는 방식은 지표가 아니다.
인용이 코퍼스 문자열의 부분 문자열로 존재하는지 대조한다.

추가로 두 가지를 **결함으로 함께 보고**한다:

- `processed` — 인용에 `...`, `…`, `[truncated]` 가 있으면 원문 그대로가 아니다.
  대조가 느슨해져 환각률이 낮게 나오는 착시를 만든다
- 인용이 하나도 없으면 환각률 0% 가 아니라 **"근거가 저장되지 않는 것 자체가 결함"**

### 4.3 탐색 효율 `exploration_efficiency`

```
value = (핵심 함수를 모두 찾기까지 읽은 함수 수) / (전체 함수 수)     낮을수록 좋다
n     = |key_functions|
```

핵심 함수를 끝까지 찾지 못하면 **1.0 이 아니라 측정 불가**다. "비효율적이었다"와
"실패했다"를 같은 숫자로 만들면 안 된다.

### 4.4 반대율 `contradiction_rate`

```
value = |{c : names_match(final(c), truth(c)) ∧ final(c) ≠ wrong_prior(c)}| / |cases|
```

**0 에 가까우면 에이전트는 분석이 아니라 복사를 하고 있다.** 리포트에서 묻지 않고
전면에 낸다. 불변식 7(사전정보는 결론이 아니라 가설)이 실제로 지켜지는지를 직접 재는
유일한 지표다.

진단 절차: 정답셋의 `wrong_prior` 를 검색 계층이 반환하도록 주입 → 에이전트가 뒤집는
비율을 측정.

### 4.5 검색 `recall_at_k` / `precision_at_1`

```
value = |{q : expected(q) ∩ ranked(q)[:k] ≠ ∅}| / |{q : q ∈ pairs}|
```

`expected` 는 정답 쌍(`pairs`)의 양방향 전개다. 정답 쌍과 겹치는 질의가 없으면 측정 불가.
채널 추가 시 **채널 단독** Recall 을 함께 낸다 — 하이브리드 점수만으로는 기여를 알 수 없다
(`/add-retrieval-channel` 4단계).

### 4.6 비용·캐시 히트율

단일 값이 아니라 **곡선**이다. x축은 `runs` 의 누적 순서, y축은 `cost_usd` /
캐시 히트율. `runs.tokens_in/out/cost_usd` 와 `finish_run()` 이 원천이다.

---

## 5. 지표 저장 — `run_metrics` (마이그레이션 `0001`)

long format(지표명을 행으로)을 쓴다. 지표를 추가할 때마다 컬럼을 늘리면 마이그레이션이
지표 수만큼 쌓인다.

| 컬럼 | 의미 |
|---|---|
| `run_id` | **NOT NULL FK.** 지표도 산출물이므로 run 에 소속된다 (불변식 5) |
| `metric`, `value` | 지표명과 값 |
| `n` | **NOT NULL CHECK (n >= 0).** 없으면 저장 불가 |
| `stratum` | 격자 셀 (`gcc:-O2`) 또는 `all` |
| `corpus_state` | `cold` \| `warm` \| `holdout` (CHECK 제약) |
| `groundtruth_version` | 정답셋이 바뀌면 이전 숫자와 비교할 수 없다 |
| `method`, `k` | 판정 방법, Recall 의 k |

`run_metrics` 는 DELETE 가 트리거로 차단된다. **나쁜 숫자를 지우면 5주차 컷라인 판단이
불가능해진다.**

---

## 6. 어블레이션 6축

**어블레이션은 SQL 한 줄이어야 한다.** 안 되면 애플리케이션에서 우회 집계하지 말고
계측 결함으로 보고한다.

```sql
SELECT r.config_json ->> '$.rename_writes' AS condition,
       m.stratum, m.corpus_state,
       AVG(m.value) AS mean_value, SUM(m.n) AS total_n, COUNT(*) AS runs
FROM run_metrics m JOIN runs r USING (run_id)
WHERE m.metric = 'naming_accuracy'
GROUP BY condition, m.stratum, m.corpus_state;
```

구현: `Repo.ablation(metric, config_key)` / CLI `loregrind eval --ablation-axis <key>`.

| 축 | `runs.config_json` 키 | 조건 | 무엇을 보는가 |
|---|---|---|---|
| 리네임 쓰기 | `rename_writes` | on/off | 쓰기 도구가 이후 컨텍스트 품질을 올리는가 |
| 탐색 전략 | `exploration` | ranked/sequential/random | L3 랭킹이 값을 하는가 |
| 컨텍스트 구성 | `context_mode` | hierarchical/flat | 요약 카드 가설 검증 |
| 검증 루프 | `verification` | on/off | **환각률 변화** — 9~10주차 핵심 결과 |
| 검색 채널 | `channels` | 채널별 on/off | 각 채널이 값을 하는가 |
| 코퍼스 상태 | `corpus_state` | cold/warm/**holdout** | 축적 효과 + 과적합 여부 |

**비교하는 두 run 은 대상 축 외의 `model` / `prompt_version` / `config` 가 같아야 한다.**
다르면 비교가 아니라 착시다. (이 동일성 검사는 아직 코드로 강제되지 않는다 — §9 참조)

---

## 7. 리포트 규율 — 코드로 강제되는 것

| 규율 | 구현 |
|---|---|
| 셀별 보고, 평균은 그다음 | `render_metric_table` 이 `stratum` × `corpus_state` 격자를 그린다 |
| **홀드아웃 열은 언제나 존재** | 데이터가 없으면 열을 지우지 않고 "측정 안 함"을 적고 경고를 붙인다 |
| 실패한 셀은 비워 두고 사유 | `_cell()` 이 `측정 불가 (사유)` 를 출력. "미측정 / 측정 불가" 절 자동 생성 |
| 판정 방법 명시 | 표 상단에 `method` 나열 |
| 숫자를 좋게 만들지 않는다 | `cutline_verdict()` 가 코어 지표 + 홀드아웃 부재를 **미충족**으로 반환 |

홀드아웃 열을 지우지 않는 것이 핵심이다. 열이 사라지면 **홀드아웃을 재지 않았다는 사실도
함께 사라진다.**

---

## 8. 게이트 명세

### `make verify` — 코드 규율

`lint` → `types` → `test` → `schema-check` → `migration-check`.
데이터 없이 항상 돌아야 한다. 평가 숫자의 타당성은 보지 않는다.

`migration-check` 는 `/db-change` 의 완료 조건을 그대로 옮긴 것이다 —
마이그레이션에 `UPDATE` / `DELETE` / `DROP TABLE` / `ALTER … DROP` 이 있으면 실패,
번호 중복이 있으면 실패.

### `make verify-holdout` — 숫자 신뢰성

```
1) 정답 누출 점검        누출 차단 발견 → exit 1
2) 홀드아웃 검증          정답셋에 홀드아웃 빌드 없음 → exit 3 (미측정)
                          run_metrics 에 holdout 지표 없음 → exit 3
                          웜 대비 하락 → exit 1 (과적합 의심)
```

| exit | 의미 |
|---|---|
| 0 | 누출 없음 · 홀드아웃 측정됨 · 하락 없음 |
| 1 | 발견 있음 (누출 차단 또는 홀드아웃 하락) |
| 3 | **미측정** — 정답셋이나 홀드아웃 지표가 없다 |

**주의: 이 코드는 `uv run python -m eval.run holdout` 의 것이다.** `make` 는 레시피가
실패하면 실패 코드에 상관없이 자기 종료 코드 **2** 를 내므로, `make verify-holdout` 의
종료 코드로는 1(발견)과 3(미측정)을 구분할 수 없다. Makefile 이 `[gate] holdout exit=N`
줄로 실제 코드를 출력한다. **CI 가 코드로 분기해야 하면 make 를 거치지 말고
`eval.run` 을 직접 호출한다.**

**exit 3 이 이 게이트의 설계 핵심이다.** 데이터가 없을 때 조용히 통과하면 게이트가
아니다. 지금 저장소에는 정답셋이 없으므로 `make verify-holdout` 은 실패한다 —
그것이 올바른 현재 상태다.

방향이 다른 지표를 주의한다: 환각률은 **낮을수록 좋다.** 하락 판정에서 부호를
반대로 읽으면 결론이 뒤집힌다(`cmd_holdout` 이 이 지표만 따로 처리한다).

---

## 9. 아직 강제되지 않는 것 (정직한 목록)

| 항목 | 현재 상태 |
|---|---|
| 어블레이션 두 run 의 축 외 동일성 | **코드로 검사하지 않는다.** 사람이 확인해야 한다. 자동화하려면 `runs.config_json` diff 검사가 필요 |
| 정답셋 생성 파이프라인 | **없다.** 컴파일→스트립→대조 자동화 미구현. 스키마와 소비 측만 있다 |
| 캐시 히트율·비용 곡선 | `runs` 에 원천 데이터는 있으나 곡선 산출 코드 없음 |
| 익스포트/RTTI 누출 검사 | L1 이 추출하지 않아 검사 불가 |
| 실제 지표 값 | **하나도 측정되지 않았다.** LLM 호출 경로(L2~L4)가 없다 |
| 반대율 주입 경로 | 검색 계층이 없어 `wrong_prior` 를 주입할 곳이 없다 (6~8주차) |

§7 5주차 컷라인의 판정 근거를 제공하는 것이 평가의 일이다. **지금 시점의 정직한 보고는
"측정 하네스는 있고 측정값은 없다"** 이다.
