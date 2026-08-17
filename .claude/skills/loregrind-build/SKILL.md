---
name: loregrind-build
description: "Loregrind 개발 오케스트레이터 — 설계(architect) → 구현(implementer) → 불변식 감사(auditor) → 수정 루프를 조율하고, 평가 작업은 evaluator에 위임한다. Loregrind의 기능 추가·스키마 변경·MCP 도구·추출 파이프라인·랭킹·검색 채널·에뮬레이션·평가/어블레이션 작업 시 사용. 후속 요청 — '다시 실행', '재실행', '업데이트', '수정', '보완', '감사만 다시', '이전 결과 기반으로', '설계만 다시', '지표 다시 뽑아줘', '그 부분 고쳐줘' — 에도 반드시 이 스킬을 사용할 것."
---

# Loregrind Build — 개발 오케스트레이터

Loregrind의 개발 작업을 4개 전문 에이전트로 조율한다. 이 프로젝트는 규칙(§11 불변식, §10 안전 규칙, §2 범위)이 결과의 유효성을 결정하므로, 설계 게이트와 감사 게이트를 양쪽에 세운 파이프라인으로 운영한다.

## 실행 모드: 서브 에이전트

이 환경에는 `TeamCreate`/`TaskCreate`가 없어 에이전트 팀 모드를 쓸 수 없다. `Agent` 도구로 각 에이전트를 호출하고, 오케스트레이터가 결과를 파일과 반환값으로 중계한다. **모든 `Agent` 호출에 `model: "opus"`를 명시한다.**

## 에이전트 구성

| 에이전트 | subagent_type | 역할 | 스킬 | 출력 |
|---|---|---|---|---|
| architect | `loregrind-architect` | 계층 배치, 범위 게이트, 스키마·도구 명세, 불변식 사전 검토 | `loregrind-architecture` | `{NN}_architect_design.md` |
| implementer | `loregrind-implementer` | Python 구현 + 테스트 + ruff/mypy | `loregrind-implementation` | `{NN}_implementer_summary.md` + 코드 |
| auditor | `loregrind-invariant-auditor` | §11 불변식, §10 안전 규칙, 경계면 교차 검증 | `loregrind-invariant-audit` | `{NN}_auditor_report.md` |
| evaluator | `loregrind-evaluator` | 정답셋, 지표, 어블레이션, 진단 테스트 | `loregrind-eval` | `{NN}_evaluator_report.md` + 평가 코드 |

작업 디렉터리: `.claude/_workspace/loregrind-build/`

## 워크플로우

### Phase 0: 컨텍스트 확인

`.claude/_workspace/loregrind-build/` 존재 여부로 실행 모드를 정한다.

| 상황 | 모드 | 행동 |
|---|---|---|
| 디렉터리 없음 | 초기 실행 | 디렉터리 생성 후 Phase 1 |
| 있음 + 이전 작업의 부분 수정/재검증 요청 | **부분 재실행** | 최신 산출물을 읽고, 해당 Phase만 재실행. 이전 산출물 경로를 에이전트 프롬프트에 포함 |
| 있음 + 새로운 무관한 작업 | 새 실행 | 기존 디렉터리를 `loregrind-build_{YYYYMMDD_HHMMSS}/`로 이동 후 새로 생성 |

판단이 애매하면 기존 산출물의 제목을 읽고 요청과 같은 주제인지 본다. 같은 주제면 부분 재실행이다.

`{NN}`은 해당 실행 내 2자리 일련번호(`01`, `02`, …)로, 파일명이 시간순으로 정렬되게 한다.

### Phase 1: 라우팅

모든 요청이 4개 에이전트를 다 거치지 않는다. 요청 유형으로 경로를 정한다.

| 요청 유형 | 경로 |
|---|---|
| 새 기능 / 스키마 변경 / 아키텍처 결정 | architect → implementer → auditor → (FAIL 시) 수정 루프 |
| 명세가 이미 있는 구현 / 버그 수정 | implementer → auditor → (FAIL 시) 수정 루프 |
| 감사·점검·리뷰만 | auditor 단독 |
| 설계 검토·타당성 판단만 | architect 단독 |
| 평가·지표·어블레이션·정답셋 | evaluator → auditor (평가 파이프라인의 정직성 감사) |
| 평가 계측이 필요한 기능 | architect → implementer → evaluator → auditor |
| 단순 질문 (사양 확인 등) | 에이전트 호출 없이 직접 답변 |

**범위 의심이 조금이라도 들면 architect를 먼저 부른다.** §2 제외 항목(언패킹·전체 샘플 실행·ELF/Mach-O·실시간 서비스/웹 UI/멀티유저)에 닿는 요청은 구현이 시작되기 전에 걸러야 비용이 싸다.

**감사는 건너뛰지 않는다.** 코드가 변경되었으면 auditor를 부른다. "작은 변경이라 괜찮다"는 판단이 불변식 붕괴의 통상적 경로다.

### Phase 2: 설계

```
Agent(
  subagent_type: "loregrind-architect",
  model: "opus",
  description: "설계: {요청 요약}",
  prompt: "{요청 전문}
           산출물: .claude/_workspace/loregrind-build/{NN}_architect_design.md
           {부분 재실행이면: 이전 설계 .../{MM}_architect_design.md 를 읽고 지적된 부분만 수정할 것 — {피드백}}"
)
```

포그라운드로 실행한다(다음 Phase가 결과에 의존).

**설계가 범위 거부를 반환하면 여기서 멈춘다.** 구현으로 넘기지 않고 사용자에게 거부 사유와 축소안을 보고한다.

### Phase 3: 구현

```
Agent(
  subagent_type: "loregrind-implementer",
  model: "opus",
  description: "구현: {요청 요약}",
  prompt: "설계 문서 .claude/_workspace/loregrind-build/{NN}_architect_design.md 를 읽고 구현하라.
           산출물: .../{NN}_implementer_summary.md
           ruff / mypy / pytest 를 실제로 실행하고 결과를 요약에 그대로 실을 것."
)
```

**구현자가 명세 결함을 보고하면** Phase 2로 돌아가 architect에게 해당 지점만 재설계를 요청한다. 오케스트레이터가 임의로 명세를 고치지 않는다.

### Phase 4: 감사

```
Agent(
  subagent_type: "loregrind-invariant-auditor",
  model: "opus",
  description: "감사: {요청 요약}",
  prompt: "검증 범위: {변경된 파일 목록}
           참조: .../{NN}_architect_design.md (불변식 검토표), .../{NN}_implementer_summary.md
           산출물: .../{NN}_auditor_report.md"
)
```

감사 범위를 "전체"로 넘기지 않는다 — 변경된 파일 목록을 구체적으로 준다. 범위가 넓으면 리포트가 얕아진다.

### Phase 5: 수정 루프 (최대 2라운드)

auditor 리포트에 FAIL이 있으면:

1. FAIL 항목의 태그를 확인한다.
   - **"설계 결함"** 태그 → architect에게 재설계 요청 후 다시 Phase 3
   - 그 외 → implementer에게 FAIL 항목만 전달해 수정
2. Phase 4 재실행 (`{NN+1}_auditor_report.md`)
3. **총 2라운드까지.** 남은 FAIL이 있으면 루프를 멈추고 사용자에게 잔여 이슈를 보고한다. 무한 루프가 예산을 태우는 것이 미해결 이슈 2개보다 나쁘다.

수정 요청 시 FAIL 항목을 그대로 전달한다 — auditor가 `파일:라인 + 무엇이 어긋남 + 어떻게 고칠 것` 3요소로 쓰므로 재해석할 필요가 없다.

### Phase 6: 평가 (해당 시)

평가 작업이거나 새 기능에 계측이 필요하면:

```
Agent(
  subagent_type: "loregrind-evaluator",
  model: "opus",
  description: "평가: {대상}",
  prompt: "{평가 요청}. 설계의 '검증 기준' 절: .../{NN}_architect_design.md
           산출물: .../{NN}_evaluator_report.md"
)
```

evaluator가 계측 부족(예: `run_id` 누락으로 어블레이션 불가)을 보고하면 이는 **불변식 5 위반**이므로 Phase 3으로 돌려 계측을 먼저 채운다.

### Phase 7: 변경 기록

**코드나 설정이 변경된 모든 작업은 `docs/changes/YYYY-MM-DD-{slug}.md`에 기록을 남긴다.** 형식과 규칙은 `docs/changes/README.md`를 읽고 따른다.

`{slug}`는 브랜치명의 접미사와 맞춘다 — 브랜치·커밋·문서가 같은 이름으로 묶여야 나중에 되짚을 수 있다.

`_workspace/`의 산출물을 원재료로 삼되, **그대로 복사하지 않는다.** 세 문서는 목적이 다르다:

| 문서 | 담는 것 |
|---|---|
| `_workspace/*` | 에이전트 간 작업 전달용 중간 산출물 |
| `docs/changes/*` | 왜 그렇게 했고, 무엇을 기각했고, **무엇이 검증되지 않았는지** |
| 커밋 메시지 | 무엇을 했는지 요약 + 기록 문서 포인터 |

기록에 반드시 반영할 것:
- architect 설계 문서의 "기각한 대안" → 기록의 동일 절. **비워두지 않는다** (§8 산출물 4번이 요구)
- auditor 리포트의 판정 집계와 **UNKNOWN 항목** → 기록의 "검증" 절
- implementer가 보고한 미검증 사항(외부 도구 부재 등) → "미검증"으로 명시. **검증했다고 쓰지 않는다**

문서화만 하는 작업(사양 질문 답변 등)은 기록을 남기지 않는다.

### Phase 8: 커밋 (Git-Flow)

`docs/GIT-FLOW.md`를 따른다. 요점:

```bash
git checkout develop && git checkout -b feature/{slug}   # develop에서 분기
# 작업 + 변경 기록을 같은 커밋에
git add -A && git status                                  # 스테이징 눈으로 확인
git commit -m "..."
git checkout develop && git merge --no-ff feature/{slug}
git branch -d feature/{slug}
```

**커밋 전 확인 (건너뛰지 않는다):**
- `ruff` / `mypy` / `pytest` 통과 — 실패 상태로 커밋하지 않는다
- **평문 PE·샘플 바이너리가 스테이징에 없는가** (§10). `.gitignore`는 1차 방어일 뿐이므로 `git status`를 눈으로 본다
- `.env`·API 키가 포함되지 않았는가
- 해당 작업의 `docs/changes/` 기록이 같은 커밋에 있는가

**`master`·`develop`에 직접 커밋하지 않는다.** 병합만 받는다. 마일스톤 완료 시의 release 브랜치·태그 절차는 `docs/GIT-FLOW.md` 참조.

커밋 메시지는 Conventional Commits + 계층 스코프(`feat(l3): ...`)를 쓰고, footer에 기록 문서 경로와 감사 결과를 남긴다.

### Phase 9: 보고

사용자에게:
- 무엇을 설계·구현했는가 (파일 목록)
- 감사 결과: PASS/FAIL/UNKNOWN 집계와 잔여 이슈
- 도구 실행 결과 (ruff/mypy/pytest) — **실패했으면 실패했다고 쓴다**
- 평가 지표 (있으면)
- 변경 기록 문서 경로, 브랜치·커밋 해시
- 다음 단계 제안 (§7 마일스톤 기준 현재 위치)

`.claude/_workspace/loregrind-build/`는 삭제하지 않는다. 감사 추적과 후속 부분 재실행의 근거다.

## 데이터 흐름

```
[오케스트레이터]
  → Agent(architect)   → 01_architect_design.md ─┐
                                                  ↓
  → Agent(implementer) → 02_implementer_summary.md + 코드 변경 ─┐
                                                                 ↓
  → Agent(auditor)     → 03_auditor_report.md (PASS/FAIL/UNKNOWN)
                              │
                     FAIL ────┤── "설계 결함" → architect 재호출
                              └── 그 외      → implementer 재호출 → auditor 재감사 (최대 2라운드)
                                                  ↓
  → Agent(evaluator)   → 04_evaluator_report.md (해당 시)
                                                  ↓
        [오케스트레이터] → docs/changes/YYYY-MM-DD-{slug}.md  (기각안·UNKNOWN·미검증 포함)
                        → feature/{slug} 커밋 → develop 병합 (--no-ff)
                        → 사용자 보고
```

## 에러 핸들링

| 상황 | 전략 |
|---|---|
| 에이전트 1회 실패 | 같은 프롬프트로 1회 재시도. 재실패 시 해당 산출물 없이 진행하되 보고서에 누락을 명시 |
| architect가 범위 거부 | 파이프라인 중단. 거부 사유와 축소안을 사용자에게 보고 |
| implementer가 명세 결함 보고 | Phase 2로 복귀, 해당 지점만 재설계. 오케스트레이터가 명세를 임의 수정하지 않음 |
| 외부 도구 부재 (Ghidra/capa/Unicorn) | 구현은 진행하되 "실행 미검증"을 보고서에 명시. 검증했다고 쓰지 않음 |
| auditor FAIL이 2라운드 후에도 잔존 | 루프 중단, 잔여 이슈를 파일·라인과 함께 사용자에게 보고 |
| auditor와 implementer의 판단 충돌 | 양측 근거를 병기해 사용자에게 판단 요청. 어느 한쪽을 임의로 채택하지 않음 |
| evaluator가 계측 부족 보고 | 불변식 5 위반으로 처리, Phase 3으로 복귀해 계측 보강 |
| 스테이징에 바이너리·`.env`가 잡힘 | 커밋 중단. `.gitignore`를 먼저 고치고 사용자에게 보고. §10 위반은 되돌리기 비싸다 |
| ruff/mypy/pytest 실패 상태 | 커밋하지 않는다. Phase 3으로 복귀해 수정하거나, 고칠 수 없으면 사용자에게 판단을 요청 |
| 병합 충돌 | 자동 해결하지 않는다. 충돌 파일과 양쪽 내용을 사용자에게 보고 |

## 테스트 시나리오

### 정상 흐름

1. 사용자: "L1 추출에서 문자열 xref도 함께 뽑아 DB에 저장해줘."
2. Phase 1 라우팅: 스키마 변경 포함 → architect부터.
3. Phase 2: architect가 L1 배치 확정, `strings`/`string_xrefs` 스키마 DDL과 추출 스크립트 인터페이스를 명세, 불변식 11개 검토표 작성 (1·2·5 관련, 나머지 무관).
4. Phase 3: implementer가 `schema.sql`, `scripts/export_facts.py`, `extract/runner.py`를 수정하고 pytest 추가. ruff/mypy 통과.
5. Phase 4: auditor가 스키마 DDL ↔ INSERT 컬럼명을 교차 검증, `run_id` 존재 확인. 전부 PASS.
6. Phase 7: `docs/changes/2026-08-20-l1-string-xrefs.md` 작성 — 기각한 대안(문자열을 별도 테이블로 분리 vs xref에 인라인)과 Ghidra 부재로 인한 미검증 항목 포함.
7. Phase 8: `feature/l1-string-xrefs`에서 커밋 → `develop`에 `--no-ff` 병합. 스테이징에 바이너리 없음 확인.
8. Phase 9: 변경 파일, 감사 결과, 기록 문서 경로, 커밋 해시, 다음 단계(1주차 완료 기준 "SQL로 직접 질의 가능" 충족) 보고.

### 에러 흐름 (감사 FAIL → 수정)

1. 사용자: "검색 결과를 프롬프트에 넣는 부분 구현해줘."
2. Phase 3: implementer가 구현.
3. Phase 4: auditor FAIL 2건 — (a) 불변식 7: 사전정보가 "이 함수는 X다" 단정형으로 주입됨(`analyze/context.py:88`), (b) §10: 검색된 문자열이 격리 래퍼를 거치지 않음(`analyze/context.py:104`).
4. Phase 5 라운드 1: implementer에게 두 FAIL 항목 전달 → 가설형 문구로 교체 + `wrap_untrusted` 경유로 수정.
5. Phase 4 재실행: 전부 PASS.
6. Phase 7: 기록 문서에 1라운드 수정이 필요했던 사실과 그 원인을 남긴다 — 반복되면 스킬을 고쳐야 할 신호이므로 묻지 않는다.
7. Phase 8~9: 커밋 후 1라운드 수정이 필요했음을 포함해 보고.

### 에러 흐름 (범위 거부)

1. 사용자: "ELF 바이너리도 지원하게 확장해줘."
2. Phase 1: 범위 의심 → architect 단독 호출.
3. Phase 2: architect가 §2 제외 항목(ELF/Mach-O — 구조는 확장 가능하게 두되 구현하지 않음)에 해당함을 판정, 설계 문서 대신 거부 사유와 "PE 전용 경로를 인터페이스 뒤로 숨겨 확장 여지만 남기는" 축소안 반환.
4. 파이프라인 중단. 코드 변경이 없으므로 Phase 7~8(기록·커밋)을 건너뛴다.
5. Phase 9: 사용자에게 거부 사유와 축소안 보고. 구현 호출 없음.
