# Loregrind 개발 하네스 초기 구성

- **날짜**: 2026-08-17
- **브랜치**: `feature/loregrind-harness`
- **계층**: harness / infra
- **마일스톤**: §7 0주차 (구현 착수 전 준비)

## 배경

저장소가 [Best-README-Template](https://github.com/othneildrew/Best-README-Template) 스캐폴드 상태에서 시작되었고, 그에 맞춘 하네스(`template-editor` / `template-qa` 에이전트 + `template-editing` / `template-sync-check` / `template-maintainer` 스킬)가 구성되어 있었다.

`docs/PROJECT.md`가 추가되면서 저장소의 실제 프로젝트가 Loregrind(Ghidra 기반 리버싱 지식베이스)로 전환되었다. 기존 하네스는 도메인이 완전히 달라 재사용·일반화 대상이 아니었고, `CLAUDE.md`도 저장소를 여전히 README 템플릿으로 서술하고 있어 새 세션마다 잘못된 컨텍스트가 로드되는 상태였다.

Loregrind는 §11 불변식 8개, §10 안전 규칙 4개, §2 범위 경계가 **결과의 유효성을 결정하는** 프로젝트다. 핵심 주장이 "하네스를 만들었다"가 아니라 "성능을 측정했다"이므로, 불변식이 조용히 깨지면 12주치 측정이 통째로 무의미해진다. 이 규칙들을 사람의 기억이 아니라 하네스에 강제로 심는 것이 이번 작업의 목적이다.

## 변경 내용

| 파일 | 변경 | 구분 |
|---|---|---|
| `.claude/agents/template-editor.md` | 제거 | 삭제 |
| `.claude/agents/template-qa.md` | 제거 | 삭제 |
| `.claude/skills/template-editing/` | 제거 | 삭제 |
| `.claude/skills/template-sync-check/` | 제거 | 삭제 |
| `.claude/skills/template-maintainer/` | 제거 | 삭제 |
| `.claude/agents/loregrind-architect.md` | 계층 배치·범위 게이트·인터페이스 명세 | 신규 |
| `.claude/agents/loregrind-implementer.md` | Python 구현 + 테스트 + ruff/mypy | 신규 |
| `.claude/agents/loregrind-invariant-auditor.md` | §11/§10 감사 + 경계면 교차 검증 | 신규 |
| `.claude/agents/loregrind-evaluator.md` | 정답셋·지표·어블레이션·진단 테스트 | 신규 |
| `.claude/skills/loregrind-architecture/SKILL.md` | 아키텍처 헌법 (L1~L5, 데이터 모델, 검색 계층, 불변식, 범위, 마일스톤) | 신규 |
| `.claude/skills/loregrind-implementation/SKILL.md` | 레이아웃·스택 규약·교차 관심사 6개·테스트 규약 | 신규 |
| `.claude/skills/loregrind-implementation/references/layer-patterns.md` | 계층별 구현 세부 (조건부 로딩) | 신규 |
| `.claude/skills/loregrind-invariant-audit/SKILL.md` | 항목별 검증 절차 + grep 패턴 | 신규 |
| `.claude/skills/loregrind-eval/SKILL.md` | 정답셋 합성·지표·어블레이션 6축·누출 차단 | 신규 |
| `.claude/skills/loregrind-build/SKILL.md` | 오케스트레이터 (라우팅·수정 루프·에러 핸들링) | 신규 |
| `CLAUDE.md` | Best-README-Template 서술 → Loregrind + 절대 규칙 + 하네스 포인터 | 전면 수정 |
| `docs/GIT-FLOW.md` | Git-Flow 브랜치 전략, 커밋 규약 | 신규 |
| `docs/changes/README.md` | 변경 기록 체계 정의 | 신규 |
| `.gitignore` | Python/uv/Ghidra 산출물 + **샘플 바이너리 차단** | 신규 |

## 설계 결정과 근거

### 에이전트 4분할

| 에이전트 | 분리 근거 |
|---|---|
| architect | 계층 배치와 범위 판단은 **구현 전에** 끝나야 한다. 잘못된 계층에 구현된 코드를 감사가 잡으면 이미 늦다 |
| implementer | 코드 작성은 컨텍스트 부담이 가장 크다. 설계 판단과 섞으면 둘 다 얕아진다 |
| invariant-auditor | §11/§10 검증이 이 프로젝트의 차별점을 지탱한다. 구현자가 자기 코드를 감사하면 같은 착각을 두 번 한다 |
| evaluator | §6이 "평가는 2주차부터 함께 만든다"고 규정. 별도 전문성(정답셋 합성, 누출 차단, 어블레이션 설계)이며 5주차 컷라인 판정의 근거를 낸다 |

### 감사를 별도 게이트로 세운 이유

`docs/PROJECT.md` §11은 "변경 제안 전에 반드시 확인할 것"으로 불변식을 규정하지만, 실제로 깨지는 방식은 **선언이 아니라 경계면**이다 — 정규화 함수는 존재하는데 해시 입력이 그것을 안 거치고, `superseded_by` 컬럼은 있는데 조회 한 곳이 필터를 빠뜨리는 식이다.

그래서 감사 스킬을 "존재 확인"이 아니라 **"양쪽 동시 읽기 교차 검증"** 으로 설계했다. 검증 항목마다 생산자·소비자 쌍을 명시하고, 약한 검증과 강한 검증을 대조표로 넣었다.

### 실행 모드: 서브 에이전트

이 환경에 `TeamCreate`/`TaskCreate`가 없어 에이전트 팀 모드를 쓸 수 없다. `Agent` 도구 기반 파이프라인 + 생성-검증 패턴으로 구성하고, 오케스트레이터가 결과를 파일·반환값으로 중계한다.

### Git-Flow 채택

§7의 12주 마일스톤이 주차 단위로 완료 기준을 갖고, 5주차에 "코어 미달 시 이후를 잘라낸다"는 컷라인이 있다. 릴리스 경계가 명확한 모델이 맞는다. `--no-ff` 병합을 강제하는 이유는 어블레이션에서 "어떤 변경이 어떤 지표 변화를 만들었는지" 되짚으려면 기능 경계가 히스토리에 남아 있어야 하기 때문이다.

## 기각한 대안

| 대안 | 기각 사유 |
|---|---|
| 기존 `template-*` 하네스를 일반화해 재사용 | 도메인이 완전히 다르다(README 동기화 ↔ 바이너리 분석). 일반화하면 양쪽 모두에 안 맞는 스킬이 된다. Phase 3-0/4-0 판정: "역할 범위가 완전히 다름 → 신규 생성" |
| 두 하네스 병존 | 스킬 목록이 길어지고 트리거 판단에 노이즈가 된다. README 템플릿 파일은 스캐폴드 잔여물이라 유지보수 대상이 아니다 |
| 3개 에이전트 (evaluator를 implementer에 통합) | 초반 1~4주차엔 충분하나 5주차 평가 전면 실행에서 컨텍스트 부담이 크다. §6이 평가를 코어로 규정하므로 분리 |
| 5개 에이전트 (retrieval 전문가 추가) | §5 검색 계층은 난이도가 높지만 6주차 이후에야 본격화된다. 지금 만들면 과설계이며, 5주차 컷라인에 걸리면 쓰이지 않고 버려진다. 필요해지는 시점에 추가 |
| 에이전트 팀 모드 | 환경에 `TeamCreate`/`TaskCreate`가 없어 선택 불가 |
| `master`에 직접 커밋 | Git-Flow 규약 위반. `master`는 릴리스된 상태만 담는다 |

## 불변식·안전 규칙 영향

코드 변경이 없으므로 런타임 불변식에 직접 영향은 없다. 하네스가 각 항목을 **강제하는 지점**을 아래에 남긴다.

| 항목 | 강제 지점 |
|---|---|
| §11 1~8 전부 | architect 설계 문서의 불변식 검토표(11개 전수) + auditor 리포트의 전수 판정표 |
| §11 3 (append-only) | `loregrind-implementation` 교차 관심사 1 + `loregrind-invariant-audit` grep 패턴 |
| §11 4 (결정론) | `rank/`에 LLM 호출 금지 grep + 안정적 타이브레이커 확인 |
| §11 5 (run 귀속) | INSERT 컬럼 검사 + `run_id IS NULL` 검증 질의 |
| §11 7 (가설로 제시) | 프롬프트 조립 코드 문구 검사 + evaluator의 반대율 진단 테스트 |
| §11 8 (예산 코드) | 게이트 우회 호출 경로 탐색 |
| §10 샘플 미실행 | auditor의 `subprocess`/`Popen` 탐색 + implementer 금지 목록 |
| §10 평문 PE 미커밋 | `.gitignore` 1차 방어 + `docs/GIT-FLOW.md` 커밋 전 확인 + auditor의 `git ls-files` 검사 |
| §10 문자열 격리 | `wrap_untrusted` 패턴 명시 + 소비 지점 전수 확인 |
| §10 키 미노출 | `runs.config` 저장 시 키 제거 규약 + auditor 검사 |
| §2 범위 | architect의 범위 게이트(구현 전 차단) + auditor의 ELF/언패킹/웹 프레임워크 grep |

## 검증

- 구조 검증: 에이전트 4 + 스킬 5 파일 배치, frontmatter(`name`/`description`) 전수 확인 — **통과**
- 참조 정합성: 오케스트레이터의 `subagent_type` 4개 ↔ 실제 에이전트 `name` 일치, 에이전트→스킬 참조 4건 유효, `references/layer-patterns.md` 링크 유효 — **통과**
- 크기: 모든 SKILL.md 500줄 이내 (최대 204줄) — **통과**
- `.claude/commands/` 미생성 — **확인**
- ruff / mypy / pytest: **해당 없음** — Python 코드가 아직 없다
- 감사 에이전트 실행: **미수행** — 감사 대상 코드가 없다

## 미해결 / 후속

- **하네스 실행 테스트 미수행.** 실제 개발 작업 1건(1주차 L1 추출)을 하네스로 돌려보기 전까지 라우팅·수정 루프·에러 핸들링은 드라이런 수준으로만 검증되었다. 첫 실행 후 피드백을 하네스에 반영한다.
- **트리거 검증 미수행.** should-trigger / should-NOT-trigger 쿼리로 스킬 description을 검증하지 않았다. 실사용에서 트리거 누락이 관찰되면 description을 확장한다.
- **retrieval 전문 에이전트 부재.** 6~8주차 검색 계층 작업 시 implementer의 컨텍스트 부담을 보고 분리를 재검토한다.
- **README 템플릿 잔여물** (`README.md`, `BLANK_README.md`, `CHANGELOG.md`, `images/`)을 남겨두었다. Loregrind 자체 README를 쓰는 시점에 정리한다.
