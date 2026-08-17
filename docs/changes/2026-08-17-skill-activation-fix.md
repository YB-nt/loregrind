# 작업 스킬 3종 프론트매터 수정 — 로드 실패 해소

- **날짜**: 2026-08-17
- **브랜치**: (미커밋) `feature/skill-activation-fix` 예정
- **계층**: harness
- **마일스톤**: 해당 없음 (구현 착수 전 하네스 정비)

## 배경

`/db-change`, `/ghidra-extract`, `/add-retrieval-channel` 세 스킬이 `.claude/skills/` 아래에 존재하는데도 Claude Code의 스킬 목록에 나타나지 않았다. `Skill(db-change)` 실제 호출로 `Unknown skill: db-change`를 확인해 미등록임을 증명했다.

원인은 두 가지였고, 둘 다 프론트매터에 있었다.

1. **`ghidra-extract`: YAML 문법 오류.** `argument-hint: [binary-path] [--reanalyze]` — YAML이 `[binary-path]`를 플로우 시퀀스로 읽고 뒤의 `[--reanalyze]`에서 `expected <block end>, but found '['`로 파싱이 중단된다. 프론트매터 전체가 무효화되므로 `name`·`description`도 읽히지 않는다.
2. **세 스킬 공통: 미지원 키와 잘못된 값 타입.** `paths:`(3개), `arguments:`(1개)는 Claude Code 스킬 프론트매터의 인식 필드가 아니다. `argument-hint` 값도 따옴표가 없어 1-원소 리스트로 파싱됐다. 정상 동작 중인 `loregrind-*` 5개는 `name`/`description`만 쓴다 — 이 대조가 원인 지목의 근거였다.

## 변경 내용

| 파일 | 변경 | 신규/수정/삭제 |
|------|------|----------------|
| `.claude/skills/ghidra-extract/SKILL.md` | `argument-hint` 인용, `paths:` 제거 → 본문 "적용 범위"로 이동 | 수정 |
| `.claude/skills/db-change/SKILL.md` | `argument-hint` 인용, `paths:` 제거 → 본문 이동, `` !`cmd` `` 동적 삽입을 명시적 bash 블록으로 교체 | 수정 |
| `.claude/skills/add-retrieval-channel/SKILL.md` | `argument-hint` 인용, `paths:`·`arguments:` 제거, 본문 `$channel` → `$1`/`<channel>` 치환 | 수정 |
| `docs/changes/2026-08-17-skill-activation-fix.md` | 이 기록 | 신규 |
| `CLAUDE.md` | 변경 이력 표에 1행 추가 | 수정 |

## 설계 결정과 근거

- **미지원 키는 지우되 정보는 살린다.** `paths:`에 담긴 "이 스킬이 관할하는 디렉터리" 의도는 유효한 정보다. 키가 동작하지 않는다고 정보를 버리는 대신 본문 첫 줄의 `적용 범위:`로 옮겼다. 프론트매터에 남겨두면 스코핑이 실제로 걸린다고 오해하게 된다 — 디렉터리 스코핑은 스킬이 놓인 위치로 결정되고 `paths:` 필드로는 되지 않는다.
- **`$channel` → `$1` + `<channel>` 2단 표기.** 슬래시 호출 시 치환되는 것은 `$ARGUMENTS`/`$1`이고 `arguments:` 키로 정의한 이름은 치환되지 않는다. 다만 bash 블록 안의 `$1`은 셸 위치 인자로 해석돼 조용히 빈 문자열이 된다. 그래서 산문에서는 `$1`로 인자를 받고, 경로·코드 블록 안에서는 `ghidra-extract`가 이미 쓰는 `<sha256>` 스타일과 맞춰 `<channel>` 플레이스홀더로 통일했다. 검증 스크립트의 `CH=$channel`은 `CH=<channel>` + 치환 지시 주석으로 바꿨다 — 원래 형태는 그대로 붙여 실행하면 `CH=""`가 되어 5단계 검증이 전부 거짓 통과한다.
- **`` !`cmd` `` 제거.** 커스텀 슬래시 명령의 동적 삽입 문법이며 SKILL.md에서 동작한다는 근거를 찾지 못했다. 동작하지 않으면 "현재 상태" 절이 리터럴 텍스트로 남아 마이그레이션 번호 `NNNN`을 추측하게 되는데, 이는 그 절이 막으려던 실패 그 자체다. 확실히 동작하는 "먼저 실행하라" bash 블록으로 바꿨다.

## 기각한 대안

| 대안 | 기각 사유 |
|------|-----------|
| `ghidra-extract`의 `argument-hint`만 인용하고 나머지는 두기 | 그것만으로는 `db-change`·`add-retrieval-channel`이 여전히 로드되지 않는다. 실제로 `paths:` 제거 시점에 두 스킬이 등록되는 것을 관찰했다 — 미지원 키가 로드를 막는 원인이었고 YAML 오류는 `ghidra-extract`만의 별개 문제였다 |
| `paths:`를 프론트매터에 유지 | 동작하지 않는 필드를 남기면 다음 스킬 작성 시 복제된다. 이미 3개 파일에 복제된 상태였다 |
| `arguments:` 키를 살리려고 커스텀 파싱 도입 | 하네스 규약을 표준에서 벗어나게 만든다. `$1`로 충분하다 |
| 세션 재시작으로 해결 시도 | 원인이 파일에 있으므로 재시작해도 로드되지 않는다. 실제로 재시작 없이 파일 수정만으로 3개 모두 등록됐다 (핫 리로드 동작 확인) |

## 불변식·안전 규칙 영향

스킬 문서의 프론트매터·플레이스홀더 표기만 바꿨다. 각 스킬이 강제하는 규율(append-only, 컬럼 삭제 금지, `-noanalysis` 금지, 5단계 완료 조건, 채널 기본값 `enabled: false`)의 **내용은 변경하지 않았다.** 오히려 로드되지 않던 스킬이 이제 실제로 적용되므로 §11 불변식 강제력은 순증한다.

한 가지 실질적 개선: `add-retrieval-channel`의 검증 스크립트가 `CH=""`로 거짓 통과하던 문제를 고쳤다. 이전 형태라면 5단계 검증이 통과했다고 보고하면서 아무것도 확인하지 않았을 것이다.

## 검증

- YAML 파싱: 8개 스킬 전부 `yaml.safe_load` 통과, `argument-hint` 값 타입 `str`, 미지원 키 0개
- 잔여 플레이스홀더 검색: `rg '\$channel|^paths:|^arguments:|!`'` → 0건
- 스킬 등록: 파일 수정 직후 `ghidra-extract` → `db-change` → `add-retrieval-channel` 순으로 세션에 로드됨을 확인
- **미검증** — 각 스킬을 실제 작업에 적용한 end-to-end 동작. `src/`가 아직 없고 Ghidra·sqlite DB도 없어 스킬 본문의 명령을 실행할 대상이 존재하지 않는다. 등록과 인자 치환까지만 확인했다
- ruff / mypy / pytest: 해당 없음 (Python 코드 변경 없음)

## 미해결 / 후속

- `ghidra-extract`의 "최초 1회" 절 요구사항이 그대로 남아 있다 — `analyzeHeadless -help`로 실제 플래그를 확인하고 힙·`-max-cpu`를 실측값으로 갱신하기 전에는 그 스킬의 정규 명령을 확정된 것으로 취급하지 않는다
- 스킬 프론트매터 린트를 하네스 차원에서 자동화할지 검토. 이번 원인 2종(YAML 오류, 미지원 키) 모두 정적 검사로 잡힌다
- 이 변경은 아직 커밋되지 않았다. Git-Flow에 따라 `feature/skill-activation-fix` 브랜치에서 커밋하고 `develop`에 `--no-ff` 병합해야 한다
