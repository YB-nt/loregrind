# Git 브랜치 전략 — Git-Flow

Loregrind는 Git-Flow를 따른다. 12주 마일스톤(`docs/PROJECT.md` §7)이 주차 단위로 구분되고, 5주차에 "코어 미달 시 이후를 잘라낸다"는 컷라인이 있어 **릴리스 경계가 명확한 브랜치 모델**이 맞기 때문이다.

## 브랜치 구조

| 브랜치 | 수명 | 역할 | 분기 원본 | 병합 대상 |
|---|---|---|---|---|
| `master` | 영구 | 릴리스된 상태만. 항상 동작 보장 | — | — |
| `develop` | 영구 | 통합 브랜치. 모든 기능이 여기 모인다 | `master` | `master` (release 경유) |
| `feature/*` | 단기 | 개별 기능·변경 | `develop` | `develop` |
| `release/*` | 단기 | 마일스톤 마감, 버그 수정만 | `develop` | `master` + `develop` |
| `hotfix/*` | 단기 | 릴리스된 상태의 긴급 수정 | `master` | `master` + `develop` |

**`master`와 `develop`에 직접 커밋하지 않는다.** 병합만 받는다.

## 브랜치 명명

```
feature/l1-extract-pipeline      계층·기능 단위. 케밥 케이스
feature/mcp-tool-get-callers
feature/eval-ablation-rename
release/w5-core-metrics          마일스톤 주차 기준
hotfix/api-key-leak-in-report
```

계층이 분명한 작업은 접두사에 계층을 드러낸다(`l1-`, `l2-`, `l3-`, `l4-`, `l5-`, `eval-`, `retrieval-`). 어느 계층인지 브랜치명에서 안 보이면 대개 작업이 너무 크다.

## 작업 흐름

```bash
# 기능 시작
git checkout develop
git pull
git checkout -b feature/l1-string-xrefs

# 작업 + 커밋 (함수/모듈 단위로 자주)
git commit -m "feat(l1): 문자열 xref 추출 및 적재"

# 완료 — 병합 커밋을 남겨 기능 경계를 보존한다
git checkout develop
git merge --no-ff feature/l1-string-xrefs
git branch -d feature/l1-string-xrefs
```

`--no-ff`를 쓰는 이유: fast-forward로 병합하면 어떤 커밋이 한 기능에 속했는지 히스토리에서 사라진다. 이 프로젝트는 어블레이션에서 "어떤 변경이 어떤 지표 변화를 만들었는지" 되짚어야 하므로 기능 경계가 보존되어야 한다.

## 릴리스

마일스톤(§7의 주차) 완료 기준을 충족하면 릴리스한다.

```bash
git checkout -b release/w1-extract develop
# 버그 수정만. 새 기능 금지
git checkout master && git merge --no-ff release/w1-extract
git tag -a w1-extract -m "1주차: L1 추출 파이프라인 — SQL로 직접 질의 가능"
git checkout develop && git merge --no-ff release/w1-extract
git branch -d release/w1-extract
```

태그명은 마일스톤과 완료 기준을 담는다. **5주차 태그(`w5-core-metrics`)가 프로젝트의 컷라인**이므로 반드시 태그를 남긴다 — 이후를 잘라낼지 판단하는 기준점이 된다.

## 커밋 메시지

Conventional Commits + 계층 스코프.

```
<type>(<scope>): <한 줄 요약>

<본문 — 왜 이렇게 했는지. 무엇을 했는지는 diff가 말한다>

<footer — 관련 변경 기록 문서, 감사 결과>
```

**type**: `feat` / `fix` / `refactor` / `test` / `docs` / `chore` / `eval` (평가 코드·정답셋·어블레이션)

**scope**: `l1` `l2` `l3` `l4` `l5` `db` `retrieval` `emulate` `eval` `harness` `docs`

```
feat(l3): 라이브러리 함수 필터를 랭킹 앞단에 추가

FID 시그니처 매칭으로 분석 대상을 사전 배제한다. 필터 결과는
버리지 않고 is_library 플래그로 저장한다 — 필터 오판을 되짚어야 하고,
필터 유무 자체가 어블레이션 대상이기 때문이다.

Docs: docs/changes/2026-08-20-l3-library-filter.md
Audit: PASS 8 / FAIL 0 / UNKNOWN 1 (Ghidra 부재로 실행 미검증)
```

**커밋 단위는 함수/모듈 단위로 작게 유지한다.** `docs/PROJECT.md` §4 원칙 4가 "함수 단위로 커밋한다 — 중간에 죽어도 거기서 이어간다"를 데이터 모델 규율로 두는 것과 같은 이유다.

## 커밋 전 확인

- `uv run ruff check .` / `uv run mypy src/` / `uv run pytest` 통과
- **평문 PE·샘플 바이너리가 스테이징에 없는지**(§10). `.gitignore`가 1차 방어지만 `git status`로 눈으로 확인한다
- API 키·`.env`가 포함되지 않았는지
- 해당 작업의 변경 기록이 `docs/changes/`에 있는지

## 변경 기록 문서

모든 작업은 `docs/changes/YYYY-MM-DD-{slug}.md`에 기록을 남긴다. 형식과 규칙은 `docs/changes/README.md` 참조.

커밋 메시지는 "무엇을"을 남기고, 변경 기록 문서는 **"왜, 무엇을 기각하고, 무엇이 검증되지 않았는지"**를 남긴다. `docs/PROJECT.md` §8 산출물 4번이 "설계 결정과 그 근거, 실패한 시도 포함"을 요구하므로, 이 기록이 최종 기술 문서의 원재료가 된다.
