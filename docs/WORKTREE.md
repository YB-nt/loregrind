# Worktree 구성 — 계층별 병렬 작업

Loregrind는 5계층(L1~L5)이 서로 다른 파일을 만진다. 계층 하나에 워크트리 하나를 붙이면
여러 세션이 같은 저장소를 공유하면서도 서로의 작업 트리를 밟지 않는다.

Git-Flow와의 관계: 워크트리는 브랜치 전략을 대체하지 않는다. 각 워크트리는 `feature/*`
브랜치 하나를 체크아웃하며, 통합은 `docs/GIT-FLOW.md`대로 `develop`에 `--no-ff` 병합으로만 한다.

## 소유권 지도

**한 경로는 한 브랜치만 만진다.** 아래 표가 그 계약이다.

| 워크트리 | 브랜치 | 소유 경로 | 마일스톤(§7) |
|---|---|---|---|
| `../lg-db` | `feature/db-<slug>` | `src/loregrind/db/` | 필요 시 단기 |
| `../lg-l1-extract` | `feature/l1-extract` | `scripts/`, `src/loregrind/extract/`, `tests/extract/` | 1주 |
| `../lg-l2-tools` | `feature/l2-tools` | `src/loregrind/tools/`, `tests/tools/` | 2주 |
| `../lg-l3-rank` | `feature/l3-rank` | `src/loregrind/rank/`, `tests/rank/` | 3주 |
| `../lg-l4-analyze` | `feature/l4-analyze` | `src/loregrind/analyze/`, `tests/analyze/` | 3–4주 |
| `../lg-l4-emulate` | `feature/l4-emulate` | `src/loregrind/emulate/`, `tests/emulate/` | 9–10주 |
| `../lg-retrieval` | `feature/retrieval` | `src/loregrind/retrieval/`, `config/retrieval.yaml`, `tests/retrieval/` | 6–8주 |
| `../lg-l5-report` | `feature/l5-report` | `src/loregrind/report/`, `tests/report/` | 12주 |
| `../lg-eval` | `feature/eval` | `eval/`, `docs/ablation.md` | 2주부터 상시 |

`tests/`를 계층별 하위 디렉터리로 쪼갠 이유가 여기 있다. 한 디렉터리에 모으면 테스트 파일이
모든 병합의 충돌 지점이 된다.

## 공유 파일 — 워크트리에서 만지지 않는다

아래는 모든 계층이 읽지만 **아무 계층도 소유하지 않는** 파일이다. 여기 변경이 필요하면
피처 워크트리에서 고치지 말고 `develop`에서 단기 브랜치를 따서 먼저 병합한 뒤,
각 워크트리가 `git rebase develop`으로 받아간다.

| 파일 | 소유 경로가 아닌 이유 |
|---|---|
| `pyproject.toml` | 의존성·린트 설정. 두 계층이 각자 `uv add` 하면 락파일이 갈라진다 |
| `uv.lock` | 같은 이유. 병합 충돌을 손으로 풀지 말고 재생성한다 |
| `src/loregrind/db/schema.sql` | DDL 단일 소스. 변경은 `/db-change`로만 |
| `src/loregrind/db/repo.py` | 모든 DB 접근의 유일한 통로. 계층별로 메서드를 늘리면 여기가 충돌한다 |
| `src/loregrind/cli.py` | 4개 서브커맨드가 계층을 가로지른다 |
| `docs/PROJECT.md` | 사양 원본. 코드가 사양을 따라가고 그 역이 아니다 |
| `CLAUDE.md`, `.gitignore`, `.claude/` | 하네스와 저장소 규약 |

`repo.py`와 `cli.py`는 구조적으로 충돌이 몰리는 지점이다. 계층이 늘어나 병합이 아파지면
계층별 하위 모듈로 쪼개는 것을 먼저 검토한다 — 충돌을 손으로 반복해 풀지 않는다.

## 만들기

```bash
git worktree add -b feature/l1-extract ../lg-l1-extract develop
cd ../lg-l1-extract
uv sync                      # .venv 는 워크트리마다 따로 만든다 (공유하지 않는다)
```

이미 있는 브랜치를 붙일 때는 `-b`를 뺀다. **한 브랜치는 한 워크트리에만** 붙는다(git이 막는다).

## 정리하기

```bash
git worktree remove ../lg-l1-extract     # 커밋 안 된 변경이 있으면 거부된다
git worktree list                        # 남은 것 확인
git worktree prune                       # 디렉터리를 손으로 지웠을 때 메타데이터 정리
```

병합이 끝난 워크트리는 남겨두지 않는다. 오래된 워크트리는 `develop`에서 멀어진 채로
잊히고, 다음에 열었을 때 리베이스 비용이 작업 자체보다 커진다.

## 워크트리마다 따로 갖는 것 — 공유하면 깨진다

| 대상 | 이유 |
|---|---|
| `.venv/` | `uv sync`를 워크트리마다 돌린다. 심링크로 공유하면 파이썬 버전이 갈릴 때 조용히 깨진다 |
| `loregrind.db` | 워크트리별 로컬 DB. 한 스키마 실험이 다른 워크트리의 데이터를 오염시키지 않는다 |
| `artifacts/`, `.ghidra-projects/` | **Ghidra는 프로젝트 디렉터리에 락을 건다.** 두 워크트리가 같은 경로를 쓰면 두 번째 `analyzeHeadless`가 실패한다. 셋 다 `.gitignore` 대상이라 기본적으로 분리된다 |
| `.env` | 커밋되지 않으므로 새 워크트리에 자동으로 오지 않는다. 워크트리를 만들면 **직접 복사한다** |

추출 산출물이 워크트리마다 따로 생기는 것은 디스크 낭비지만, 재추출 비용은 한 번이고
락 충돌 디버깅은 매번이다. 필요하면 나중에 `artifacts/`만 공유 경로로 빼되
`.ghidra-projects/`는 절대 공유하지 않는다.

## 워크트리에서 첫 명령

```bash
uv sync
cp ../loregrind/.env .env 2>/dev/null || true    # 있으면 가져온다. 없으면 .env.example 참조
uv run pytest                                     # ghidra 마커는 기본 제외된다
```
