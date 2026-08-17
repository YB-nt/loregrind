---
name: loregrind-invariant-audit
description: "Loregrind 코드 감사 절차 — §11 불변식 8개, §10 안전 규칙 4개, 경계면 교차 검증(스키마↔추출↔도구↔프롬프트), 범위 이탈 탐지의 항목별 검증 방법과 grep 패턴. 코드 변경 후 검증·감사·점검·리뷰 요청 시, 불변식 준수 여부를 확인할 때, 또는 '이 변경이 규칙을 깨는지' 판단할 때 반드시 로드할 것."
---

# Loregrind Invariant Audit — 감사 절차

Loregrind의 핵심 주장은 "성능을 측정했다"이다. 불변식이 깨지면 측정 결과가 무의미해지므로, 이 감사는 스타일 리뷰가 아니라 **결과의 유효성 검사**다.

**증거 없는 판정을 내지 않는다.** 모든 PASS/FAIL에 `파일:라인`을 인용한다 — 인용 없는 판정은 이 프로젝트가 측정하려는 환각 그 자체다.

**확신하지 못하면 UNKNOWN이다.** PASS로 밀어 넣지 않는다.

**미구현은 위반이 아니다.** 0~5주차에는 대부분 항목이 N-A다. 설계 문서가 요구했는데 없으면 FAIL, 아예 해당 계층이 없으면 N-A.

## 감사 순서

1. 도구 실행 (`ruff` / `mypy` / `pytest`) — 실패는 그대로 인용한다
2. §11 불변식 8개 전수
3. §10 안전 규칙 4개
4. 경계면 교차 검증
5. §2 범위 이탈

시간이 부족하면 이 순서대로 처리하고 미완료 범위를 리포트에 명시한다.

## §11 불변식 검증

### 1. 추출과 에이전트 런타임 분리

런타임 경로에서 Ghidra를 부르면 위반.

```bash
rg -n "analyzeHeadless|pyghidra|import ghidra" src/loregrind/{analyze,tools,rank,retrieval}/
rg -n "from .*extract|import extract" src/loregrind/{analyze,tools,rank}/
```

두 검색 모두 결과가 없어야 PASS. `extract/`가 `analyze/`에서 임포트되는 것 자체가 위반 신호다.

### 2. DB 단일 진실 소스 · Ghidra 단방향 apply

Ghidra의 현재 상태를 읽어 DB를 갱신하는 역방향 경로가 있으면 위반.

```bash
rg -n "getFunction|getSymbol|currentProgram" src/loregrind/ --glob '!extract/**'
```

Ghidra 읽기가 `extract/` 밖에 있으면 조사한다. apply 코드(`report/` 또는 전용 모듈)는 DB에서 읽어 Ghidra에 쓰는 방향만 가져야 한다.

### 3. append-only (`superseded_by`)

**양쪽을 함께 본다** — 갱신 경로와 조회 경로.

```bash
# 판단 테이블에 대한 직접 UPDATE (superseded_by 부착 외에는 위반)
rg -n "UPDATE (function_analyses|hypotheses)" src/

# 조회에 superseded_by 필터가 붙는지
rg -n "FROM function_analyses|JOIN function_analyses" src/ -A3
```

강한 검증: **모든** 조회 경로가 필터하는가? 필터가 `repo.py` 내부에 있어 호출자가 잊을 수 없는 구조라면 PASS. 각 호출부에 흩어져 있으면 하나씩 확인하고, 빠진 곳이 있으면 FAIL.

허용: `superseded_by` 컬럼 자체를 채우는 UPDATE(링크 부착). 금지: 판단 필드(`proposed_name`/`summary`/`confidence`/`evidence_json`)의 제자리 수정.

### 4. 랭킹·성공 판정은 결정론적 코드

```bash
rg -n "anthropic|client\.|messages\.create|complete\(" src/loregrind/rank/
```

`rank/`에 LLM 호출이 있으면 FAIL. 추가로 랭킹 함수의 정렬에 안정적 타이브레이커가 있는지 본다 — 동점을 dict/set 순서에 맡기면 재현이 깨진다(재현성 결함으로 보고).

### 5. 모든 산출물은 run에 소속

```bash
rg -n "INSERT INTO (function_analyses|hypotheses|findings|entries)" src/ -A5
```

각 INSERT의 컬럼 목록에 `run_id`가 있는가. `run_id`가 옵셔널이거나 기본값을 갖는 스키마면 그것도 결함이다 — 없으면 INSERT가 실패해야 한다.

**검증 질의로 확인한다** (DB가 있으면):
```sql
SELECT COUNT(*) FROM function_analyses WHERE run_id IS NULL;  -- 0이어야 한다
```

### 6. 미검증 판단은 검색 인덱스에 미포함

색인 함수 진입부에 게이팅이 있는가.

```bash
rg -n "def (index|upsert|embed|add_entry)" src/loregrind/retrieval/ -A10
rg -n "source in|source ==|confidence >" src/loregrind/retrieval/
```

강한 검증: 게이팅을 **우회하는** 색인 경로가 있는가. 색인 함수가 둘 이상이면 각각 확인한다.

### 7. 사전정보는 결론이 아니라 가설로

검색 결과를 프롬프트에 넣는 코드를 읽고, 단정형인지 가설형인지 본다.

```bash
rg -n "known_analysis|prior|retrieved|similar" src/loregrind/analyze/ -B2 -A8
```

"이 함수는 X다" 형태면 FAIL. "유사 함수가 X로 분석된 적이 있다 — 검증하라" 형태여야 한다. 이것이 무너지면 §6 반대율이 0으로 붕괴한다.

### 8. 예산 상한은 코드에

```bash
rg -n "budget|max_tokens|cost_limit|BudgetExceeded" src/
rg -n "messages\.create|client\." src/loregrind/analyze/ -B5
```

강한 검증: 모든 LLM 호출이 예산 게이트를 지나는가. 게이트를 우회하는 직접 클라이언트 호출이 하나라도 있으면 FAIL. 상수만 선언되어 있고 차단 로직이 없으면 FAIL.

## §10 안전 규칙 검증

| 규칙 | 검증 |
|---|---|
| 샘플 미실행 | `rg -n "subprocess|os\.system|Popen|exec\(" src/` — 결과 중 Ghidra headless 호출(`extract/`) 외에 샘플 바이너리를 실행하는 경로가 있으면 FAIL. `emulate/`는 Unicorn/Qiling 인프로세스여야 하며 프로세스 생성이 없어야 한다 |
| 평문 PE 미커밋 | `git ls-files \| rg -i "\.(exe\|dll\|sys\|bin)$"` + `rg -n "MZ" --binary` 로 추적 중인 파일 확인. `.gitignore`에 샘플 경로가 있는지도 본다 |
| 문자열 인젝션 격리 | 프롬프트 조립 코드와 바이너리 문자열 소비 지점을 **함께** 읽는다. `rg -n "strings\|pdb\|export_name\|section_name" src/loregrind/analyze/` 로 소비 지점을 찾고, 각각이 격리 래퍼를 거치는지 확인. 격리 래퍼를 우회하는 경로가 하나라도 있으면 FAIL |
| API 키 미노출 | `rg -n "api_key\|ANTHROPIC_API_KEY\|getenv" src/` — 키가 로그·예외 메시지·`runs.config` 저장에 실리는 경로가 있는지. 설정 객체를 통째로 로깅하거나 `runs.config`에 저장하면 FAIL |

## 경계면 교차 검증

**양쪽을 동시에 열어 비교한다.** 한쪽만 읽으면 절대 못 잡는다. 각 항목은 "존재하는가"가 아니라 "계약이 일치하는가"를 묻는다.

### 스키마 ↔ 추출 ↔ 도구

```bash
rg -n "CREATE TABLE" -A20 src/loregrind/db/schema.sql   # 왼쪽: 컬럼명·타입·NOT NULL
rg -n "INSERT INTO" src/loregrind/extract/ scripts/      # 오른쪽 1
rg -n "SELECT .* FROM" src/loregrind/tools/              # 오른쪽 2
```

확인: 컬럼명 오타, 스키마에 없는 컬럼 참조, NOT NULL 컬럼을 INSERT에서 누락, 타입 불일치(주소를 int로 저장하는데 str로 조회 등).

### MCP 도구 시그니처 ↔ 호출부

```bash
rg -n "@(server\.)?tool|def (list_candidates|get_function|record_analysis)" src/loregrind/tools/
rg -n "list_candidates|get_function|record_analysis|emulate_function" src/loregrind/analyze/
```

확인: 도구명 불일치, 인자 개수·이름 불일치, 반환 shape과 소비측 기대 불일치(도구가 `{"items": [...]}`를 주는데 호출부가 리스트를 기대하는 등).

### 정규화 ↔ 해시 입력

```bash
rg -n "def (normalize|code_hash|cfg_hash)" src/ -A10
rg -n "code_hash\(|cfg_hash\(" src/                      # 모든 호출부
```

강한 검증: **모든** 해시 호출부의 인자가 정규화를 거친 값인가. 원시 디컴파일 문자열이 직접 들어가는 곳이 하나라도 있으면 FAIL — 히트율이 0이 되는데 증상이 눈에 안 보인다.

### 무효화 전파 ↔ 콜그래프

`code_hash` 변경을 감지하는 코드와 무효화를 실행하는 코드를 함께 읽는다. 변경된 함수만 무효화하고 호출자로 역방향 전파하지 않으면 FAIL. 전파 깊이가 파라미터로 노출되어 있는지도 확인한다.

### 랭킹 신호 정의 ↔ 계산 코드

설계 문서/스킬이 명시한 신호(의심 API 클러스터, 고신호 문자열, capa 매핑, 콜그래프 위치, 복잡도 이상치)가 실제로 계산되는가. 신호별 점수가 개별 필드로 남는가 — 합계만 저장하면 어블레이션이 불가능하다.

### 검색 융합 ↔ RRF

```bash
rg -n "def (fuse|rrf|merge_rankings)" src/loregrind/retrieval/ -A15
```

가중합(`score * weight` 합산)이면 FAIL. RRF(`1/(k+rank)` 합)여야 한다. 채널을 개별적으로 끌 수 있는가도 확인한다 — §6 채널 어블레이션이 이것을 요구한다.

## §2 범위 이탈 탐지

```bash
rg -in "elf|mach-o|macho|unpack|packer|upx" src/ docs/
rg -in "fastapi|flask|uvicorn|django|websocket" src/ pyproject.toml
```

- ELF/Mach-O 지원 코드가 실제로 들어왔으면 FAIL (구조적 확장 여지는 허용, **구현은 제외**)
- 언패킹 로직이 있으면 FAIL
- 웹 프레임워크 의존성이 들어왔으면 FAIL (MCP 서버는 웹 UI가 아니다 — MCP SDK 자체는 정상)
- 멀티유저·인증·실시간 서비스 코드가 있으면 FAIL

## 리포트 작성

에이전트 정의(`loregrind-invariant-auditor.md`)의 리포트 구조를 따른다. 핵심:

- 판정은 PASS / FAIL / UNKNOWN / N-A 넷 중 하나. 임의 등급을 만들지 않는다
- 모든 판정에 `파일:라인`
- FAIL 항목은 **`파일:라인` + 무엇이 어긋났는지 + 어떻게 고칠 것인지** 3요소를 반드시 갖춘다. 이것이 없으면 수정 라운드가 낭비된다
- architect가 고쳐야 할 설계 결함은 "설계 결함" 태그로 구분한다 — 구현자가 고칠 수 있는 문제가 아니다
- UNKNOWN은 이유와 함께 남긴다. 검증 못 한 항목이 있는 리포트는 정직하지만, 검증했다고 거짓말한 리포트는 하네스 전체를 무력화한다

## 약한 검증 vs 강한 검증

| 약함 (하지 말 것) | 강함 (할 것) |
|---|---|
| `superseded_by` 컬럼이 있는가 | 모든 조회 경로가 그것으로 필터하는가 |
| 정규화 함수가 존재하는가 | 해시 입력이 실제로 정규화를 거쳐 들어가는가 |
| 예산 상수가 정의되어 있는가 | 상수를 우회하는 호출 경로가 있는가 |
| 도구가 정의되어 있는가 | 시그니처와 호출부의 인자·반환 shape이 일치하는가 |
| 게이팅 코드가 있는가 | 게이팅을 우회하는 색인 경로가 없는가 |
| 격리 래퍼가 존재하는가 | 바이너리 문자열의 **모든** 소비 지점이 래퍼를 거치는가 |
