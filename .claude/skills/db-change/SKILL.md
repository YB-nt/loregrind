---
name: db-change
description: 스키마나 저장 데이터를 바꾸는 모든 작업의 절차. 테이블/컬럼 추가, 마이그레이션 작성, 인덱스 변경, 잘못된 분석 결과 정정이 필요할 때 반드시 이 스킬을 쓴다. Loregrind DB는 append-only이며 UPDATE/DELETE는 원칙적으로 금지다.
argument-hint: "[변경 내용 한 줄]"
---

# db-change

적용 범위: `src/loregrind/db/**` (`schema.sql`, `models.py`, `repo.py`, `migrations/`)

## 현재 상태 — 무엇을 하기 전에 이것부터 읽는다

```bash
ls -1 src/loregrind/db/migrations | grep -v gitkeep | tail -5   # 최근 마이그레이션
sqlite3 loregrind.db ".schema" 2>/dev/null | head -80 || true   # 현재 스키마
```

출력이 비어 있으면 아직 DB가 없는 것이다. `NNNN`을 추측하지 말고 `0001`부터 시작한다.

## 절대 규칙

1. **커밋된 마이그레이션 파일은 수정하지 않는다.** 잘못됐으면 되돌리는 새 마이그레이션을 추가한다.
2. **분석 결과 테이블에 UPDATE / DELETE 금지.** 정정은 새 행 삽입으로 한다.
3. **컬럼 삭제 금지.** 안 쓰게 됐으면 주석으로 deprecated 표시만 하고 남긴다.
   SQLite에서 컬럼 삭제는 테이블 재생성이고, 그 순간 append-only 이력이 날아간다.
4. 마이그레이션 하나에 논리적 변경 하나만 담는다.

## 파일 명명

```
src/loregrind/db/migrations/NNNN__<verb>_<subject>.sql
```

`NNNN`은 **위 목록의 최댓값 + 1** (추측하지 말고 위에서 읽는다), 4자리 zero-pad.
`verb` ∈ `add` / `create` / `backfill` / `index` / `revert`.
예: `0017__add_decompile_error_to_functions.sql`

## 정정 패턴

기본형은 새 행에 `supersedes`를 두는 완전 append-only:

```sql
INSERT INTO analysis (function_id, verdict, prompt_version, supersedes)
VALUES (:fid, :new_verdict, :pv, :old_analysis_id);
```

조회는 가려진 행을 제외하는 뷰를 통해서만 한다.

기존 스키마가 `superseded_by`(이전 행을 갱신하는 방식)라면 **그 컬럼에 대한 단 한 번의
UPDATE만이 유일하게 허용된 UPDATE**다. 이 예외는 마이그레이션 파일 상단 주석에 명시한다.
다른 어떤 컬럼도 UPDATE 대상이 아니다.

## 인덱스 판단

컬럼을 추가했으면 순서대로 확인하고 결론을 답변에 적는다.

- WHERE / JOIN / ORDER BY에 안 들어가면 인덱스를 만들지 않는다
- 카디널리티가 낮으면(enum류) 단독 인덱스 대신 복합 인덱스 뒷자리로
- 기존 복합 인덱스의 선두 컬럼 순서를 바꿔야 하면 `DROP INDEX` + `CREATE INDEX`를
  **같은 마이그레이션 안에서** 한다 (인덱스는 파생물이라 재생성이 append-only 위반이 아니다)
- 대량 backfill이 있으면 인덱스는 그 뒤에 만든다

## 완료 조건 — 전부 통과해야 커밋한다

```bash
DB=src/loregrind/db
NEW=$DB/migrations/<새-파일>.sql
rg -n -i '^\s*(UPDATE|DELETE|DROP TABLE|ALTER TABLE .* DROP)' "$NEW"   # 출력 없어야 함
sqlite3 :memory: ".read $DB/schema.sql" ".read $NEW" ".schema" > /dev/null
ls $DB/migrations | grep -v gitkeep | cut -d_ -f1 | sort | uniq -d     # 출력 없어야 함
```

첫 번째가 출력을 내면 **진행하지 말고 왜 필요한지 사용자에게 먼저 묻는다.**
