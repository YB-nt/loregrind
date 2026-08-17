-- Loregrind 기반 스키마 — DDL 단일 소스
--
-- 이 파일이 현재 스키마의 전부다. 여기서부터의 변경은
-- migrations/NNNN__<verb>_<subject>.sql 로 쌓는다 (0001 부터).
-- 절차는 /db-change 스킬을 따른다.
--
-- 규율 (docs/PROJECT.md §4, §11):
--   1. 추출 사실은 불변, 에이전트 판단은 append-only
--   2. 모든 산출물은 run 에 소속된다 (run_id NOT NULL)
--   3. DB 가 단일 진실 소스. Ghidra 에는 단방향 apply 만 한다
--
-- append-only 는 문서가 아니라 트리거로 강제한다. 파일 하단 참조.

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- 추출 사실 (immutable) — L1 이 적재하고 이후 아무도 고치지 않는다
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS binaries (
    id                     INTEGER PRIMARY KEY,
    sha256                 TEXT    NOT NULL UNIQUE,
    -- 원본 파일명. 샘플 자체는 저장하지 않는다 (§10)
    filename               TEXT,
    arch                   TEXT    NOT NULL,
    -- 패밀리 라벨은 사전정보다. 결론이 아니라 가설로만 쓴다 (불변식 7)
    family_label           TEXT,
    ghidra_path            TEXT,
    ghidra_version         TEXT,
    extract_schema_version INTEGER NOT NULL,
    function_count         INTEGER NOT NULL,
    -- 디컴파일 실패 수. 레코드를 빼지 않고 세는 이유는 실패율을 측정하기 위함이다
    decompile_failure_count INTEGER NOT NULL DEFAULT 0,
    analyzed_at            TEXT    NOT NULL,
    duration_sec           REAL,
    imported_at            TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS functions (
    id              INTEGER PRIMARY KEY,
    binary_id       INTEGER NOT NULL REFERENCES binaries(id),
    -- Ghidra 가 준 형태 그대로의 16진 문자열 ("0x401000"). 정수 변환하지 않는다 —
    -- 추출 사실을 원형으로 보존해야 재현성 비교가 가능하다
    addr            TEXT    NOT NULL,
    -- 스트립된 바이너리에서는 대개 FUN_00401000. 이것이 명명의 출발점이다
    original_name   TEXT    NOT NULL,
    signature       TEXT,
    size            INTEGER,
    cyclomatic      INTEGER,
    is_thunk        INTEGER NOT NULL DEFAULT 0 CHECK (is_thunk IN (0, 1)),
    is_external     INTEGER NOT NULL DEFAULT 0 CHECK (is_external IN (0, 1)),
    -- 라이브러리 판정. L3 필터가 채운다. NULL = 아직 판정 안 함
    is_library      INTEGER CHECK (is_library IN (0, 1)),
    decompiled      TEXT,
    -- 디컴파일 실패는 레코드를 빼지 않고 여기에 사유를 남긴다
    decompile_error TEXT,
    -- 정규화(주소·레지스터·스택 오프셋 제거) 후 해시. 정규화 없는 해시는 히트율이 0 이다
    code_hash       TEXT,
    cfg_hash        TEXT,
    UNIQUE (binary_id, addr),
    -- decompiled 와 decompile_error 가 동시에 채워지면 어느 쪽이 진실인지 알 수 없다
    CHECK (decompiled IS NULL OR decompile_error IS NULL)
);

CREATE INDEX IF NOT EXISTS idx_functions_code_hash ON functions(code_hash)
    WHERE code_hash IS NOT NULL;
-- L3 랭킹이 "미판정 + 라이브러리 아님"을 자주 훑는다
CREATE INDEX IF NOT EXISTS idx_functions_binary_library ON functions(binary_id, is_library);

-- 콜 그래프. 바텀업 순서와 무효화 역전파의 근거가 된다 (§4 증분 재분석)
CREATE TABLE IF NOT EXISTS call_edges (
    binary_id   INTEGER NOT NULL REFERENCES binaries(id),
    caller_addr TEXT    NOT NULL,
    callee_addr TEXT    NOT NULL,
    PRIMARY KEY (binary_id, caller_addr, callee_addr)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_call_edges_callee ON call_edges(binary_id, callee_addr);

-- ---------------------------------------------------------------------------
-- run — 모든 산출물의 소속 (불변식 5)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS runs (
    run_id         TEXT    PRIMARY KEY,
    -- 무엇으로 만든 결과인지. 어블레이션이 이 세 컬럼으로 GROUP BY 된다
    model          TEXT    NOT NULL,
    prompt_version TEXT    NOT NULL,
    -- API 키를 제거한 사본만 저장한다 (§10). config 객체를 통째로 넣지 않는다
    config_json    TEXT    NOT NULL,
    -- 무작위성을 쓰면 시드를 여기 남긴다. 없으면 NULL
    seed           INTEGER,
    tokens_in      INTEGER NOT NULL DEFAULT 0,
    tokens_out     INTEGER NOT NULL DEFAULT 0,
    cost_usd       REAL    NOT NULL DEFAULT 0.0,
    started_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    finished_at    TEXT
);

-- ---------------------------------------------------------------------------
-- 에이전트 판단 (append-only) — UPDATE 하지 않는다. 새 행 + superseded_by
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS function_analyses (
    id             INTEGER PRIMARY KEY,
    -- NOT NULL 이 §6 평가 설계의 전제다. 옵셔널로 두면 어블레이션이 SQL 한 줄이 되지 않는다
    run_id         TEXT    NOT NULL REFERENCES runs(run_id),
    -- §4 는 addr 로 적었지만 function_id 를 쓴다. addr 만으로는 binary 가 다르면
    -- 같은 주소가 충돌하고, 존재하지 않는 함수에 대한 판단을 막을 수 없다
    function_id    INTEGER NOT NULL REFERENCES functions(id),
    proposed_name  TEXT,
    summary        TEXT,
    -- 근거 인용. 근거 없는 판단은 §8 산출물에서 쓸 수 없다
    evidence_json  TEXT,
    confidence     REAL    CHECK (confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)),
    -- 신뢰도 계층. human > emulation > agent
    source         TEXT    NOT NULL CHECK (source IN ('agent', 'emulation', 'human')),
    -- 판단 시점의 code_hash. 이후 함수가 바뀌면 이 판단이 낡았음을 알 수 있다
    code_hash      TEXT,
    superseded_by  INTEGER REFERENCES function_analyses(id),
    created_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    -- 자기 자신으로 가려질 수는 없다
    CHECK (superseded_by IS NULL OR superseded_by <> id)
);

-- 조회는 대개 "현재 유효한 판단"만 본다
CREATE INDEX IF NOT EXISTS idx_analyses_current
    ON function_analyses(function_id) WHERE superseded_by IS NULL;
CREATE INDEX IF NOT EXISTS idx_analyses_run ON function_analyses(run_id);

CREATE TABLE IF NOT EXISTS hypotheses (
    id              INTEGER PRIMARY KEY,
    run_id          TEXT    NOT NULL REFERENCES runs(run_id),
    function_id     INTEGER REFERENCES functions(id),
    statement       TEXT    NOT NULL,
    -- 상태 전이는 UPDATE 가 아니다. 새 행을 넣고 이전 행을 superseded_by 로 가린다
    status          TEXT    NOT NULL CHECK (status IN ('open', 'confirmed', 'refuted')),
    experiment_json TEXT,
    result_json     TEXT,
    superseded_by   INTEGER REFERENCES hypotheses(id),
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    CHECK (superseded_by IS NULL OR superseded_by <> id)
);

CREATE INDEX IF NOT EXISTS idx_hypotheses_current
    ON hypotheses(function_id) WHERE superseded_by IS NULL;

-- ---------------------------------------------------------------------------
-- 지식 축적 — 정규 엔트리와 출현 (§5 축적 정책). 6주차부터 채운다
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS entries (
    id                      INTEGER PRIMARY KEY,
    canonical_name          TEXT    NOT NULL,
    summary                 TEXT,
    -- 정규화 해시. 완전 일치 채널의 키 (§5)
    code_hash               TEXT,
    api_set_json            TEXT,
    -- 모델 교체 시 재색인 대상을 찾기 위해 벡터마다 버전을 남긴다
    embedding_model_version TEXT,
    -- 이 엔트리를 만든 run. 불변식 5
    run_id                  TEXT    NOT NULL REFERENCES runs(run_id),
    created_at              TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_entries_code_hash ON entries(code_hash)
    WHERE code_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS occurrences (
    entry_id    INTEGER NOT NULL REFERENCES entries(id),
    function_id INTEGER NOT NULL REFERENCES functions(id),
    PRIMARY KEY (entry_id, function_id)
) WITHOUT ROWID;

-- ---------------------------------------------------------------------------
-- 현재 유효한 판단만 노출하는 뷰
--
-- 호출부가 superseded_by IS NULL 을 잊을 수 없게 만드는 장치다.
-- 흩어 놓으면 반드시 빠뜨리는 곳이 생긴다.
-- ---------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_current_analyses AS
SELECT fa.*, f.binary_id, f.addr, f.original_name
FROM function_analyses fa
JOIN functions f ON f.id = fa.function_id
WHERE fa.superseded_by IS NULL;

CREATE VIEW IF NOT EXISTS v_current_hypotheses AS
SELECT * FROM hypotheses WHERE superseded_by IS NULL;

-- ---------------------------------------------------------------------------
-- append-only 강제 (불변식 3)
--
-- 규칙을 문서에만 두면 어긋난다. DB 가 직접 거부하게 만든다.
-- 허용되는 UPDATE 는 superseded_by 링크 부착 단 하나다 — 판단 내용의 변경이
-- 아니라 "이 행은 이제 가려졌다"는 표시이기 때문이다.
-- ---------------------------------------------------------------------------

CREATE TRIGGER IF NOT EXISTS trg_function_analyses_append_only
BEFORE UPDATE ON function_analyses
FOR EACH ROW
WHEN OLD.run_id        IS NOT NEW.run_id
  OR OLD.function_id   IS NOT NEW.function_id
  OR OLD.proposed_name IS NOT NEW.proposed_name
  OR OLD.summary       IS NOT NEW.summary
  OR OLD.evidence_json IS NOT NEW.evidence_json
  OR OLD.confidence    IS NOT NEW.confidence
  OR OLD.source        IS NOT NEW.source
  OR OLD.code_hash     IS NOT NEW.code_hash
  OR OLD.created_at    IS NOT NEW.created_at
BEGIN
    SELECT RAISE(ABORT,
        'function_analyses is append-only: insert a new row and link via superseded_by');
END;

-- 이미 가려진 행을 다시 가리는 것은 이력을 갈라놓는다
CREATE TRIGGER IF NOT EXISTS trg_function_analyses_supersede_once
BEFORE UPDATE OF superseded_by ON function_analyses
FOR EACH ROW
WHEN OLD.superseded_by IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'function_analyses row is already superseded');
END;

CREATE TRIGGER IF NOT EXISTS trg_function_analyses_no_delete
BEFORE DELETE ON function_analyses
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'function_analyses is append-only: rows are never deleted');
END;

CREATE TRIGGER IF NOT EXISTS trg_hypotheses_append_only
BEFORE UPDATE ON hypotheses
FOR EACH ROW
WHEN OLD.run_id          IS NOT NEW.run_id
  OR OLD.function_id     IS NOT NEW.function_id
  OR OLD.statement       IS NOT NEW.statement
  OR OLD.status          IS NOT NEW.status
  OR OLD.experiment_json IS NOT NEW.experiment_json
  OR OLD.result_json     IS NOT NEW.result_json
  OR OLD.created_at      IS NOT NEW.created_at
BEGIN
    SELECT RAISE(ABORT,
        'hypotheses is append-only: status transitions insert a new row');
END;

CREATE TRIGGER IF NOT EXISTS trg_hypotheses_no_delete
BEFORE DELETE ON hypotheses
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'hypotheses is append-only: rows are never deleted');
END;
