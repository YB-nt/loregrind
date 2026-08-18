-- 0003 — 라이브러리 판정 근거 (docs/SPEC.md §7)
--
-- 왜 별도 테이블인가: `functions.is_library` 만 갱신하면 **왜 이 함수가 걸러졌는지**
-- 를 나중에 복원할 수 없다. 라이브러리 필터는 "분석 대상을 절반 이하로 줄이는"
-- 단일 최대 효과의 최적화이므로, 그 판정이 틀렸을 때 되짚을 수 있어야 한다.
--
-- `functions.is_library` 는 이 표의 **파생 캐시**로만 다룬다 — 언제든 재계산
-- 가능하고, 근거와 버전은 여기에 append-only 로 쌓인다.
--
-- run_id NOT NULL: 판정도 산출물이다 (불변식 5). 어떤 method_version 이 무엇을
-- 걸렀는지 어블레이션할 수 있어야 한다.

CREATE TABLE IF NOT EXISTS library_verdicts (
    id             INTEGER PRIMARY KEY,
    run_id         TEXT    NOT NULL REFERENCES runs(run_id),
    function_id    INTEGER NOT NULL REFERENCES functions(id),
    is_library     INTEGER NOT NULL CHECK (is_library IN (0, 1)),
    -- 'thunk' | 'external' | 'signature' | 'name' | 'fid' | 'heuristic'
    method         TEXT    NOT NULL,
    -- 규칙을 고치면 올린다. 버전 없이 고치면 이전 판정과 비교할 수 없다
    method_version TEXT    NOT NULL,
    confidence     REAL    CHECK (confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)),
    created_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_library_verdicts_function ON library_verdicts(function_id);
CREATE INDEX IF NOT EXISTS idx_library_verdicts_run ON library_verdicts(run_id);

-- 판정 이력은 지우지 않는다. 나쁜 판정을 지우면 필터가 왜 틀렸는지 못 본다
CREATE TRIGGER IF NOT EXISTS trg_library_verdicts_no_delete
BEFORE DELETE ON library_verdicts
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'library_verdicts is append-only: recompute inserts a new row');
END;

-- 랭킹 점수 — 신호별로 따로 남긴다
--
-- **합계만 저장하면 어블레이션이 불가능하다.** "어느 신호가 값을 했는가"를 물을 수
-- 없게 되고, §6 어블레이션 2축(랭킹 vs 순차 vs 랜덤)의 해석도 얕아진다.
CREATE TABLE IF NOT EXISTS function_scores (
    id              INTEGER PRIMARY KEY,
    run_id          TEXT    NOT NULL REFERENCES runs(run_id),
    function_id     INTEGER NOT NULL REFERENCES functions(id),
    -- 최종 점수 = 신호별 점수 × 가중치의 합. 가중치는 runs.config_json 에 실린다
    score           REAL    NOT NULL,
    s_api           REAL    NOT NULL DEFAULT 0.0,
    s_strings       REAL    NOT NULL DEFAULT 0.0,
    s_callgraph     REAL    NOT NULL DEFAULT 0.0,
    s_complexity    REAL    NOT NULL DEFAULT 0.0,
    -- capa 는 선택 의존성이다. 없으면 0 이 아니라 NULL — 측정 불가와 0 을 구별한다
    s_capa          REAL,
    -- 사람이 읽을 근거. "왜 이 함수가 위에 있는가"에 답해야 한다
    reasons_json    TEXT    NOT NULL DEFAULT '[]',
    ranker_version  TEXT    NOT NULL,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (run_id, function_id)
);

CREATE INDEX IF NOT EXISTS idx_function_scores_rank ON function_scores(run_id, score DESC);

CREATE TRIGGER IF NOT EXISTS trg_function_scores_no_delete
BEFORE DELETE ON function_scores
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'function_scores is append-only: rescoring uses a new run');
END;
