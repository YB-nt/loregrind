-- 0001 — 평가 지표 저장 (§6, docs/PROJECT.md)
--
-- 왜 필요한가: 어블레이션이 SQL 한 줄이어야 한다. 지표가 DB 밖(파일·노트북)에 있으면
-- runs 와 조인할 수 없고, 그 순간 §6 평가 설계가 애플리케이션 우회 집계로 무너진다.
--
--   SELECT r.config_json ->> '$.rename_writes' AS cond,
--          AVG(m.value), SUM(m.n)
--   FROM run_metrics m JOIN runs r USING (run_id)
--   WHERE m.metric = 'naming_accuracy'
--   GROUP BY cond;
--
-- 왜 long format(지표명을 컬럼이 아니라 행으로)인가: 지표를 추가할 때마다 컬럼을
-- 늘리면 마이그레이션이 지표 수만큼 쌓인다. §6 의 지표 6종은 시작점이고 진단 테스트가
-- 늘어난다. 이름을 값으로 두면 스키마가 고정된다.
--
-- append-only: 이 테이블은 계측 결과이지 에이전트 판단이 아니다. 그러나 재계산 이력을
-- 남기는 편이 안전하므로 UPDATE 하지 않고 새 행을 넣는다. 같은 (run_id, metric,
-- stratum, groundtruth_version) 이 여러 번 나오면 computed_at 이 큰 것이 최신이다.

CREATE TABLE IF NOT EXISTS run_metrics (
    id                  INTEGER PRIMARY KEY,
    -- 모든 산출물은 run 에 소속된다 (불변식 5). 지표도 예외가 아니다
    run_id              TEXT    NOT NULL REFERENCES runs(run_id),
    -- 'naming_accuracy' | 'hallucination_rate' | 'exploration_efficiency'
    -- | 'contradiction_rate' | 'recall_at_k' | 'precision_at_1' | 'cost_usd' ...
    metric              TEXT    NOT NULL,
    value               REAL    NOT NULL,
    -- **n 없는 지표는 저장하지 않는다.** 함수 12개에서 잰 92% 는 92% 가 아니다
    n                   INTEGER NOT NULL CHECK (n >= 0),
    -- 난이도 격자 셀: 'gcc:-O0' | 'clang:-O2' | 'msvc:-O2' ...
    -- 격자 전체 평균은 'all'. 평균만 보면 -O0 의 쉬운 성공이 -O3 의 실패를 가린다
    stratum             TEXT    NOT NULL DEFAULT 'all',
    -- 코퍼스 상태: 'cold' | 'warm' | 'holdout'.
    -- holdout 성능이 떨어지면 개선이 아니라 과적합이다 — 항상 함께 보고한다
    corpus_state        TEXT    NOT NULL DEFAULT 'cold'
                        CHECK (corpus_state IN ('cold', 'warm', 'holdout')),
    -- 어느 정답셋으로 재었는가. 정답셋이 바뀌면 이전 숫자와 비교할 수 없다
    groundtruth_version TEXT,
    -- 판정 방법을 리포트에 명시해야 한다 (명명 정확도의 'exact' | 'token' | 'alias')
    method              TEXT,
    -- k 가 필요한 지표(recall_at_k)용. 없으면 NULL
    k                   INTEGER,
    computed_at         TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- 어블레이션 질의는 (metric, stratum) 으로 그룹핑하고 run 과 조인한다
CREATE INDEX IF NOT EXISTS idx_run_metrics_lookup
    ON run_metrics(metric, stratum, corpus_state);
CREATE INDEX IF NOT EXISTS idx_run_metrics_run ON run_metrics(run_id);

-- 계측 결과도 지우지 않는다. 나쁜 숫자를 지우면 5주차 컷라인 판단이 불가능해진다
CREATE TRIGGER IF NOT EXISTS trg_run_metrics_no_delete
BEFORE DELETE ON run_metrics
FOR EACH ROW
BEGIN
    SELECT RAISE(ABORT, 'run_metrics is append-only: recompute inserts a new row');
END;
