-- 0002 — 문자열·임포트 추출 사실 (docs/SPEC.md §3)
--
-- 왜 지금인가: L2 도구 search_strings / get_apis_used 가 요구하는 사실이 DB 에 없다.
-- 미루면 같은 사실을 L3 랭킹 신호(의심 API 클러스터, 고신호 문자열)와 §5 BM25 토큰
-- 스트림이 다시 요구하므로 **추출을 두 번 돌려야 한다**. 대형 바이너리에서 이 비용이
-- 가장 크다.
--
-- 왜 트리거가 없는가: 이것은 추출 사실이지 에이전트 판단이 아니다. append-only 규율의
-- 대상이 아니며 정정 경로는 재추출이다 (불변식 1).
--
-- 신뢰 경계: strings.value, imports.api_name 은 **바이너리에서 나온 데이터**다.
-- 프롬프트로 나갈 때 격리 래퍼를 거쳐야 한다 (§10, docs/SPEC.md §5).

CREATE TABLE IF NOT EXISTS strings (
    id        INTEGER PRIMARY KEY,
    binary_id INTEGER NOT NULL REFERENCES binaries(id),
    -- functions.addr 와 같은 표기. "0x403040"
    addr      TEXT    NOT NULL,
    value     TEXT    NOT NULL,
    encoding  TEXT    NOT NULL CHECK (encoding IN ('ascii', 'utf16le', 'other')),
    -- 잘리기 전 원본 길이. truncated 와 함께 보면 손실 여부를 알 수 있다
    length    INTEGER NOT NULL CHECK (length >= 0),
    -- 추출 시점에 잘렸는가. 조용히 자르면 에이전트가 문자열 전체를 봤다고 착각한다
    truncated INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0, 1)),
    UNIQUE (binary_id, addr)
);

-- 부분 문자열 검색이 주 경로다. 접두 일치는 이 인덱스를 타고, 중간 일치는 스캔한다
CREATE INDEX IF NOT EXISTS idx_strings_value ON strings(binary_id, value);

-- 함수 → 문자열. L3 의 "고신호 문자열 참조" 신호가 이 표를 센다
CREATE TABLE IF NOT EXISTS string_xrefs (
    binary_id     INTEGER NOT NULL REFERENCES binaries(id),
    function_addr TEXT    NOT NULL,
    string_addr   TEXT    NOT NULL,
    PRIMARY KEY (binary_id, function_addr, string_addr)
) WITHOUT ROWID;

-- 역방향("이 문자열을 누가 쓰는가")도 자주 묻는다
CREATE INDEX IF NOT EXISTS idx_string_xrefs_string ON string_xrefs(binary_id, string_addr);

CREATE TABLE IF NOT EXISTS imports (
    id        INTEGER PRIMARY KEY,
    binary_id INTEGER NOT NULL REFERENCES binaries(id),
    -- 소문자로 정규화해서 넣는다. KERNEL32.dll 과 kernel32.dll 이 갈라지면
    -- API 집합 Jaccard 채널(§5)의 교집합이 조용히 비어간다
    module    TEXT    NOT NULL,
    api_name  TEXT    NOT NULL,
    iat_addr  TEXT,
    ordinal   INTEGER,
    -- ordinal 을 UNIQUE 에 넣지 않는 이유: SQLite 는 NULL 을 서로 다른 값으로 보므로
    -- 이름 임포트의 중복을 잡지 못한다. 서수 전용 임포트는 api_name 이
    -- "Ordinal_5" 형태로 들어오므로 (module, api_name) 만으로 유일하다
    UNIQUE (binary_id, module, api_name)
);

-- 함수 → API 호출 지점
CREATE TABLE IF NOT EXISTS api_calls (
    binary_id     INTEGER NOT NULL REFERENCES binaries(id),
    function_addr TEXT    NOT NULL,
    import_id     INTEGER NOT NULL REFERENCES imports(id),
    call_addr     TEXT    NOT NULL,
    PRIMARY KEY (binary_id, function_addr, import_id, call_addr)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_api_calls_function ON api_calls(binary_id, function_addr);
CREATE INDEX IF NOT EXISTS idx_api_calls_import ON api_calls(import_id);
