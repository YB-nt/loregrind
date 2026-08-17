---
name: add-retrieval-channel
description: 검색 채널(BM25, 임베딩, 심볼 매칭, 호출그래프 등)을 추가하거나 제거할 때 쓴다. 채널 추가는 5단계 고정 작업이고 5단계를 전부 끝내야 완료다. 리트리버, 하이브리드 검색, RRF, Recall@k 이야기가 나오면 이 스킬을 쓴다.
argument-hint: "[channel-name]"
---

# add-retrieval-channel

적용 범위: `src/loregrind/retrieval/**`, `eval/**`

대상 채널: `$1` — 아래에서 `<channel>`은 모두 이 이름으로 치환한다.
인자 없이 호출됐으면 **채널명을 사용자에게 먼저 묻는다.** 임의로 정하지 않는다.

이 스킬의 존재 이유는 **4·5번이 매번 빠지기 때문**이다. 1~3번만 하고 완료 보고하지 않는다.

### 1. 인터페이스 구현
`src/loregrind/retrieval/channels/<channel>.py`
`Retriever` 프로토콜 구현: `name`, `index(docs)`, `search(query, k) -> list[Hit]`.
`Hit = (doc_id, score, channel)`. **점수 정규화는 하지 않는다** — RRF가 순위만 쓴다.

### 2. RRF 등록
`src/loregrind/retrieval/fusion.py`의 채널 레지스트리에 추가.
RRF 상수 `k`는 채널별로 두지 않는다. 전역 하나만 유지한다.

### 3. config 플래그
`config/retrieval.yaml`의 `channels:` 아래 `<channel>: {enabled: false}`.
**기본값은 반드시 `false`.** 켜는 건 어블레이션에서 근거가 나온 뒤에.

### 4. Recall@k 평가 추가  ← 여기서 빠진다
`eval/retrieval/cases.yaml`에 이 채널이 강한 케이스 최소 3개 추가.
`eval/retrieval/run.py`의 채널 목록에 `<channel>` 추가.
**채널 단독** Recall@1/@5/@20이 나와야 한다. 하이브리드 점수만으로는 기여를 알 수 없다.

### 5. 어블레이션 테이블에 행 추가  ← 여기서 빠진다
`docs/ablation.md` 표에 `<channel>` 행 추가. 열은 기존 그대로:
`채널 | 단독 Recall@5 | 제거 시 ΔRecall@5 | 지연(p50) | 인덱스 크기`.
측정 전이면 값 칸에 `측정 전`이라 쓴 행을 **먼저 만들어 둔다.** 행을 나중에 추가하지 않는다.

## 완료 검증 — 돌리기 전에 완료 보고하지 않는다

```bash
CH=<channel>   # ← 실제 채널명으로 치환해서 실행한다
MISS=0
[ -f "src/loregrind/retrieval/channels/$CH.py" ] || { echo "1 인터페이스 없음"; MISS=1; }
rg -q "\b$CH\b" src/loregrind/retrieval/fusion.py || { echo "2 RRF 미등록"; MISS=1; }
rg -q "^\s*$CH\s*:" config/retrieval.yaml       || { echo "3 config 플래그 없음"; MISS=1; }
rg -q "\b$CH\b" eval/retrieval/run.py           || { echo "4 Recall@k 평가 없음"; MISS=1; }
rg -q "^\|\s*$CH\s*\|" docs/ablation.md         || { echo "5 어블레이션 행 없음"; MISS=1; }
[ $MISS -eq 0 ] && echo "채널 $CH: 5단계 확인됨" || echo "미완료"
```

## 채널 제거

같은 5곳을 역순으로. 단, config 플래그는 지우지 말고 `enabled: false`로, 어블레이션 표의 행도
지우지 말고 "제거됨(날짜, 이유)"로 남긴다. 실험 이력은 append-only다.
