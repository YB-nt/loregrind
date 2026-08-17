# 어블레이션 결과

§6 이 요구하는 필수 6축. **표를 먼저 만들고 값은 나중에 채운다** — 행을 나중에 추가하는
방식은 측정하지 않은 축을 조용히 빠뜨린다.

- 정의와 SQL: `docs/EVAL-SPEC.md` §6
- 값 산출: `loregrind eval --ablation-axis <key> --metric <metric>`
- **측정된 값 없음.** LLM 호출 경로(L2~L4)와 정답셋이 아직 없다.
  빈 칸은 "0" 이 아니라 "측정 전"이다.

## 6축

| 축 | config 키 | 조건 | 지표 | 결과 | 비고 |
|---|---|---|---|---|---|
| 리네임 쓰기 | `rename_writes` | on / off | naming_accuracy | 측정 전 | 3주차 첫 어블레이션 |
| 탐색 전략 | `exploration` | ranked / sequential / random | exploration_efficiency | 측정 전 | L3 랭킹의 값 |
| 컨텍스트 구성 | `context_mode` | hierarchical / flat | naming_accuracy | 측정 전 | 요약 카드 가설 |
| 검증 루프 | `verification` | on / off | **hallucination_rate** | 측정 전 | 9~10주차 핵심 결과 |
| 검색 채널 | `channels` | 채널별 on/off | recall_at_k | 측정 전 | 아래 채널 표 참조 |
| 코퍼스 상태 | `corpus_state` | cold / warm / **holdout** | 전체 | 측정 전 | 홀드아웃 없으면 과적합 판정 불가 |

## 검색 채널

`/add-retrieval-channel` 5단계가 채널을 추가할 때마다 이 표에 행을 넣도록 요구한다.
**채널 단독** Recall 을 낸다 — 하이브리드 점수만으로는 개별 기여를 알 수 없다.

| 채널 | 단독 Recall@5 | 제거 시 ΔRecall@5 | 지연(p50) | 인덱스 크기 |
|---|---|---|---|---|
| 정규화 해시 | 측정 전 | 측정 전 | 측정 전 | 측정 전 |
| API 집합 | 측정 전 | 측정 전 | 측정 전 | 측정 전 |
| 구조 지문 | 측정 전 | 측정 전 | 측정 전 | 측정 전 |
| BM25 | 측정 전 | 측정 전 | 측정 전 | 측정 전 |
| 임베딩 | 측정 전 | 측정 전 | 측정 전 | 측정 전 |

구현된 채널은 아직 없다. 위 5개는 §5 가 정의한 계획이며 `config/retrieval.yaml` 의
기본값은 전부 `enabled: false` 여야 한다 — 켜는 근거는 이 표에서 나온다.

## 기록 규칙

- **비교하는 두 run 은 대상 축 외의 `model` / `prompt_version` / `config` 가 같아야 한다.**
  다르면 비교가 아니라 착시다. 이 동일성은 아직 코드로 검사되지 않으므로 사람이 확인한다
- 지표에는 `n` 을 함께 적는다. 함수 12개에서 잰 92% 는 92% 가 아니다
- 셀 단위(`gcc:-O2` 등)로 적고 평균은 그다음이다
- 실패한 셀은 채우지 말고 비워 두고 **이유를 적는다**
- 채널을 제거해도 행을 지우지 않고 "제거됨(날짜, 이유)"로 남긴다. 실험 이력은 append-only 다
