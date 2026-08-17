# Loregrind — 개발·검증 게이트
#
# 게이트의 목적은 "초록을 만드는 것"이 아니라 **위반이 보이게 하는 것**이다.
# 그래서 아무 데이터가 없을 때 조용히 통과하는 타깃을 두지 않는다.
# 정답셋이 없으면 verify-holdout 은 exit 3(미측정)으로 실패한다.

.DEFAULT_GOAL := help
SHELL := /bin/bash

DB          ?= loregrind.db
GROUNDTRUTH ?= eval/groundtruth/groundtruth.json
SCHEMA      := src/loregrind/db/schema.sql
MIGRATIONS  := src/loregrind/db/migrations

.PHONY: help install fmt lint types test verify verify-holdout \
        schema-check migration-check leakage report ablation clean

help:  ## 타깃 목록
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install:  ## 의존성 설치 (워크트리마다 따로 — .venv 를 공유하지 않는다)
	uv sync

fmt:  ## 포매팅 (*.md 는 제외 — 문서의 예시 코드는 줄바꿈이 설명의 일부다)
	uv run ruff format .
	uv run ruff check --fix .

lint:  ## 린트만 (수정하지 않는다)
	uv run ruff check .
	uv run ruff format --check .

types:  ## mypy strict (src + eval)
	uv run mypy

test:  ## 테스트 (ghidra 마커는 기본 제외, 스킵 사실은 -ra 로 드러낸다)
	uv run pytest

# ---------------------------------------------------------------------------
# 스키마 게이트 — /db-change 의 완료 조건을 그대로 옮긴 것이다
# ---------------------------------------------------------------------------

schema-check:  ## schema.sql + 마이그레이션이 실제로 적재되는지
	@sqlite3 :memory: ".read $(SCHEMA)" ".schema" > /dev/null \
		&& echo "  schema.sql 적재 OK"
	@for m in $(MIGRATIONS)/*.sql; do \
		[ -e "$$m" ] || continue; \
		sqlite3 :memory: ".read $(SCHEMA)" ".read $$m" ".schema" > /dev/null \
			&& echo "  $$(basename $$m) 적재 OK" || exit 1; \
	done

migration-check:  ## 마이그레이션에 UPDATE/DELETE/DROP 이 없는지, 번호 중복이 없는지
	@violations=$$(grep -rniE '^[[:space:]]*(UPDATE|DELETE|DROP TABLE|ALTER TABLE .* DROP)' \
		$(MIGRATIONS) 2>/dev/null || true); \
	if [ -n "$$violations" ]; then \
		echo "  append-only 위반 후보:"; echo "$$violations"; \
		echo "  → 진행하지 말고 왜 필요한지 먼저 확인하라 (/db-change)"; exit 1; \
	else echo "  마이그레이션 append-only OK"; fi
	@dupes=$$(ls $(MIGRATIONS) 2>/dev/null | grep -v gitkeep | cut -d_ -f1 \
		| sort | uniq -d); \
	if [ -n "$$dupes" ]; then echo "  번호 중복: $$dupes"; exit 1; \
	else echo "  마이그레이션 번호 OK"; fi

# ---------------------------------------------------------------------------
# verify — 코드가 규율을 지키는지. 데이터 없이도 항상 돌아야 한다
# ---------------------------------------------------------------------------

verify: lint types test schema-check migration-check  ## 전체 검증 게이트 (커밋 전)
	@echo ""
	@echo "verify PASS — lint / types / test / schema / migration"
	@echo "  주의: 이것은 코드 규율 검증이다. 평가 숫자의 타당성은 verify-holdout 이 본다."

# ---------------------------------------------------------------------------
# verify-holdout — 평가 숫자를 신뢰할 수 있는지
#
# 1. 정답 누출 점검 (통과해야 지표를 재는 의미가 있다)
# 2. 홀드아웃 지표 존재 여부 (없으면 미측정 = 실패)
# 3. 웜 대비 홀드아웃 하락 검사 (하락하면 개선이 아니라 과적합)
#
# 정답셋이 없으면 exit 3 으로 실패한다. "데이터가 없어서 통과"는 게이트가 아니다.
# ---------------------------------------------------------------------------

leakage:  ## 정답 누출 점검만
	uv run python -m eval.run --db $(DB) --groundtruth $(GROUNDTRUTH) leakage

report:  ## 지표 리포트 + §7 5주차 컷라인 판정
	uv run python -m eval.run --db $(DB) --groundtruth $(GROUNDTRUTH) report

# make 는 레시피가 실패하면 실패 코드에 상관없이 자기 종료 코드 2 를 낸다.
# 그래서 1(발견)과 3(미측정)의 구분이 make 경계에서 사라진다 — 아래에서 실제 코드를
# 눈에 보이게 출력한다. CI 가 코드로 분기해야 하면 make 를 거치지 말고
# `uv run python -m eval.run holdout` 을 직접 호출한다 (docs/EVAL-SPEC.md §8).
verify-holdout:  ## 누출 + 홀드아웃 + 과적합 검증 (평가 게이트)
	@echo "== 1/2 정답 누출 점검"
	@uv run python -m eval.run --db $(DB) --groundtruth $(GROUNDTRUTH) leakage; \
	rc=$$?; \
	if [ $$rc -ne 0 ]; then \
		echo ""; echo "[gate] leakage exit=$$rc $$([ $$rc -eq 3 ] && echo '(미측정)' || echo '(발견)')"; \
		exit $$rc; \
	fi
	@echo ""
	@echo "== 2/2 홀드아웃 대비 검증"
	@uv run python -m eval.run --db $(DB) --groundtruth $(GROUNDTRUTH) holdout; \
	rc=$$?; \
	if [ $$rc -ne 0 ]; then \
		echo ""; echo "[gate] holdout exit=$$rc $$([ $$rc -eq 3 ] && echo '(미측정)' || echo '(발견)')"; \
		exit $$rc; \
	fi
	@echo ""
	@echo "verify-holdout PASS — 누출 없음, 홀드아웃 측정됨, 하락 없음"

ablation:  ## 어블레이션 표 (SQL 한 줄로 뽑히는지 확인)
	uv run loregrind --db $(DB) eval --ablation-axis rename_writes

clean:  ## 캐시 정리 (DB·artifacts 는 지우지 않는다 — 재추출 비용이 크다)
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
