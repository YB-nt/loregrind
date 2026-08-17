---
name: ghidra-extract
description: Ghidra analyzeHeadless로 바이너리를 디컴파일해 정규 JSONL로 추출한다. 바이너리 임포트, 함수 목록/디컴파일 텍스트/호출그래프 추출, Ghidra 스크립트 실행, 추출 결과 재생성이 필요할 때 반드시 이 스킬을 쓴다. analyzeHeadless 명령을 즉석에서 조립하지 말 것.
argument-hint: "[binary-path] [--reanalyze]"
---

# ghidra-extract

적용 범위: `scripts/**` (Ghidra 인터프리터), `src/loregrind/extract/**` (적재), `artifacts/extract/**` (산출물)

## 정규 명령 — 이 형태에서 벗어나지 않는다

```bash
export _JAVA_OPTIONS="-Xmx8G"            # 힙은 CLI 플래그로 못 준다
"$GHIDRA_HOME/support/analyzeHeadless" \
  ".ghidra-projects/<sha256>" loregrind \
  -import "<binary>" \
  -scriptPath "scripts" \
  -postScript export_functions.py "<config.json>" \
  -log "artifacts/extract/<sha256>/ghidra.log" \
  -max-cpu 4 \
  -deleteProject
```

## 불변 규칙

1. **실행 경로는 하나만.** `analyzeHeadless -postScript`만 쓴다. `python -m pyghidra` 임베드 방식과
   섞지 않는다. 두 경로는 심볼 해석과 디컴파일러 옵션이 달라 결과가 재현되지 않는다.
2. **`-postScript` 인자는 config JSON 경로 하나만** 넘긴다. 인자를 여러 개 넘기면 공백/따옴표
   처리가 버전마다 달라 조용히 어긋난다.
3. **프로젝트 디렉터리는 샘플당 하나**: `.ghidra-projects/<sha256>/`.
   재분석은 `--reanalyze`(디렉터리 삭제 후 재생성)로만. 기존 프로젝트에 덮어쓰지 않는다.
4. **`-noanalysis` 금지.** 디컴파일 결과가 비어버린다.
5. **종료 코드 0을 믿지 않는다.** 끝나면 반드시:
   `rg -n 'ERROR|Script failed|OutOfMemory' artifacts/extract/<sha256>/ghidra.log`
   OOM은 로그에만 남고 종료 코드는 0이다.
6. 힙이 부족하면 큰 샘플에서 디컴파일러가 조용히 죽는다. `_JAVA_OPTIONS` 대신
   `$GHIDRA_HOME/support/launch.properties`의 `VMARGS`를 써도 되지만 **둘 중 하나만** 쓴다.

## 출력 — 경로와 스키마 고정

`artifacts/extract/<sha256>/functions.jsonl` — 함수당 한 줄, 주소 오름차순:

```json
{"address":"0x401000","name":"FUN_00401000","is_thunk":false,"is_external":false,
 "signature":"undefined4 FUN_00401000(void)","decompiled":"...","decompile_error":null,
 "callees":["0x401230"],"size":142,"cyclomatic":7}
```

`artifacts/extract/<sha256>/meta.json`:

```json
{"sha256":"...","ghidra_version":"11.x","extract_schema_version":1,
 "analyzed_at":"2026-01-01T00:00:00Z","duration_sec":91.2,"function_count":812,
 "decompile_failure_count":3,"warnings":[]}
```

- 디컴파일 실패는 `decompiled: null` + `decompile_error`로 **기록한다.** 레코드를 빼지 않는다.
- 필드 추가 시 `extract_schema_version`을 올리고 `/db-change`로 마이그레이션을 동반한다.
- 필드 삭제/의미 변경 금지. 새 필드를 추가하고 옛 필드는 남긴다.

## 최초 1회 (아직 안 했으면 이것부터)

`"$GHIDRA_HOME/support/analyzeHeadless" -help`로 이 버전이 실제로 받는 플래그를 확인하고,
작은 샘플로 한 번 완주시킨 뒤 위 "정규 명령"의 힙·`-max-cpu`·경로를 실측값으로 갱신한다.
검증 전에는 이 스킬의 명령을 확정된 것으로 취급하지 않는다.
