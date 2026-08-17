# scripts/ — Ghidra 인터프리터에서 도는 코드

여기 있는 파일은 **Ghidra의 Jython/PyGhidra 인터프리터**가 실행한다.
`analyzeHeadless -scriptPath scripts -postScript <name>.py` 로만 호출된다.

## 규칙

- **`src/loregrind/`를 임포트하지 않는다.** 프로젝트 의존성(uv가 설치한 패키지)을 쓸 수 없다.
  표준 라이브러리와 Ghidra API만 쓴다.
- **`src/`의 코드를 여기로 옮기지 않는다.** 두 세계가 한 디렉터리에 섞이면
  어느 인터프리터에서 도는지 헷갈려 임포트 에러가 반복된다.
- 두 세계의 유일한 접점은 **파일**이다 — 이 스크립트가 JSONL을 쓰고,
  `src/loregrind/extract/`가 그것을 읽어 DB에 적재한다. 함수 호출로 잇지 않는다.
- 인자는 config JSON 경로 **하나만** 받는다. 여러 인자를 넘기면 공백·따옴표 처리가
  Ghidra 버전마다 달라 조용히 어긋난다.

출력 경로와 스키마, 정규 `analyzeHeadless` 명령은 `/ghidra-extract` 스킬이 정한다.
