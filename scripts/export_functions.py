# Loregrind L1 추출 — Ghidra 인터프리터에서 도는 스크립트
#
# 호출:
#   analyzeHeadless <proj> loregrind -import <bin> \
#     -scriptPath scripts -postScript export_functions.py <config.json>
#
# 제약 (scripts/README.md):
#   - src/loregrind/ 를 임포트하지 않는다. 프로젝트 의존성을 쓸 수 없다
#   - 표준 라이브러리 + Ghidra API 만 쓴다
#   - Jython 2.7 과 Python 3 양쪽에서 도는 문법만 쓴다 (f-string 금지)
#   - 인자는 config JSON 경로 하나만 받는다
#
# 출력 (경로·스키마는 /ghidra-extract 가 고정한다):
#   <out_dir>/functions.jsonl  함수당 한 줄, 주소 오름차순
#   <out_dir>/meta.json
#
# 디컴파일 실패는 레코드를 빼지 않고 decompiled=null + decompile_error 로 남긴다.
# 빼면 "실패한 함수"와 "존재하지 않는 함수"가 구분되지 않고 실패율을 측정할 수 없다.

import io
import json
import os
import time

from ghidra.app.decompiler import DecompInterface, DecompileOptions

EXTRACT_SCHEMA_VERSION = 1
DECOMPILE_TIMEOUT_SEC = 60


def read_config():
    args = getScriptArgs()  # noqa: F821 - Ghidra 가 주입한다
    if len(args) != 1:
        raise ValueError("config JSON 경로 하나만 받는다. 받은 인자 수: %d" % len(args))
    fh = io.open(args[0], "r", encoding="utf-8")
    try:
        return json.loads(fh.read())
    finally:
        fh.close()


def make_decompiler(program):
    iface = DecompInterface()
    iface.setOptions(DecompileOptions())
    iface.openProgram(program)
    return iface


def cyclomatic_complexity(function, monitor):
    """복잡도. 실패하면 None — 이것 때문에 추출 전체를 세우지 않는다."""
    try:
        from ghidra.program.util import CyclomaticComplexity

        return int(CyclomaticComplexity().calculateCyclomaticComplexity(function, monitor))
    except Exception:
        return None


def decompile(iface, function, monitor):
    """(decompiled_text, error) 를 돌려준다. 둘 중 하나는 항상 None 이다."""
    try:
        result = iface.decompileFunction(function, DECOMPILE_TIMEOUT_SEC, monitor)
    except Exception as exc:
        return None, "decompile raised: %s" % exc

    if result is None:
        return None, "decompileFunction returned null"
    if not result.decompileCompleted():
        msg = result.getErrorMessage() or "decompile did not complete"
        return None, msg
    high = result.getDecompiledFunction()
    if high is None:
        return None, "getDecompiledFunction returned null"
    text = high.getC()
    if text is None:
        return None, "getC returned null"
    return text, None


def callee_addresses(function, monitor):
    out = []
    try:
        for callee in function.getCalledFunctions(monitor):
            out.append("0x%s" % callee.getEntryPoint().toString())
    except Exception:
        # 콜 그래프를 못 얻어도 함수 레코드 자체는 남긴다
        return []
    return sorted(set(out))


def function_record(function, iface, monitor):
    entry = function.getEntryPoint()
    text, error = decompile(iface, function, monitor)
    body = function.getBody()
    return {
        "address": "0x%s" % entry.toString(),
        "name": function.getName(),
        "is_thunk": bool(function.isThunk()),
        "is_external": bool(function.isExternal()),
        "signature": function.getPrototypeString(True, False),
        "decompiled": text,
        "decompile_error": error,
        "callees": callee_addresses(function, monitor),
        "size": int(body.getNumAddresses()) if body is not None else None,
        "cyclomatic": cyclomatic_complexity(function, monitor),
    }


def main():
    config = read_config()
    out_dir = config["out_dir"]
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    program = getCurrentProgram()  # noqa: F821 - Ghidra 가 주입한다
    monitor_ = monitor  # noqa: F821 - Ghidra 가 주입한다
    started = time.time()

    iface = make_decompiler(program)
    warnings = []
    failures = 0
    count = 0

    # 주소 오름차순으로 순회한다 (getFunctions(True)). 출력 순서를 고정해야
    # 두 번 돌린 결과를 그대로 비교할 수 있다
    functions = program.getFunctionManager().getFunctions(True)

    jsonl_path = os.path.join(out_dir, "functions.jsonl")
    out = io.open(jsonl_path, "w", encoding="utf-8")
    try:
        for function in functions:
            if monitor_.isCancelled():
                warnings.append("cancelled by monitor after %d functions" % count)
                break
            record = function_record(function, iface, monitor_)
            if record["decompile_error"]:
                failures += 1
            out.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
            out.write(u"\n")
            count += 1
    finally:
        out.close()
        iface.dispose()

    meta = {
        "sha256": config["sha256"],
        "ghidra_version": str(getGhidraVersion()),  # noqa: F821 - Ghidra 가 주입한다
        "extract_schema_version": EXTRACT_SCHEMA_VERSION,
        "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_sec": round(time.time() - started, 1),
        "function_count": count,
        "decompile_failure_count": failures,
        "warnings": warnings,
    }
    meta_fh = io.open(os.path.join(out_dir, "meta.json"), "w", encoding="utf-8")
    try:
        meta_fh.write(json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True))
    finally:
        meta_fh.close()

    print("[loregrind] %d functions, %d decompile failures -> %s" % (count, failures, out_dir))


main()
