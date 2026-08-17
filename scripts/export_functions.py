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
#   <out_dir>/strings.jsonl    문자열당 한 줄, 주소 오름차순   (schema v2)
#   <out_dir>/imports.jsonl    임포트당 한 줄, 모듈·이름 순     (schema v2)
#   <out_dir>/meta.json
#
# 디컴파일 실패는 레코드를 빼지 않고 decompiled=null + decompile_error 로 남긴다.
# 빼면 "실패한 함수"와 "존재하지 않는 함수"가 구분되지 않고 실패율을 측정할 수 없다.
#
# 문자열·임포트를 함수와 **같은 패스에서** 뽑는 이유: analyzeHeadless 를 두 번 돌리면
# 대형 바이너리에서 분석 시간이 두 배가 된다. -postScript 를 여러 개 거는 것도
# 같은 프로그램을 다시 여는 비용이 있다.

import io
import json
import os
import time

from ghidra.app.decompiler import DecompInterface, DecompileOptions

EXTRACT_SCHEMA_VERSION = 2
DECOMPILE_TIMEOUT_SEC = 60

# 문자열 하나가 이보다 길면 자른다. 자른 사실은 truncated 로 남긴다 —
# 조용히 자르면 적재 후에 손실 여부를 알 방법이 없다
MAX_STRING_CHARS = 4096


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


def containing_function_addr(program, address):
    """참조가 어느 함수 안에서 났는지. 함수 밖이면 None."""
    try:
        function = program.getFunctionManager().getFunctionContaining(address)
    except Exception:
        return None
    if function is None:
        return None
    return "0x%s" % function.getEntryPoint().toString()


def string_encoding(data):
    """'ascii' | 'utf16le' | 'other'. 정확한 판정이 아니라 분류다."""
    try:
        name = data.getDataType().getName().lower()
    except Exception:
        return "other"
    if "unicode" in name or "utf16" in name or "wchar" in name:
        return "utf16le"
    if "string" in name or "char" in name:
        return "ascii"
    return "other"


def string_records(program, monitor_):
    """정의된 문자열 데이터와 그 참조 함수를 뽑는다.

    참조가 하나도 없는 문자열도 남긴다 — 참조를 못 찾은 것과 참조가 없는 것을
    적재 단계에서 구별할 수 없으므로, 여기서 버리면 정보가 사라진다.
    """
    out = []
    warnings = []
    listing = program.getListing()
    ref_manager = program.getReferenceManager()

    for data in listing.getDefinedData(True):
        if monitor_.isCancelled():
            warnings.append("string extraction cancelled after %d strings" % len(out))
            break
        try:
            if not data.hasStringValue():
                continue
            value = data.getValue()
            if value is None:
                continue
            value = unicode(value)  # noqa: F821 - Jython 2.7. Py3 에서는 아래 except 로 간다
        except NameError:
            value = str(data.getValue())
        except Exception:
            continue

        length = len(value)
        truncated = length > MAX_STRING_CHARS
        addr = data.getAddress()

        referenced_by = []
        try:
            for ref in ref_manager.getReferencesTo(addr):
                caller = containing_function_addr(program, ref.getFromAddress())
                if caller is not None:
                    referenced_by.append(caller)
        except Exception:
            warnings.append("xref lookup failed at 0x%s" % addr.toString())

        out.append(
            {
                "address": "0x%s" % addr.toString(),
                "value": value[:MAX_STRING_CHARS],
                "encoding": string_encoding(data),
                "length": length,
                "truncated": truncated,
                "referenced_by": sorted(set(referenced_by)),
            }
        )
    return out, warnings


def import_records(program, monitor_):
    """임포트와 호출 지점. 반환은 (records, warnings).

    module 은 소문자로 정규화한다. KERNEL32.dll 과 kernel32.dll 이 갈라지면
    API 집합 채널의 교집합이 조용히 비어간다.
    """
    out = []
    warnings = []
    symbol_table = program.getSymbolTable()
    ref_manager = program.getReferenceManager()

    try:
        symbols = list(symbol_table.getExternalSymbols())
    except Exception as exc:
        return [], ["getExternalSymbols failed: %s" % exc]

    for symbol in symbols:
        if monitor_.isCancelled():
            warnings.append("import extraction cancelled after %d imports" % len(out))
            break
        try:
            namespace = symbol.getParentNamespace()
            module = namespace.getName() if namespace is not None else "<unknown>"
            api_name = symbol.getName()
            addr = symbol.getAddress()
        except Exception as exc:
            warnings.append("import symbol read failed: %s" % exc)
            continue

        calls = []
        try:
            for ref in ref_manager.getReferencesTo(addr):
                caller = containing_function_addr(program, ref.getFromAddress())
                if caller is not None:
                    calls.append(
                        {
                            "function_addr": caller,
                            "call_addr": "0x%s" % ref.getFromAddress().toString(),
                        }
                    )
        except Exception:
            warnings.append("call-site lookup failed for %s" % api_name)

        out.append(
            {
                "module": module.lower(),
                "api_name": api_name,
                "iat_addr": "0x%s" % addr.toString() if addr is not None else None,
                "ordinal": None,
                "calls": calls,
            }
        )

    out.sort(key=lambda r: (r["module"], r["api_name"]))
    return out, warnings


def write_jsonl(path, records):
    fh = io.open(path, "w", encoding="utf-8")
    try:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
            fh.write(u"\n")
    finally:
        fh.close()


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

    strings, string_warnings = string_records(program, monitor_)
    warnings.extend(string_warnings)
    write_jsonl(os.path.join(out_dir, "strings.jsonl"), strings)

    imports, import_warnings = import_records(program, monitor_)
    warnings.extend(import_warnings)
    write_jsonl(os.path.join(out_dir, "imports.jsonl"), imports)

    api_call_count = 0
    for record in imports:
        api_call_count += len(record["calls"])

    meta = {
        "sha256": config["sha256"],
        "ghidra_version": str(getGhidraVersion()),  # noqa: F821 - Ghidra 가 주입한다
        "extract_schema_version": EXTRACT_SCHEMA_VERSION,
        "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_sec": round(time.time() - started, 1),
        "function_count": count,
        "decompile_failure_count": failures,
        "string_count": len(strings),
        "import_count": len(imports),
        "api_call_count": api_call_count,
        "warnings": warnings,
    }
    meta_fh = io.open(os.path.join(out_dir, "meta.json"), "w", encoding="utf-8")
    try:
        meta_fh.write(json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True))
    finally:
        meta_fh.close()

    print(
        "[loregrind] %d functions (%d decompile failures), %d strings, "
        "%d imports, %d api calls -> %s"
        % (count, failures, len(strings), len(imports), api_call_count, out_dir)
    )


main()
