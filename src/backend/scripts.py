"""Inspect Python syntax as data. Never import, compile, eval or execute payloads."""

import ast
import base64
import binascii
import bz2
import io
import lzma
import re
import tokenize
import zlib
from backend.script_symbols import recover_symbols
from backend.deobfuscator import analyze_python_source
from backend.behaviors import correlate_capabilities

MAX_SOURCE = 2 * 1024 * 1024
MAX_NODES = 50000
MAX_LAYERS = 3
DECODERS = {"base64.b64decode", "base64.urlsafe_b64decode", "base64.b85decode",
            "base64.a85decode", "binascii.unhexlify", "bytes.fromhex",
            "zlib.decompress", "gzip.decompress", "bz2.decompress", "lzma.decompress"}


def _decompress(data, kind):
    if kind in {"zlib.decompress", "gzip.decompress"}:
        decoder = zlib.decompressobj(31 if kind == "gzip.decompress" else 15)
    elif kind == "bz2.decompress":
        decoder = bz2.BZ2Decompressor()
    else:
        decoder = lzma.LZMADecompressor(memlimit=64 * 1024 * 1024)
    value = decoder.decompress(data, max_length=MAX_SOURCE + 1)
    if len(value) > MAX_SOURCE or not decoder.eof:
        raise ValueError("Decompressed source exceeds limit or stream is incomplete")
    return value


def inspect_python(data, source, layer=0, budget=None):
    if budget is None:
        budget = {"bytes": 8 * 1024 * 1024, "layers": 12}
    result = {"source": source, "language": "python", "layer": layer,
              "status": "inspected", "findings": [], "decoded_layers": [], "limitations": []}
    if len(data) > MAX_SOURCE or len(data) > budget["bytes"] or budget["layers"] <= 0:
        result.update(status="limited", limitations=["Source or decoded-layer budget exceeded"])
        return result
    budget["bytes"] -= len(data)
    budget["layers"] -= 1
    result["deobfuscation"] = analyze_python_source(data)
    deobfuscation = result["deobfuscation"]
    result["limitations"].extend(
        "Static deobfuscation limit: " + name
        for name in deobfuscation["coverage"]["limits_hit"])
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        tree = ast.parse(data.decode(encoding))
        nodes = []
        for node in ast.walk(tree):
            nodes.append(node)
            if len(nodes) > MAX_NODES:
                raise ValueError("Python syntax exceeds 50000-node limit")
    except (SyntaxError, ValueError, UnicodeError, LookupError, RecursionError) as error:
        result.update(status="limited", limitations=[f"Source could not be parsed: {type(error).__name__}"])
        return result

    try:
        aliases, recovered_symbols, resolved_names, resolved_literals, symbol_limits = recover_symbols(tree, detailed=True)
    except (ValueError, TypeError, RecursionError, OverflowError):
        result.update(status="limited", limitations=["Bounded symbol recovery could not complete"])
        return result
    result["limitations"].extend(symbol_limits)
    assignments = {}
    for node in nodes:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments.setdefault(target.id, []).append(node.value)

    def name(node):
        if id(node) in resolved_names:
            return resolved_names[id(node)]
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{name(node.value)}.{node.attr}"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "__import__" and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            return node.args[0].value
        return "<expression>"

    def resolve(node, depth=0):
        if depth > 12:
            raise ValueError("Expression depth limit")
        if id(node) in resolved_literals and not isinstance(node, (ast.Constant, ast.Name)):
            return resolved_literals[id(node)], ["bounded_literal_transformation"]
        if isinstance(node, ast.Name) and id(node) in resolved_literals:
            return resolved_literals[id(node)], []
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            value, chain = node.value, []
        elif isinstance(node, ast.Name) and len(assignments.get(node.id, [])) == 1:
            return resolve(assignments[node.id][0], depth + 1)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, lc = resolve(node.left, depth + 1)
            right, rc = resolve(node.right, depth + 1)
            value, chain = left + right, lc + rc
        elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice) and node.slice.lower is None and node.slice.upper is None and isinstance(node.slice.step, ast.UnaryOp) and isinstance(node.slice.step.op, ast.USub) and isinstance(node.slice.step.operand, ast.Constant) and node.slice.step.operand.value == 1:
            value, chain = resolve(node.value, depth + 1)
            value, chain = value[::-1], chain + ["reverse"]
        elif isinstance(node, ast.Call) and node.args and name(node.func) in DECODERS and not node.keywords and len(node.args) == 1:
            value, chain = resolve(node.args[0], depth + 1)
            method = name(node.func)
            if method.endswith(".decompress"):
                value = _decompress(value, method)
            elif method == "bytes.fromhex":
                value = bytes.fromhex(value)
            else:
                decoders = {"base64.b64decode": base64.b64decode, "base64.urlsafe_b64decode": base64.urlsafe_b64decode,
                            "base64.b85decode": base64.b85decode, "base64.a85decode": base64.a85decode,
                            "binascii.unhexlify": binascii.unhexlify}
                value = decoders[method](value)
            chain = chain + [method]
        else:
            raise ValueError("Expression is not a supported literal transformation")
        if len(value) > MAX_SOURCE:
            raise ValueError("Decoded literal exceeds limit")
        return value, chain

    calls = [node for node in nodes if isinstance(node, ast.Call)]
    call_names = sorted({name(node.func) for node in calls}
                        | set(deobfuscation["resolved_calls"]))
    result["calls"] = call_names[:100]
    result["call_count"] = len(calls)
    result["imports"] = sorted(set(aliases.values())
                               | {item["name"] for item in deobfuscation["imports"]})[:80]
    result["recovered_symbols"] = recovered_symbols
    literals = [node.value for node in nodes if isinstance(node, ast.Constant) and isinstance(node.value, str)]
    recovered_text = sorted({value for value in resolved_literals.values() if isinstance(value, str)})
    literals.extend(recovered_text)
    literals.extend(item["value"] for item in deobfuscation["decoded_strings"]
                    if not item["truncated"])
    result["recovered_literals"] = [value[:500] for value in recovered_text[:80]]
    result["literal_recovery_limits"] = {"text_bytes": 8192, "operations": 200000, "scope": "Lexical blocks with conservative invalidation; no arbitrary function evaluation"}

    def finding(identifier, family, strength, reason, evidence):
        result["findings"].append({"id": identifier, "family": family, "strength": strength,
                                   "reason": reason, "evidence": {"source": source, "layer": layer, **evidence}})

    resolved_import_sites = {(site["line"], site["column"])
                             for site in deobfuscation["resolved_import_sites"]}
    dynamic_imports = [node.lineno for node in calls
                       if name(node.func).removeprefix("builtins.") == "__import__"
                       and node.args and not isinstance(resolved_literals.get(id(node.args[0])), str)
                       and (node.lineno, node.col_offset) not in resolved_import_sites]
    result["unresolved_dynamic_imports"] = dynamic_imports[:80]
    if dynamic_imports:
        finding("obfuscated_runtime_resolution", "packing", "weak",
                "Encoded built-in lookup combines with dynamically constructed module imports",
                {"recovered_symbols": recovered_symbols, "dynamic_import_lines": dynamic_imports[:20],
                 "limitation": "Indicates concealed capabilities, not a specific malicious behavior; code protectors can match."})
        result["limitations"].append("Some dynamic module names could not be resolved by bounded constant propagation")

    for node in calls:
        if name(node.func) not in {"exec", "eval", "builtins.exec", "builtins.eval"} or not node.args:
            continue
        try:
            value, chain = resolve(node.args[0])
            if chain:
                finding("encoded_script_execution", "execution", "strong",
                        "A literal decoding chain feeds a Python execution call",
                        {"line": node.lineno, "sink": name(node.func), "transformations": chain,
                         "limitation": "Obfuscation can protect legitimate code; this is not proof of malware."})
            if layer < MAX_LAYERS and len(result["decoded_layers"]) < 4:
                value = value.encode() if isinstance(value, str) else value
                result["decoded_layers"].append(inspect_python(value, source + f"::decoded@{node.lineno}", layer + 1, budget))
            else:
                result["limitations"].append("Decoded execution layer limit reached")
        except (ValueError, TypeError, binascii.Error, zlib.error, lzma.LZMAError, OSError, RecursionError):
            # A decoder reaching a sink is evidence even when its data cannot be
            # resolved. Mere coexistence of exec and a decoder is not enough.
            def transforms(expr, seen=None):
                seen = set() if seen is None else seen
                if len(seen) > 12:
                    return set()
                found = set()
                for item in ast.walk(expr):
                    if isinstance(item, ast.Call):
                        method = name(item.func)
                        if method in DECODERS or method.endswith(".decrypt") or method == "marshal.loads":
                            found.add(method)
                    if isinstance(item, ast.Name) and item.id not in seen and len(assignments.get(item.id, [])) == 1:
                        seen.add(item.id)
                        found.update(transforms(assignments[item.id][0], seen))
                return found
            methods = transforms(node.args[0])
            if methods:
                finding("encoded_script_execution", "execution", "strong",
                        "Decoded/decrypted content feeds a Python execution call",
                        {"line": node.lineno, "sink": name(node.func), "transformations": sorted(methods),
                         "limitation": "Static assignment references do not prove reachability; content could not be fully recovered."})
            elif isinstance(node.func, ast.Name) and node.func.id not in {"exec", "eval"} and any(r["alias"] == node.func.id and r.get("encoded_name") and r["symbol"] in {"builtins.exec", "builtins.eval"} for r in recovered_symbols):
                finding("concealed_script_execution", "execution", "moderate",
                        "An indirectly recovered built-in execution function consumes dynamically constructed code",
                        {"line": node.lineno, "alias": node.func.id, "resolved_sink": name(node.func),
                         "limitation": "Obfuscated execution is suspicious but can also be used by legitimate code protection; the executed contents remain unresolved."})
            result["limitations"].append(f"Dynamic execution input at line {node.lineno} could not be resolved statically")

    # Feed recovered names and literals into the same semantic engine used for PE imports.
    # Facts stay in one source member/layer; never union unrelated archive libraries.
    joined = "\n".join(text[:4096] for text in literals if len(text) < 8192).lower()
    names = set(call_names)
    def calls_matching(*terms):
        return sorted(n for n in names if n in terms)
    browser_profile = re.findall(r"(?:google[\\/]chrome[\\/]user data|mozilla[\\/]firefox[\\/]profiles|microsoft[\\/]edge[\\/]user data)", joined)
    storage = [term for term in ("login data", "logins.json", "key4.db", "local state", "cookies") if term in joined]
    query = "select" in joined and any(term in joined for term in ("password_value", "encrypted_value", "logins", "cookies"))
    database = calls_matching("sqlite3.connect", "sqlite3.dbapi2.connect")
    decrypt = sorted(n for n in names if n.endswith((".CryptUnprotectData", ".decrypt", ".decrypt_and_verify")))
    writes = calls_matching("pathlib.Path.write_bytes", "shutil.copy", "shutil.copy2", "urllib.request.urlretrieve")
    for call in calls:
        if name(call.func) in {"open", "builtins.open"}:
            mode_node = call.args[1] if len(call.args) > 1 else next((kw.value for kw in call.keywords if kw.arg == "mode"), None)
            mode = resolved_literals.get(id(mode_node), "r") if mode_node is not None else "r"
            if isinstance(mode, str) and any(flag in mode for flag in "wax+"):
                writes.append(f"open(mode={mode})")
    execute = calls_matching("subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output", "os.system", "os.startfile")
    facts = {
        "browser_profile": browser_profile, "credential_storage": storage,
        "file_read": database if query else calls_matching("pathlib.Path.read_bytes", "json.load"),
        "decrypt": decrypt,
        "network_send": calls_matching("requests.post", "httpx.post", "socket.send", "socket.sendall"),
        "network_retrieve": calls_matching("requests.get", "httpx.get", "urllib.request.urlopen", "urllib.request.urlretrieve"),
        "file_write": writes, "process_execute": execute,
        "registry_write": calls_matching("winreg.SetValueEx", "winreg.SetValue"),
        "autorun": re.findall(r"software[\\/]microsoft[\\/]windows[\\/]currentversion[\\/](?:runonce|run)\b", joined),
        "startup": ["Startup folder"] if "start menu" in joined and "startup" in joined else [],
        "scheduled_task": re.findall(r"schtasks[^\n]{0,300}/create[^\n]{0,300}/tr", joined),
        "suspicious_shell": re.findall(r"powershell[^\n]{0,200}-(?:enc|encodedcommand|windowstyle\s+hidden)\b", joined),
    }
    # Native APIs reached via ctypes retain exact API suffixes as source-local facts.
    for capability, suffixes in {
        "process_access": (".OpenProcess", ".NtOpenProcess"),
        "remote_allocate": (".VirtualAllocEx", ".NtAllocateVirtualMemory"),
        "remote_write": (".WriteProcessMemory", ".NtWriteVirtualMemory"),
        "remote_execute": (".CreateRemoteThread", ".NtCreateThreadEx", ".QueueUserAPC"),
    }.items():
        facts[capability] = sorted(n for n in names if n.endswith(suffixes))
    result["capabilities"] = {key: value for key, value in facts.items() if value}
    result["findings"].extend(correlate_capabilities(facts, source + f"::layer{layer}"))
    if result["limitations"] or any(child["status"] != "inspected" for child in result["decoded_layers"]):
        result["status"] = "limited"
    return result
