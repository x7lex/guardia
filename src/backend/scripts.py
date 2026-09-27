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

    aliases, recovered_symbols = recover_symbols(tree)
    assignments = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments.setdefault(target.id, []).append(node.value)

    def name(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{name(node.value)}.{node.attr}"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "__import__" and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            return node.args[0].value
        return "<expression>"

    def resolve(node, depth=0):
        if depth > 12:
            raise ValueError("Expression depth limit")
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
    call_names = sorted({name(node.func) for node in calls})
    result["calls"] = call_names[:100]
    result["call_count"] = len(calls)
    result["imports"] = sorted(set(aliases.values()))[:80]
    result["recovered_symbols"] = recovered_symbols
    literals = [node.value for node in nodes if isinstance(node, ast.Constant) and isinstance(node.value, str)]

    def finding(identifier, family, strength, reason, evidence):
        result["findings"].append({"id": identifier, "family": family, "strength": strength,
                                   "reason": reason, "evidence": {"source": source, "layer": layer, **evidence}})

    recovered = {item["symbol"] for item in recovered_symbols if item.get("encoded_name")}
    dynamic_imports = [node.lineno for node in calls
                       if name(node.func).removeprefix("builtins.") == "__import__"
                       and node.args and not isinstance(node.args[0], ast.Constant)]
    if {"builtins.__dict__", "builtins.__import__"} <= recovered and dynamic_imports:
        finding("obfuscated_runtime_resolution", "packing", "weak",
                "Encoded built-in lookup combines with dynamically constructed module imports",
                {"recovered_symbols": recovered_symbols, "dynamic_import_lines": dynamic_imports[:20],
                 "limitation": "Indicates concealed capabilities, not a specific malicious behavior; code protectors can match."})
        result["limitations"].append("Encoded runtime bindings and dynamic module names prevent complete capability recovery")

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

    # Scope patterns to a single source member. Do not combine capabilities from
    # unrelated runtime libraries into an artificial behavior chain.
    joined = "\n".join(s[:4096] for s in literals if len(s) < 8192).lower()
    names = set(call_names)
    browsers = [term for term in ("login data", "logins.json", "local state", "cookies") if term in joined]
    query = "select" in joined and any(term in joined for term in ("password_value", "encrypted_value", "logins", "cookies"))
    database = any(n in {"sqlite3.connect", "sqlite3.dbapi2.connect"} for n in names)
    decrypt = any(n.endswith((".CryptUnprotectData", ".decrypt", ".decrypt_and_verify")) for n in names)
    if browsers and query and database and decrypt:
        finding("script_browser_credentials", "credentials", "strong",
                "Script queries browser credential records and decrypts stored values",
                {"storage": browsers, "calls": sorted(n for n in names if n.endswith((".connect", ".decrypt", ".CryptUnprotectData", ".decrypt_and_verify")))})
    outbound = sorted(n for n in names if n in {"requests.post", "httpx.post", "urllib.request.urlopen"})
    webhook = bool(re.search(r"https?://(?:[^/]+/api/webhooks/|api\.telegram\.org/bot)", joined))
    if outbound and webhook and browsers and query and database:
        finding("credential_exfiltration", "exfiltration", "strong",
                "Browser credential queries coexist with outbound POST and webhook/bot destination",
                {"calls": outbound, "storage": browsers, "limitation": "Static co-occurrence within the same script, not observed transfer."})
    if result["limitations"] or any(child["status"] != "inspected" for child in result["decoded_layers"]):
        result["status"] = "limited"
    return result
