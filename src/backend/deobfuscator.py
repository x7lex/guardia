"""Bounded Python constant recovery. Target calls are syntax, never executable code.

Symbols represent semantic relationships, not imported modules or live functions.
Only literal values and explicitly implemented pure operations can be folded.
"""

import ast
import base64
import binascii
import operator
import re
from dataclasses import dataclass

MAX_SOURCE = 1_000_000
MAX_NODES = 50_000
MAX_RECURSION_DEPTH = 24
MAX_OPERATIONS = 50_000
MAX_COLLECTION_ITEMS = 2_000
MAX_STRING_LENGTH = 64_000
MAX_DECODED_BYTES = 4_000_000
MAX_FACTS = 200
MAX_EXAMPLE = 500
MAX_INTEGER_BITS = 128
UNKNOWN = object()


@dataclass(frozen=True)
class Symbol:
    name: str


class LimitReached(ValueError):
    pass


class Recovery:
    def __init__(self):
        self.result = {
            "supported": True,
            "language": "python",
            "decoded_strings": [],
            "imports": [],
            "resolved_attributes": [],
            "resolved_calls": [],
            "resolved_import_sites": [],
            "behavior_hints": {
                key: []
                for key in (
                    "process_execution",
                    "networking",
                    "filesystem",
                    "browser_data",
                    "credential_access",
                    "persistence",
                    "shell",
                    "crypto",
                )
            },
            "transformations": [],
            "obfuscation": {
                "dynamic_import_resolution": False,
                "dynamic_attribute_resolution": False,
                "encoded_strings": False,
                "multiple_decode_layers": False,
            },
            "coverage": {
                "ast_parsed": False,
                "expressions_examined": 0,
                "expressions_resolved": 0,
                "expressions_unresolved": 0,
                "resolution_ratio": 0.0,
                "limits_hit": [],
            },
            "diagnostics": [],
        }
        self.operations = 0
        self.value_bytes = 0
        self.seen_strings = {}
        self.decode_nodes = set()
        # Known external names may appear in recovered fragments without imports.
        self.env = {
            name: Symbol(name)
            for name in (
                "chr",
                "ord",
                "bytes",
                "bytearray",
                "reversed",
                "map",
                "getattr",
                "__import__",
                "globals",
                "locals",
                "builtins",
                "base64",
            )
        }
        self.env["__builtins__"] = Symbol("builtins")

    def limit(self, name):
        if name not in self.result["coverage"]["limits_hit"]:
            self.result["coverage"]["limits_hit"].append(name)
        raise LimitReached(name)

    def tick(self):
        self.operations += 1
        if self.operations > MAX_OPERATIONS:
            self.limit("operations")

    def append(self, key, value):
        entries = self.result[key]
        if value not in entries:
            if len(entries) >= MAX_FACTS:
                self.limit("report_facts")
            entries.append(value)

    def size(self, length, collection=False):
        if length > (MAX_COLLECTION_ITEMS if collection else MAX_STRING_LENGTH):
            self.limit("collection_items" if collection else "string_length")

    def checked(self, value):
        if isinstance(value, Symbol) and len(value.name) > MAX_EXAMPLE:
            self.limit("symbol_length")
        if type(value) is int and value.bit_length() > MAX_INTEGER_BITS:
            self.limit("integer_bits")
        if isinstance(value, (str, bytes)):
            self.size(len(value))
            self.value_bytes += len(value) * (4 if isinstance(value, str) else 1)
            if self.value_bytes > MAX_DECODED_BYTES:
                self.limit("decoded_bytes")
        elif isinstance(value, (list, tuple, set, dict)):
            self.size(len(value), True)
        return value

    def text(self, value, category=None):
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8")
            except UnicodeError:
                return
        if not isinstance(value, str) or not value:
            return
        if value in self.seen_strings:
            categories = self.seen_strings[value]["categories"]
            if category and category not in categories:
                if categories == ["general_strings"]:
                    categories.clear()
                categories.append(category)
            return
        if len(self.seen_strings) >= MAX_FACTS:
            self.limit("report_facts")
        lower = value.lower()
        categories = []
        if category:
            categories.append(category)
        if any(term in lower for term in ("powershell", "cmd.exe", "schtasks")):
            categories.append("commands")
        if "currentversion\\" in lower or lower.startswith(
            ("hkey_", "hklm\\", "hkcu\\")
        ):
            categories.append("registry_paths")
        if re.search(r"https?://", lower):
            categories.append("URLs")
        if re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,24}", lower):
            categories.append("domains")
        if "\\" in value or "/" in value or "appdata" in lower:
            categories.append("paths")
        if re.search(r"\.(?:exe|dll|py|ps1|bat|db)$", lower):
            categories.append("file_extensions")
        hints = self.result["behavior_hints"]
        for family, terms in {
            "process_execution": ("subprocess", "popen", "os.system", "schtasks"),
            "networking": (
                "requests",
                "socket",
                "http://",
                "https://",
                "urllib",
                "httpx",
            ),
            "filesystem": ("appdata", "pathlib", "shutil"),
            "browser_data": (
                "login data",
                "cookies",
                "local state",
                "chrome",
                "firefox",
                "edge",
                "discord",
            ),
            "credential_access": (
                "cryptunprotectdata",
                "password_value",
                "logins.json",
                "key4.db",
            ),
            "persistence": ("currentversion\\run", "schtasks", "startup"),
            "shell": ("powershell", "cmd.exe", "/bin/sh"),
            "crypto": ("cryptography", "crypto.", "decrypt"),
        }.items():
            if any(term in lower for term in terms):
                hints[family].append(value[:MAX_EXAMPLE])
                if family in {"shell", "browser_data", "persistence"}:
                    categories.append(
                        {
                            "shell": "shell_references",
                            "browser_data": "browser_artifacts",
                            "persistence": "persistence_references",
                        }[family]
                    )
        entry = {
            "value": value[:MAX_EXAMPLE],
            "categories": categories or ["general_strings"],
            "truncated": len(value) > MAX_EXAMPLE,
        }
        self.append("decoded_strings", entry)
        self.seen_strings[value] = entry

    def expression(self, node, env, depth=0):
        self.tick()
        coverage = self.result["coverage"]
        coverage["expressions_examined"] += 1
        value = UNKNOWN
        try:
            if depth > MAX_RECURSION_DEPTH:
                self.limit("expression_depth")
            value = self.checked(self.fold(node, env, depth))
            if value is not UNKNOWN:
                self.text(value)
                if isinstance(value, (str, bytes)) and not isinstance(
                    node, (ast.Constant, ast.Name)
                ):
                    kind = type(node).__name__
                    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                        kind = "string_concat"
                    elif isinstance(node, ast.Subscript):
                        kind = "slice"
                    elif isinstance(node, ast.Call):
                        kind = "static_call"
                    self.append(
                        "transformations",
                        {
                            "type": kind,
                            "line": getattr(node, "lineno", None),
                            "result": str(value)[:MAX_EXAMPLE],
                        },
                    )
        except (
            ValueError,
            TypeError,
            IndexError,
            KeyError,
            UnicodeError,
            OverflowError,
            ZeroDivisionError,
            binascii.Error,
        ):
            value = UNKNOWN
        if value is UNKNOWN:
            coverage["expressions_unresolved"] += 1
        else:
            coverage["expressions_resolved"] += 1
        return value

    @staticmethod
    def scalar(value):
        # Flat containers avoid exponential nested equality/hashing/representation.
        return type(value) in (str, bytes, int, bool, type(None))

    def fold(self, node, env, depth):
        def read(child):
            return self.expression(child, env, depth + 1)

        if isinstance(node, ast.Constant):
            return (
                node.value
                if type(node.value) in (str, bytes, int, bool, type(None))
                else UNKNOWN
            )
        if isinstance(node, ast.Name):
            return env.get(node.id, UNKNOWN)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            self.size(len(node.elts), True)
            values = [read(item) for item in node.elts]
            if any(not self.scalar(v) for v in values):
                return UNKNOWN
            return (
                tuple(values)
                if isinstance(node, ast.Tuple)
                else set(values)
                if isinstance(node, ast.Set)
                else values
            )
        if isinstance(node, ast.Dict):
            self.size(len(node.keys), True)
            pairs = [
                (read(k), read(v))
                for k, v in zip(node.keys, node.values)
                if k is not None
            ]
            if len(pairs) != len(node.keys) or any(
                not self.scalar(k) or not self.scalar(v) for k, v in pairs
            ):
                return UNKNOWN
            return dict(pairs)
        if isinstance(node, ast.UnaryOp):
            value = read(node.operand)
            ops = {
                ast.USub: operator.neg,
                ast.UAdd: operator.pos,
                ast.Invert: operator.invert,
            }
            if type(value) is int and type(node.op) in ops:
                return ops[type(node.op)](value)
        if isinstance(node, ast.BinOp):
            left, right = read(node.left), read(node.right)
            if (
                isinstance(node.op, ast.Add)
                and type(left) is type(right)
                and isinstance(left, (str, bytes, list, tuple))
            ):
                self.size(len(left) + len(right), isinstance(left, (list, tuple)))
                return left + right
            if isinstance(node.op, ast.Mult):
                if type(left) is int and isinstance(right, (str, bytes, list, tuple)):
                    left, right = right, left
                if isinstance(left, (str, bytes, list, tuple)) and type(right) is int:
                    self.size(
                        len(left) * max(0, right), isinstance(left, (list, tuple))
                    )
                    return left * max(0, right)
            ops = {
                ast.Add: operator.add,
                ast.Sub: operator.sub,
                ast.Mult: operator.mul,
                ast.BitXor: operator.xor,
                ast.BitAnd: operator.and_,
                ast.BitOr: operator.or_,
                ast.FloorDiv: operator.floordiv,
                ast.Mod: operator.mod,
                ast.LShift: operator.lshift,
                ast.RShift: operator.rshift,
            }
            if type(left) is int and type(right) is int and type(node.op) in ops:
                if (
                    isinstance(node.op, (ast.LShift, ast.RShift))
                    and not 0 <= right <= MAX_INTEGER_BITS
                ):
                    self.limit("integer_bits")
                return ops[type(node.op)](left, right)
        if isinstance(node, ast.Slice):
            bounds = [
                read(n) if n is not None else None
                for n in (node.lower, node.upper, node.step)
            ]
            if all(v is None or type(v) is int for v in bounds) and bounds[2] != 0:
                return slice(*bounds)
        if isinstance(node, ast.Subscript):
            obj, key = read(node.value), read(node.slice)
            if isinstance(obj, Symbol) and isinstance(key, str):
                if obj.name in {"builtins", "builtins.__dict__"}:
                    return Symbol("builtins." + key)
                if obj.name == "<namespace>" and key == "__builtins__":
                    return Symbol("builtins")
            if isinstance(obj, (str, bytes, list, tuple, dict)) and key is not UNKNOWN:
                return obj[key]
        if isinstance(node, ast.JoinedStr):
            parts = []
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    value = read(part.value)
                    # No format mini-language or custom conversion machinery.
                    if (
                        type(value) not in (str, int, bool)
                        or part.format_spec is not None
                        or part.conversion != -1
                    ):
                        return UNKNOWN
                    parts.append(str(value))
                else:
                    value = read(part)
                    if not isinstance(value, str):
                        return UNKNOWN
                    parts.append(value)
            self.size(sum(map(len, parts)))
            return "".join(parts)
        if (
            isinstance(node, (ast.ListComp, ast.GeneratorExp))
            and len(node.generators) == 1
        ):
            generator = node.generators[0]
            if (
                generator.ifs
                or generator.is_async
                or not isinstance(generator.target, ast.Name)
            ):
                return UNKNOWN
            items = read(generator.iter)
            if not isinstance(items, (list, tuple, str, bytes)):
                return UNKNOWN
            self.size(len(items), True)
            local = env.copy()
            values = []
            for item in items:
                self.tick()
                local[generator.target.id] = item
                value = self.expression(node.elt, local, depth + 1)
                if not self.scalar(value):
                    return UNKNOWN
                values.append(value)
            return values
        if isinstance(node, ast.Attribute):
            obj = read(node.value)
            if isinstance(obj, Symbol):
                return Symbol(obj.name + "." + node.attr)
        if isinstance(node, ast.Call):
            function = read(node.func)
            args = [read(arg) for arg in node.args]
            # Unsupported keywords/star expansion never silently change semantics.
            if node.keywords or any(isinstance(a, ast.Starred) for a in node.args):
                return UNKNOWN
            if isinstance(function, Symbol):
                name = function.name.removeprefix("builtins.")
                self.append("resolved_calls", function.name)
                self.text(function.name, "attribute_names")
                if (
                    name in {"__import__", "importlib.import_module"}
                    and len(args) == 1
                    and isinstance(args[0], str)
                ):
                    self.append(
                        "imports",
                        {
                            "name": args[0][:MAX_EXAMPLE],
                            "source": "dynamic_resolved",
                            "confidence": "high",
                        },
                    )
                    self.text(args[0], "module_names")
                    self.result["obfuscation"]["dynamic_import_resolution"] = True
                    self.append(
                        "resolved_import_sites",
                        {"line": node.lineno, "column": node.col_offset},
                    )
                    return Symbol(
                        args[0].split(".")[0] if name == "__import__" else args[0]
                    )
                if (
                    name == "getattr"
                    and len(args) in (2, 3)
                    and isinstance(args[1], str)
                ):
                    obj = args[0].name if isinstance(args[0], Symbol) else None
                    self.append(
                        "resolved_attributes",
                        {
                            "object": obj[:MAX_EXAMPLE] if obj else None,
                            "attribute": args[1][:MAX_EXAMPLE],
                            "confidence": "high" if obj else "medium",
                        },
                    )
                    self.text(args[1], "attribute_names")
                    self.result["obfuscation"]["dynamic_attribute_resolution"] = True
                    return Symbol(obj + "." + args[1]) if obj else UNKNOWN
                if name in {"globals", "locals"} and not args:
                    return Symbol("<namespace>")
                if name == "chr" and len(args) == 1 and type(args[0]) is int:
                    return chr(args[0])
                if (
                    name == "ord"
                    and len(args) == 1
                    and isinstance(args[0], (str, bytes))
                    and len(args[0]) == 1
                ):
                    return ord(args[0])
                if (
                    name in {"bytes", "bytearray"}
                    and len(args) == 1
                    and isinstance(args[0], (list, tuple))
                    and all(type(v) is int and 0 <= v < 256 for v in args[0])
                ):
                    return bytes(args[0])
                if (
                    name == "reversed"
                    and len(args) == 1
                    and isinstance(args[0], (str, bytes, list, tuple))
                ):
                    self.size(len(args[0]), True)
                    return list(reversed(args[0]))
                if (
                    name == "map"
                    and len(args) == 2
                    and isinstance(args[0], Symbol)
                    and isinstance(args[1], (list, tuple, str, bytes))
                ):
                    self.size(len(args[1]), True)
                    mapped = args[0].name.removeprefix("builtins.")
                    if mapped == "chr" and all(type(v) is int for v in args[1]):
                        return [chr(v) for v in args[1]]
                    if mapped == "ord" and all(
                        isinstance(v, (str, bytes)) and len(v) == 1 for v in args[1]
                    ):
                        return [ord(v) for v in args[1]]
                if (
                    name
                    in {
                        "bytes.fromhex",
                        "bytearray.fromhex",
                        "base64.b64decode",
                        "base64.urlsafe_b64decode",
                    }
                    and len(args) == 1
                    and isinstance(args[0], (str, bytes))
                ):
                    self.decode_nodes.add(id(node))
                    self.result["obfuscation"]["encoded_strings"] = True
                    # Inputs already obey the string and aggregate byte budgets.
                    if name.endswith("fromhex") and isinstance(args[0], str):
                        value = bytes.fromhex(args[0])
                    elif name == "base64.b64decode":
                        value = base64.b64decode(args[0])
                    elif name == "base64.urlsafe_b64decode":
                        value = base64.urlsafe_b64decode(args[0])
                    else:
                        return UNKNOWN
                    self.append(
                        "transformations",
                        {
                            "type": name,
                            "line": node.lineno,
                            "result": str(value)[:MAX_EXAMPLE],
                        },
                    )
                    return value
            if isinstance(node.func, ast.Attribute):
                obj = read(node.func.value)
                method = node.func.attr
                if (
                    method == "join"
                    and isinstance(obj, (str, bytes))
                    and len(args) == 1
                    and isinstance(args[0], (list, tuple))
                    and all(type(v) is type(obj) for v in args[0])
                ):
                    self.size(
                        sum(map(len, args[0])) + len(obj) * max(0, len(args[0]) - 1)
                    )
                    return obj.join(args[0])
                if (
                    method == "replace"
                    and isinstance(obj, (str, bytes))
                    and len(args) in (2, 3)
                    and all(type(v) is type(obj) for v in args[:2])
                ):
                    count = args[2] if len(args) == 3 else -1
                    if type(count) is int:
                        matches = obj.count(args[0])
                        if count >= 0:
                            matches = min(matches, count)
                        self.size(
                            len(obj) + matches * max(0, len(args[1]) - len(args[0]))
                        )
                        return obj.replace(args[0], args[1], count)
                encoding = args[0] if len(args) == 1 else "utf-8" if not args else None
                if isinstance(encoding, str) and encoding in {
                    "utf-8",
                    "ascii",
                    "latin1",
                    "latin-1",
                    "utf-16le",
                }:
                    if method == "decode" and isinstance(obj, bytes):
                        return obj.decode(encoding)
                    if method == "encode" and isinstance(obj, str):
                        self.size(len(obj) * 4)
                        return obj.encode(encoding)
            # Any unknown call can mutate containers or monkey-patch symbolic objects.
            # Drop propagated state; builtin names remain unavailable if invalidated.
            env.clear()
        return UNKNOWN

    def statements(self, statements, env, depth=0):
        if depth > MAX_RECURSION_DEPTH:
            self.limit("statement_depth")
        for node in statements:
            self.tick()
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for item in node.names:
                    module = (
                        node.module if isinstance(node, ast.ImportFrom) else item.name
                    )
                    if not module or getattr(node, "level", 0) or item.name == "*":
                        env.clear()
                        continue
                    self.append(
                        "imports",
                        {
                            "name": module[:MAX_EXAMPLE],
                            "source": "normal",
                            "confidence": "high",
                        },
                    )
                    self.text(module, "module_names")
                    name = (
                        f"{module}.{item.name}"
                        if isinstance(node, ast.ImportFrom)
                        else item.name
                        if item.asname
                        else item.name.split(".")[0]
                    )
                    env[item.asname or item.name.split(".")[0]] = self.checked(
                        Symbol(name)
                    )
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                value = self.expression(node.value, env) if node.value else UNKNOWN
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                for target in targets:
                    if isinstance(target, ast.Name):
                        env[target.id] = value
                    else:
                        # Includes aliased container mutation, attributes, destructuring.
                        env.clear()
            elif isinstance(node, ast.Expr):
                self.expression(node.value, env)
            elif isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                # Bodies are not called. Inspect independently of mutable outer bindings.
                local = {
                    key: value
                    for key, value in Recovery().env.items()
                    if env.get(key) == value
                }
                for part in ast.walk(node):
                    if isinstance(part, ast.Name) and isinstance(
                        part.ctx, (ast.Store, ast.Del)
                    ):
                        local[part.id] = UNKNOWN
                    if isinstance(part, ast.arg):
                        local[part.arg] = UNKNOWN
                    if isinstance(
                        part, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                    ):
                        local[part.name] = UNKNOWN
                    if isinstance(part, (ast.Import, ast.ImportFrom)):
                        for alias in part.names:
                            local[alias.asname or alias.name.split(".")[0]] = UNKNOWN
                    if isinstance(part, ast.ExceptHandler) and part.name:
                        local[part.name] = UNKNOWN
                self.statements(node.body, local, depth + 1)
                env[node.name] = UNKNOWN
                if node.decorator_list or isinstance(node, ast.ClassDef):
                    env.clear()
            elif isinstance(node, ast.If):
                # Analyze both alternatives as possible syntax, with explicit uncertainty.
                # Forget outer state first: branch tests/bodies may mutate it.
                env.clear()
                for body in (node.body, node.orelse):
                    self.statements(body, {}, depth + 1)
            elif isinstance(node, (ast.Pass, ast.Break, ast.Continue)):
                continue
            else:
                # Unsupported control flow, deletes and augmented writes invalidate state.
                env.clear()

    def analyze(self, source):
        coverage = self.result["coverage"]
        try:
            if not isinstance(source, (str, bytes)):
                raise TypeError("Expected Python source text")
            if len(source) > MAX_SOURCE:
                self.limit("source_length")
            tree = ast.parse(source)
            coverage["ast_parsed"] = True
            for count, _ in enumerate(ast.walk(tree), 1):
                if count > MAX_NODES:
                    self.limit("ast_nodes")
            self.statements(tree.body, self.env)
            # Report actual nested decoding, not independent encoded constants.
            for node in ast.walk(tree):
                if (
                    id(node) in self.decode_nodes or isinstance(node, ast.Subscript)
                ) and any(
                    id(child) in self.decode_nodes
                    for child in ast.walk(node)
                    if child is not node
                ):
                    self.result["obfuscation"]["multiple_decode_layers"] = True
                    break
        except (
            SyntaxError,
            ValueError,
            TypeError,
            UnicodeError,
            RecursionError,
            MemoryError,
        ) as error:
            self.result["diagnostics"].append(
                type(error).__name__ + ": " + str(error)[:200]
            )
        examined = coverage["expressions_examined"]
        coverage["resolution_ratio"] = (
            round(coverage["expressions_resolved"] / examined, 3) if examined else 0.0
        )
        coverage["operations"] = self.operations
        self.result["supported"] = coverage["ast_parsed"]
        return self.result


def analyze_python_source(source):
    """Return JSON-compatible evidence only; no imports, execution or risk verdicts."""
    return Recovery().analyze(source)
