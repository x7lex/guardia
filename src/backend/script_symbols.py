"""Bounded literal/name propagation; only whitelisted syntax, never target calls."""

import ast
import operator


def recover_symbols(tree, detailed=False):
    symbols = {"__builtins__": "builtins", "builtins": "builtins"}
    xor_templates = {}
    recovered = []
    constants = {}
    operations = [0]
    resolved_names, resolved_literals = {}, {}
    literal_bytes = [0]
    limitations = []

    def constant(node, depth=0):
        operations[0] += 1
        if operations[0] > 200000 or depth > 24:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes, int)) and (not isinstance(node.value, (str, bytes)) or len(node.value) <= 8192):
            return node.value
        if isinstance(node, ast.Name):
            return constants.get(node.id)
        if isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) <= 1024:
            values = [constant(item, depth + 1) for item in node.elts]
            return values if all(type(v) in (int, str, bytes) for v in values) else None
        if isinstance(node, ast.Subscript):
            value = constant(node.value, depth + 1)
            if isinstance(value, (str, bytes, list)):
                if isinstance(node.slice, ast.Slice):
                    bounds = [constant(n, depth + 1) if n is not None else None for n in (node.slice.lower, node.slice.upper, node.slice.step)]
                    if all(v is None or type(v) is int for v in bounds) and bounds[2] != 0:
                        return value[slice(*bounds)]
                index = constant(node.slice, depth + 1)
                if type(index) is int and -len(value) <= index < len(value):
                    return value[index]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd, ast.Invert)):
            value = constant(node.operand, depth + 1)
            if type(value) is int and value.bit_length() <= 128:
                return {ast.USub: operator.neg, ast.UAdd: operator.pos, ast.Invert: operator.invert}[type(node.op)](value)
        if isinstance(node, ast.BinOp):
            left, right = constant(node.left, depth + 1), constant(node.right, depth + 1)
            if isinstance(node.op, ast.Add) and type(left) is type(right) and isinstance(left, (str, bytes, list)) and len(left) + len(right) <= 8192:
                return left + right
            if isinstance(node.op, ast.Mult) and isinstance(left, (str, bytes)) and type(right) is int and 0 <= right <= 8192 and len(left) * right <= 8192:
                return left * right
            ops = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
                   ast.BitXor: operator.xor, ast.BitAnd: operator.and_, ast.BitOr: operator.or_,
                   ast.RShift: operator.rshift, ast.LShift: operator.lshift}
            if type(left) is int and type(right) is int and max(left.bit_length(), right.bit_length()) <= 128 and type(node.op) in ops:
                if isinstance(node.op, (ast.LShift, ast.RShift)) and not 0 <= right <= 64:
                    return None
                value = ops[type(node.op)](left, right)
                return value if value.bit_length() <= 128 else None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in xor_templates and not node.keywords and len(node.args) <= 256:
            values = [constant(arg, depth + 1) for arg in node.args]
            key = xor_templates[node.func.id]
            if all(type(v) is int and 0 <= (v ^ key) < 128 for v in values):
                return "".join(chr(v ^ key) for v in values)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and symbols.get(node.func.id, node.func.id).removeprefix("builtins.") == "ord" and len(node.args) == 1:
            value = constant(node.args[0], depth + 1)
            if isinstance(value, str) and len(value) == 1:
                return ord(value)
        if isinstance(node, ast.Call) and not node.keywords:
            function = symbol(node.func).removeprefix("builtins.")
            if len(node.args) == 1:
                value = constant(node.args[0], depth + 1)
                if function == "chr" and type(value) is int and 0 <= value <= 0x10ffff:
                    return chr(value)
                if function in {"bytes", "bytearray"} and isinstance(value, list) and all(type(v) is int and 0 <= v <= 255 for v in value):
                    return bytes(value)
                if function == "bytes.fromhex" and isinstance(value, str):
                    try:
                        return bytes.fromhex(value)
                    except ValueError:
                        return None
                if isinstance(node.func, ast.Attribute) and node.func.attr == "join":
                    separator = constant(node.func.value, depth + 1)
                    if isinstance(separator, (str, bytes)) and isinstance(value, list) and all(type(v) is type(separator) for v in value) and sum(map(len, value)) + len(separator)*len(value) <= 8192:
                        return separator.join(value)
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"decode", "encode"} and len(node.args) <= 1:
                value = constant(node.func.value, depth + 1)
                encoding = constant(node.args[0], depth + 1) if node.args else "utf-8"
                if encoding in {"utf-8", "ascii", "latin1"}:
                    try:
                        if isinstance(value, bytes) and node.func.attr == "decode":
                            return value.decode(encoding)
                        if isinstance(value, str) and node.func.attr == "encode":
                            return value.encode(encoding)
                    except UnicodeError:
                        return None
        return None

    def symbol(node):
        if isinstance(node, ast.Name):
            return symbols.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{symbol(node.value)}.{node.attr}"
        if isinstance(node, ast.Subscript):
            key = constant(node.slice)
            if symbol(node.value) in {"builtins", "builtins.__dict__"} and isinstance(key, str):
                return "builtins." + key
        if isinstance(node, ast.Call):
            function = symbol(node.func).removeprefix("builtins.")
            if function in {"__import__", "importlib.import_module"} and node.args:
                module = constant(node.args[0])
                if isinstance(module, str):
                    return module
            if function == "getattr" and len(node.args) >= 2:
                attribute = constant(node.args[1])
                if isinstance(attribute, str):
                    return f"{symbol(node.args[0])}.{attribute}"
        return "<expression>"

    def xor_template(node):
        # Match syntax, never call a target-defined lambda. Only this exact
        # join(map(chr, [argument ^ literal for argument in *args])) form folds.
        if not isinstance(node, ast.Lambda) or not node.args.vararg:
            return None
        body = node.body
        if not (isinstance(body, ast.Call) and not body.keywords and len(body.args) == 1 and isinstance(body.func, ast.Attribute) and body.func.attr == "join" and isinstance(body.func.value, ast.Constant) and body.func.value.value == ""):
            return None
        mapped = body.args[0]
        if not (isinstance(mapped, ast.Call) and symbol(mapped.func).removeprefix("builtins.") == "map" and len(mapped.args) == 2 and symbol(mapped.args[0]).removeprefix("builtins.") == "chr"):
            return None
        comp = mapped.args[1]
        if not isinstance(comp, ast.ListComp) or len(comp.generators) != 1:
            return None
        generator = comp.generators[0]
        if generator.ifs or generator.is_async or not isinstance(generator.target, ast.Name) or not isinstance(generator.iter, ast.Name) or generator.iter.id != node.args.vararg.arg:
            return None
        expr = comp.elt
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.BitXor) and isinstance(expr.left, ast.Name) and expr.left.id == generator.target.id and isinstance(expr.right, ast.Constant) and type(expr.right.value) is int and 0 <= expr.right.value < 128:
            return expr.right.value
        return None

    def capture(node):
        for part in ast.walk(node):
            if isinstance(part, (ast.Call, ast.Attribute, ast.Name)):
                resolved_names[id(part)] = symbol(part)
            if isinstance(part, (ast.Call, ast.BinOp, ast.Subscript, ast.Name, ast.Constant)):
                value = constant(part)
                if isinstance(value, (str, bytes)) and len(value) <= 8192 and literal_bytes[0] + len(value) <= 2 * 1024 * 1024:
                    resolved_literals[id(part)] = value
                    literal_bytes[0] += len(value)
                else:
                    resolved_literals.pop(id(part), None)

    def invalidate(node):
        for part in ast.walk(node):
            if isinstance(part, ast.Name) and isinstance(part.ctx, (ast.Store, ast.Del)):
                constants.pop(part.id, None)
                symbols[part.id] = "<unknown>"
                xor_templates.pop(part.id, None)

    def process(statements):
        for node in statements:
            if operations[0] > 200000:
                limitations.append("Constant propagation operation budget exceeded")
                break
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                saved = (symbols.copy(), constants.copy(), xor_templates.copy())
                # Locals must not inherit same-named global constants/imports.
                invalidate(node)
                if not isinstance(node, ast.ClassDef):
                    for arg in ast.walk(node.args):
                        if isinstance(arg, ast.arg):
                            symbols[arg.arg] = "<unknown>"; constants.pop(arg.arg, None); xor_templates.pop(arg.arg, None)
                process(node.body)
                symbols.clear(); symbols.update(saved[0])
                constants.clear(); constants.update(saved[1])
                xor_templates.clear(); xor_templates.update(saved[2])
                symbols[node.name] = "<unknown>"; constants.pop(node.name, None)
                continue
            capture(node)
            if isinstance(node, ast.Import):
                for item in node.names:
                    symbols[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
            elif isinstance(node, ast.ImportFrom) and node.module:
                for item in node.names:
                    symbols[item.asname or item.name] = f"{node.module}.{item.name}"
            elif isinstance(node, ast.For) and isinstance(node.target, ast.Name) and len(node.body) == 1 and not node.orelse:
                # Fold only a bounded literal accumulator, e.g. a rolling string
                # hash used to encode symbol names. No general loop interpreter.
                folded = False
                update = node.body[0]
                sequence = constant(node.iter)
                if isinstance(sequence, str) and len(sequence) <= 4096 and isinstance(update, ast.Assign) and len(update.targets) == 1 and isinstance(update.targets[0], ast.Name):
                    accumulator = update.targets[0].id
                    if type(constants.get(accumulator)) is int:
                        folded = True
                        for character in sequence:
                            constants[node.target.id] = character
                            value = constant(update.value)
                            if type(value) is not int:
                                constants.pop(accumulator, None)
                                break
                            constants[accumulator] = value
                        constants.pop(node.target.id, None)
                if not folded:
                    invalidate(node)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    key = target.id if isinstance(target, ast.Name) else None
                    if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Call) and symbol(target.value.func).removeprefix("builtins.") == "globals":
                        key = constant(target.slice)
                    if not isinstance(key, str):
                        continue
                    template = xor_template(node.value)
                    value = symbol(node.value)
                    literal = constant(node.value)
                    if literal is not None:
                        constants[key] = literal
                    else:
                        constants.pop(key, None)
                    if template is not None:
                        xor_templates[key] = template
                    else:
                        xor_templates.pop(key, None)
                    if value != "<expression>":
                        symbols[key] = value
                        if isinstance(node.value, (ast.Call, ast.Subscript)):
                            encoded = any(isinstance(part, ast.Call) and isinstance(part.func, ast.Name) and part.func.id in xor_templates for part in ast.walk(node.value))
                            recovered.append({"alias": key, "symbol": value, "line": node.lineno, "encoded_name": encoded})
                    else:
                        symbols[key] = "<unknown>"
            elif isinstance(node, (ast.If, ast.While, ast.Try, ast.For, ast.With)):
                # No branch execution or general loop simulation. Analyze branches in
                # isolated environments and forget possibly assigned values afterwards.
                saved = (symbols.copy(), constants.copy(), xor_templates.copy())
                bodies = [getattr(node, key, []) for key in ("body", "orelse", "finalbody")]
                bodies.extend(handler.body for handler in getattr(node, "handlers", []))
                for body in bodies:
                    process(body)
                    symbols.clear(); symbols.update(saved[0])
                    constants.clear(); constants.update(saved[1])
                    xor_templates.clear(); xor_templates.update(saved[2])
                invalidate(node)
            elif isinstance(node, (ast.AugAssign, ast.Delete)):
                invalidate(node)
    process(tree.body)
    if operations[0] > 200000 and not limitations:
        limitations.append("Constant propagation operation budget exceeded")
    if detailed:
        return symbols, recovered[:80], resolved_names, resolved_literals, limitations
    return symbols, recovered[:80]
