"""Recover symbols from literal aliases and a narrow XOR-to-text AST template."""

import ast
import operator


def recover_symbols(tree):
    symbols = {"__builtins__": "builtins", "builtins": "builtins"}
    xor_templates = {}
    recovered = []
    constants = {}
    operations = [0]

    def constant(node, depth=0):
        operations[0] += 1
        if operations[0] > 50000 or depth > 24:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, int)):
            return node.value
        if isinstance(node, ast.Name):
            return constants.get(node.id)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd, ast.Invert)):
            value = constant(node.operand, depth + 1)
            if type(value) is int and value.bit_length() <= 128:
                return {ast.USub: operator.neg, ast.UAdd: operator.pos, ast.Invert: operator.invert}[type(node.op)](value)
        if isinstance(node, ast.BinOp):
            left, right = constant(node.left, depth + 1), constant(node.right, depth + 1)
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
            if function == "__import__" and node.args:
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

    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                symbols[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                symbols[item.asname or item.name] = f"{node.module}.{item.name}"
        elif isinstance(node, ast.For) and isinstance(node.target, ast.Name) and len(node.body) == 1 and not node.orelse:
            # Fold only a bounded literal accumulator, e.g. a rolling string
            # hash used to encode symbol names. No general loop interpreter.
            update = node.body[0]
            sequence = constant(node.iter)
            if isinstance(sequence, str) and len(sequence) <= 4096 and isinstance(update, ast.Assign) and len(update.targets) == 1 and isinstance(update.targets[0], ast.Name):
                accumulator = update.targets[0].id
                if type(constants.get(accumulator)) is int:
                    for character in sequence:
                        constants[node.target.id] = character
                        value = constant(update.value)
                        if type(value) is not int:
                            constants.pop(accumulator, None)
                            break
                        constants[accumulator] = value
                    constants.pop(node.target.id, None)
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
                    symbols.pop(key, None)
    return symbols, recovered[:80]
