import ast


_NON_VALUE_NAMES = {
    "abs", "bool", "bytes", "bytearray", "int", "len", "max", "min", "range",
    "str", "sum",
}

_RISKY_RANGE_NAME_FRAGMENTS = (
    "len", "length", "size", "count", "num", "total",
)


def _names_in(node):
    return {
        item.id
        for item in ast.walk(node)
        if isinstance(item, ast.Name)
        and item.id not in _NON_VALUE_NAMES
    }


def _contains_name(node, name):
    return name in _names_in(node)


def _block_exits(statements):
    if not statements:
        return False
    last = statements[-1]
    if isinstance(last, (ast.Return, ast.Raise)):
        return True
    if isinstance(last, ast.If):
        return _block_exits(last.body) and _block_exits(last.orelse)
    return False


def _repeat_count(node):
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Mult):
        return None
    if isinstance(node.left, (ast.Constant, ast.List, ast.Tuple)):
        return node.right
    if isinstance(node.right, (ast.Constant, ast.List, ast.Tuple)):
        return node.left
    return None


def _max_size_bound_names(node, safe_when_true):
    result = set()
    for comparison in ast.walk(node):
        if not isinstance(comparison, ast.Compare):
            continue
        operands = [comparison.left] + list(comparison.comparators)
        for index, operator in enumerate(comparison.ops):
            left = operands[index]
            right = operands[index + 1]
            left_is_max = isinstance(left, ast.Name) and left.id == "max_size"
            right_is_max = isinstance(right, ast.Name) and right.id == "max_size"
            if safe_when_true:
                if right_is_max and isinstance(operator, (ast.Lt, ast.LtE)):
                    result.update(_names_in(left))
                elif left_is_max and isinstance(operator, (ast.Gt, ast.GtE)):
                    result.update(_names_in(right))
            else:
                if right_is_max and isinstance(operator, (ast.Gt, ast.GtE)):
                    result.update(_names_in(left))
                elif left_is_max and isinstance(operator, (ast.Lt, ast.LtE)):
                    result.update(_names_in(right))
    return result


def _unsafe_growth_call(stmt, bounded_names):
    for node in ast.walk(stmt):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "extend"
            and len(node.args) == 1
        ):
            continue
        count = _repeat_count(node.args[0])
        if count is None or _contains_name(count, "max_size"):
            continue
        count_names = _names_in(count)
        if count_names and not count_names.intersection(bounded_names):
            return node.lineno, sorted(count_names)
    return None


def _range_bound_names(call):
    if not (
        isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "range"
    ):
        return set()
    result = set()
    for arg in call.args:
        if not isinstance(arg, ast.Constant):
            result.update(_names_in(arg))
    return result


def _risky_range_names(names):
    result = set()
    for name in names:
        lowered = name.lower()
        if any(fragment in lowered for fragment in _RISKY_RANGE_NAME_FRAGMENTS):
            result.add(name)
    return result


def _unsafe_range_materialization(stmt, bounded_names):
    for node in ast.walk(stmt):
        if not isinstance(node, ast.Call):
            continue

        range_names = set()
        operation = None
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"extend", "update"}
            and len(node.args) == 1
        ):
            range_names = _range_bound_names(node.args[0])
            operation = node.func.attr
        elif (
            isinstance(node.func, ast.Name)
            and node.func.id in {"list", "tuple", "set", "sorted"}
            and len(node.args) == 1
        ):
            range_names = _range_bound_names(node.args[0])
            operation = node.func.id

        if not range_names:
            continue
        unbounded_names = _risky_range_names(range_names - set(bounded_names))
        if unbounded_names:
            return node.lineno, operation, sorted(unbounded_names)
    return None


def _check_block(statements, inherited_bounds, function_name):
    bounded_names = set(inherited_bounds)
    for stmt in statements:
        if isinstance(stmt, ast.If):
            body_bounds = set(bounded_names)
            body_bounds.update(_max_size_bound_names(stmt.test, safe_when_true=True))
            error = _check_block(stmt.body, body_bounds, function_name)
            if error:
                return error
            error = _check_block(stmt.orelse, bounded_names, function_name)
            if error:
                return error
            if _block_exits(stmt.body):
                bounded_names.update(
                    _max_size_bound_names(stmt.test, safe_when_true=False)
                )
            continue

        error = _unsafe_growth_call(stmt, bounded_names)
        if error:
            lineno, names = error
            return (
                f"unsafe dynamic buffer growth in {function_name} at line {lineno}: "
                f"allocation length depends on {', '.join(names)} before a max_size guard"
            )

        error = _unsafe_range_materialization(stmt, bounded_names)
        if error:
            lineno, operation, names = error
            return (
                f"unsafe range materialization in {function_name} at line {lineno}: "
                f"{operation}() consumes range depending on {', '.join(names)} "
                "before a max_size guard"
            )

        for child_block in (
            getattr(stmt, "body", None),
            getattr(stmt, "orelse", None),
            getattr(stmt, "finalbody", None),
        ):
            if isinstance(child_block, list):
                error = _check_block(child_block, bounded_names, function_name)
                if error:
                    return error
    return None


def validate_template_memory_safety(code):
    try:
        tree = ast.parse(code, filename="<template_executor>", mode="exec")
    except SyntaxError as e:
        return False, f"syntax error: {e}"

    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        argument_names = {
            argument.arg
            for argument in node.args.args
        }
        if "max_size" not in argument_names:
            continue
        error = _check_block(node.body, set(), node.name)
        if error:
            return False, error
    return True, None
