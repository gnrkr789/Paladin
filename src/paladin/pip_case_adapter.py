"""Narrow source matching and deterministic repair for pip Mercurial revisions."""

import ast


CVE_ID = "CVE-2023-5752"
RULE_ID = CVE_ID + ":mercurial-revision-v1"


def revision_lists(tree):
    """Return the unique supported revision list, without importing target code."""
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Mercurial"]
    if len(classes) != 1:
        return []
    methods = [node for node in classes[0].body
               if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "get_base_rev_args"]
    if len(methods) != 1:
        return []
    method = methods[0]
    if not isinstance(method, ast.FunctionDef):
        return []
    args = method.args
    if (args.posonlyargs or len(args.args) != 1 or args.args[0].arg != "rev"
            or args.vararg or args.kwarg or args.kwonlyargs or args.defaults or args.kw_defaults):
        return []
    if (len(method.decorator_list) != 1 or not isinstance(method.decorator_list[0], ast.Name)
            or method.decorator_list[0].id != "staticmethod"):
        return []
    if len(method.body) != 1 or not isinstance(method.body[0], ast.Return):
        return []
    value = method.body[0].value
    if not isinstance(value, ast.List) or len(value.elts) != 2:
        return []
    flag, revision = value.elts
    if (not isinstance(flag, ast.Constant) or flag.value != "-r"
            or not isinstance(revision, ast.Name) or revision.id != "rev"):
        return []
    return [value]


def repair_bytes(original):
    """Replace only one supported list; reject fixed or ambiguous source bytes."""
    if not isinstance(original, bytes):
        raise ValueError("Pip repair requires source bytes")
    try:
        source = original.decode("ascii")
        tree = ast.parse(source)
    except (UnicodeError, SyntaxError, ValueError) as error:
        raise ValueError("Unsupported pip repair source") from error
    values = revision_lists(tree)
    if len(values) != 1:
        raise ValueError("Pip repair requires one unambiguous revision list")
    value = values[0]
    lines = original.splitlines(keepends=True)
    start = sum(map(len, lines[:value.lineno - 1])) + value.col_offset
    end = sum(map(len, lines[:value.end_lineno - 1])) + value.end_col_offset
    # Paladin's attached long-option form. pip 23.3's "-r=VALUE" is parsed by
    # Mercurial 7.0.1 as the revision "=VALUE" and breaks ordinary revisions.
    repaired = original[:start] + b"['--rev=' + rev]" + original[end:]
    if revision_lists(ast.parse(repaired)):
        raise ValueError("Pip repair left an affected revision list")
    return repaired
