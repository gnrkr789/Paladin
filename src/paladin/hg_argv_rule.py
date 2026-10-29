"""Generalized Mercurial argv option-injection rule.

Matches any argv list whose first element is the constant "hg" and whose second is
a checkout/update subcommand, when a non-constant value can reach Mercurial before
a "--" terminator. The call target does not matter (wrappers such as self.run or
_run are covered), and lists built with append/extend/+= inside one function are
followed. Findings are review-level source observations: there is no execution
adapter, so they are never verified or promoted automatically.
"""
import ast
import io
import re
import tokenize

RULE_ID = "mercurial-argv-option-injection-v1"
# Mercurial parses early options such as --config and --debugger anywhere in argv,
# including the value position after -r, unless "--" terminates option parsing.
SUBCOMMANDS = {"checkout": "CVE-2022-24065", "co": "CVE-2022-24065",
               "update": "CVE-2023-5752", "up": "CVE-2023-5752"}
GROWTH_METHODS = {"append", "extend", "insert"}
# Global options that may precede the subcommand and consume the next element.
VALUE_GLOBALS = {"--cwd", "-R", "--repository", "--config", "--encoding", "--encodingmode"}


def _text(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _prefix(node):
    """Constant leading text of a built string, or None when it is not fixed."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _text(node.left) if isinstance(node.op, ast.Mod) else _prefix(node.left)
    if isinstance(node, ast.JoinedStr) and node.values:
        return _text(node.values[0])
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"):
        return _text(node.func.value)
    return _text(node)


def _safe_prefix(prefix):
    """A fixed non-option prefix ('tip~%d') or an attached option ('--rev=' + v) cannot inject."""
    return bool(prefix) and (not prefix.startswith("-") or "=" in prefix)


def _attached(node):
    return _text(node) is None and _safe_prefix(_prefix(node))


def _exposed(nodes):
    for node in nodes:
        text = _text(node)
        if text == "--":
            return False
        if text is None and not _attached(node):
            return True
    return False


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        inner = _dotted(node.value)
        return None if inner is None else inner + "." + node.attr
    return None


def _is_hg(node, text):
    """The constant 'hg', or a name such as HgClient._executable or hg_bin."""
    if text(node) == "hg":
        return True
    if text is not _text:
        return False
    name = _dotted(node)
    return name is not None and bool(re.search(r"(^|[._])(hg|mercurial)", name.lower()))


def _split(elements, text=None):
    """Return (cve, arguments after the subcommand) for an hg checkout/update argv."""
    text = text or _text
    if not elements or not _is_hg(elements[0], text):
        return None, []
    index = 1
    while index < len(elements):
        option = text(elements[index])
        if option is None or not option.startswith("-"):
            break
        index += 2 if option in VALUE_GLOBALS else 1
    if index >= len(elements):
        return None, []
    cve = SUBCOMMANDS.get(text(elements[index]))
    return cve, (elements[index + 1:] if cve else [])


def _subcommand(elements):
    return _split(elements)[0]


# A shell command string: hg [global options] checkout|update ... with a placeholder
# for a value and no "--" before it.
_SHELL = re.compile(r"(?:^|[;&|(]\s*)hg(?:\s+-\S+(?:\s+[^-\s]\S*)?)*?\s+(checkout|co|update|up)\b([^;&|]*)")
_PLACEHOLDER = re.compile(r"%[-#0 +]*[0-9]*(?:\.[0-9]+)?[sdr]|\{[^{}]*\}")


def _shell_findings(tree):
    for node in ast.walk(tree):
        template = None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            template = _text(node.left)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            template = _text(node.func.value)
        elif isinstance(node, ast.JoinedStr):
            template = "".join(_text(part) or "{}" for part in node.values)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = _text(node.left)
            template = None if left is None else left + "{}"
        if not template:
            continue
        for match in _SHELL.finditer(template):
            arguments = match[2]
            terminator = arguments.find(" -- ")
            placeholder = _PLACEHOLDER.search(arguments)
            if placeholder and (terminator < 0 or placeholder.start() < terminator):
                yield node.lineno, SUBCOMMANDS[match[1]]
                break


def _literal_findings(tree):
    for node in ast.walk(tree):
        if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
                and isinstance(node.left, (ast.List, ast.Tuple))):
            # ['hg', 'checkout', '-C'] + revargs: the right side is unknown values.
            cve, rest = _split(node.left.elts)
            if cve and "--" not in map(_text, rest) and not _exposed(rest):
                right = node.right.elts if isinstance(node.right, (ast.List, ast.Tuple)) else [node.right]
                if _exposed(right):
                    yield node.lineno, cve
        if isinstance(node, (ast.List, ast.Tuple)):
            cve, rest = _split(node.elts)
            if cve and _exposed(rest):
                yield node.lineno, cve
        elif isinstance(node, ast.Call) and node.args and _text(node.args[0]) == "hg":
            # Variadic helpers such as execute_command('hg', 'update', '-q', revision).
            cve, rest = _split(node.args)
            if cve and _exposed(rest):
                yield node.lineno, cve


def _growth_target(node):
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.attr in GROWTH_METHODS):
        return node.func.value.id
    if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add) and isinstance(node.target, ast.Name):
        return node.target.id
    return None


def _growth(node, name):
    """Return the nodes appended to `name` by one statement-level expression, or None."""
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id == name
            and node.func.attr in GROWTH_METHODS and node.args):
        value = node.args[-1]
        if node.func.attr == "append":
            return [value]
        return list(value.elts) if isinstance(value, (ast.List, ast.Tuple)) else [value]
    if (isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add)
            and isinstance(node.target, ast.Name) and node.target.id == name):
        return list(node.value.elts) if isinstance(node.value, (ast.List, ast.Tuple)) else [node.value]
    return None


def _scope_walk(scope):
    """Walk one scope without entering nested functions, lambdas or classes."""
    pending = list(ast.iter_child_nodes(scope))
    while pending:
        node = pending.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            pending.extend(ast.iter_child_nodes(node))


def _built_findings(tree):
    """Lists started as ['hg', <subcommand>, constants...] and grown in the same scope."""
    scopes = [tree] + [node for node in ast.walk(tree)
                       if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for scope in scopes:
        nodes = sorted((node for node in _scope_walk(scope) if hasattr(node, "lineno")),
                       key=lambda node: (node.lineno, node.col_offset))
        growth = {}
        for node in nodes:
            target = _growth_target(node)
            if target is not None:
                growth.setdefault(target, []).append(node)
        for start in nodes:
            if not (isinstance(start, ast.Assign) and len(start.targets) == 1
                    and isinstance(start.targets[0], ast.Name)
                    and isinstance(start.value, (ast.List, ast.Tuple))):
                continue
            cve, rest = _split(start.value.elts)
            if not cve or _exposed(rest) or "--" in map(_text, rest):
                continue
            name = start.targets[0].id
            for node in growth.get(name, []):
                if node.lineno <= start.lineno:
                    continue
                added = _growth(node, name)
                if added is None:
                    continue
                if "--" in map(_text, added):
                    break
                if _exposed(added):
                    yield node.lineno, cve
                    break


def ast_findings(tree):
    """Sorted unique (line, cve_id) findings for a parsed module."""
    return sorted(set(_literal_findings(tree)) | set(_built_findings(tree)) | set(_shell_findings(tree)))


def _token_elements(tokens, start):
    """Split a bracketed token run into top-level elements; return (elements, end)."""
    depth, elements, current = 0, [], []
    for index in range(start, len(tokens)):
        token = tokens[index]
        if token.type == tokenize.OP and token.string in "([{":
            depth += 1
            if depth == 1:
                continue
        elif token.type == tokenize.OP and token.string in ")]}":
            depth -= 1
            if depth == 0:
                if current:
                    elements.append(current)
                return elements, index
        if depth == 1 and token.type == tokenize.OP and token.string == ",":
            elements.append(current)
            current = []
        elif token.type not in (tokenize.NL, tokenize.NEWLINE, tokenize.COMMENT):
            current.append(token)
    return None, len(tokens)


def _token_text(element):
    if len(element) != 1 or element[0].type != tokenize.STRING:
        return None
    try:
        value = ast.literal_eval(element[0].string)
    except (ValueError, SyntaxError):
        return None
    return value if isinstance(value, str) else None


def token_findings(data):
    """Fallback for sources the current parser rejects (for example Python 2)."""
    try:
        tokens = list(tokenize.tokenize(io.BytesIO(data).readline))
    except (tokenize.TokenError, SyntaxError, UnicodeError):
        return None
    findings = set()
    for index, token in enumerate(tokens):
        if token.type != tokenize.OP or token.string != "[":
            continue
        elements, end = _token_elements(tokens, index)
        cve, rest = _split(elements or [], _token_text)
        if not cve:
            continue
        following = tokens[end + 1:end + 3]
        if (len(following) == 2 and following[0].string == "+" and following[1].type == tokenize.NAME
                and all(_token_text(element) not in (None, "--") for element in rest)):
            # ['hg', 'checkout', '-C'] + revargs in a file the parser rejects.
            findings.add((token.start[0], cve))
            continue
        for element in rest:
            text = _token_text(element)
            if text == "--":
                break
            attached = (len(element) >= 2 and element[1].string in ("+", "%")
                        and _safe_prefix(_token_text(element[:1])))
            if text is None and not attached:
                findings.add((token.start[0], cve))
                break
    return sorted(findings)
