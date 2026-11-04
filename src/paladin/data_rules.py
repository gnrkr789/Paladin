"""Declarative change-check rules stored as data and matched with one AST pass.

A rule names the calls it watches (resolved through import aliases) and the argument
conditions that must all hold. Nothing in a rule is executed; the hook only interprets it.
"""
import ast
import re

from paladin.language import require_english

RULE_KEYS = {"rule_id", "cve_ids", "family", "severity", "title", "fix", "call", "require", "examples"}
CALL = re.compile(r"^(\*|[A-Za-z_]\w*)(\.[A-Za-z_]\w*)+$")
RULE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,80}$")
CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
KINDS = {"non_constant", "built_string"}
PREDICATES = {"equals", "absent_or_not_in", "is"}
MAX_TEXT = 300


def _dotted(node, aliases):
    """Resolved dotted name of a Name/Attribute chain, or None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(aliases.get(node.id, node.id if parts else "builtins." + node.id))
    return ".".join(reversed(parts))


def _imports(tree):
    aliases, modules = {}, set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name.split(".")[0])
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            modules.add(node.module.split(".")[0])
            for alias in node.names:
                aliases[alias.asname or alias.name] = node.module + "." + alias.name
    return aliases, modules


def _constant(node):
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        return not any(isinstance(value, ast.FormattedValue) for value in node.values)
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(_constant(item) for item in node.elts)
    if isinstance(node, ast.BinOp):
        return _constant(node.left) and _constant(node.right)
    return False


def _stringy(node):
    """Text literal, f-string, or a +/% expression that contains one."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _stringy(node.left) or _stringy(node.right)
    return (isinstance(node, ast.Constant) and isinstance(node.value, str)) or isinstance(node, ast.JoinedStr)


def _built_string(node):
    if isinstance(node, ast.JoinedStr):
        return not _constant(node)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        sides = (node.left, node.right)
        return any(_stringy(side) or _built_string(side) for side in sides) and not all(map(_constant, sides))
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"
            and _stringy(node.func.value) and bool(node.args or node.keywords))


def _value(call, condition):
    if "arg" in condition and condition["arg"] < len(call.args):
        return call.args[condition["arg"]]
    for keyword in call.keywords:
        if keyword.arg is not None and keyword.arg == condition.get("keyword"):
            return keyword.value
    return None


def _holds(call, condition, aliases):
    value = _value(call, condition)
    if "equals" in condition:
        return isinstance(value, ast.Constant) and value.value == condition["equals"]
    if "absent_or_not_in" in condition:
        if value is None:
            return True
        name = value.value if isinstance(value, ast.Constant) else _dotted(value, aliases)
        return name not in condition["absent_or_not_in"]
    if value is None:
        return False
    return _built_string(value) if condition["is"] == "built_string" else not _constant(value)


def compile_rules(rules):
    compiled = []
    for rule in rules:
        exact = {name for name in rule["call"] if not name.startswith("*.")}
        methods = {name[2:] for name in rule["call"] if name.startswith("*.")}
        modules = None if methods else {name.split(".")[0] for name in exact}
        compiled.append(dict(rule, _exact=exact, _methods=methods, _modules=modules))
    return compiled


def applicable(compiled, modules):
    """Rules worth running for a file importing these top-level modules."""
    return [rule for rule in compiled
            if rule["_modules"] is None or "builtins" in rule["_modules"] or rule["_modules"] & modules]


def scan(compiled, source):
    """Return (findings, notes) for one Python source text."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return [], ["source could not be parsed; data rules did not run"]
    aliases, modules = _imports(tree)
    rules = applicable(compiled, modules)
    if not rules:
        return [], []
    findings, seen = [], set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func, aliases)
        method = node.func.attr if isinstance(node.func, ast.Attribute) else None
        for rule in rules:
            if (name in rule["_exact"] or method in rule["_methods"]) and \
                    all(_holds(node, condition, aliases) for condition in rule["require"]):
                key = (rule["rule_id"], node.lineno)
                if key not in seen:
                    seen.add(key)
                    findings.append({"rule_id": rule["rule_id"], "cve_ids": rule["cve_ids"], "line": node.lineno,
                                     "severity": rule["severity"], "cve_severity": rule.get("cve_severity"),
                                     "title": rule["title"], "fix": rule["fix"]})
    return sorted(findings, key=lambda item: (item["line"], item["rule_id"])), []


def _condition_errors(condition):
    if not isinstance(condition, dict):
        return ["require: each condition must be an object"]
    targets = {"arg", "keyword"} & set(condition)
    predicates = PREDICATES & set(condition)
    errors = []
    if not targets or len(predicates) != 1 or set(condition) - targets - predicates:
        errors.append("require: need arg and/or keyword plus exactly one of " + ", ".join(sorted(PREDICATES)))
    if "arg" in condition and not (isinstance(condition["arg"], int) and 0 <= condition["arg"] <= 10):
        errors.append("require: arg must be 0-10")
    if "keyword" in condition and not (isinstance(condition["keyword"], str) and condition["keyword"].isidentifier()):
        errors.append("require: keyword must be an identifier")
    if "is" in condition and condition["is"] not in KINDS:
        errors.append("require: is must be one of " + ", ".join(sorted(KINDS)))
    if "absent_or_not_in" in condition and ("keyword" not in condition
                                            or not isinstance(condition["absent_or_not_in"], list)):
        errors.append("require: absent_or_not_in needs a keyword and a list")
    if "equals" in condition and not isinstance(condition["equals"], (bool, int, str, type(None))):
        errors.append("require: equals must be a constant")
    return errors


def _shape_errors(rule, runtime=False):
    # Shipped rules carry the CVE severity that decides block or review; drafts do not.
    keys = (RULE_KEYS - {"examples"}) | {"cve_severity", "precision_hold"} if runtime else RULE_KEYS
    if not isinstance(rule, dict) or set(rule) != keys:
        return ["rule: keys must be exactly " + ", ".join(sorted(keys))]
    errors = []
    if not (isinstance(rule["rule_id"], str) and RULE_ID.match(rule["rule_id"])):
        errors.append("rule_id: lowercase letters, digits and hyphens")
    if not (isinstance(rule["cve_ids"], list) and rule["cve_ids"] and all(
            isinstance(cve, str) and CVE_ID.match(cve) for cve in rule["cve_ids"])):
        errors.append("cve_ids: need CVE ids")
    if runtime and (rule["cve_severity"] not in {None, "LOW", "MEDIUM", "HIGH", "CRITICAL"}
                    or not isinstance(rule["precision_hold"], bool)
                    or rule["severity"] != ("block" if rule["cve_severity"] in {"MEDIUM", "HIGH", "CRITICAL"}
                                            and not rule["precision_hold"] else "review")):
        errors.append("severity: block exactly for MEDIUM, HIGH and CRITICAL CVEs not held for precision")
    elif not runtime and rule["severity"] != "review":
        errors.append("severity: drafted rules start as review")
    for name in ("family", "title", "fix"):
        try:
            if not (isinstance(rule[name], str) and 0 < len(rule[name]) <= MAX_TEXT):
                raise ValueError
            require_english(rule[name])
        except ValueError:
            errors.append(name + ": need printable ASCII text up to {} characters".format(MAX_TEXT))
    if not (isinstance(rule["call"], list) and rule["call"] and all(
            isinstance(name, str) and CALL.match(name) for name in rule["call"])):
        errors.append("call: need dotted names such as yaml.load or *.execute")
    if not isinstance(rule["require"], list):
        errors.append("require: need a list")
    else:
        for condition in rule["require"]:
            errors += _condition_errors(condition)
    if runtime:
        return errors
    examples = rule["examples"]
    if not (isinstance(examples, dict) and set(examples) == {"vulnerable", "fixed", "negative"} and all(
            isinstance(items, list) and items and all(isinstance(item, str) for item in items)
            for items in examples.values())):
        errors.append("examples: need non-empty vulnerable, fixed and negative lists of source text")
    return errors


def load_runtime(document):
    """Validate shipped rule data (examples stripped) and return its rules."""
    if not isinstance(document, dict) or document.get("schema_version") != 1 or not isinstance(
            document.get("rules"), list):
        raise ValueError("invalid change rule data")
    for rule in document["rules"]:
        errors = _shape_errors(rule, runtime=True)
        if errors:
            raise ValueError("invalid change rule {}: {}".format(rule.get("rule_id") if isinstance(rule, dict)
                                                                 else None, errors[0]))
    return document["rules"]


def validate_rule(rule):
    """Return reasons to reject a drafted rule; its own examples must behave."""
    errors = _shape_errors(rule)
    if errors:
        return errors
    compiled = compile_rules([rule])
    for role, expected in (("vulnerable", True), ("fixed", False), ("negative", False)):
        for index, source in enumerate(rule["examples"][role]):
            findings, notes = scan(compiled, source)
            if notes:
                errors.append("examples.{}[{}]: does not parse".format(role, index))
            elif bool(findings) != expected:
                errors.append("examples.{}[{}]: {}".format(role, index, "not flagged" if expected else "flagged"))
    return errors
