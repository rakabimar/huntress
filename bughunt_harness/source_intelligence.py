"""Progressive, commit-scoped source security intelligence.

The index is intentionally best effort.  Python uses the standard AST; other
languages use small framework adapters and honest confidence labels.  UNKNOWN
is an analysis result, never evidence that a control is absent.
"""

from __future__ import annotations

import ast
import re
from collections import Counter, defaultdict
from pathlib import Path

LANGUAGES = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".php": "PHP",
    ".java": "Java", ".kt": "Kotlin", ".go": "Go", ".rb": "Ruby",
    ".rs": "Rust", ".c": "C", ".h": "C/C++", ".cc": "C++", ".cpp": "C++",
}

TREE_SITTER_LANGUAGE = {
    "JavaScript": "javascript", "TypeScript": "typescript", "PHP": "php",
    "Java": "java", "Kotlin": "kotlin", "Go": "go", "Ruby": "ruby",
    "Rust": "rust", "C": "c", "C++": "cpp", "C/C++": "cpp",
}

TREE_SYMBOL_KINDS = {
    "function_declaration": "function", "function_definition": "function",
    "function_item": "function", "function": "function", "method": "method",
    "singleton_method": "method", "method_definition": "method",
    "method_declaration": "method", "method_definition": "method",
    "function_definition": "function", "function_declaration": "function",
    "class_declaration": "class", "class_definition": "class", "class": "class",
    "interface_declaration": "class", "object_declaration": "class",
}

TREE_CALL_KINDS = {
    "call_expression", "function_call_expression", "method_invocation",
    "call", "command", "invocation_expression",
}

CONTROL_RE = re.compile(
    r"(?i)\b(require(?:owner|role|permission|auth)|authoriz\w*|permit\w*|"
    r"ensure(?:owner|tenant|admin)|check(?:owner|permission|tenant)|canaccess|"
    r"isauthenticated|tenantscope|preauthorize|permission_classes|csrf\w*|"
    r"validatesignature|validateexternalurl|safepath|sanitize\w*)\b"
)
SINKS = {
    "sql": re.compile(r"(?i)\b(execute|rawquery|queryraw|cursor\.execute|jdbcTemplate)\s*\("),
    "filesystem": re.compile(r"(?i)\b(open|writeFile|readFile|extract|unzip|createWriteStream)\s*\("),
    "process": re.compile(r"(?i)\b(exec|spawn|system|popen|ProcessBuilder|Runtime\.getRuntime)\s*\("),
    "network": re.compile(r"(?i)\b(fetch|axios|requests\.(?:get|post)|httpClient|urlopen)\s*\("),
    "deserialization": re.compile(r"(?i)\b(pickle\.loads|yaml\.load|ObjectInputStream|unserialize)\s*\("),
    "dynamic_code": re.compile(r"(?i)\b(eval|exec|Function)\s*\("),
}
SOURCE_RE = re.compile(r"(?i)\b(request\.(?:args|form|json|headers|body|query|params)|req\.(?:body|query|params|headers)|graphql|message|argv)\b")


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return ""


def _literal(node: ast.AST) -> str:
    return str(node.value) if isinstance(node, ast.Constant) and isinstance(node.value, str) else ""


class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, file: str, text: str) -> None:
        self.file, self.text = file, text
        self.stack: list[str] = []
        self.symbols: list[dict] = []
        self.entry_points: list[dict] = []
        self.imports: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            self.imports[item.asname or item.name.split(".", 1)[0]] = item.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for item in node.names:
            self.imports[item.asname or item.name] = f"{module}.{item.name}".strip(".")

    @staticmethod
    def _local_dataflow(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict:
        """Conservative LEVEL_1 intra-function assignment/argument flow."""
        tainted: set[str] = set()
        transformations: list[dict] = []
        confirmed: list[dict] = []

        def expression_text(value: ast.AST) -> str:
            try:
                return ast.unparse(value)
            except Exception:  # pragma: no cover - unparsing is stdlib-stable
                return ""

        def influenced(value: ast.AST) -> bool:
            text = expression_text(value)
            if SOURCE_RE.search(text):
                return True
            return any(isinstance(item, ast.Name) and item.id in tainted for item in ast.walk(value))

        for item in ast.walk(node):
            if isinstance(item, (ast.Assign, ast.AnnAssign)):
                value = item.value
                if value is None or not influenced(value):
                    continue
                targets = item.targets if isinstance(item, ast.Assign) else [item.target]
                for target in targets:
                    for name in (part.id for part in ast.walk(target) if isinstance(part, ast.Name)):
                        tainted.add(name)
                        transformations.append({"kind": "assignment", "target": name, "line": item.lineno})
            if not isinstance(item, ast.Call):
                continue
            sink = next((kind for kind, pattern in SINKS.items() if pattern.search(f"{_name(item.func)}(")), None)
            if sink and any(influenced(arg) for arg in (*item.args, *(kw.value for kw in item.keywords))):
                confirmed.append({"sink": sink, "call": _name(item.func), "line": item.lineno})
        return {
            "level": "LEVEL_1" if confirmed else "LEVEL_0",
            "classification": "LOCAL_FLOW_CONFIRMED" if confirmed else "SOURCE_AND_SINK_PRESENT",
            "tainted_variables": sorted(tainted),
            "transformations": transformations[:100],
            "confirmed_sinks": confirmed[:50],
            "unknown_transformations": not bool(confirmed),
        }

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualified = ".".join([*self.stack, node.name])
        decorators = [_name(item) for item in node.decorator_list]
        callees = sorted({_name(item.func) for item in ast.walk(node) if isinstance(item, ast.Call) and _name(item.func)})
        inputs = [arg.arg for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)]
        body_text = ast.get_source_segment(self.text, node) or ""
        call_names = [_name(item.func) for item in ast.walk(node) if isinstance(item, ast.Call)]
        controls = sorted({
            name for name in (*decorators, *call_names)
            if name and CONTROL_RE.search(name)
        })
        side_effects = [name for name, pattern in SINKS.items() if pattern.search(body_text)]
        attacker_input = bool(SOURCE_RE.search(body_text))
        routes = []
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            called = _name(decorator.func)
            method = called.rsplit(".", 1)[-1].upper()
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "ROUTE"}:
                continue
            path = _literal(decorator.args[0]) if decorator.args else ""
            if not path:
                continue
            if method == "ROUTE":
                methods = next((kw.value for kw in decorator.keywords if kw.arg == "methods"), None)
                values = [_literal(item).upper() for item in methods.elts] if isinstance(methods, (ast.List, ast.Tuple)) else ["ANY"]
            else:
                values = [method]
            framework = "FastAPI/Flask" if called.split(".")[0] in {"app", "router", "blueprint", "bp"} else "Python decorator"
            for value in values:
                routes.append({
                    "method": value, "path": path, "handler": qualified,
                    "middleware": controls, "file": self.file, "line": node.lineno,
                    "framework": framework, "confidence": "EXACT",
                })
        assumptions = []
        guarantees = []
        unresolved = []
        if routes and not controls:
            unresolved.append("authorization may be inherited from application/router middleware or a callee")
        if controls:
            guarantees.append("visible security control executes on this call path")
        if attacker_input:
            assumptions.append("one or more values may originate at an untrusted request boundary")
        symbol = {
            "language": "Python", "file": self.file, "line_start": node.lineno,
            "line_end": getattr(node, "end_lineno", node.lineno), "name": node.name,
            "qualified_name": qualified, "kind": "handler" if routes else "method" if self.stack else "function",
            "confidence": "EXACT", "assumptions": assumptions, "guarantees": guarantees,
            "controls": controls, "inputs": inputs, "outputs": [], "callers": [], "callees": callees,
            "side_effects": side_effects, "trust_boundary": "request_to_application" if routes else "",
            "unresolved_assumptions": unresolved,
            "metadata": {
                "decorators": decorators, "imports": dict(self.imports),
                "attacker_input": attacker_input,
                "control_evidence": [
                    {"control": name, "basis": "decorator" if name in decorators else "function_call"}
                    for name in controls
                ],
                "dataflow": self._local_dataflow(node) if attacker_input and side_effects else {},
            },
        }
        self.symbols.append(symbol); self.entry_points.extend(routes)
        self.stack.append(node.name); self.generic_visit(node); self.stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qualified = ".".join([*self.stack, node.name])
        self.symbols.append({
            "language": "Python", "file": self.file, "line_start": node.lineno,
            "line_end": getattr(node, "end_lineno", node.lineno), "name": node.name,
            "qualified_name": qualified, "kind": "class", "confidence": "EXACT", "metadata": {},
        })
        self.stack.append(node.name); self.generic_visit(node); self.stack.pop()


FRAMEWORK_ROUTES = (
    ("Express", re.compile(r"\b(?:app|router)\.(get|post|put|patch|delete|options|head)\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*([^\n;]+)", re.I)),
    ("Laravel", re.compile(r"\bRoute::(get|post|put|patch|delete|options)\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*([^\n;]+)", re.I)),
    ("Spring", re.compile(r"@(Get|Post|Put|Patch|Delete)Mapping\s*\(\s*(?:value\s*=\s*)?['\"]([^'\"]+)['\"]", re.I)),
    ("Go", re.compile(r"\b(?:http\.)?HandleFunc\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_][\w.]*)", re.I)),
    ("Gin/Echo", re.compile(r"\b(?:router|r|e)\.(GET|POST|PUT|PATCH|DELETE)\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*([^\n;)]+)", re.I)),
    ("Rails", re.compile(r"^\s*(get|post|put|patch|delete)\s+['\"]([^'\"]+)['\"]\s*(?:=>|,\s*to:)\s*['\"]([^'\"]+)", re.I | re.M)),
    ("Django", re.compile(r"\b(?:path|re_path)\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_][\w.]*)", re.I)),
    ("WordPress", re.compile(r"\bregister_rest_route\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]", re.I)),
    ("WordPress Action", re.compile(r"\badd_action\s*\(\s*['\"](wp_ajax(?:_nopriv)?_[^'\"]+)['\"]\s*,\s*([A-Za-z_][\w.]*)", re.I)),
)

FUNC_RE = re.compile(r"(?m)^\s*(?:export\s+)?(?:async\s+)?(?:function|def|func)\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)")


class SourceIntelligence:
    def __init__(self, snapshot: Path, *, max_file_bytes: int = 256 * 1024, max_files: int = 5000) -> None:
        self.snapshot = snapshot
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files

    def analyze(self) -> dict:
        symbols: list[dict] = []
        entries: list[dict] = []
        languages: Counter[str] = Counter()
        controls: dict[str, dict] = {}
        data_stores: set[str] = set()
        integrations: set[str] = set()
        sensitive_assets: set[str] = set()
        security_files: list[str] = []
        unresolved: list[str] = []
        files_read = 0
        for path in self.snapshot.rglob("*"):
            if files_read >= self.max_files:
                unresolved.append(f"source index stopped at the configured {self.max_files}-file budget")
                break
            if not path.is_file() or path.suffix.lower() not in LANGUAGES or path.stat().st_size > self.max_file_bytes:
                continue
            files_read += 1
            rel = str(path.relative_to(self.snapshot))
            language = LANGUAGES[path.suffix.lower()]; languages[language] += 1
            text = path.read_text(encoding="utf-8", errors="replace")
            if re.search(r"(?i)(auth|permission|policy|tenant|session|webhook|upload|parser|plugin)", rel):
                security_files.append(rel)
            parsed_for_file: list[dict] = []
            if language == "Python":
                try:
                    visitor = _PythonVisitor(rel, text); visitor.visit(ast.parse(text, filename=rel))
                    parsed_for_file = visitor.symbols; entries.extend(visitor.entry_points)
                except SyntaxError:
                    unresolved.append(f"Python AST parse failed: {rel}")
            else:
                parsed_symbols = self._tree_sitter_symbols(rel, language, text)
                parsed_for_file = parsed_symbols or self._fallback_symbols(rel, language, text)
                entries.extend(self._framework_entries(rel, language, text))
            symbols.extend(parsed_for_file)
            for symbol in parsed_for_file:
                for control in symbol.get("controls", []):
                    key = control.lower()
                    item = controls.setdefault(control.lower(), {
                        "name": control, "locations": [], "confidence": "HIGH",
                        "basis": "structural_call_decorator_or_annotation",
                    })
                    if len(item["locations"]) < 20:
                        item["locations"].append({"file": rel, "line": symbol.get("line_start", 1)})
            for match in CONTROL_RE.finditer(text):
                name = match.group(1)
                item = controls.setdefault(name.lower(), {
                    "name": name, "locations": [], "confidence": "MEDIUM",
                    "basis": "lexical_name_candidate",
                })
                line = text.count("\n", 0, match.start()) + 1
                if len(item["locations"]) < 20:
                    item["locations"].append({"file": rel, "line": line})
            for name, pattern in {
                "PostgreSQL/SQL": r"(?i)\b(postgres|sqlalchemy|prisma|sequelize|jdbc|activerecord|gorm)\b",
                "Redis": r"(?i)\bredis\b", "MongoDB": r"(?i)\b(mongo|mongoose)\b",
            }.items():
                if re.search(pattern, text): data_stores.add(name)
            for name, pattern in {
                "HTTP client": r"(?i)\b(fetch|axios|requests\.|httpClient|urlopen)\b",
                "message/queue": r"(?i)\b(kafka|rabbitmq|sqs|celery|sidekiq)\b",
                "plugin/extension": r"(?i)\b(plugin|extension|hook|callback)\b",
            }.items():
                if re.search(pattern, text): integrations.add(name)
            for name, pattern in {
                "credentials/tokens": r"(?i)\b(password|credential|api[_-]?key|token|secret)\b",
                "tenant-owned records": r"(?i)\b(tenant|organization|workspace|account)_id\b",
                "payments": r"(?i)\b(payment|invoice|refund|credit)\b",
                "uploaded files": r"(?i)\b(upload|archive|attachment)\b",
            }.items():
                if re.search(pattern, text): sensitive_assets.add(name)

        self._resolve_callers(symbols)
        invariants = self._infer_invariants(entries)
        components = self._components()
        trust_boundaries = self._trust_boundaries(entries, integrations)
        architecture_summary = self._summary(languages, entries, controls, data_stores, integrations, sensitive_assets)
        if entries and not controls:
            unresolved.append("entry points were found but no reusable security control could be identified")
        unresolved.append("deployment-wide interceptors, generated routes, reflection, and runtime configuration remain unknown until correlated")
        return {
            "architecture_summary": architecture_summary,
            "components": components, "entry_points": entries[:2000],
            "trust_boundaries": trust_boundaries, "security_controls": list(controls.values())[:500],
            "sensitive_assets": sorted(sensitive_assets), "external_integrations": sorted(integrations),
            "data_stores": sorted(data_stores), "security_invariants": invariants,
            "unresolved_questions": list(dict.fromkeys(unresolved))[:200],
            "symbols": symbols[:20_000],
            "metadata": {"languages": dict(languages), "files_read": files_read,
                         "security_critical_files": security_files[:200],
                         "analysis_levels": ["AST" if languages.get("Python") else "syntax-aware", "tree-sitter_optional", "framework_adapters", "lexical_fallback"]},
        }

    def _tree_sitter_symbols(self, file: str, language: str, text: str) -> list[dict]:
        """Best-effort structural symbols; absence/failure honestly falls back.

        Tree-sitter identifies syntax and local call constructs. It does not
        claim type-aware name resolution, framework interception, or dynamic
        dispatch; those remain HIGH/UNKNOWN until a deeper tool resolves them.
        """
        parser_name = TREE_SITTER_LANGUAGE.get(language)
        if not parser_name:
            return []
        try:
            from tree_sitter_language_pack import get_parser  # type: ignore
            parser = get_parser(parser_name)
            raw = text.encode("utf-8", "replace")
            root = parser.parse(raw).root_node
        except (ImportError, LookupError, RuntimeError, ValueError):
            return []

        def node_text(node) -> str:
            return raw[node.start_byte:node.end_byte].decode("utf-8", "replace")

        def field(node, *names):
            for name in names:
                child = node.child_by_field_name(name)
                if child is not None:
                    return child
            return None

        def first_named(node, *types):
            return next((child for child in node.named_children if child.type in types), None)

        results: list[dict] = []
        visited = 0

        def walk(node, scope: tuple[str, ...] = ()) -> None:
            nonlocal visited
            visited += 1
            if visited > 100_000:
                return
            symbol_kind = TREE_SYMBOL_KINDS.get(node.type)
            next_scope = scope
            if symbol_kind:
                name_node = field(node, "name", "declarator") or first_named(
                    node, "identifier", "simple_identifier", "type_identifier", "name",
                )
                name = node_text(name_node).strip() if name_node is not None else ""
                name = re.sub(r"[^A-Za-z0-9_$].*$", "", name)
                if name:
                    params_node = field(node, "parameters", "parameter") or first_named(
                        node, "parameters", "formal_parameters", "function_value_parameters",
                        "parameter_list",
                    )
                    inputs = []
                    if params_node is not None:
                        inputs = [part.strip() for part in node_text(params_node).strip("()| ").split(",") if part.strip()][:30]
                    body = node_text(node)
                    callees: set[str] = set()
                    stack = [node]
                    scanned = 0
                    while stack and scanned < 20_000:
                        current = stack.pop(); scanned += 1
                        if current is not node and current.type in TREE_CALL_KINDS:
                            called = field(current, "function", "name", "method") or first_named(
                                current, "identifier", "simple_identifier", "selector_expression",
                                "member_expression", "field_expression",
                            )
                            value = node_text(called).strip() if called is not None else ""
                            if value and len(value) <= 200:
                                callees.add(value)
                        stack.extend(reversed(current.named_children))
                    if symbol_kind == "class":
                        callees.clear()
                        controls, side_effects = [], []
                    else:
                        controls = sorted(set(CONTROL_RE.findall(body)))
                        side_effects = [key for key, pattern in SINKS.items() if pattern.search(body)]
                    qualified = ".".join((*scope, name))
                    results.append({
                        "language": language, "file": file,
                        "line_start": node.start_point[0] + 1,
                        "line_end": node.end_point[0] + 1,
                        "name": name, "qualified_name": qualified,
                        "kind": symbol_kind, "confidence": "EXACT",
                        "assumptions": ["attacker influence is unresolved"] if SOURCE_RE.search(body) else [],
                        "guarantees": ["visible security control executes locally"] if controls else [],
                        "controls": controls, "inputs": inputs, "outputs": [],
                        "callers": [], "callees": sorted(callees), "side_effects": side_effects,
                        "trust_boundary": "", "unresolved_assumptions": [
                            "type resolution, dynamic dispatch, and framework interception remain unresolved"
                        ],
                        "metadata": {
                            "parser": "tree-sitter-language-pack", "node_type": node.type,
                            "call_binding": "unresolved",
                            "control_evidence": [
                                {"control": value, "basis": "syntax_call_or_annotation"}
                                for value in controls
                            ],
                            "attacker_input": bool(SOURCE_RE.search(body)),
                            "dataflow": {
                                "level": "LEVEL_0", "classification": "SOURCE_AND_SINK_PRESENT",
                                "unknown_transformations": True,
                            } if SOURCE_RE.search(body) and side_effects else {},
                        },
                    })
                    if symbol_kind == "class":
                        next_scope = (*scope, name)
            for child in node.named_children:
                walk(child, next_scope)

        walk(root)
        return results

    def _fallback_symbols(self, file: str, language: str, text: str) -> list[dict]:
        result = []
        for match in FUNC_RE.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            nearby = text[match.start():match.start() + 4000]
            result.append({
                "language": language, "file": file, "line_start": line, "line_end": line,
                "name": match.group(1), "qualified_name": match.group(1), "kind": "function",
                "confidence": "HIGH", "inputs": [item.strip() for item in match.group(2).split(",") if item.strip()][:30],
                "controls": sorted(set(CONTROL_RE.findall(nearby))),
                "callees": [], "callers": [], "side_effects": [name for name, pattern in SINKS.items() if pattern.search(nearby)],
                "unresolved_assumptions": ["dynamic dispatch and framework interception are unresolved"], "metadata": {},
            })
        return result

    def _framework_entries(self, file: str, language: str, text: str) -> list[dict]:
        result = []
        for framework, pattern in FRAMEWORK_ROUTES:
            for match in pattern.finditer(text):
                groups = match.groups()
                if framework in {"Go", "Django"}: method, route, handler = "ANY", groups[0], groups[1]
                elif framework == "WordPress": method, route, handler = "ANY", f"/{groups[0]}/{groups[1]}", "registered callback"
                elif framework == "WordPress Action": method, route, handler = "POST", f"/wp-admin/admin-ajax.php?action={groups[0]}", groups[1]
                else: method, route, handler = groups[0].upper(), groups[1], groups[2] if len(groups) > 2 else ""
                line = text.count("\n", 0, match.start()) + 1
                controls = sorted(set(CONTROL_RE.findall(match.group(0))))
                result.append({"method": method, "path": route, "handler": handler.strip(),
                               "middleware": controls, "file": file, "line": line,
                               "framework": framework, "confidence": "HIGH"})
        if file.endswith(("/route.ts", "/route.js")) or re.search(r"(^|/)pages/api/", file):
            for method in re.findall(r"(?m)^\s*export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b", text):
                result.append({"method": method, "path": self._next_path(file), "handler": method,
                               "middleware": [], "file": file, "line": 1,
                               "framework": "Next.js", "confidence": "HIGH"})
        return result

    @staticmethod
    def _next_path(file: str) -> str:
        value = re.sub(r"(^|/)(app|pages)/api/", "/api/", file)
        value = re.sub(r"/(route|index)\.(?:js|ts)$", "", value)
        value = re.sub(r"\[([^]]+)\]", r"{\1}", value)
        return value if value.startswith("/") else "/" + value

    @staticmethod
    def _resolve_callers(symbols: list[dict]) -> None:
        by_name: dict[str, list[dict]] = defaultdict(list)
        for item in symbols: by_name[item.get("name", "")].append(item)
        for caller in symbols:
            for callee_name in caller.get("callees", []):
                short = callee_name.rsplit(".", 1)[-1]
                candidates = by_name.get(short, [])
                resolved = candidates
                confidence = "UNKNOWN"
                basis = "no_static_binding"
                same_file = [item for item in candidates if item.get("file") == caller.get("file")]
                if caller.get("language") == "Python":
                    imports = caller.get("metadata", {}).get("imports", {})
                    imported = imports.get(callee_name) or imports.get(callee_name.split(".", 1)[0])
                    if len(same_file) == 1 and "." not in callee_name:
                        resolved, confidence, basis = same_file, "EXACT", "python_ast_local_binding"
                    elif imported:
                        module = imported.rsplit(".", 1)[0].replace(".", "/")
                        imported_candidates = [
                            item for item in candidates
                            if str(item.get("file", "")).removesuffix(".py").endswith(module)
                        ]
                        if len(imported_candidates) == 1:
                            resolved, confidence, basis = imported_candidates, "EXACT", "python_import_binding"
                    elif len(candidates) == 1:
                        confidence, basis = "MEDIUM", "unique_lexical_candidate_without_import_binding"
                    elif candidates:
                        confidence, basis = "LOW", "ambiguous_lexical_candidates"
                elif len(same_file) == 1:
                    resolved, confidence, basis = same_file, "HIGH", "syntax_local_file_resolution"
                elif len(candidates) == 1:
                    confidence, basis = "MEDIUM", "unique_lexical_candidate"
                elif candidates:
                    confidence, basis = "LOW", "ambiguous_lexical_candidates"
                caller.setdefault("metadata", {}).setdefault("callee_resolution", []).append({
                    "call": callee_name, "confidence": confidence, "basis": basis,
                    "candidate_count": len(resolved),
                })
                for callee in resolved[:20]:
                    callee.setdefault("callers", []).append({
                        "symbol": caller.get("qualified_name"), "file": caller.get("file"),
                        "confidence": confidence, "basis": basis,
                    })

    @staticmethod
    def _infer_invariants(entries: list[dict]) -> list[dict]:
        groups: dict[str, list[dict]] = defaultdict(list)
        for entry in entries:
            shape = re.sub(r"(?::\w+|\{[^}]+\}|<[^>]+>)", "{}", entry["path"])
            shape = re.sub(r"/\{\}(?:/.*)?$", "/{}", shape)
            groups[shape].append(entry)
        result = []
        for component, siblings in groups.items():
            controlled = [item for item in siblings if item.get("middleware")]
            if len(siblings) < 2 or not controlled:
                continue
            common = Counter(name for item in controlled for name in item["middleware"])
            controls = [name for name, count in common.items() if count >= max(1, len(controlled) // 2)]
            outliers = [f"{item['method']} {item['path']} ({item['file']}:{item['line']})" for item in siblings if not item.get("middleware")]
            result.append({
                "component": component,
                "description": f"Sibling operations for {component} should enforce the same ownership/tenant/role controls.",
                "source_evidence": [f"{item['method']} {item['path']}" for item in controlled[:10]],
                "confidence": 0.75 if outliers else 0.65, "supporting_controls": controls,
                "possible_violations": outliers,
                "source_skill": "source-authorization-analysis",
            })
        return result

    def _components(self) -> list[dict]:
        counts: Counter[str] = Counter()
        for path in self.snapshot.rglob("*"):
            if path.is_file(): counts[path.relative_to(self.snapshot).parts[0]] += 1
        return [{"name": name, "file_count": count, "basis": "top_level_source_layout"} for name, count in counts.most_common(50)]

    @staticmethod
    def _trust_boundaries(entries: list[dict], integrations: set[str]) -> list[dict]:
        result = []
        if entries: result.append({"from": "untrusted client", "to": "application entry point", "surfaces": len(entries), "confidence": "HIGH"})
        if "HTTP client" in integrations: result.append({"from": "application", "to": "external network service", "confidence": "MEDIUM"})
        if "message/queue" in integrations: result.append({"from": "message producer", "to": "background consumer", "confidence": "MEDIUM"})
        if "plugin/extension" in integrations: result.append({"from": "extension/plugin", "to": "host application", "confidence": "MEDIUM"})
        return result

    @staticmethod
    def _summary(languages, entries, controls, data_stores, integrations, sensitive_assets) -> str:
        primary = ", ".join(name for name, _ in languages.most_common(4)) or "unknown language"
        return (
            f"Source is primarily {primary}. Indexed {len(entries)} entry points and "
            f"{len(controls)} reusable security-control candidates. Data stores: "
            f"{', '.join(sorted(data_stores)) or 'unresolved'}. External/extension boundaries: "
            f"{', '.join(sorted(integrations)) or 'none identified'}. Sensitive asset classes: "
            f"{', '.join(sorted(sensitive_assets)) or 'unresolved'}."
        )


__all__ = ["SourceIntelligence", "LANGUAGES"]
