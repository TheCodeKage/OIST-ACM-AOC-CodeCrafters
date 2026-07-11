"""
Static call graph builder.

Scope (problem-statement.md Section 3, "Reachable (static)"): a path exists
in the call graph, ignoring runtime conditionals, from any entry point to
the flagged function.

This is deliberately a *name-resolution* approximation, not full points-to
analysis. Decorators, dynamic dispatch, and reflection are known blind spots
(problem-statement.md Section 1) — that gap is exactly what Stage 2 exists
to catch, so don't over-invest here trying to close it.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

IGNORED_DIR_NAMES = {".venv", "venv", "__pycache__", "tests", "test", ".git"}


@dataclass
class FunctionNode:
    qualname: str          # e.g. "app.routes.upload_endpoint" or "app.services.upload.UploadHandler.save_file"
    file: str
    lineno: int
    calls: set[str] = field(default_factory=set)   # best-effort resolved callee names, unqualified


class CallGraph:
    def __init__(self) -> None:
        self.functions: dict[str, FunctionNode] = {}

    def add_function(self, node: FunctionNode) -> None:
        self.functions[node.qualname] = node

    def find_path(self, start: str, target: str) -> list[str] | None:
        if start not in self.functions:
            return None
        if start == target:
            return [start]
        visited = {start}
        queue: list[list[str]] = [[start]]
        while queue:
            path = queue.pop(0)
            current = self.functions.get(path[-1])
            if current is None:
                continue
            for callee in current.calls:
                # ── NEW: check if this external call IS the target ──
                if callee == target:
                    return path + [target]
                resolved = self._resolve(callee)
                if resolved is None or resolved in visited:
                    continue
                new_path = path + [resolved]
                if resolved == target:
                    return new_path
                visited.add(resolved)
                queue.append(new_path)
        return None

    def _resolve(self, callee_name: str) -> str | None:
        """Match a bare or dotted call name against known qualnames by exact
        match or suffix match (handles `self.foo()` -> `Class.foo`, and bare
        `helper()` calls within the same module)."""
        if callee_name in self.functions:
            return callee_name
        for qualname in self.functions:
            if qualname == callee_name or qualname.endswith("." + callee_name):
                return qualname
        # Fallback: for instance calls like `handler.process` or `self.save_file`,
        # try matching just the method name (last component) against qualname suffixes
        if "." in callee_name:
            last_part = callee_name.split(".")[-1]
            for qualname in self.functions:
                if qualname.endswith("." + last_part):
                    return qualname
        return None


class _ModuleVisitor(ast.NodeVisitor):
    """Records every function/method def in a module and, for each, the set
    of call expressions found anywhere inside its body."""

    def __init__(self, module_qualname: str, file_path: str, graph: CallGraph):
        self.module_qualname = module_qualname
        self.file_path = file_path
        self.graph = graph
        self._class_stack: list[str] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        for child in node.body:
            self.visit(child)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_func(node)

    def _visit_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualname = ".".join([self.module_qualname, *self._class_stack, node.name])
        fn = FunctionNode(qualname=qualname, file=self.file_path, lineno=node.lineno)
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                name = self._call_name(sub.func)
                if name:
                    fn.calls.add(name)
        self.graph.add_function(fn)
        # Visit nested defs (closures/inner functions get their own qualname
        # entries) without double-walking calls already captured above.
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.visit(child)

    @staticmethod
    def _call_name(func_expr: ast.expr) -> str | None:
        if isinstance(func_expr, ast.Name):
            return func_expr.id
        if isinstance(func_expr, ast.Attribute):
            # Build full dotted name: yaml.load, os.path.join, etc.
            parts = [func_expr.attr]
            value = func_expr.value
            while isinstance(value, ast.Attribute):
                parts.append(value.attr)
                value = value.value
            if isinstance(value, ast.Name):
                parts.append(value.id)
            return ".".join(reversed(parts))  # ← "yaml.load(...)" now returns "yaml.load"
        return None


def module_qualname_for(file_path: Path, root: Path) -> str:
    rel = file_path.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts else file_path.stem


def build_graph(app_root: str | Path) -> CallGraph:
    root = Path(app_root).resolve()
    graph = CallGraph()
    for py_file in root.rglob("*.py"):
        rel_parts = py_file.relative_to(root).parts
        if any(part in IGNORED_DIR_NAMES for part in rel_parts):
            continue
        try:
            tree = ast.parse(py_file.read_text(), filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue
        module_qualname = module_qualname_for(py_file, root)
        _ModuleVisitor(module_qualname, str(py_file), graph).visit(tree)
    return graph
