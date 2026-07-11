"""
Monkeypatch dynamic confirmation harness (problem-statement.md Section 3,
Stage 2). Wraps the flagged function so any invocation is logged, then
drives one real entry point with a hypothesized input. The only question
Stage 2 answers: did the wrapped function fire at least once?
"""
from __future__ import annotations

import importlib
import inspect
import os.path
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class InvocationLog:
    fired: bool = False
    call_args: list[tuple[Any, ...]] = field(default_factory=list)
    call_kwargs: list[dict[str, Any]] = field(default_factory=list)


def _import_owner_and_attr(module_path: str, func_name: str) -> tuple[Any, Callable, str]:
    """module_path like 'app.services.upload', func_name like 'save_file' or
    a dotted class path like 'UploadHandler.save_file'."""
    module = importlib.import_module(module_path)
    parts = func_name.split(".")
    owner: Any = module
    for part in parts[:-1]:
        owner = getattr(owner, part)
    attr_name = parts[-1]
    return owner, getattr(owner, attr_name), attr_name


def entry_point_param_names(module_path: str, func_name: str) -> list[str]:
    """Introspects the REAL parameter names of an entry point via
    inspect.signature -- ground truth, not a guess. This is handed to the
    hypothesis-generation prompt so the LLM only has to supply values, not
    reverse-engineer the call shape from prose. (A shape mismatch here was
    a real bug: the model kept guessing an {"args": [...], "kwargs": {...}}
    envelope that didn't match how the entry point actually gets called.)"""
    _, func, _ = _import_owner_and_attr(module_path, func_name)
    sig = inspect.signature(func)
    return [name for name in sig.parameters if name not in ("self", "cls")]


@contextmanager
def patch_flagged_function(module_path: str, func_name: str):
    """Patches module_path.func_name to log invocation. Yields an
    InvocationLog. Always restores the original, even if the driven entry
    point raises — a raised exception is not itself evidence either way."""
    log = InvocationLog()
    owner, original, attr_name = _import_owner_and_attr(module_path, func_name)

    def _wrapper(*args: Any, **kwargs: Any) -> Any:
        log.fired = True
        log.call_args.append(args)
        log.call_kwargs.append(kwargs)
        return original(*args, **kwargs)

    setattr(owner, attr_name, _wrapper)
    try:
        yield log
    finally:
        setattr(owner, attr_name, original)


class EntryPointDriver:
    """Drives a real entry point with a hypothesized input. Two shapes
    supported for MVP: a plain callable, and a Flask test-client route.
    Extend this class (not nodes.py) if B's fixture needs a third shape
    (e.g. CLI arg parsing) — keep the branching in one place."""

    def __init__(self, target_app_root: str):
        if target_app_root not in sys.path:
            sys.path.insert(0, target_app_root)

        parent = os.path.dirname(os.path.abspath(target_app_root))
        if parent not in sys.path:
            sys.path.insert(0, parent)

    def drive_callable(self, module_path: str, func_name: str, kwargs: dict) -> Any:
        """kwargs keys must match the entry point's real parameter names
        (see entry_point_param_names) -- called as func(**kwargs), no
        positional-args guessing."""
        _, func, _ = _import_owner_and_attr(module_path, func_name)
        return func(**kwargs)

    def drive_flask_route(
        self,
        flask_app_import: str,   # "module_path:app_variable"
        route: str,
        method: str,
        hypothesis_input: dict,
    ) -> Any:
        module_path, app_var = flask_app_import.split(":")
        module = importlib.import_module(module_path)
        flask_app = getattr(module, app_var)
        client = flask_app.test_client()
        request_method = getattr(client, method.lower())
        return request_method(
            route,
            data=hypothesis_input.get("data"),
            json=hypothesis_input.get("json"),
            query_string=hypothesis_input.get("query_string"),
        )

    def drive_fastapi_route(
            self,
            fastapi_app_import: str,  # "module_path:factory_or_variable"
            route: str,
            method: str,
            hypothesis_input: dict,
    ) -> Any:
        """Drive a FastAPI route using Starlette's TestClient."""
        module_path, app_var = fastapi_app_import.split(":")
        module = importlib.import_module(module_path)
        app_or_factory = getattr(module, app_var)
        # Support both app instances and factory functions
        if callable(app_or_factory):
            try:
                app = app_or_factory()
            except TypeError:
                app = app_or_factory
        else:
            app = app_or_factory

        from starlette.testclient import TestClient
        client = TestClient(app)
        request_method = getattr(client, method.lower())
        return request_method(
            route,
            data=hypothesis_input.get("data"),
            json=hypothesis_input.get("json"),
            params=hypothesis_input.get("query_string"),
            content=hypothesis_input.get("content"),
        )
