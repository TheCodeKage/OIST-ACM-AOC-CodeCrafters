"""
The two shapes from the interface contract (build-plan.md Section 2).
Sync this file with Engineer B before either of you writes pipeline code —
it is the single highest-leverage artifact of the first 30 minutes.
"""
from __future__ import annotations

from typing import Literal, Optional, TypedDict

from pydantic import BaseModel, Field

# The three label strings, verbatim (problem-statement.md Section 2). Do not
# let these drift into synonyms anywhere in the codebase.
Label = Literal["Confirmed-Reachable", "Static-Match-Only", "Not-Reachable"]


class CVETarget(BaseModel):
    """Interface contract 2.1 — what a CVE + entry-point manifest looks like.
    Engineer B's manifest must serialize to exactly this."""

    cve_id: str
    flagged_function: str          # e.g. "UploadHandler.save_file"
    flagged_module: str            # importable dotted path, e.g. "app.services.upload"
    flagged_file: str              # path, for display/trace only
    entry_points: list[str] = Field(default_factory=list)   # qualnames as they appear in the call graph

    advisory_summary: str = ""
    function_signature: Optional[str] = None

    # Driver metadata — how dynamic_harness actually invokes an entry point.
    driver_kind: Literal["callable", "flask_route", "fastapi_route"] = "callable"
    flask_app_import: Optional[str] = None  # "module_path:app_variable", flask_route only
    fastapi_app_import: Optional[str] = None  # "module_path:factory_or_var", fastapi_route only
    entry_point_routes: dict[str, dict] = Field(default_factory=dict)
    # entry_point_routes["app.routes.upload_endpoint"] = {"route": "/upload", "method": "POST"}


class TraceStep(BaseModel):
    stage: str        # "static" | "hypothesis" | "dynamic" | "decide"
    detail: str


class EngineOutput(BaseModel):
    """Interface contract 2.2 — what the pipeline returns for the CLI to render."""

    cve_id: str
    label: Label
    trace: list[TraceStep]
    static_path: Optional[list[str]] = None
    hypothesis_attempts: list[str] = Field(default_factory=list)


class ReachState(TypedDict, total=False):
    """Internal LangGraph state — not part of the interface contract, safe
    to reshape without telling B, as long as run_pipeline()'s return type
    stays EngineOutput."""

    target: CVETarget
    target_app_root: str
    static_path: Optional[list[str]]
    matched_entry_point: Optional[str]
    hypothesis_attempts: list[str]
    retry_count: int
    dynamic_fired: bool
    label: Optional[Label]
    trace: list[TraceStep]
