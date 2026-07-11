"""
Runs the real end-to-end pipeline (static -> hypothesis via Groq ->
dynamic -> decide) against the dummy fixture app. Requires GROQ_API_KEY to
be set (see .env.example).

Usage:
    uv run python scripts/smoke_test.py
"""
from __future__ import annotations

import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "dummy_target_app"))

load_dotenv()

from src import CVETarget, run_pipeline  # noqa: E402


def main() -> None:
    reachable_target = CVETarget(
        cve_id="DUMMY-0001",
        flagged_function="UploadHandler.save_file",
        flagged_module="app.services.upload",
        flagged_file="app/services/upload.py",
        entry_points=["app.routes.upload_endpoint"],
        advisory_summary=(
            "Unsanitized filename passed directly to a file write, "
            "allowing path traversal if the caller controls the filename."
        ),
        function_signature="def save_file(self, filename: str, contents: bytes)",
    )

    not_reachable_target = reachable_target.model_copy(
        update={"cve_id": "DUMMY-0002", "entry_points": ["app.routes.unrelated_endpoint"]}
    )

    for target in (reachable_target, not_reachable_target):
        result = run_pipeline(target, str(ROOT / "tests" / "fixtures" / "dummy_target_app"))
        print(f"\n=== {result.cve_id} -> {result.label} ===")
        for step in result.trace:
            print(f"  [{step.stage}] {step.detail}")


if __name__ == "__main__":
    main()
