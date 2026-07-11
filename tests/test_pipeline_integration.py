import sys
from pathlib import Path
from unittest.mock import patch

FIXTURE_ROOT = str(Path(__file__).parent / "fixtures" / "dummy_target_app")
if FIXTURE_ROOT not in sys.path:
    sys.path.insert(0, FIXTURE_ROOT)

from src.hypothesis import Hypothesis  # noqa: E402
from src.pipeline import run_pipeline  # noqa: E402
from src.schemas import CVETarget  # noqa: E402


def _target(entry_points):
    return CVETarget(
        cve_id="DUMMY-0001",
        flagged_function="UploadHandler.save_file",
        flagged_module="app.services.upload",   # deliberately NOT app.routes
        flagged_file="app/services/upload.py",
        entry_points=entry_points,
        advisory_summary="path traversal",
        function_signature="def save_file(self, filename, contents)",
    )


def test_dynamic_confirm_drives_entry_point_module_not_flagged_module(tmp_path):
    """Regression test: dynamic_confirm_node must import the callable from
    the entry point's own module (app.routes), not target.flagged_module
    (app.services.upload) where the vulnerable function lives -- those are
    different modules and conflating them was a real bug."""
    out_file = str(tmp_path / "out.bin")
    fake_hyp = Hypothesis(
        reasoning="test stub",
        driver_kind="callable",
        hypothesis_input={"filename": out_file, "contents": b"hello"},
    )

    with patch("src.nodes.generate_hypothesis", return_value=fake_hyp):
        result = run_pipeline(_target(["app.routes.upload_endpoint"]), FIXTURE_ROOT)

    assert result.label == "Confirmed-Reachable"
    assert Path(out_file).read_bytes() == b"hello"


def test_static_match_only_when_hypothesis_never_fires(tmp_path):
    fake_hyp = Hypothesis(
        reasoning="deliberately wrong args",
        driver_kind="callable",
        hypothesis_input={"wrong_param": "value"},  # wrong parameter name
    )

    with patch("src.nodes.generate_hypothesis", return_value=fake_hyp):
        result = run_pipeline(_target(["app.routes.upload_endpoint"]), FIXTURE_ROOT)

    assert result.label == "Static-Match-Only"
    assert len(result.hypothesis_attempts) == 3   # 1 initial + 2 revised retries, per MAX_ATTEMPTS
