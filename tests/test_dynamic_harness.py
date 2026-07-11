import sys
from pathlib import Path

FIXTURE_ROOT = str(Path(__file__).parent / "fixtures" / "dummy_target_app")
if FIXTURE_ROOT not in sys.path:
    sys.path.insert(0, FIXTURE_ROOT)

from src.dynamic_harness import EntryPointDriver, patch_flagged_function  # noqa: E402


def test_patch_logs_invocation_when_reached(tmp_path):
    driver = EntryPointDriver(FIXTURE_ROOT)
    target_file = str(tmp_path / "out.bin")

    with patch_flagged_function("app.services.upload", "UploadHandler.save_file") as log:
        driver.drive_callable(
            "app.routes",
            "upload_endpoint",
            {"filename": target_file, "contents": b"hello"},
        )

    assert log.fired is True
    assert Path(target_file).read_bytes() == b"hello"


def test_patch_does_not_fire_when_unreached():
    driver = EntryPointDriver(FIXTURE_ROOT)
    with patch_flagged_function("app.services.upload", "UploadHandler.save_file") as log:
        driver.drive_callable("app.routes", "unrelated_endpoint", {})

    assert log.fired is False
