from pathlib import Path

from src.graph_builder import build_graph

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "dummy_target_app"


def test_finds_reachable_path():
    graph = build_graph(FIXTURE_ROOT)
    path = graph.find_path(
        "app.routes.upload_endpoint",
        "app.services.upload.UploadHandler.save_file",
    )
    assert path is not None
    assert path[0] == "app.routes.upload_endpoint"
    assert path[-1] == "app.services.upload.UploadHandler.save_file"


def test_no_path_for_unrelated_entry_point():
    graph = build_graph(FIXTURE_ROOT)
    path = graph.find_path(
        "app.routes.unrelated_endpoint",
        "app.services.upload.UploadHandler.save_file",
    )
    assert path is None
