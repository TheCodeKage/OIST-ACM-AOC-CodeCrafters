from app.services.upload import UploadHandler


def upload_endpoint(filename: str, contents: bytes):
    """Entry point 1 -- reaches the flagged function via UploadHandler."""
    handler = UploadHandler()
    return handler.process(filename, contents)


def unrelated_endpoint():
    """Entry point 2 -- deliberately does NOT reach the flagged function.
    Use this one to exercise the Not-Reachable path."""
    return "ok"
