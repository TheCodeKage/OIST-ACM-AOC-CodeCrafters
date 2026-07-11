class UploadHandler:
    def process(self, filename: str, contents: bytes):
        return self.save_file(filename, contents)

    def save_file(self, filename: str, contents: bytes):
        """Stand-in for a flagged vulnerable function, e.g. an unsanitized
        path-traversal-style CVE. Real filesystem write is fine here --
        this fixture only exists to exercise graph_builder + dynamic_harness."""
        with open(filename, "wb") as f:
            f.write(contents)
        return filename
