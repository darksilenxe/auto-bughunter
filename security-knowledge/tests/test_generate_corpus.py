from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import threading
import unittest
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "security-knowledge" / "tools" / "generate_corpus.py"
APP_MAIN_PATH = REPO_ROOT / "security-knowledge" / "app" / "main.py"
SOURCE_PATH = REPO_ROOT / "security-knowledge" / "sources" / "corpus_sources.json"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader  # nosec B101 - test helper, asserts are intentional
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


generator = load_module(SCRIPT_PATH, "generate_corpus")


class GenerateCorpusTests(unittest.TestCase):
    def test_build_corpus_validates_with_service_schema(self) -> None:
        app_main = load_module(APP_MAIN_PATH, "security_knowledge_main")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            output_path = temp_path / "corpus.json"
            review_path = temp_path / "review.json"
            corpus, review = generator.build_corpus(SOURCE_PATH, output_path, review_path)

            self.assertEqual(len(corpus), 8)
            self.assertEqual(review["summary"]["errors"], 0)

            written = json.loads(output_path.read_text(encoding="utf-8"))
            for item in written:
                validated = app_main.CorpusDocument.model_validate(item)
                self.assertTrue(validated.id)
                self.assertTrue(validated.title)

    def test_build_corpus_deduplicates_near_identical_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            source_path = temp_path / "sources.json"
            source_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "phase": "phase-1",
                        "allowlists": {
                            "sourceTypes": ["portswigger"],
                            "licenses": ["source-url-only"],
                        },
                        "entries": [
                            {
                                "id": "alpha",
                                "title": "Example SQL Injection Guidance",
                                "url": "https://example.test/sql-a",
                                "sourceType": "portswigger",
                                "license": "source-url-only",
                                "topic": "SQL injection guidance",
                                "vulnerabilityClass": "sql injection",
                                "technique": "parameterized queries",
                                "keywords": ["SQLI", "sqli", "prepared statements"],
                                "passage": "Curated note: use parameterized queries and avoid dynamic string concatenation in SQL handlers."
                            },
                            {
                                "id": "beta",
                                "title": "Example SQL Injection Guidance Duplicate",
                                "url": "https://example.test/sql-b",
                                "sourceType": "portswigger",
                                "license": "source-url-only",
                                "topic": "SQL injection guidance",
                                "vulnerabilityClass": "sql injection",
                                "technique": "parameterized queries",
                                "keywords": ["sqli", "prepared statements"],
                                "passage": "Curated note: use parameterized queries and avoid dynamic string concatenation in SQL handlers."
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output_path = temp_path / "corpus.json"
            review_path = temp_path / "review.json"
            corpus, review = generator.build_corpus(source_path, output_path, review_path)

            self.assertEqual(len(corpus), 1)
            self.assertEqual(review["summary"]["warnings"], 1)
            self.assertEqual(review["exceptions"][0]["type"], "duplicate-cluster")
            self.assertEqual(corpus[0]["keywords"], ["sqli", "prepared statements"])

    def test_fetch_web_text_extracts_plain_text_into_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            html_path = temp_path / "page.html"
            html_path.write_text(
                """
                <html>
                  <head><title>Example</title><style>body { color: red; }</style></head>
                  <body>
                    <h1>Website Title</h1>
                    <p>Useful information for the corpus.</p>
                    <script>console.log("ignore me")</script>
                  </body>
                </html>
                """,
                encoding="utf-8",
            )

            handler = partial(SimpleHTTPRequestHandler, directory=str(temp_path))
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                source_path = temp_path / "sources.json"
                source_path.write_text(
                    json.dumps(
                        {
                            "version": 1,
                            "phase": "phase-1",
                            "allowlists": {
                                "sourceTypes": ["owasp"],
                                "licenses": ["source-url-only"],
                            },
                            "entries": [
                                {
                                    "id": "web-text",
                                    "title": "Website Title",
                                    "url": f"http://127.0.0.1:{server.server_address[1]}/page.html",
                                    "sourceType": "owasp",
                                    "license": "source-url-only",
                                    "topic": "topic",
                                    "vulnerabilityClass": "class",
                                    "technique": "technique",
                                    "keywords": ["one"],
                                    "passage": "Curated note: local source.",
                                    "websiteImport": {"enabled": True}
                                }
                            ]
                        }
                    ),
                    encoding="utf-8",
                )
                output_path = temp_path / "website_text.json"
                fetched = generator.fetch_website_texts(source_path, output_path, timeout=5)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            self.assertEqual(len(fetched["entries"]), 1)
            entry = fetched["entries"][0]
            self.assertIn("Useful information for the corpus.", entry["text"])
            self.assertNotIn("ignore me", entry["text"])
            written = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(written["entries"][0]["id"], "web-text")


if __name__ == "__main__":
    unittest.main()
