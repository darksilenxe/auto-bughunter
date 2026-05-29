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
    assert spec and spec.loader
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

            # The seed corpus pairs curated PortSwigger/OWASP/CWE notes with
            # HackTricks and PayloadsAllTheThings references for each major class.
            self.assertGreaterEqual(len(corpus), 30)
            self.assertEqual(review["summary"]["errors"], 0)

            source_types = {item["sourceType"] for item in corpus}
            self.assertIn("hacktricks", source_types)
            self.assertIn("payloadsallthethings", source_types)

            written = json.loads(output_path.read_text(encoding="utf-8"))
            for item in written:
                validated = app_main.CorpusDocument.model_validate(item)
                self.assertTrue(validated.id)
                self.assertTrue(validated.title)

    def test_full_text_ingestion_default_on_with_opt_out(self) -> None:
        app_main = load_module(APP_MAIN_PATH, "security_knowledge_main")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            source_path = temp_path / "sources.json"
            source_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "phase": "phase-1",
                        "allowlists": {
                            "sourceTypes": ["hacktricks"],
                            "licenses": ["source-url-only"],
                        },
                        "entries": [
                            {
                                "id": "ht-xss",
                                "title": "HackTricks XSS",
                                "url": "https://hacktricks.wiki/en/pentesting-web/xss.html",
                                "sourceType": "hacktricks",
                                "license": "source-url-only",
                                "topic": "xss",
                                "vulnerabilityClass": "cross-site scripting",
                                "technique": "reflected and dom xss probing",
                                "keywords": ["xss"],
                                "passage": "Curated note: confirm the reflection sink before probing.",
                                "fullText": True,
                                "websiteImport": {"enabled": True},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            website_text_path = temp_path / "website_text.json"
            website_text_path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "generatedAt": "2026-01-01T00:00:00+00:00",
                        "source": str(source_path),
                        "entries": [
                            {
                                "id": "ht-xss",
                                "title": "HackTricks XSS",
                                "url": "https://hacktricks.wiki/en/pentesting-web/xss.html",
                                "fetchedAt": "2026-01-01T00:00:00+00:00",
                                "text": "Full HackTricks XSS chapter body about contexts and bypasses.",
                                "wordCount": 9,
                                "confidence": "high",
                                "flags": [],
                                "error": "",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            # Opt-out (--no-full-text): full text is NOT mirrored into the corpus.
            out_no = temp_path / "corpus_no.json"
            rev_no = temp_path / "review_no.json"
            corpus_no, _ = generator.build_corpus(source_path, out_no, rev_no, website_text_path, allow_full_text=False)
            self.assertEqual(corpus_no[0].get("content", ""), "")

            # Default (owner sign-off, no arg): the fetched body is stored in
            # `content` while passage, url and license attribution are retained.
            out_yes = temp_path / "corpus_yes.json"
            rev_yes = temp_path / "review_yes.json"
            corpus_yes, _ = generator.build_corpus(source_path, out_yes, rev_yes, website_text_path)
            self.assertIn("Full HackTricks XSS chapter body", corpus_yes[0]["content"])
            self.assertEqual(corpus_yes[0]["contentSource"], "website-import")
            self.assertTrue(corpus_yes[0]["url"].startswith("https://hacktricks.wiki/"))
            self.assertEqual(corpus_yes[0]["license"], "source-url-only")

            validated = app_main.CorpusDocument.model_validate(corpus_yes[0])
            self.assertTrue(validated.content)

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
