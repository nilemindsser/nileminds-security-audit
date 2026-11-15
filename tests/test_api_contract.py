import http.server
import json
import tempfile
import threading
import unittest
from pathlib import Path
from nmsa.api_contract import audit, validate_base, validate_spec


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/private":
            self.send_response(401)
        elif self.path == "/bad":
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
        elif self.path == "/leak":
            self.send_response(500)
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://example.invalid/private")
        else:
            self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Traceback (most recent call last)" if self.path == "/leak" else b'{"ok":true}')
    def log_message(self, *_args):
        pass


class TestApiContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=5)

    def test_protected_route_valid_behavior(self):
        result = audit(self.base, {"endpoints": [{"path": "/private", "access": "protected"}]})
        self.assertEqual(result["verdict"], "OBSERVED_NO_FINDINGS")

    def test_auth_and_cors_violation(self):
        result = audit(self.base, {"endpoints": [{"path": "/bad", "access": "protected"}]})
        self.assertEqual(result["verdict"], "REVIEW")
        self.assertEqual({f["id"] for f in result["findings"]},
                         {"protected-route-auth-contract", "protected-route-cors"})

    def test_information_leak_without_leaking_payload(self):
        result = audit(self.base, {"endpoints": [{"path": "/leak", "access": "public"}]})
        self.assertIn("error-information-disclosure", [x["id"] for x in result["findings"]])
        self.assertNotIn("Traceback", str(result))

    def test_remote_origin_rejected(self):
        for host in ("https://example.com:443", "http://192.168.1.10:80",
                     "http://127.0.0.1.evil.test:8080", "http://user:pw@localhost:80"):
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    validate_base(host)

    def test_mutating_or_unsafe_paths_rejected(self):
        for path in ("//other", "/../../private", "https://evil.test/", "/foo#x"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    validate_spec({"endpoints": [{"path": path, "access": "public"}]})

    def test_redirect_not_followed_and_not_clean(self):
        result = audit(self.base, {"endpoints": [{"path": "/redirect", "access": "public"}]})
        self.assertEqual(result["verdict"], "INCOMPLETE")
        self.assertEqual(result["observations"][0]["status"], 302)
        self.assertNotIn("example.invalid", str(result))

    def test_server_failure_is_not_clean(self):
        result = audit(self.base, {"endpoints": [{"path": "/leak", "access": "public"}]})
        self.assertEqual(result["verdict"], "INCOMPLETE")

    def test_unreachable_is_not_pass(self):
        result = audit("http://127.0.0.1:1", {"endpoints": [{"path": "/ping", "access": "public"}]})
        self.assertEqual(result["verdict"], "INCOMPLETE")


if __name__ == "__main__":
    unittest.main()
