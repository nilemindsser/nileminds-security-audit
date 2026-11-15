import http.server
import threading
import unittest
from nmsa.tenant_contract import audit_tenants, validate_cases


class TenantFixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        identity = self.headers.get("Authorization", "")
        if self.path == "/case/a":
            code = 200 if identity == "Bearer nmsa-fixture-A" else 404
        elif self.path == "/case/b":
            code = 200 if identity == "Bearer nmsa-fixture-B" else 403
        elif self.path == "/case/broken":
            code = 200
        elif self.path == "/case/not-found":
            code = 404
        else:
            code = 404
        self.send_response(code)
        self.end_headers()
        self.wfile.write(b"fixture-only")
    def log_message(self, *_args):
        pass


class TenantIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), TenantFixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def test_isolated_tenants(self):
        r = audit_tenants(self.base, {"cases": [
            {"path": "/case/a", "owner": "A", "other": "B"},
            {"path": "/case/b", "owner": "B", "other": "A"}]})
        self.assertEqual(r["status"], "OBSERVED_NO_FINDINGS")
        self.assertEqual(r["findings"], [])

    def test_cross_tenant_regression_detected(self):
        r = audit_tenants(self.base, {"cases": [
            {"path": "/case/broken", "owner": "A", "other": "B"}]})
        self.assertEqual(r["status"], "REVIEW")
        self.assertEqual(r["findings"][0]["type"], "CROSS_TENANT_ACCESS_REVIEW")

    def test_baseline_must_work(self):
        r = audit_tenants(self.base, {"cases": [
            {"path": "/case/not-found", "owner": "A", "other": "B"}]})
        self.assertEqual(r["status"], "INCOMPLETE")

    def test_reject_arbitrary_hosts(self):
        with self.assertRaises(ValueError):
            audit_tenants("http://example.com:80", {"cases": []})

    def test_reject_non_fixture_identity_and_traversal(self):
        for spec in ({"cases": [{"path": "/case/a", "owner": "real-token", "other": "B"}]},
                     {"cases": [{"path": "/../admin", "owner": "A", "other": "B"}]},
                     {"cases": [{"path": "/case/a", "owner": "A", "other": "A"}]}):
            with self.subTest(spec=spec):
                with self.assertRaises(ValueError):
                    validate_cases(spec)

    def test_unknown_case_fields_rejected(self):
        with self.assertRaises(ValueError):
            validate_cases({"cases": [{"path": "/case/a", "owner": "A", "other": "B", "token": "secret"}]})


if __name__ == "__main__":
    unittest.main()
