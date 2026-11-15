import unittest
from nmsa.safe_target import validate_fixture_origin, validate_fixture_path
from nmsa.api_contract import validate_spec, audit
from nmsa.tenant_contract import validate_cases


class StrictTargetsTests(unittest.TestCase):
    def test_only_literal_ipv4_loopback(self):
        for value in (
            "http://localhost:3000", "http://[::1]:3000",
            "http://127.0.0.2:3000", "http://127.1:3000",
            "http://0x7f000001:3000", "https://127.0.0.1:3000",
            "http://127.0.0.1:3000/path", "http://127.0.0.1:3000?x=1",
            "http://127.0.0.1:3000#frag", "http://127.0.0.1:abc",
            "http://127.0.0.1:0", "http://127.0.0.1:65536",
            "http://user:secret@127.0.0.1:3000",
            "http://127.0.0.1.evil.test:3000"
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_fixture_origin(value)
        self.assertEqual(validate_fixture_origin("http://127.0.0.1:3000"), ("127.0.0.1", 3000))

    def test_encoded_and_query_path_rejected(self):
        for path in ("/%2e%2e/secret", "/foo%2fbar", "/api?debug=1",
                     "/api#fragment", "/a/../b", "//evil.test/",
                     "/a/./b", "/a\\b", "http://example.test/path",
                     "/abc%00x"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    validate_fixture_path(path)
        self.assertEqual(validate_fixture_path("/api/v1/orders"), "/api/v1/orders")

    def test_strict_schema_rejects_extra_fields(self):
        with self.assertRaises(ValueError):
            validate_spec({"endpoints": [{"path": "/health", "access": "public", "headers": {"Authorization": "secret"}}]})
        with self.assertRaises(ValueError):
            validate_spec({"endpoints": [], "ignore_security": True})
        with self.assertRaises(ValueError):
            validate_cases({"cases": [{"path": "/tenant/a", "owner": "A", "other": "B"}],
                            "bearer_token": "not-supported"})

    def test_empty_spec_rejected(self):
        with self.assertRaises(ValueError):
            validate_spec({"endpoints": []})
        with self.assertRaises(ValueError):
            validate_cases({"cases": []})

    def test_no_network_for_nonloopback(self):
        with self.assertRaises(ValueError):
            audit("http://localhost:8080", {"endpoints": [{"path": "/", "access": "public"}]})


if __name__ == "__main__":
    unittest.main()
