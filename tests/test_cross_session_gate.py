import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from nmsa.cross_session_gate import capture, confirm, SCHEMA

PASS = {"status": "STABLE_FOR_FIXTURE_PRECHECK"}
BLOCK = {"status": "BLOCKED"}


class CrossSessionGateTests(unittest.TestCase):
    def test_success_requires_different_process_and_second_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "marker.json"
            a = capture(marker, probe=lambda **kw: PASS, clock=lambda: 100,
                        process_id=lambda: 123)
            b = confirm(marker, probe=lambda **kw: PASS, clock=lambda: 101,
                        process_id=lambda: 456)
            self.assertEqual(a["status"], "CAPTURED")
            self.assertEqual(b["status"], "CROSS_PROCESS_LIVENESS_PASS")
            self.assertFalse(b["isolation_verified"])

    def test_engine_dies_after_first_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "marker.json"
            capture(marker, probe=lambda **kw: PASS, clock=lambda: 100,
                    process_id=lambda: 123)
            b = confirm(marker, probe=lambda **kw: BLOCK, clock=lambda: 101,
                        process_id=lambda: 456)
            self.assertEqual(b["reason"], "daemon_unavailable_after_session_boundary")
            self.assertFalse(b["cross_session_verified"])

    def test_same_process_is_not_a_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "marker.json"
            capture(marker, probe=lambda **kw: PASS, clock=lambda: 100,
                    process_id=lambda: 123)
            with patch("nmsa.cross_session_gate.verify") as probe:
                b = confirm(marker, probe=probe, clock=lambda: 101,
                            process_id=lambda: 123)
                probe.assert_not_called()
            self.assertEqual(b["reason"], "same_process_not_independent")

    def test_capture_failure_stays_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "marker.json"
            capture(marker, probe=lambda **kw: BLOCK, clock=lambda: 100,
                    process_id=lambda: 123)
            b = confirm(marker, probe=lambda **kw: PASS, clock=lambda: 101,
                        process_id=lambda: 456)
            self.assertEqual(b["reason"], "capture_phase_not_ready")

    def test_future_stale_and_corrupt_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "marker.json"
            capture(marker, probe=lambda **kw: PASS, clock=lambda: 100,
                    process_id=lambda: 123)
            for time in (99, 701):
                self.assertEqual(confirm(marker, clock=lambda: time,
                    process_id=lambda: 456)["reason"], "stale_or_future_marker")
            marker.write_text('{"nonce":"secret","other":"key"}', encoding="utf-8")
            self.assertEqual(confirm(marker)["reason"], "invalid_marker_schema")

    def test_existing_file_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "marker.json"
            marker.write_text("USER CONTENT", encoding="utf-8")
            with self.assertRaises(ValueError):
                capture(marker, probe=lambda **kw: PASS)
            self.assertEqual(marker.read_text(encoding="utf-8"), "USER CONTENT")

    def test_missing_marker_does_not_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("nmsa.cross_session_gate.verify") as probe:
                b = confirm(Path(tmp) / "missing", probe=probe)
                probe.assert_not_called()
            self.assertEqual(b["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
