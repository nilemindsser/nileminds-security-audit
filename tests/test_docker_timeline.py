import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nmsa.docker_timeline import hour_bucket, evaluate_lines, timeline


class DockerTimelineTests(unittest.TestCase):
    def test_hour_timestamp_bracket_and_fraction(self):
        self.assertEqual(
            hour_bucket("[2026-11-15T11:43:59.123456789Z][component] WSL error"),
            "2026-11-15T11:00Z")

    def test_timezone_normalized_to_utc(self):
        self.assertEqual(
            hour_bucket("[2026-11-15T14:05:00+03:00] backend exited"),
            "2026-11-15T11:00Z")

    def test_json_time(self):
        self.assertEqual(
            hour_bucket('{"level":"error","time":"2026-11-15T11:18:00Z","message":"wsl failed"}'),
            "2026-11-15T11:00Z")

    def test_bad_time_is_skipped(self):
        for line in ("password=private", "[2026-13-77T11:30:00Z] wsl error",
                     '2026-11-15 some error', "2026-11-15T11:50:00"):
            self.assertIsNone(hour_bucket(line))

    @patch("nmsa.docker_timeline.running_on_windows", return_value=True)
    def test_aggregate_redacts_contents_and_limits_sources(self, _):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "host").mkdir()
            (base / "vm").mkdir()
            (base / "host" / "com.docker.backend.exe.log").write_text(
                "[2026-11-15T11:00:00Z] WSL error token=NEVER_REPORT\n"
                "[2026-11-15T11:00:01Z] backend exited\n",
                encoding="utf-8")
            (base / "host" / "monitor.log").write_text(
                "[2026-11-15T11:00:03Z] permission denied SECRET_VALUE\n",
                encoding="utf-8")
            report = timeline(tmp)
        self.assertEqual(report["status"], "REVIEW")
        self.assertEqual(report["logs_processed"], 2)
        self.assertEqual(report["recent_hour_buckets"][0]["source_count"], 2)
        self.assertFalse(report["root_cause_confirmed"])
        self.assertNotIn("NEVER_REPORT", str(report))
        self.assertNotIn("SECRET_VALUE", str(report))

    @patch("nmsa.docker_timeline.running_on_windows", return_value=True)
    def test_absent_logs_no_clean_result(self, _):
        with tempfile.TemporaryDirectory() as tmp:
            report = timeline(tmp)
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["logs_processed"], 0)

    @patch("nmsa.docker_timeline.running_on_windows", return_value=False)
    def test_non_windows_no_io(self, _):
        self.assertEqual(timeline()["status"], "UNSUPPORTED_PLATFORM")

    def test_no_unbounded_raw_messages(self):
        from collections import defaultdict
        b = defaultdict(lambda: {"sources": set(), "signals": defaultdict(int)})
        parsed, matched = evaluate_lines([
            "[2026-11-15T11:00:01Z] WSL failed private_token=abc",
            "sensitive_line_without_time WSL failed",
        ], "backend", b)
        self.assertEqual((parsed, matched), (1, 1))
        self.assertNotIn("abc", str(b))


if __name__ == "__main__":
    unittest.main()
