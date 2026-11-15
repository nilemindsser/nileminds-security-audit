import unittest
from unittest.mock import patch
from nmsa.benchmark import calculate, CASES, benchmark


class BenchmarkTests(unittest.TestCase):
    def test_confusion_matrix(self):
        cases = (
            ("a", "rule", True, "a"),
            ("b", "rule", True, "b"),
            ("c", "rule", False, "c"),
            ("d", "rule", False, "d"),
        )
        result = calculate(cases, {"a": {"rule"}, "c": {"rule"}})
        self.assertEqual((result["TP"], result["FP"], result["FN"], result["TN"]), (1, 1, 1, 1))
        self.assertEqual(result["precision"], 0.5)
        self.assertEqual(result["recall"], 0.5)

    def test_missing_scanner_incomplete(self):
        with patch("nmsa.benchmark.run", return_value={"status": "NOT_INSTALLED", "findings": []}):
            result = benchmark()
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertNotIn("precision", result)

    def test_cases_balanced_and_unique(self):
        names = [case[0] for case in CASES]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(sum(bool(c[2]) for c in CASES), len(CASES) // 2)

    def test_reference_precision_is_not_safety_claim(self):
        result = calculate(CASES, {})
        self.assertEqual(result["TP"], 0)
        self.assertEqual(result["FN"], 8)
        self.assertIsNone(result["precision"])
        self.assertEqual(result["recall"], 0)


if __name__ == "__main__":
    unittest.main()
