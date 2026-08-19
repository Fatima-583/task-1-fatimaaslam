import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from password_checker.checker import Strength, check_password


class TestPasswordChecker(unittest.TestCase):
    def test_too_short_is_weak(self):
        report = check_password("Ab1!")
        self.assertEqual(report.strength, Strength.WEAK)
        self.assertLess(report.password_length, 8)

    def test_common_password_is_weak_even_if_long(self):
        report = check_password("Password1")
        self.assertEqual(report.strength, Strength.WEAK)
        self.assertTrue(report.is_common)

    def test_medium_password(self):
        # Long-ish, has upper/lower/digit, missing symbol
        report = check_password("Ilovecats2026")
        self.assertIn(report.strength, (Strength.MEDIUM, Strength.STRONG))

    def test_strong_password(self):
        report = check_password("Tr#8kLp!qZ92mN")
        self.assertEqual(report.strength, Strength.STRONG)
        self.assertTrue(report.has_lower)
        self.assertTrue(report.has_upper)
        self.assertTrue(report.has_digit)
        self.assertTrue(report.has_symbol)

    def test_feedback_present_for_weak(self):
        report = check_password("abc")
        self.assertTrue(len(report.feedback) > 0)

    def test_no_feedback_message_when_all_good(self):
        report = check_password("Tr#8kLp!qZ92mN")
        self.assertIn("Looks good", report.feedback[0])

    def test_entropy_increases_with_length(self):
        short_report = check_password("Ab1!")
        long_report = check_password("Ab1!Ab1!Ab1!Ab1!")
        self.assertGreater(long_report.entropy_bits, short_report.entropy_bits)

    def test_empty_password(self):
        report = check_password("")
        self.assertEqual(report.strength, Strength.WEAK)
        self.assertEqual(report.password_length, 0)

    def test_custom_min_length(self):
        report = check_password("Short1!", min_length=10)
        self.assertEqual(report.strength, Strength.WEAK)


if __name__ == "__main__":
    unittest.main()
