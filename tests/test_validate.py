"""Tests for scripts/validate.py: every shipped policy passes, every broken fixture fails."""
import glob
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import validate  # noqa: E402

REF = validate.ServiceReference()


class ShippedPolicies(unittest.TestCase):
    def test_all_policies_pass(self):
        paths = sorted(glob.glob(os.path.join(ROOT, "policies", "*.json")))
        self.assertGreaterEqual(len(paths), 10)
        for path in paths:
            with self.subTest(policy=os.path.basename(path)):
                self.assertEqual(validate.check_policy(path, REF), [])


class BrokenFixtures(unittest.TestCase):
    """Each fixture contains one deliberate mistake; the validator must catch it."""

    def test_every_fixture_fails(self):
        paths = sorted(glob.glob(os.path.join(ROOT, "tests", "fixtures", "invalid", "*.json")))
        self.assertGreater(len(paths), 0)
        for path in paths:
            with self.subTest(fixture=os.path.basename(path)):
                self.assertNotEqual(validate.check_policy(path, REF), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
