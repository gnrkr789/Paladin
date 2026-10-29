"""Independent behavior checks; not a CVE reproduction or product detector."""
import importlib.util
from pathlib import Path
import sys
import unittest

MODULE_PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".cache/m4-task/run-001/containment.py")
spec = importlib.util.spec_from_file_location("containment_under_test", MODULE_PATH)
target = importlib.util.module_from_spec(spec)
spec.loader.exec_module(target)


class ContainmentBehavior(unittest.TestCase):
    def test_normal_child_is_retained(self):
        self.assertTrue(target.is_within(r"C:\uploads", r"C:\uploads\report.txt"))

    def test_nested_child_is_retained(self):
        self.assertTrue(target.is_within(r"C:\uploads", r"C:\uploads\team\report.txt"))

    def test_root_itself_is_retained(self):
        self.assertTrue(target.is_within(r"C:\uploads", r"C:\uploads"))

    def test_windows_case_is_normalized(self):
        self.assertTrue(target.is_within(r"C:\Uploads", r"c:\UPLOADS\report.txt"))

    def test_sibling_prefix_is_outside(self):
        self.assertFalse(target.is_within(r"C:\uploads", r"C:\uploads-archive\report.txt"))

    def test_parent_traversal_to_sibling_is_outside(self):
        self.assertFalse(target.is_within(r"C:\uploads", r"C:\uploads\..\uploads-archive\report.txt"))

    def test_different_drive_is_outside(self):
        self.assertFalse(target.is_within(r"C:\uploads", r"D:\uploads\report.txt"))

    def test_unrelated_path_is_outside(self):
        self.assertFalse(target.is_within(r"C:\uploads", r"C:\private\report.txt"))


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
