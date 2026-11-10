"""Verify the user's invariant: vendored G2FUZZ source stays unchanged."""

import hashlib
import json
import os
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class VendorSnapshotTests(unittest.TestCase):
    def test_all_upstream_source_files_match_the_recorded_git_blobs(self):
        record = json.loads((ROOT / "G2FUZZ_UPSTREAM.json").read_text())
        self.assertEqual(len(record["files"]), 881)
        for name, entry in record["files"].items():
            with self.subTest(path=name):
                path = ROOT / "G2FUZZ" / name
                if entry["mode"] == "120000":
                    self.assertTrue(path.is_symlink())
                    data = os.readlink(path).encode()
                else:
                    self.assertTrue(path.is_file(), name)
                    data = path.read_bytes()
                blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
                self.assertEqual(blob, entry["blob"])
        self.assertFalse((ROOT / "G2FUZZ" / ".git").exists())


if __name__ == "__main__":
    unittest.main()
