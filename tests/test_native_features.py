import json
from pathlib import Path
import tempfile
import unittest

from template_expander import load_feature_context, _build_feature_prompt


class NativeFeatureTests(unittest.TestCase):
    def load(self, data):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "feature_pool.json"
            path.write_text(json.dumps(data))
            return load_feature_context(str(path))

    def test_native_string_mapping_reaches_the_expansion_prompt(self):
        context = self.load({"ELF Header": "1. ELF Header: magic bytes", "Sections": "2. Sections: section table"})
        self.assertEqual([f["id"] for f in context["features"]], ["ELF Header", "Sections"])
        prompt = _build_feature_prompt(context)
        self.assertIn("ELF Header", prompt)
        self.assertIn("magic bytes", prompt)

    def test_existing_structured_pool_is_still_accepted(self):
        context = self.load({"features": [{"id": "header", "description": "header bytes", "status": "success"}]})
        self.assertEqual(context["features"][0]["id"], "header")


if __name__ == "__main__":
    unittest.main()
