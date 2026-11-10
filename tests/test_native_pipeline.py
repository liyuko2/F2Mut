"""Execute real native/template CLIs with an explicit offline SDK fixture."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class NativePipelineTests(unittest.TestCase):
    def test_native_generation_to_real_mutator_callbacks(self):
        self.check_chain("http://offline.invalid/v1")

    def test_default_endpoint_is_the_same_for_all_three_real_clis(self):
        self.check_chain(None)

    def check_chain(self, base_url):
        with tempfile.TemporaryDirectory(prefix="f2mut-native-") as tmp:
            work = Path(tmp)
            project = work / "project"
            project.mkdir()
            for name in ("run_pipeline.py", "run.sh", "run_fuzz.sh", "template_seed_prompt_generator.py",
                         "template_expander.py", "llm_config.py", "llm_generation_metrics.py",
                         "template_safety.py", "MutatorMin.py", "elf_template_executor.py"):
                shutil.copy2(ROOT / name, project / name)
            g2 = project / "G2FUZZ"
            g2.mkdir()
            for name in ("program_gen.py", "generator_mutation.py", "program_to_format.json", "model_setting.json"):
                shutil.copy2(ROOT / "G2FUZZ" / name, g2 / name)
            shutil.copytree(ROOT / "G2FUZZ" / "py_utils", g2 / "py_utils", ignore=shutil.ignore_patterns("__pycache__"))
            inputs = work / "inputs"
            inputs.mkdir()
            llm_log = work / "offline_llm.jsonl"
            env = {key: value for key, value in os.environ.items()
                   if not key.lower().endswith("_proxy") and not key.startswith("AFL_LLM_")}
            env.update({"PYTHONPATH": str(ROOT / "tests" / "fixtures" / "offline_sdk"),
                        "PYTHONDONTWRITEBYTECODE": "1", "OPENAI_API_KEY": "offline-fixture-key",
                        "AFL_LLM_API_KEY": "different-offline-fixture-key",
                        "OFFLINE_LLM_LOG": str(llm_log),
                        "OFFLINE_EXECUTOR": str(ROOT / "tests" / "fixtures" / "simple_executor.py")})
            env.pop("OPENAI_BASE_URL", None)
            result = subprocess.run([str(project / "run.sh"), "--prepare-only", "--program", "objdump",
                "--format", "elf", "--model", "offline-fixture", *(["--base-url", base_url] if base_url else []),
                str(inputs), str(work / "run"), "--", "/target", "-d", "@@"],
                env=env, text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout[-6000:])
            manifest = json.loads((work / "run" / "pipeline.json").read_text())
            native = Path(manifest["native_state"])
            self.assertEqual(json.loads((native / "feature_pool.json").read_text()), {"Header": "1. Header: offline native header"})
            self.assertTrue(list((native / "generators").glob("*.py")))
            self.assertTrue(json.loads((native / "feature_programs.json").read_text()))
            calls = [json.loads(line) for line in llm_log.read_text().splitlines()]
            self.assertEqual({call["base_url"] for call in calls}, {base_url or "https://api.openai.com/v1"})
            self.assertTrue(all(call["uses_selected_key"] for call in calls))
            self.assertEqual(len([call for call in calls if call["json"]]), 2)
            self.assertTrue(all(call["has_features"] for call in calls if call["json"]))
            env.update({"PYTHONPATH": str(project),
                        "AFL_LLM_FALLBACK_TEMPLATE_EXECUTOR": manifest["initial_template"],
                        "AFL_LLM_FORMAT_EXECUTOR_DIR": manifest["executor_dir"],
                        "AFL_LLM_MUTATORS_DIR": str(work / "runtime_state"),
                        "AFL_LLM_TEMPLATE_MODE": "1", "AFL_LLM_TEMPLATE_POOL": "1", "AFL_LLM_TEMPLATE_INITIAL_ONLY": "0",
                        "AFL_LLM_TEMPLATE_PLAN_MODE": "default"})
            callback_check = '''
import os
from pathlib import Path
import MutatorMin as m
m.init(1)
m._scan_template_pool()
paths = {str(Path(p).resolve()) for p in m.__template_pool__["paths"]}
assert str(Path(os.environ["AFL_LLM_FALLBACK_TEMPLATE_EXECUTOR"]).resolve()) in paths
assert len(paths) == 2, paths
sample = b"\\x7fELF" + bytes(60)
assert m.fuzz_count(bytearray(sample)) == 64
assert bytes(m.fuzz(bytearray(sample), bytearray(), 1048576)) != sample
print("real MutatorMin callbacks loaded initial and expanded executors")
'''
            check = subprocess.run([sys.executable, "-B", "-c", callback_check], env=env,
                                   text=True, capture_output=True, timeout=10)
            self.assertEqual(check.returncode, 0, check.stderr)


if __name__ == "__main__":
    unittest.main()
