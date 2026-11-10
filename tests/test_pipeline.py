"""Offline subprocess fixtures test orchestration, not model quality."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="f2mut-pipeline-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.root = self.work / "project"
        self.root.mkdir()
        shutil.copy2(ROOT / "run_pipeline.py", self.root)
        shutil.copy2(ROOT / "run_fuzz.sh", self.root)
        shutil.copy2(ROOT / "run.sh", self.root)
        self.g2 = self.root / "G2FUZZ"
        self.g2.mkdir()
        (self.g2 / "model_setting.json").write_text('{"model": ["fixture-model"]}')
        (self.g2 / "program_to_format.json").write_text('{"objdump": ["elf", "other"]}')
        (self.g2 / "generator_mutation.py").write_text("# PLACEHOLDER: native runtime generator is not called by the fixture fuzzer\n")
        self.input = self.work / "seeds"
        self.input.mkdir()
        self.output = self.work / "run"
        self.events = self.work / "events.jsonl"
        self.env = dict(os.environ, FIXTURE_EVENTS=str(self.events), OPENAI_API_KEY="offline-fixture-key")
        # PLACEHOLDER: external CLI responses are synthetic for orchestration tests.
        scripts = {
            self.g2 / "program_gen.py": '''
import argparse, json, os
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument('--output'); p.add_argument('--program'); a=p.parse_args()
d=Path(a.output)/'default'; (d/'gen_seeds').mkdir(parents=True, exist_ok=True)
(d/'gen_seeds'/'elf-1_1.bin').write_bytes(b'ELF fixture')
(d/'feature_pool.json').write_text(json.dumps({'header': 'ELF header'}))
(d/'feature_programs.json').write_text(json.dumps({'header': '# offline generator'}))
(d/'generators').mkdir(exist_ok=True)
(d/'generators'/'elf-1.py').write_text('# offline generator')
with open(os.environ['FIXTURE_EVENTS'], 'a') as f: f.write('"program_gen"\\n')
''',
            self.root / "template_seed_prompt_generator.py": '''
import os, sys
from pathlib import Path
Path(sys.argv[sys.argv.index('--output-code')+1]).write_text('# PLACEHOLDER: initial executor\\n')
with open(os.environ['FIXTURE_EVENTS'], 'a') as f: f.write('"initial_template"\\n')
''',
            self.root / "template_expander.py": '''
import os, sys
from pathlib import Path
Path(sys.argv[sys.argv.index('--output-dir')+1], 'expanded.py').write_text('# PLACEHOLDER: expanded executor\\n')
with open(os.environ['FIXTURE_EVENTS'], 'a') as f: f.write('"template_expansion"\\n')
''',
        }
        for path, code in scripts.items():
            path.write_text(code)
        fuzzer = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
event = {"fuzzer": str(Path(sys.argv[0]).resolve()), "args": sys.argv[1:],
         "cwd": os.getcwd(), "seed_gen": os.environ.get("AFL_LLM_SEED_GEN"),
         "pool": os.environ.get("AFL_LLM_TEMPLATE_POOL"),
         "initial_only": os.environ.get("AFL_LLM_TEMPLATE_INITIAL_ONLY"),
         "initial": os.environ.get("AFL_LLM_FALLBACK_TEMPLATE_EXECUTOR"),
         "executors": os.environ.get("AFL_LLM_FORMAT_EXECUTOR_DIR")}
with open(os.environ['FIXTURE_EVENTS'], 'a') as f: f.write(json.dumps(event)+'\\n')
'''
        for path in (self.root / "afl-fuzz", self.g2 / "afl-fuzz"):
            path.write_text(fuzzer)
            path.chmod(0o755)

    def launch(self, *extra):
        return subprocess.run([sys.executable, self.root / "run_pipeline.py",
            "--program", "objdump", "--format", "elf", *extra,
            self.input, self.output, "--", "/target", "-d", "@@"],
            env=self.env, text=True, capture_output=True, timeout=20)

    def test_preparation_spine(self):
        result = self.launch("--prepare-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([json.loads(s) for s in self.events.read_text().splitlines()],
                         ["program_gen", "initial_template", "template_expansion"])
        manifest = json.loads((self.output / "pipeline.json").read_text())
        self.assertTrue(Path(manifest["initial_template"]).is_file())
        self.assertTrue(all(Path(p).is_file() for p in manifest["executors"]))

    def test_native_config_is_staged_without_changing_sources(self):
        before = {p.name: p.read_bytes() for p in self.g2.iterdir()}
        result = self.launch("--prepare-only", "--model", "explicit-model")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.g2.iterdir()})
        staged = self.output / "g2fuzz_work"
        self.assertEqual(json.loads((staged / "model_setting.json").read_text())["model"], ["explicit-model"])
        self.assertEqual(json.loads((staged / "program_to_format.json").read_text())["objdump"], ["elf"])
        self.assertEqual((staged / "openai_key.txt").stat().st_mode & 0o777, 0o600)

    def test_existing_run_is_not_silently_overwritten(self):
        self.output.mkdir()
        (self.output / "previous").write_text("keep")
        result = self.launch("--prepare-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.events.exists())

    def test_native_seed_names_and_user_seeds_are_both_retained(self):
        (self.input / "original.bin").write_bytes(b"user seed")
        result = self.launch("--prepare-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        corpus = self.output / "seeds"
        self.assertEqual((corpus / "elf-1_1.bin").read_bytes(), b"ELF fixture")
        self.assertEqual((corpus / "user-000000.bin").read_bytes(), b"user seed")

    def test_failed_expansion_never_records_success(self):
        (self.root / "template_expander.py").write_text("raise SystemExit(7)\n")
        result = self.launch("--prepare-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.output / "pipeline.json").exists())

    def test_normal_uses_native_binary_and_prepared_pool(self):
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        events = [json.loads(s) for s in self.events.read_text().splitlines()]
        event = events[-1]
        self.assertEqual(events[:3], ["program_gen", "initial_template", "template_expansion"])
        self.assertEqual(event["fuzzer"], str(self.g2 / "afl-fuzz"))
        self.assertEqual(event["args"], ["-i", str(self.output / "seeds"), "-o", str(self.output / "fuzzer"), "-k", str(self.g2), "--", "/target", "-d", "@@"])
        self.assertEqual(event["cwd"], str(self.output / "g2fuzz_work"))
        self.assertEqual((event["pool"], event["initial_only"], event["seed_gen"]), ("1", "0", "0"))

    def test_nogen_uses_local_binary_and_still_prepares_all_stages(self):
        self.env["AFL_LLM_SEED_GEN"] = "1"
        result = self.launch("--nogen")
        self.assertEqual(result.returncode, 0, result.stderr)
        events = [json.loads(s) for s in self.events.read_text().splitlines()]
        self.assertEqual(events[:3], ["program_gen", "initial_template", "template_expansion"])
        self.assertEqual(events[-1]["fuzzer"], str(self.root / "afl-fuzz"))
        self.assertNotIn("-k", events[-1]["args"])
        self.assertEqual(events[-1]["seed_gen"], "0")

    def test_reuse_prepared_does_not_call_generation_again(self):
        self.assertEqual(self.launch("--prepare-only").returncode, 0)
        self.env["OPENAI_API_KEY"] = ""
        result = self.launch("--reuse-prepared", "--nogen")
        self.assertEqual(result.returncode, 0, result.stderr)
        events = [json.loads(s) for s in self.events.read_text().splitlines()]
        self.assertEqual(len(events), 4)

    def test_reuse_rejects_a_missing_expanded_executor(self):
        self.assertEqual(self.launch("--prepare-only").returncode, 0)
        (self.output / "generated_format_executors" / "expanded.py").unlink()
        result = self.launch("--reuse-prepared", "--nogen")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.events.read_text().splitlines()), 3)

    def test_missing_normal_binary_fails_before_any_generation(self):
        (self.g2 / "afl-fuzz").unlink()
        result = self.launch()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.events.exists())


if __name__ == "__main__":
    unittest.main()
