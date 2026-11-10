#!/usr/bin/env python3
"""Run native G2FUZZ generation, template synthesis, expansion, and fuzzing."""

import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parent


def run_stage(name, command, cwd, env):
    print(f"[F2Mut] {name}: {shlex.join(map(str, command))}", flush=True)
    subprocess.run(list(map(str, command)), cwd=cwd, env=env, check=True)


def nonempty_files(directory):
    return sorted(p for p in directory.rglob("*") if p.is_file() and p.stat().st_size)


def stage_native_config(args, g2fuzz_dir, work_dir, env):
    """Provide the original scripts' relative config files outside their source tree."""
    config_dir = Path(args.g2fuzz_config_dir).resolve() if args.g2fuzz_config_dir else g2fuzz_dir
    model_config = json.loads((config_dir / "model_setting.json").read_text())
    models = model_config.get("model")
    model = args.model or (models[0] if isinstance(models, list) and models else None)
    if not isinstance(model, str) or not model.strip():
        raise ValueError("set --model or provide model_setting.json with a non-empty model list")
    model_config["model"] = [model]
    program_config = json.loads((config_dir / "program_to_format.json").read_text())
    program_config[args.program] = [args.format]
    key = env.get("OPENAI_API_KEY") or env.get("AFL_LLM_API_KEY")
    if not key and (config_dir / "openai_key.txt").is_file():
        key = (config_dir / "openai_key.txt").read_text().strip()
    if not key or not key.strip():
        raise ValueError("set OPENAI_API_KEY/AFL_LLM_API_KEY or provide openai_key.txt in --g2fuzz-config-dir")
    work_dir.mkdir(parents=True, exist_ok=True)
    for name, config in (("model_setting.json", model_config),
                         ("program_to_format.json", program_config)):
        (work_dir / name).write_text(json.dumps(config, indent=2) + "\n")
    key_path = work_dir / "openai_key.txt"
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(key.strip() + "\n")
    env["OPENAI_API_KEY"] = key.strip()
    env["AFL_LLM_API_KEY"] = key.strip()
    if args.base_url:
        env["OPENAI_BASE_URL"] = args.base_url
        env["AFL_LLM_BASE_URL"] = args.base_url
    return model


def prepare(args, target):
    run_dir = Path(args.output_dir).resolve()
    work_dir = run_dir / "g2fuzz_work"
    fuzz_dir = run_dir / "fuzzer"
    initial_dir = run_dir / "initial_template"
    pool_dir = run_dir / "generated_format_executors"
    g2fuzz_dir = Path(args.g2fuzz_dir).resolve()
    if run_dir == g2fuzz_dir or g2fuzz_dir in run_dir.parents:
        raise ValueError("the run directory must be outside the G2FUZZ source directory")
    if run_dir.exists() and any(run_dir.iterdir()):
        raise ValueError("run directory is not empty; use a new directory or --reuse-prepared")
    for directory in (initial_dir, pool_dir, fuzz_dir / "default"):
        directory.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    model = stage_native_config(args, g2fuzz_dir, work_dir, env)
    run_stage("program_gen", [sys.executable, g2fuzz_dir / "program_gen.py",
              "--output", fuzz_dir, "--program", args.program], work_dir, env)
    native_state = fuzz_dir / "default"
    feature_pool = native_state / "feature_pool.json"
    features = json.loads(feature_pool.read_text())
    if not isinstance(features, dict) or not features:
        raise ValueError("program_gen.py did not produce a non-empty native feature_pool.json")
    seeds = nonempty_files(native_state / "gen_seeds")
    if not seeds:
        raise ValueError("program_gen.py did not produce any non-empty seeds")
    seed = Path(args.template_seed).resolve() if args.template_seed else seeds[0]
    if not seed.is_file() or not seed.stat().st_size:
        raise ValueError("template seed must be a non-empty file")
    corpus_dir = run_dir / "seeds"
    corpus_dir.mkdir()
    for source in seeds:
        destination = corpus_dir / source.name
        if destination.exists():
            raise ValueError("duplicate native seed filename: " + source.name)
        # G2FUZZ uses the original seed name to associate it with its generator.
        shutil.copy2(source, destination)
    for index, source in enumerate(nonempty_files(Path(args.input_dir).resolve())):
        destination = corpus_dir / f"user-{index:06d}{source.suffix}"
        if destination.exists():
            raise ValueError("seed filename collision: " + destination.name)
        shutil.copy2(source, destination)
    initial = initial_dir / "executor.py"
    model_options = ["--model", model]
    initial_options = model_options + (["--base-url", args.base_url] if args.base_url else [])
    expansion_options = model_options + (["--url", args.base_url] if args.base_url else [])
    run_stage("initial_template", [sys.executable, ROOT / "template_seed_prompt_generator.py",
              args.format, seed, "--call-llm", "--target-program", args.program,
              "--target-args=" + shlex.join(target[1:]), "--output-code", initial,
              "--output-json", initial_dir / "executor.json",
              "--summary-json", initial_dir / "seed_summary.json",
              "--tool-output", "g2fuzz_features=" + str(feature_pool), *initial_options],
              work_dir, env)
    run_stage("template_expansion", [sys.executable, ROOT / "template_expander.py",
              initial, "--sample", seed, "--feature-pool", native_state / "feature_pool.json",
              "--output-dir", pool_dir, "--count", args.expand_count,
              "--style", args.expand_style, *expansion_options], work_dir, env)
    executors = sorted(pool_dir.glob("*.py"))
    if not initial.is_file() or not executors:
        raise ValueError("template generation/expansion did not produce Python executors")
    manifest = {
        "version": 1, "program": args.program, "format": args.format,
        "g2fuzz_dir": str(g2fuzz_dir), "work_dir": str(work_dir),
        "model": model,
        "corpus_dir": str(corpus_dir), "native_state": str(native_state),
        "fuzz_dir": str(fuzz_dir), "template_seed": str(seed),
        "initial_template": str(initial), "executor_dir": str(pool_dir),
        "executors": [str(p) for p in executors],
        "base_url": args.base_url,
    }
    (run_dir / "pipeline.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def load_prepared(args):
    manifest_path = Path(args.output_dir).resolve() / "pipeline.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("version") != 1 or manifest.get("program") != args.program or manifest.get("format") != args.format:
        raise ValueError("prepared artifacts do not match the requested program and format")
    for field in ("initial_template", "template_seed"):
        path = Path(manifest[field])
        if not path.is_file() or not path.stat().st_size:
            raise ValueError("prepared artifact missing: " + str(path))
    if not nonempty_files(Path(manifest["corpus_dir"])):
        raise ValueError("prepared corpus is empty")
    if not manifest.get("executors") or not all(Path(p).is_file() and Path(p).stat().st_size for p in manifest["executors"]):
        raise ValueError("prepared expanded executors are missing")
    return manifest


def launch_fuzzer(args, manifest, target):
    env = dict(os.environ)
    env.update({
        "G2FUZZ_DIR": manifest["g2fuzz_dir"],
        "AFL_LLM_G2FUZZ_SOURCE_DIR": manifest["g2fuzz_dir"],
        "AFL_LLM_G2FUZZ_WORK_DIR": manifest["work_dir"],
        "AFL_LLM_FALLBACK_TEMPLATE_EXECUTOR": manifest["initial_template"],
        "AFL_LLM_FORMAT_EXECUTOR_DIR": manifest["executor_dir"],
        "AFL_LLM_MUTATORS_DIR": str(Path(args.output_dir).resolve() / "runtime_state"),
        "AFL_LLM_SEED_GEN": "0",
        "AFL_LLM_TEMPLATE_POOL": "1",
        "AFL_LLM_TEMPLATE_INITIAL_ONLY": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    if manifest.get("base_url"):
        env["OPENAI_BASE_URL"] = manifest["base_url"]
    command = [ROOT / "run_fuzz.sh"]
    if args.nogen:
        command.append("--nogen")
    command.extend([manifest["corpus_dir"], manifest["fuzz_dir"], "--", *target])
    run_stage("fuzzer", command, Path.cwd(), env)


def check_native_launch(g2fuzz_dir, fuzz_dir):
    binary = Path(g2fuzz_dir) / "afl-fuzz"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError(f"build native G2FUZZ first: make -C {g2fuzz_dir} afl-fuzz")
    # Upstream's runtime generator uses an unquoted system() command.
    for path in (g2fuzz_dir, fuzz_dir):
        if shlex.quote(str(path)) != str(path):
            raise ValueError("native G2FUZZ runtime requires source/output paths without shell metacharacters or spaces")


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--program", required=True, help="native G2FUZZ target program name")
    result.add_argument("--format", required=True, help="format to generate and mutate")
    result.add_argument("--g2fuzz-dir", default=os.environ.get("G2FUZZ_DIR", str(ROOT / "G2FUZZ")))
    result.add_argument("--g2fuzz-config-dir", help="directory containing native config overrides")
    result.add_argument("--model", default=os.environ.get("AFL_LLM_MODEL"))
    result.add_argument("--base-url", default=os.environ.get("AFL_LLM_BASE_URL") or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1")
    result.add_argument("--template-seed", help="override the generated seed used for template synthesis")
    result.add_argument("--expand-count", type=int, default=1)
    result.add_argument("--expand-style", default="mixed")
    result.add_argument("--prepare-only", action="store_true")
    result.add_argument("--reuse-prepared", action="store_true", help="reuse a successful pipeline.json without model calls")
    result.add_argument("--nogen", action="store_true")
    result.add_argument("input_dir", help="directory of additional initial seeds (may be empty)")
    result.add_argument("output_dir", help="run directory for all generated artifacts")
    result.add_argument("target", nargs=argparse.REMAINDER, help="-- TARGET [TARGET_ARGS...]")
    return result


def main(argv=None):
    cli = parser()
    args = cli.parse_args(argv)
    target = args.target
    if target[:1] == ["--"]:
        target = target[1:]
    if not target:
        cli.error("a target command is required after --")
    if args.expand_count < 1:
        cli.error("--expand-count must be at least 1")
    if not Path(args.input_dir).is_dir():
        cli.error("input directory not found: " + args.input_dir)
    input_dir = Path(args.input_dir).resolve()
    run_dir = Path(args.output_dir).resolve()
    if run_dir == input_dir or input_dir in run_dir.parents or run_dir in input_dir.parents:
        cli.error("input and run directories must not contain one another")
    target[0] = str(Path(target[0]).resolve()) if os.sep in target[0] else (shutil.which(target[0]) or target[0])
    try:
        if not args.prepare_only and not args.nogen and not args.reuse_prepared:
            check_native_launch(Path(args.g2fuzz_dir).resolve(), run_dir / "fuzzer")
        manifest = load_prepared(args) if args.reuse_prepared else prepare(args, target)
        if args.prepare_only:
            print("[F2Mut] prepared: " + str(Path(args.output_dir).resolve() / "pipeline.json"))
            return 0
        if not args.nogen:
            check_native_launch(manifest["g2fuzz_dir"], manifest["fuzz_dir"])
        launch_fuzzer(args, manifest, target)
        return 0
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"[F2Mut] failed: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
