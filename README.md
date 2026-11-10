# F2Mut

Minimal source-instrumented AFL++ distribution with the MutatorMin Python
scheduler, template generation/expansion, and G2FUZZ Python generator sources.

## Build

Requires a C/C++ toolchain, GNU make, Python 3 development headers, and LLVM/Clang
development packages (including llvm-config). From this directory:

```sh
python3 -m pip install -r requirements-mgl.txt
make -j2
```

The default build produces AFL++ tools and LLVM instrumentation. Python support
is required; the build checks it. Nyx, QEMU, Frida, Unicorn, examples, benchmark
tools, and upstream test suites are not included in this minimal distribution.
Use the supported default target or explicit AFL++ binary/LLVM targets, not
the upstream distribution/install/test targets that refer to omitted content.

## Template Pipeline

```sh
python3 template_seed_prompt_generator.py --help
python3 template_expander.py --help
```

The first entry builds or requests a seed-specific executor. The second extends
an existing executor, validates the result, and supports per-style deduplication.
Their required helpers are llm_config.py, llm_generation_metrics.py and
template_safety.py. No model calls occur with --help.

Keep credentials in environment variables, never in source files. Configure
AFL_LLM_MODEL, AFL_LLM_BASE_URL and AFL_LLM_API_KEY for the initial generator.
The expander retains its own existing CLI/environment configuration; use its
--help for the supported options.

## Fuzzing

Compile the target using the built afl-clang-fast/afl-clang-fast++ wrapper.
Prepare non-empty input seeds, then run:

```sh
./run_fuzz.sh ./seeds ./output -- ./instrumented-target @@
```

The launcher selects MutatorMin, stores state under the output directory and
uses elf_template_executor.py as fallback. For another format, set
AFL_LLM_FALLBACK_TEMPLATE_EXECUTOR to a bundled format_template/*_template_executor.py.
Set AFL_LLM_FORMAT_EXECUTOR_DIR to an existing generated-executor pool.

To select across that pool, set AFL_LLM_TEMPLATE_POOL=1 and
AFL_LLM_TEMPLATE_INITIAL_ONLY=0. Choose one pool scheduler with
AFL_LLM_TEMPLATE_POOL_SCHEDULE:

| Value | Selection weight | Recorded metric |
| --- | --- | --- |
| `random` | Uniform random selection across eligible executors | `uniform` |
| `coverage_per_call` | `max(C / N, 1e-6)`; `1e-6` when `N <= 0` | `new_coverage_finds_per_call` |
| `coverage` | `1 + C`, the original cumulative coverage weighting | `new_coverage_finds` |

`C` counts cumulative AFL `+cov` queue discoveries, not individual new edges.
`N` counts cumulative Python `fuzz()` attempts, including errors and unchanged
outputs. In both weighted modes, untried executors are selected first.
Afterward, selections explore uniformly with probability
AFL_LLM_TEMPLATE_POOL_EXPLORE (default 0.15), and otherwise sample in proportion
to the weights. Random mode always samples the whole eligible pool uniformly;
it does not prioritize untried executors or use the exploration setting.
Each stage retains one executor for 64 calls.

For example, launch from F2Mut with normalized weighting:

```sh
AFL_LLM_TEMPLATE_POOL=1 AFL_LLM_TEMPLATE_INITIAL_ONLY=0 \
AFL_LLM_TEMPLATE_POOL_SCHEDULE=coverage_per_call \
./run_fuzz.sh ./seeds ./output -- ./instrumented-target @@
```

An explicit schedule takes precedence over the old
AFL_LLM_TEMPLATE_POOL_WEIGHTED switch. If no schedule is set (or it is empty),
the old switch still selects `coverage_per_call` for 1 (the default) and
`random` for 0. Invalid schedule names fail at initialization.
Restart the fuzzer to change modes. Existing feedback counts remain usable;
feedback JSON records `schedule_mode`, `selection_metric` and the weight floor.
The startup log also reports the selected pool schedule. Set
AFL_LLM_TEMPLATE_FEEDBACK_WRITES=1 to persist feedback and
AFL_LLM_RUNTIME_STATUS_WRITES=1 to persist runtime status.

MutatorMin's scheduling, feedback, AFL++ callbacks, and C-side Python bridge are
retained. Its optional seed-generation branch still requires
seed_generator_builder.py and g2fuzz_adapter.py, so both remain.
AFL_LLM_SEED_GEN defaults to 0. Generated G2FUZZ programs may need additional
format-specific libraries; install those separately as needed.

G2FUZZ/program_gen.py, generator_mutation.py, py_utils/, and native configuration
files are retained. Run native entry points from G2FUZZ/ so relative config paths
resolve; configure OPENAI_API_KEY and, if needed, OPENAI_BASE_URL externally.

The previous bottleneck_expansion_manager.py is absent from the original
workspace. That incomplete integration is disabled when the manager is missing;
do not expect online feature-mutator expansion in this minimal distribution.

## License

See LICENSE (AFL++) and G2FUZZ/LICENSE. This is a curated derivative, not a
complete upstream AFL++ or G2FUZZ repository.
