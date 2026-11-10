# Source Manifest

| Component | Retained files |
| --- | --- |
| AFL++ driver and Python bridge | src/, include/ |
| Instrumentation | instrumentation/, GNUmakefile.llvm, GNUmakefile.gcc_plugin |
| Build support | GNUmakefile, config.h, types.h, dynamic_list.txt, injections.dic, entitlements.plist, test-instr.c, utils/aflpp_driver/ |
| Mutation callbacks and scheduler | MutatorMin.py |
| Initial executor generation | template_seed_prompt_generator.py |
| Executor expansion and same-style deduplication | template_expander.py |
| Shared configuration, validation, usage metrics | llm_config.py, template_safety.py, llm_generation_metrics.py |
| Runtime seed-generation branch | seed_generator_builder.py, g2fuzz_adapter.py |
| Built-in executors | elf_template_executor.py, format_template/ |
| G2FUZZ native Python sources | G2FUZZ/program_gen.py, G2FUZZ/generator_mutation.py, G2FUZZ/py_utils/ |
| G2FUZZ configuration | G2FUZZ/model_setting.json, G2FUZZ/program_to_format.json |
| Entry, dependencies, licenses | run.sh, run_fuzz.sh, requirements-mgl.txt, README.md, .gitignore, LICENSE, G2FUZZ/LICENSE, G2FUZZ/README.md |

Removed: upstream test suites, benchmarks, example/custom mutators, dictionaries,
large documentation trees, optional emulation backends, standalone analysis
tools, alternate template/feature generators, unused top-level configuration
copies, and the unused G2FUZZ online_extension.py wrapper.

The scheduler and C callback logic are not redesigned. The only MutatorMin
behavioral adjustment guards the already-incomplete bottleneck manager hook
against launching a missing script.
