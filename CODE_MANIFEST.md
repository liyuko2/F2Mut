# 源码组成与执行边界

| 组件 | 文件或目录 | 执行用途 |
| --- | --- | --- |
| 原生 G2FUZZ | `G2FUZZ/` | 原生种子/特征生成，以及正常版原生 fuzzer |
| 完整流程 | `run.sh`、`run_pipeline.py` | 原生生成 → 初始模板 → 模板扩展 → fuzzer |
| 已准备产物的启动器 | `run_fuzz.sh` | 正常版选择原生二进制，NoGen 选择本项目二进制 |
| 初始模板生成 | `template_seed_prompt_generator.py` | 消费原生生成种子及特征上下文 |
| 模板扩展 | `template_expander.py` | 消费初始模板和原生 `feature_pool.json`，生成执行器 `.py` |
| 调度器 | `MutatorMin.py` | 加载初始模板和扩展池；无 adapter 生成器启动路径 |
| 共用工具 | `llm_config.py`、`llm_generation_metrics.py`、`template_safety.py` | 模型配置、调用记录和现有模板检查 |
| 本项目 AFL++ | 根目录 `src/`、`include/`、`instrumentation/`、GNUmakefile 系列 | 编译 NoGen 二进制及目标插桩工具 |
| 基础执行器 | `elf_template_executor.py` | 独立工具保留；完整流程使用实际生成的初始模板 |
| 验证 | `tests/` | 原生 CLI 离线集成、特征传递、产物加载和启动选择 |

完整流程直接调用 `G2FUZZ/program_gen.py`，依次生成初始模板和扩展执行器，
然后启动所选 fuzzer，由其加载 `MutatorMin.py` 及执行器池。

本项目根目录的 AFL++ 构建 NoGen 二进制，`G2FUZZ/` 构建正常版二进制。
两者独立构建，不相互覆盖二进制。运行期配置、密钥、生成代码与状态写入运行目录。
