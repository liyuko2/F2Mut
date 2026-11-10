# F2Mut

F2Mut 使用原生 G2FUZZ 生成种子与初始特征，再生成、扩展模板执行器，由
`MutatorMin.py` 加载生成的 Python 代码参与 AFL 模糊测试。

执行顺序固定为：

```text
G2FUZZ/program_gen.py
  ├─ gen_seeds/、generators/
  └─ feature_pool.json、feature_programs.json
                 ↓
template_seed_prompt_generator.py
  └─ 初始 executor.py
                 ↓
template_expander.py
  └─ generated_format_executors/*.py
                 ↓
MutatorMin.py 加载初始模板和扩展执行器
                 ↓
正常版：G2FUZZ/afl-fuzz
NoGen ：本项目源码构建的 ./afl-fuzz
```

两个版本共用前三个生成步骤。NoGen 表示 fuzzing 阶段使用本项目的 AFL++
循环，不执行 G2FUZZ 二进制中的运行期生成逻辑；它仍使用原生 G2FUZZ 预先
生成的种子和特征。项目不再保留或调用 `g2fuzz_adapter.py` / `seed_generator_builder.py`。

## 目录结构

```text
F2Mut/
├── G2FUZZ/                         # 完整上游源码快照，保持源码原样
│   ├── program_gen.py
│   ├── generator_mutation.py
│   ├── py_utils/
│   ├── src/、include/、instrumentation/
│   ├── GNUmakefile、utils/、test/、docs/ ...
│   └── LICENSE
├── G2FUZZ_UPSTREAM.json             # 来源版本及上游文件校验记录
├── G2FUZZ_UPSTREAM.md
├── run.sh                          # 完整流程入口
├── run_pipeline.py                 # 顺序调用原生 CLI 与模板 CLI
├── run_fuzz.sh                     # 只启动已准备好产物的 fuzzer
├── template_seed_prompt_generator.py
├── template_expander.py
├── MutatorMin.py
├── elf_template_executor.py
├── src/、include/、instrumentation/ # NoGen 使用的本项目 AFL++ 源码
├── tests/                          # 离线集成和上游完整性检查
└── runs/                           # 运行产物，已忽略
```

`G2FUZZ/` 来自上游提交 `f62cc550c0cdc715bc960937d3017fcb1e5c11bc`。
保留完整源码、构建文件、文档与测试数据，不包含嵌套 `.git`。上游缓存文件和空的
密钥占位文件不进入本项目的版本控制。来源和校验方法见
[G2FUZZ_UPSTREAM.md](G2FUZZ_UPSTREAM.md)。配置与凭据使用运行目录中的副本，
不需要修改该子目录中的代码或配置。

## 构建

需要 C/C++ 编译器、GNU make、Python 3 开发头文件和 LLVM/Clang 开发包
（包括 `llvm-config`）。原生 G2FUZZ 会调用 `python`，请确保它和安装依赖时的
解释器一致，例如使用虚拟环境：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-mgl.txt

# 本项目的 NoGen 二进制与目标插桩工具
make -j2

# 正常版使用的原生 G2FUZZ 二进制与工具
make -C G2FUZZ -j2 source-only
```

两套 `afl-fuzz` 都需要 Python 自定义变异器支持。NoGen 缺少本地 `afl-fuzz`
时，启动脚本会执行 `make afl-fuzz`；正常版要求先构建原生 G2FUZZ，若二进制
缺失则在模型生成前报错。可用 `--g2fuzz-dir /path/to/G2FUZZ` 或 `G2FUZZ_DIR`
选择另一份完整原生构建；默认使用本项目的 `G2FUZZ/`。

目标程序可使用本项目构建的 `afl-clang-fast` / `afl-clang-fast++` 进行插桩。
本项目根目录的裁剪版 AFL++ 不包含完整上游的可选模拟后端；请使用默认构建目标。

## 配置模型

原生 G2FUZZ 的模型设置保存在 `model_setting.json`，并从当前工作目录的
`openai_key.txt` 读取凭据。完整入口会在 `RUN_DIR/g2fuzz_work/` 创建配置副本，
将所选程序映射到 `--format` 指定的格式，并将密钥文件权限设为 `0600`。

```bash
export OPENAI_API_KEY='your-api-key'
# 使用 OpenAI 兼容服务时设置；原生 OpenAI 服务可省略
export OPENAI_BASE_URL='https://your-provider.example/v1'
```

也支持 `AFL_LLM_API_KEY`、`AFL_LLM_BASE_URL`。模型可以用 `--model` 指定；
未指定时使用 `AFL_LLM_MODEL`，再使用原生 `model_setting.json` 中的第一个模型。
所选模型和地址会传给三个生成阶段；未配置服务地址时三个阶段统一使用
`https://api.openai.com/v1`。

如需自定义原生配置文件，可指定 `--g2fuzz-config-dir DIR`，该目录需提供
`model_setting.json` 和 `program_to_format.json`，也可以提供 `openai_key.txt`。
环境变量中的密钥优先于配置目录的密钥文件。无需改动 `G2FUZZ/` 中的配置。

原生生成器可能需要额外的格式相关依赖，按原生 G2FUZZ 的运行要求准备。

## 启动完整流程

接口为：

```text
./run.sh [OPTIONS] --program NAME --format FORMAT INPUT_DIR RUN_DIR -- TARGET [TARGET_ARGS...]
```

`INPUT_DIR` 存放用户已有种子，可以为空目录。原生生成成功后，项目会将非空的
用户种子和原生种子合并到 `RUN_DIR/seeds/`，并保留原生种子文件名以维持它与
原生生成器的关联。默认从原生生成目录中选择排序后的第一个非空种子来生成初始
模板；可用 `--template-seed /absolute/path/to/seed` 覆盖。

正常版示例：

```bash
mkdir -p seeds
./run.sh --program objdump --format elf --model your-model \
  --expand-count 5 \
  ./seeds ./runs/objdump-normal -- /absolute/path/to/objdump.afl -d @@
```

NoGen 示例：

```bash
./run.sh --nogen --program objdump --format elf --model your-model \
  --expand-count 5 \
  ./seeds ./runs/objdump-nogen -- /absolute/path/to/objdump.afl -d @@
```

正常版传入原生 `-k G2FUZZ_DIR`，继续使用原生运行期生成；NoGen 使用根目录的
`afl-fuzz`，不传入 `-k`。两种版本均加载 `MutatorMin`，设置
`AFL_LLM_TEMPLATE_POOL=1`、`AFL_LLM_TEMPLATE_INITIAL_ONLY=0`，让初始模板
和扩展目录中的执行器共同进入调度池。原 adapter 分支的
`AFL_LLM_SEED_GEN` 在两种版本中均固定为 `0`。

fuzzer 在 `RUN_DIR/g2fuzz_work/` 工作目录下启动，以满足未改动的原生代码对
相对配置文件的要求。目标可执行文件会在切换目录前解析；目标参数中引用的其他
文件或目录请使用绝对路径。原生 fuzzer 的运行期命令使用未加引号的 shell
字符串，因此正常版的 G2FUZZ 源码和输出路径不能包含空格或 shell 元字符。

## 分开准备和执行

先生成所有产物，暂不启动 fuzzer：

```bash
./run.sh --prepare-only --program objdump --format elf --model your-model \
  --expand-count 5 \
  ./seeds ./runs/objdump-prepared -- /absolute/path/to/objdump.afl -d @@
```

随后显式复用这次成功准备的产物，例如用 NoGen 启动：

```bash
./run.sh --reuse-prepared --nogen --program objdump --format elf \
  ./seeds ./runs/objdump-prepared -- /absolute/path/to/objdump.afl -d @@
```

复用时使用 `pipeline.json` 中记录的模板、种子、原生目录和配置，不再请求模型。
程序名、格式必须匹配，模板、扩展代码和种子必须存在。完整流程默认要求一个新的
或空的运行目录，避免覆盖旧产物；任一生成阶段失败，都不会启动 fuzzer。
`--reuse-prepared` 用于准备完成后的启动，不会自动恢复一个已有的 AFL fuzzing 会话。

`run_fuzz.sh` 仍保留为低层启动入口。它要求调用者已经设置初始模板路径、执行器池
路径和原生工作目录；一般直接使用 `run.sh --reuse-prepared` 即可。

## 手动分步执行

以下命令逐个调用原生脚本、模板工具和 fuzzer，不经过 `run.sh`。先完成前面的
构建与依赖安装，然后在同一个 Bash 会话中按顺序执行。示例使用 `objdump` 和
`elf`；更换目标时同步修改程序名、格式、目标路径和目标参数。

### 1. 设置路径、模型和原生配置副本

从 F2Mut 项目根目录执行，替换模型、密钥和目标路径。`RUN_DIR` 必须是尚不存在的
新目录，且正常版的源码与输出路径不能包含空格或 shell 元字符。

```bash
set -euo pipefail

export F2MUT_ROOT="$(pwd -P)"
export G2FUZZ_DIR="$F2MUT_ROOT/G2FUZZ"
export RUN_DIR="$F2MUT_ROOT/runs/objdump-manual-normal"
export INPUT_DIR="$F2MUT_ROOT/seeds"
export TARGET_BIN='/absolute/path/to/objdump.afl'
export PROGRAM='objdump'
export FORMAT='elf'
export MODEL='your-model'

export OPENAI_API_KEY='your-api-key'
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://api.openai.com/v1}"
export PYTHONPATH="$F2MUT_ROOT${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1

test ! -e "$RUN_DIR"
test -x "$TARGET_BIN"
mkdir -p "$INPUT_DIR" "$RUN_DIR/g2fuzz_work" "$RUN_DIR/fuzzer/default" \
  "$RUN_DIR/initial_template" "$RUN_DIR/generated_format_executors" \
  "$RUN_DIR/seeds"

python - <<'PY'
import json
import os
from pathlib import Path

source = Path(os.environ['G2FUZZ_DIR'])
work = Path(os.environ['RUN_DIR']) / 'g2fuzz_work'
models = json.loads((source / 'model_setting.json').read_text())
models['model'] = [os.environ['MODEL']]
programs = json.loads((source / 'program_to_format.json').read_text())
programs[os.environ['PROGRAM']] = [os.environ['FORMAT']]
(work / 'model_setting.json').write_text(json.dumps(models, indent=2) + '\n')
(work / 'program_to_format.json').write_text(json.dumps(programs, indent=2) + '\n')
fd = os.open(work / 'openai_key.txt', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, 'w') as output:
    os.fchmod(output.fileno(), 0o600)
    output.write(os.environ['OPENAI_API_KEY'].strip() + '\n')
PY

cd "$RUN_DIR/g2fuzz_work"
```

后续命令均在这个工作目录执行，所有源码和产物路径使用绝对路径。原生代码从
这里读取配置与凭据，`G2FUZZ/` 中的原始文件保持不变。这里的 `python` 应指向
已安装依赖的解释器，原生生成器执行生成代码时也会使用它。

### 2. 使用原生 program_gen.py 生成种子和初始特征

```bash
python "$G2FUZZ_DIR/program_gen.py" \
  --output "$RUN_DIR/fuzzer" \
  --program "$PROGRAM"
```

检查 `RUN_DIR/fuzzer/default/` 下的 `gen_seeds/`、`generators/`、
`feature_pool.json` 和 `feature_programs.json`。下一段将原生非空种子与用户已有
种子合并，并选定供初始模板使用的种子；用户种子目录可以为空。

```bash
python - <<'PY'
import json
import os
from pathlib import Path
import shutil

run = Path(os.environ['RUN_DIR'])
state = run / 'fuzzer' / 'default'
features = json.loads((state / 'feature_pool.json').read_text())
if not isinstance(features, dict) or not features:
    raise SystemExit('原生特征池为空，请先检查 program_gen.py 的输出')
native_seeds = sorted(p for p in (state / 'gen_seeds').rglob('*')
                      if p.is_file() and p.stat().st_size)
if not native_seeds:
    raise SystemExit('原生生成目录中没有非空种子')
corpus = run / 'seeds'
for source in native_seeds:
    destination = corpus / source.name
    if destination.exists():
        raise SystemExit('种子文件名冲突：' + str(destination))
    shutil.copy2(source, destination)
user_seeds = sorted(p for p in Path(os.environ['INPUT_DIR']).rglob('*')
                    if p.is_file() and p.stat().st_size)
for index, source in enumerate(user_seeds):
    destination = corpus / f'user-{index:06d}{source.suffix}'
    if destination.exists():
        raise SystemExit('种子文件名冲突：' + str(destination))
    shutil.copy2(source, destination)
(run / 'template_seed.txt').write_text(str(native_seeds[0]) + '\n')
print('初始模板种子：', native_seeds[0])
print('合并后的语料目录：', corpus)
PY

TEMPLATE_SEED="$(cat "$RUN_DIR/template_seed.txt")"
export TEMPLATE_SEED
```

原生种子保留原文件名，以便 G2FUZZ 运行期关联对应生成器。若要使用其他样本生成
初始模板，可在下一步前手动设置 `TEMPLATE_SEED=/absolute/path/to/seed`。

### 3. 使用 template_seed_prompt_generator.py 生成初始模板

```bash
python "$F2MUT_ROOT/template_seed_prompt_generator.py" \
  "$FORMAT" "$TEMPLATE_SEED" \
  --call-llm \
  --model "$MODEL" \
  --base-url "$OPENAI_BASE_URL" \
  --api-key-env OPENAI_API_KEY \
  --target-program "$PROGRAM" \
  --target-args='-d @@' \
  --tool-output "g2fuzz_features=$RUN_DIR/fuzzer/default/feature_pool.json" \
  --output-code "$RUN_DIR/initial_template/executor.py" \
  --output-json "$RUN_DIR/initial_template/executor.json" \
  --summary-json "$RUN_DIR/initial_template/seed_summary.json"
```

`--target-args` 需和最终目标命令的参数保持一致。该步骤读取选定种子及原生初始
特征，验证并保存初始执行器 `initial_template/executor.py`。

### 4. 使用 template_expander.py 扩展可加载的执行器

```bash
python "$F2MUT_ROOT/template_expander.py" \
  "$RUN_DIR/initial_template/executor.py" \
  --sample "$TEMPLATE_SEED" \
  --feature-pool "$RUN_DIR/fuzzer/default/feature_pool.json" \
  --model "$MODEL" \
  --url "$OPENAI_BASE_URL" \
  --style mixed \
  --count 5 \
  --output-dir "$RUN_DIR/generated_format_executors"
```

扩展结果保存在 `generated_format_executors/`，其中 `.py` 文件由 `MutatorMin`
加载，配套 `.json` 文件记录生成内容。确认该命令成功且目录中有非空 `.py` 文件后，
再启动 fuzzer。

### 5. 配置 MutatorMin 的模板和执行器池

```bash
export AFL_PYTHON_MODULE=MutatorMin
export AFL_IGNORE_UNKNOWN_ENVS=1
export AFL_LLM_TEMPLATE_MODE=1
export AFL_LLM_TEMPLATE_POOL=1
export AFL_LLM_TEMPLATE_INITIAL_ONLY=0
export AFL_LLM_FALLBACK_TEMPLATE_EXECUTOR="$RUN_DIR/initial_template/executor.py"
export AFL_LLM_FORMAT_EXECUTOR_DIR="$RUN_DIR/generated_format_executors"
export AFL_LLM_MUTATORS_DIR="$RUN_DIR/runtime_state"
export AFL_LLM_AFL_OUT="$RUN_DIR/fuzzer/default"
export AFL_LLM_G2FUZZ_SOURCE_DIR="$G2FUZZ_DIR"
export AFL_LLM_G2FUZZ_WORK_DIR="$RUN_DIR/g2fuzz_work"
export AFL_LLM_SEED_GEN=0
export AFL_LLM_BOTTLENECK_EXPANSION=0
unset AFL_LLM_API_KEY

cd "$RUN_DIR/g2fuzz_work"
```

原生 G2FUZZ 会在启动日志中回显未识别的 `AFL_` 变量，因此启动前清除
`AFL_LLM_API_KEY`。原生运行期仍从工作目录的 `openai_key.txt` 读取密钥，
前面的两个模板工具已使用 `OPENAI_API_KEY` 完成生成。

### 6. 选择正常版或 NoGen 启动

正常版使用原生 G2FUZZ 二进制，`-k` 指向原生脚本目录；它的输出目录与第 2 步
相同，因此可以继续使用已有的生成器和特征状态：

```bash
"$G2FUZZ_DIR/afl-fuzz" \
  -i "$RUN_DIR/seeds" \
  -o "$RUN_DIR/fuzzer" \
  -k "$G2FUZZ_DIR" \
  -- "$TARGET_BIN" -d @@
```

NoGen 使用本项目源码构建的二进制，执行相同的初始语料和模板池：

```bash
"$F2MUT_ROOT/afl-fuzz" \
  -i "$RUN_DIR/seeds" \
  -o "$RUN_DIR/fuzzer" \
  -- "$TARGET_BIN" -d @@
```

两条启动命令选择一条执行。若要分别运行两种版本，应在第 1 步使用不同的
`RUN_DIR` 并各自准备产物，不要向已经运行过的 AFL 输出目录直接启动另一个版本。
目标参数中的其他文件路径使用绝对路径。

完成第 1～5 步后，也可以让低层启动器代为检查路径并选择二进制：

```bash
# 正常版
"$F2MUT_ROOT/run_fuzz.sh" "$RUN_DIR/seeds" "$RUN_DIR/fuzzer" -- "$TARGET_BIN" -d @@

# 或选择 NoGen
"$F2MUT_ROOT/run_fuzz.sh" --nogen "$RUN_DIR/seeds" "$RUN_DIR/fuzzer" -- "$TARGET_BIN" -d @@
```

纯手动流程不创建 `pipeline.json`，因此后续继续使用上述直接命令或
`run_fuzz.sh`；`run.sh --reuse-prepared` 适用于由完整入口成功准备并记录的产物。

## 运行产物

```text
RUN_DIR/
├── pipeline.json                   # 成功准备记录，不含密钥
├── g2fuzz_work/
│   ├── model_setting.json
│   ├── program_to_format.json
│   └── openai_key.txt               # 运行期凭据副本，0600
├── seeds/                          # 合并后的 AFL 初始语料
├── initial_template/
│   ├── executor.py
│   ├── executor.json
│   └── seed_summary.json            # 包含原生初始特征上下文
├── generated_format_executors/      # 扩展 .py/.json，供调度器加载
├── runtime_state/                  # 调度与反馈状态
└── fuzzer/
    └── default/
        ├── gen_seeds/
        ├── generators/
        ├── feature_pool.json
        ├── feature_programs.json
        ├── queue/                  # 启动 fuzzer 后创建
        ├── crashes/
        └── fuzzer_stats
```

`template_expander.py` 直接读取原生 `feature_pool.json` 的字符串映射，同时保留
原有结构化特征池格式的支持。`--expand-style` 默认为 `mixed`，`--expand-count`
默认为 `1`。两个模板工具的其他独立参数可分别通过 `--help` 查看。

## 执行器调度

使用环境变量 `AFL_LLM_TEMPLATE_POOL_SCHEDULE` 选择策略：

| 值 | 选择权重 |
| --- | --- |
| `random` | 所有可用执行器均匀随机 |
| `coverage_per_call` | `max(C / N, 1e-6)`，未尝试的执行器优先 |
| `coverage` | `1 + C`，未尝试的执行器优先 |

`C` 为 AFL 标记 `+cov` 的队列发现累计次数，`N` 为 Python `fuzz()` 调用次数。
加权策略默认以 `0.15` 的概率均匀探索，使用 `AFL_LLM_TEMPLATE_POOL_EXPLORE`
调整。每个阶段固定一个执行器执行 64 次调用。原有
`AFL_LLM_TEMPLATE_FEEDBACK_WRITES=1` 和 `AFL_LLM_RUNTIME_STATUS_WRITES=1`
可分别启用反馈与运行状态持久化。

## 验证

```bash
python3 -B -m unittest discover -s tests -v
bash -n run.sh run_fuzz.sh
```

离线集成测试运行真实的原生 `program_gen.py` 和两个模板 CLI，仅在模型 SDK
边界提供明确的测试响应；随后用真实 `MutatorMin` 回调加载、执行生成的代码。
二进制选择检查使用替身程序，不进行外部模型调用或正式 fuzzing 实验。
上游完整性测试逐一校验 881 个源码、文档和测试文件与固定提交的 Git blob 一致。

## 许可证

本项目保留根目录的 [LICENSE](LICENSE) 与原生 G2FUZZ 的
[LICENSE](G2FUZZ/LICENSE)，上游版权声明和文档一并保留。
