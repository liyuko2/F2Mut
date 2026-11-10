# 执行链路约定
<!-- ASK mode: never; effort: balanced; assurance: draft -->

| ID | 请求未确定的部分 | 选择 | Class | Source |
| --- | --- | --- | --- | --- |
| A-001 | NoGen 是否跳过离线初始化 | 两种版本共用原生种子生成、初始模板和模板扩展；NoGen 只改变 fuzzing 二进制，并禁用 Python adapter 生成分支 | semantic | default |
| A-002 | 完整 G2FUZZ 的来源和版本 | 从现有原生仓库提交 `f62cc550c0cdc715bc960937d3017fcb1e5c11bc` 提取全部受版本控制的文件；排除工作区改动和嵌套 `.git`，在子目录外记录来源 | interface | default |
| A-003 | 入口和输入参数 | `run.sh` 执行完整流水线，要求 `--program`、`--format` 和原有的种子目录、运行目录、目标命令；`run_fuzz.sh` 保留为已准备产物的启动入口 | interface | default |
| A-004 | 相对路径配置和 API 凭据 | 原生脚本在运行目录中的独立工作目录执行；在那里写入配置副本和仅当前用户可读的密钥文件，不修改 G2FUZZ 源文件及其配置 | interface | default |
| A-005 | 一个程序对应多个格式时本次生成哪种 | 按显式 `--format` 在运行期配置副本中设置该程序的格式；不覆盖上游配置 | interface | default |
| A-006 | 初始模板使用哪个种子 | 默认选择原生生成目录中排序后的第一个非空种子；允许 `--template-seed` 指定。原生种子保持文件名并和用户种子合并 | semantic | default |
| A-007 | 产物复用与失败行为 | 默认要求新的运行目录；`--prepare-only` 只生成产物，`--reuse-prepared` 显式复用已成功准备且程序/格式匹配的产物；任一阶段失败不启动 fuzzer | interface | default |
| A-008 | 扩展执行器如何加载 | 使用生成的初始模板作为 fallback，扩展目录作为 pool，显式启用 pool 并关闭 initial-only；不退回固定 ELF 模板掩盖产物缺失 | interface | default |
| A-009 | 本次验证是否调用真实模型 | 自动化检查使用标明用途的离线响应/子进程替身，不调用外部模型，不把测试产物作为实验结果 | semantic | default |
| A-010 | 模型和扩展数量的默认值 | 默认沿用原生 model_setting.json 的首个模型并传给两个模板工具；`--model` 可覆盖。扩展数量沿用扩展器默认的 1，允许 `--expand-count` 覆盖 | interface | default |
| A-011 | 原生运行期代码需要相对配置路径，而目标可能使用相对路径 | fuzzer 在独立 G2FUZZ 工作目录运行；目标可执行文件在进入目录前解析为绝对路径，其他目标文件参数须由调用者使用绝对路径 | interface | default |
| A-012 | 原生 fuzzer 使用未加引号的 system 命令调用生成器 | 正常版拒绝含空格或 shell 元字符的原生源码/输出路径，避免修改上游 C 代码；准备阶段和 NoGen 不受这个原生运行期限制 | interface | default |
| A-013 | 各工具对缺省服务地址的解释不同 | 完整流程统一把未配置的地址解析为 `https://api.openai.com/v1`，显式传给模板生成和扩展，并通过环境传给原生 SDK | interface | sweep |
| A-014 | 同时设置两个不同密钥环境变量时各工具的读取优先级不同 | 完整流程按 OPENAI_API_KEY、AFL_LLM_API_KEY、配置文件的顺序选定密钥，并统一写入原生凭据副本和两个子进程环境变量 | interface | sweep |

## 说明

默认保持现有初始模板与扩展工具的接口；原生 `feature_pool.json` 的字符串映射需要由本项目的读取端识别，不能为适配它而修改 G2FUZZ。
