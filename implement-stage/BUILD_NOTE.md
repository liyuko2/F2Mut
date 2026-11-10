# 执行链路实现记录

| Rung | 内容 | 验证命令 | Tier | Status |
| --- | --- | --- | --- | --- |
| F0 | 参数入口和阶段顺序骨架 | `python3 -m unittest discover -s tests -p test_pipeline.py -v` | MUST | passed |
| F1 | 完整原生快照与原生 CLI/config 工作目录 | `python3 -m unittest discover -s tests -v` | MUST | passed |
| F2 | 原生特征、初始模板和扩展执行器衔接 | `python3 -m unittest discover -s tests -v` | MUST | passed |
| F3 | 二进制选择、产物池加载和 adapter 退出 | `python3 -m unittest discover -s tests -v` | MUST | passed |
| F4 | 文档与独立审查 | `python3 -m unittest discover -s tests -v` | MUST | passed |

## 运行记录

工作区最初干净。源仓库工作区存在本地 Python 修改，使用提交对象恢复完整上游快照。

- F0：离线 CLI 替身执行三阶段并生成 pipeline.json，1 项检查通过，退出码 0。
- F1：完整源码快照 881 个源码/文档/测试文件逐一与上游 Git blob 匹配；原生配置副本、0600 凭据文件、已有目录保护及 F0 共 4 项检查通过，退出码 0。
- F2：原生特征映射进入初始模板和扩展提示词、原生种子名保留、原生 CLI 生成器执行和真实调度回调通过。模型 SDK 为明确的离线测试边界。
- F3：完整累积测试 14 项通过，退出码 0；两个版本均执行三阶段准备，选择不同二进制；复用和失败中止已覆盖。源码中不再存在 adapter/builder 的导入或启动路径。
- F4：15 项累计检查通过，退出码 0；新增无显式服务地址、同时设置不同密钥的真实 CLI 检查。
- 两套实际 fuzzer：`make -j2 afl-fuzz` 和 `make -C G2FUZZ -j2 afl-fuzz` 均退出 0，均包含 Python 支持。编译后原生源码完整性检查仍通过。
- 真实二进制短程启动：`python3 -B /tmp/f2mut_actual_smoke.py` 退出 0。正常版和 NoGen 都加载实际 MutatorMin，运行本地共享内存覆盖率测试目标并生成 fuzzer_stats；模型 SDK 使用离线响应。日志位于 `/tmp/f2mut-actual-smoke-esjb61f_/normal.log` 和 `nogen.log`。首次使用普通 AFL 阶段的尝试在 30 秒上限被终止；改为仅执行自定义变异器后，两模式均正常退出。
- 独立上下文复核共两轮：首轮发现 2 项 interface 配置分歧，0 项 semantic 未声明决策；修复并补测后，第二轮 verdict 为 clean。原始回复保存在两个 SWEEP JSON 文件中。
- 审查者为 GPT-6-Astra xhigh，执行者同属 GPT 系列：这是独立上下文复核，不满足跨模型家族独立性的要求；跨家族审查记为 SWEEP_UNAVAILABLE。assurance=draft，不阻止交付，未把该复核称为跨家族审查。

## 验证边界

生产代码中没有残留的 F0 占位逻辑。测试模型 SDK、确定性测试执行器和路由测试的 fuzzer 替身仅存在于 tests/fixtures 与临时测试目录中。真实二进制短程检查仍使用离线模型响应，未进行付费模型调用或正式性能实验。

## Deferred

无用户要求的步骤被延期。真实模型生成与正式 fuzzing 实验不属于本次结构调整的验收。

## 提交

保留可检查的工作区差异；此次不自动生成 Git 提交。
