# 原生 G2FUZZ 执行链路重整

- Target：完整且不改动源码的 G2FUZZ 快照放在 `G2FUZZ/`；正式入口依次调用原生 `program_gen.py`、`template_seed_prompt_generator.py`、`template_expander.py`，再启动 fuzzer。
- Inputs：程序名、格式、原始种子目录、运行目录、目标命令，以及外部提供的模型配置。
- Outputs：运行目录内的原生特征和生成器、合并种子、初始模板、扩展执行器、fuzzer 输出和阶段记录。
- Success command：`python3 -m unittest discover -s tests -v`，覆盖原生 CLI 的离线集成、阶段顺序、实际执行器加载和两个版本的二进制选择。
- Base commit：`5241449fe0847ac7df2e4b03fe7750d71091ac46`。
- Scope：移除 adapter 执行入口；正常版使用 G2FUZZ 二进制，NoGen 使用本项目源码构建的二进制。此次不发送付费模型请求，也不运行正式实验。
