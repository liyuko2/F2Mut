# 原生 G2FUZZ 来源

- 上游仓库：`https://github.com/G2FUZZ/G2FUZZ`
- 固定提交：`f62cc550c0cdc715bc960937d3017fcb1e5c11bc`
- 获取方式：从本机已有上游仓库的 Git 提交对象提取完整快照，不复制其存在本地改动的工作区。
- 目录：`G2FUZZ/`，不保留嵌套 `.git`。
- 许可证：`G2FUZZ/LICENSE`，源码版权声明和原生 README 保持原样。

该提交包含 888 个文件/符号链接。全部源码、构建脚本、文档和测试数据共 881 个
条目保留原样；6 个上游 Python 缓存和空的 `openai_key.txt` 占位文件属于忽略项，
不加入外层版本控制。运行时密钥和配置由 `run_pipeline.py` 写入运行目录。

`G2FUZZ_UPSTREAM.json` 记录提交、Git tree 与逐文件 Git blob 和链接类型。
在不需要网络、也不需要嵌套 Git 仓库的情况下，可检查所有保留源码是否仍与原生版本一致：

```bash
python3 -B -m unittest discover -s tests -p test_vendor_snapshot.py -v
```

本项目的改动集中在根目录的流程、模板工具和调度器。需要适配原生特征格式时修改
本项目的读取端；需要不同程序或模型设置时修改运行目录中的配置副本。不要在
`G2FUZZ/` 中加入本项目的 adapter 或修改原生 Python/C 逻辑。
