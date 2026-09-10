# Detection evaluation / 检测效果评估

v0.3 提供可复现的规则评估。它回答“当前阈值在这些人工场景上能发现什么、会误报和漏报什么”，不代表线上检测精度。

## 运行

```sh
python -m tracesentinel evaluate examples/evaluation/auth-synthetic-v1.json --output output/evaluation
python -m tracesentinel evaluate examples/evaluation/auth-synthetic-v1.json --threshold 6 --output output/evaluation-threshold-6
python -m tracesentinel evaluate examples/evaluation/auth-synthetic-v1.json --window 600 --output output/evaluation-window-600
```

输出 `evaluation.json`（完整指标、规则参数、标签、告警证据）和 `evaluation.md`（可读摘要）。成功执行退出码为 0，即使有误报或漏报；无效输入和写入失败为 2。已有同名输出会被覆盖。输入文件及其硬链接不可作为输出文件。

## 统计单位与匹配标准

**每个“场景 × 规则”组合是一个二分类样本。** 每个场景单独运行检测，三个规则都参与计分，因此 12 个场景产生 36 个统计样本。这里的样本数既不是日志条数，也不是独立安全事件数。

`expected_rules` 由场景作者根据模拟行为意图标注。例如合法用户连续输错密码后想起密码属于正常行为，标签为空；模拟攻击者猜中密码的标签为 TS-AUTH-001、TS-AUTH-003。两者可以产生完全相同的日志，区别来自作者提供的场景背景，检测器无法只靠这些字段辨别。

**预测标准：** 场景中某条规则至少产生一条告警，则该规则预测为正。同一规则产生多条告警仍只计一个预测，但全部原始告警保留在 JSON 报告中。

| 标签 | 预测 | 计数 | 含义 |
|---|---|---|---|
| 正 | 正 | TP | 该场景中的目标行为被对应规则提示 |
| 负 | 正 | FP | 标签不要求该规则告警，但实际触发 |
| 正 | 负 | FN | 标签要求提示的行为没有触发该规则 |
| 负 | 负 | TN | 该规则在无需提示的场景中保持安静 |

匹配只检查场景内的规则 ID。它不判断告警是否指向正确账号、主机、时间范围或证据，也不惩罚重复告警；单个场景中混入多个独立攻击会掩盖局部漏报。当前应保持场景意图单一，证据正确性仍由单元测试和人工复核保证。更细的事件匹配属于后续工作。

总体采用 micro aggregation：先把各规则 TP/FP/FN/TN 相加，再计算比例；不会平均各规则百分比。

- Precision = TP / (TP + FP)：预测为正的组合里，标签也为正的比例。
- Recall = TP / (TP + FN)：标签为正的组合里，被发现的比例。
- F1 = 2TP / (2TP + FP + FN)。
- 分母为 0 时写入 JSON `null`，摘要显示 `N/A`，不伪装成 0 或 100%。

## 已复现的基线

`auth-synthetic-v1` 包含 12 个场景、64 条模拟事件。默认参数下生成 11 条原始告警，其中两次分开的猜测属于同一个场景，计分时合并为一次正预测。

| 配置 | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| 窗口 300 秒，阈值 5 | 6 | 4 | 2 | 24 | 60.0% | 75.0% |
| 窗口 300 秒，阈值 6 | 2 | 0 | 6 | 28 | 100.0% | 25.0% |
| 窗口 600 秒，阈值 5 | 7 | 4 | 1 | 24 | 63.6% | 87.5% |

把阈值提高到 6 消除了这个小数据集中的误报，也漏掉了更多已标注行为。把窗口放大到 600 秒发现了慢速猜测，但仍无法关联不同来源的喷洒。不要仅因为这个结果更好就将它当作生产推荐配置。

## 输入格式与来源

单个 UTF-8 JSON 文件（允许 BOM），字段如下。场景和事件数组必须非空；空标签数组表示该场景对三个规则均为负。ID 使用小写 ASCII 字母/数字以及分隔用的 `-` 或 `_`，场景 ID 不可重复。

```json
{
  "schema_version": 1,
  "dataset_id": "custom-synthetic-v1",
  "synthetic": true,
  "description": "人工模拟的正常登录",
  "scenarios": [{
    "id": "normal-login",
    "description": "合法用户正常登录，不应提示攻击",
    "expected_rules": [],
    "events": [{
      "timestamp": "2026-09-01T00:00:00Z",
      "event_type": "auth_success",
      "source_ip": "192.0.2.1",
      "username": "alice",
      "host": "synthetic-ssh"
    }]
  }]
}
```

仅接受列出的字段，拒绝未知字段、重复 JSON 键、重复/未知标签、NaN 和无效事件。先校验整个数据集再运行检测。当前只允许 `synthetic: true`；该声明来自作者，工具无法验证数据是否真实采集，勿将真实敏感日志标成合成样本上传。

报告记录原始输入字节的 SHA-256、软件版本和实际参数。同一文件内容与配置重复执行会得到相同报告，不记录运行时钟或绝对路径。告警来源为 `dataset_id/scenario_id`，其中 `line_number` 是 **events 数组中的 1-based 序号**，不是外层 JSON 文件物理行号；保留事件顺序以解释同一时间戳的先后。

内置数据由 [生成脚本](../scripts/build_evaluation_fixture.py)确定性创建，脚本不导入检测器、不会从实际输出生成标签。使用保留给文档的 IP 与虚构账号，无真实网络操作。标签和说明可在数据文件中直接审阅。

## 边界

这是刻意包含已知错误的人工回归集，不是代表性生产样本，也不是独立留出的测试集。不能在同一批样本上调参后声称具有泛化精度。未来需要带授权来源的独立样本、标注审查、采集链路评估和更细的实体/事件匹配。

该命令评估归一化事件进入规则后的行为。它不经过 OpenSSH 解析器，所以不能检验 OpenSSH 格式漂移、静默跳过行、时区推断或采集丢失造成的漏报。
