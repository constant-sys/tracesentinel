# TraceSentinel · 迹哨

**从认证日志到可复查的安全证据。**

An offline, evidence-first blue-team engineering lab. Normalize authentication events, detect suspicious sequences, and produce reproducible investigation reports.

TraceSentinel 是持续迭代的蓝队安全工程项目。v0.3 提供 **认证日志 → 输入校验 → 滑动窗口检测 → 带证据的调查报告 → 标注场景评估** 的可复现流程。

## 五分钟运行

需要 Python 3.11+。运行和测试不依赖第三方包，也不需要 API Key、数据库或云服务。

```sh
git clone https://github.com/constant-sys/tracesentinel.git
cd tracesentinel
python -m tracesentinel analyze examples/auth-demo.jsonl --output output/demo
python -m unittest discover -s tests -v
```

用浏览器打开 `output/demo/report.html`。预期 **14 条事件、3 条告警**；查看[示例说明](examples/README.md)逐条复核。也可以下载仓库内的[示例报告](examples/report.html)后本地打开。[结构化报告](examples/report.json)可直接查看。

可选安装：`python -m pip install -e .`，之后使用 `tracesentinel analyze ...`。

也可以直接分析常见的 OpenSSH `auth.log`（RFC 3164 时间戳）。由于这类日志不包含年份，归档日志请显式传入年份；默认按当前 UTC 年解释，并按 UTC 解析：

```sh
python -m tracesentinel analyze /var/log/auth.log --format openssh --year 2026 --output output/ssh
```

适配器识别 `Failed password` 和 `Accepted password`（含 `invalid user`），保留原始物理行号。匹配支持格式后的无效 IP/日期会报错；未匹配行（包括部分损坏认证行、其他服务和 `Failed publickey`）会跳过，目前没有跳过统计。CLI 按 UTC 解释时间，不自动识别采集主机时区；非 UTC 数据应通过 API 显式提供 `timezone_info`。补齐这些限制是下一轮目标。

## 检测效果评估

```sh
python -m tracesentinel evaluate examples/evaluation/auth-synthetic-v1.json --output output/evaluation
python -m tracesentinel evaluate examples/evaluation/auth-synthetic-v1.json --threshold 6 --output output/evaluation-threshold-6
```

内置 **12 个场景、64 条模拟事件**，含正常活动、攻击意图、已知误报与漏报。默认得到 **TP 6 / FP 4 / FN 2 / TN 24**，对应场景规则级 precision 60%、recall 75%。这些数字仅衡量这组人工回归场景，不是生产精度。

评估按“场景 × 规则”计分，重复告警不重复计入比例；同时保留全部告警、标签和 SHA-256。查看[示例评估报告](examples/evaluation/evaluation.md)及[统计标准与参数对比](docs/evaluation.md)。

## 已实现

| 检测 | 触发条件（默认 5 分钟） | 输出 |
|---|---|---|
| TS-AUTH-001 密集失败 | 同源 IP、同主机、同账号 ≥5 次失败 | 中风险线索、原始行号、窗口证据 |
| TS-AUTH-002 疑似喷洒 | 同源 IP、同主机 ≥5 个不同账号失败 | 中风险线索、涉及账号、证据 |
| TS-AUTH-003 失败后成功 | 同源 IP、同主机、同账号 ≥5 次失败后成功 | 高风险线索、完整关联序列 |

- 严格校验时间、IP、事件类型和必填字段，输入错误返回实际行号。
- 支持 UTC 和带时区时间、IPv4 / IPv6、乱序输入。
- 报告记录分析输入的 SHA-256、实际阈值、稳定告警标识和证据。
- 静态 HTML 转义日志内容，无远程资源、无 JavaScript，支持离线分享。
- 检测核心、边界情况和命令行端到端测试；GitHub Actions 自动执行。

```sh
python -m tracesentinel analyze examples/auth-demo.jsonl --window 600 --threshold 8 --output output/custom
```

正常分析退出码为 `0`（包括发现告警），无效输入或写入失败为 `2`。输出目录中的 `report.json` / `report.html` 会被本次结果覆盖。

## 数据格式

一行一个 JSON 对象，时间必须包含秒和时区。原始日志应保留，报告行号用于回溯。

```json
{"timestamp":"2026-09-01T08:01:00Z","event_type":"auth_failure","source_ip":"198.51.100.23","username":"admin","host":"lab-web"}
```

事件类型为 `auth_failure` 或 `auth_success`。更多约定见[架构说明](docs/architecture.md)和[规则说明](docs/detection-rules.md)。Windows Event Log 等其他平台适配属于后续阶段。

## 范围与局限

这是学习与实验工具。告警说明规则触发，并不证明账号已被攻陷。日志里没有密码值，因此多账号失败只能提示疑似喷洒。共享出口、账号误输、自动化任务都可能造成误报；分布式和低速攻击可能漏报。三个规则可命中同一事件序列，告警数不能等同事件数。

当前版本仍在内存中排序输入，复杂度约为 O(n log n)，尚未验证生产规模。样例完全由模拟数据构成，不将它的通过情况表述为真实检出率。大文件、持续流处理、允许列表、真实样本评估和跨主机关联见[路线图](docs/roadmap.md)。

## 长期开发

每次迭代交付一个可复现的改进：提出问题 → 实现 → 正反例测试 → 解释设计取舍 → 演示。开发状态见[进度记录](docs/progress.md)，学习任务见[学习路径](docs/learning-path.md)。

这是 AI 辅助开发项目。能否写进简历，以能独立解释、修改、验证对应功能为准；只陈述实际完成的功能与测量结果。欢迎通过 Issue 提交经脱敏的复现数据，见[贡献说明](CONTRIBUTING.md)。

MIT License. Security reports: [SECURITY.md](SECURITY.md).
