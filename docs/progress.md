# Progress / 开发记录

## 2026-10-22 · v0.3.1 OpenSSH parser accounting

已实现：

- 新增 `OpenSSHParseResult`、`parse_openssh_result` 和 `load_openssh_result`，记录总行、空行、未匹配行、损坏认证行及逐行警告。
- CLI 的 OpenSSH 路径使用质量接口；`report.json` 与 HTML 报告展示解析统计，损坏认证行会在标准错误中提示。
- 质量接口覆盖 password、publickey、`Invalid user`、坏 IP、坏 RFC 3164 日期和不支持认证方式；旧的严格 `parse_openssh` 行为保持兼容。
- 84 项测试通过，包含 CLI 报告字段、坏行警告、IPv6、时区和旧 API 兼容性；版本更新为 0.3.1。

仍待处理：CLI 尚未提供显式时区参数，RFC 3164 未传年份时仍使用当前 UTC 年；下一步进入多日志来源合并与时间线设计。

## 2026-09-10 · v0.3 detection evaluation

已实现：

- 新增 `evaluate` 命令，按场景与三个规则的组合计算 TP/FP/FN/TN、precision、recall、F1。
- 每个场景独立运行，同规则重复告警在指标中只计一次，完整证据保留。
- 12 个手工标注场景、64 条合成事件，包含合法重试/共享 NAT 误报和慢速/分布式漏报。
- 可复现 JSON/Markdown 评估报告，包含数据集指纹、实际参数、标签与逐场景错误。
- 默认结果 TP 6 / FP 4 / FN 2 / TN 24；阈值 6 时 TP 2 / FP 0 / FN 6 / TN 28；600 秒窗口时 TP 7 / FP 4 / FN 1 / TN 24。
- 本地 Python 3.14.5：76 项测试通过；原有 JSONL 与 SSH 演示结果保持一致。指标限定于合成回归集，不代表生产精度。
- 已构建 0.3.0 wheel，在独立虚拟环境中安装，并从项目外运行评估命令验证相同结果。

当前限制：v0.3 评估不会检查解析器漏掉的行；OpenSSH 的显式时区参数、完整 ISO 时间格式和多日志时间线仍未实现。

协作偏好：不设置定时；用户希望先集中开发，等功能完善后再系统讲解。继续时读取最新记录，保留独立设计说明与可复现证据。

## 2026-09-09 · v0.1 foundation

目标：建立原创蓝队项目的可运行起点，作为长期学习与作品积累。

已实现：

- 规范认证事件、严格 JSONL 校验和 UTC 时间标准化。
- 按源 IP / 主机 / 账号分组的三个窗口检测规则。
- JSON 与离线 HTML 报告、输入 SHA-256、告警证据和参数。
- 14 条合成演示日志，预期 3 条告警；示例不代表真实检测精度。
- 核心与端到端测试，跨平台 CI 配置，规则说明与长期路线图。

本地验证：Python 3.14.5 上 42 项测试通过；演示输出 14 条事件、3 条告警；构建 `tracesentinel-0.1.0-py3-none-any.whl` 成功。

当时局限：仅归一化 JSONL；全部数据在内存处理；暂无生产日志评估；没有后台采集服务。完整条件见 `docs/detection-rules.md`。

后续进展见本文件顶部。

## 2026-09-09 · v0.2 OpenSSH adapter

- 支持常见 RFC 3164 `sshd` `Failed password` / `Accepted password` 行，含 `invalid user`。
- CLI 增加 `--format openssh --year YEAR`，API 提供 `parse_openssh` / `load_openssh`。
- 保留文件名、物理行号和原始证据；IPv4/IPv6 规范化，归一化到 UTC。
- 未匹配行跳过；匹配到支持格式后的坏 IP/日期定位报错。部分损坏行仍会被静默跳过，尚无统计。
- 新增 4 项适配器测试和 1 项 CLI 测试；全套 47 项测试通过，GitHub Actions 已通过（提交 ea30d94）。

## Continue checklist

1. 检查工作区未提交改动并保留已有工作。
2. 运行现有测试，确认起点。
3. 选择路线图中一个具体验收项，先理解检测意义与限制。
4. 实现、测试、演示；记录真实结果。
5. 更新本文件和 CHANGELOG，提交可审查的代码；确认 GitHub 同步状态。
