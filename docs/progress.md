# Progress / 开发记录

## 2026-09-09 · v0.1 foundation

目标：建立原创蓝队项目的可运行起点，作为长期学习与作品积累。

已实现：

- 规范认证事件、严格 JSONL 校验和 UTC 时间标准化。
- 按源 IP / 主机 / 账号分组的三个窗口检测规则。
- JSON 与离线 HTML 报告、输入 SHA-256、告警证据和参数。
- 14 条合成演示日志，预期 3 条告警；示例不代表真实检测精度。
- 核心与端到端测试，跨平台 CI 配置，规则说明与长期路线图。

本地验证：Python 3.14.5 上 42 项测试通过；演示输出 14 条事件、3 条告警；构建 `tracesentinel-0.1.0-py3-none-any.whl` 成功。

当前局限：仅归一化 JSONL；全部数据在内存处理；暂无生产日志评估；没有后台采集服务。完整条件见 `docs/detection-rules.md`。

下一次：补充 OpenSSH 适配器的更多认证方法和解析失败统计，再开始 v0.3 的标注场景与 precision/recall 评估。

## 2026-09-09 · v0.2 OpenSSH adapter

- 支持常见 RFC 3164 `sshd` `Failed password` / `Accepted password` 行，含 `invalid user`。
- CLI 增加 `--format openssh --year YEAR`，API 提供 `parse_openssh` / `load_openssh`。
- 保留文件名、物理行号和原始证据；IPv4/IPv6 规范化，归一化到 UTC。
- 无关行跳过；认证消息中的坏 IP/时间显式定位并报错，避免静默漏报。
- 新增 4 项适配器测试；全套测试在 Python 3.14.5 上通过（待本轮最终验证）。

## Continue checklist

1. 检查工作区未提交改动并保留已有工作。
2. 运行现有测试，确认起点。
3. 选择路线图中一个具体验收项，先理解检测意义与限制。
4. 实现、测试、演示；记录真实结果。
5. 更新本文件和 CHANGELOG，提交可审查的代码；确认 GitHub 同步状态。
