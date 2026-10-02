# meshdispatch

**面向多 Agent 团队的跨服务器任务调度与可观测系统。**

meshdispatch 通过 [A2A 协议](https://github.com/a2aproject/A2A) 把**跑在不同服务器上**的
异构 agent 运行时装进同一个视野：一眼看到每个 agent 现在在做什么、之前做过什么，
以及**协作时它们彼此说了什么**。

<p>
  <img alt="license" src="https://img.shields.io/badge/license-MIT-blue">
  <img alt="python" src="https://img.shields.io/badge/python-3.11%2B-blue">
  <img alt="status" src="https://img.shields.io/badge/status-early%20development-orange">
  <img alt="dependencies" src="https://img.shields.io/badge/runtime%20deps-none-brightgreen">
</p>

---

## 为什么还要再做一个调度器？

因为现有的同类项目几乎都默认「只有一个运行时」。今天那些控制面板是围着**某一个** CLI
（Claude Code / Codex / OpenClaw …）和**某一台**机器设计的。如果你的 agent 是异构的，
或者它们分布在不止一台服务器上，那就没人管了。

meshdispatch 走的是相反的路：

| | 常见的控制面板 | meshdispatch |
|---|---|---|
| Agent 运行时 | 绑死某一个 CLI | **任意运行时** —— 走 A2A 协议，不绑厂商 API |
| 拓扑 | 单机 | **多服务器，点对点** |
| 协作 | 并行干活，彼此不知道 | **一等公民** —— 参与者、交接、对话记录 |
| 任务标识 | 隐含 | **每个任务都有编号、目的、创建时间** |

## 它做什么

- **任务登记。** 每个任务都有编号（`md-20261002-a3f19c`）、目的、创建时间、执行者，
  并标明它是**单 agent 任务**还是**多 agent 协作任务**。
- **把多 Agent 协作当成一等公民。** 任务记录 `participants`、每个 agent 各自的执行记录，
  以及协作过程中 agent 之间**交流的消息** —— 「它们当时说了什么」在事后可查。
- **天生跨服务器。** 来自对端服务器的任务，和本机任务用同一套模型登记与追踪。
- **保留每次执行的完整历史**，而不只是最后一次的状态。
- **零运行时依赖。** 第 1 期是纯 Python 标准库 + SQLite。

## 任务模型

| 表 | 存什么 |
|---|---|
| `tasks` | 编号、标题、描述、来源、执行者、单/多 agent、参与者、状态、创建时间、最近执行时间、结果 |
| `runs` | 每次执行一行：哪个 agent、状态、开始/结束时间、结果 |
| `messages` | **agent 之间的对话**：谁说的、什么身份、说了什么、什么时候 |
| `events` | 过程事件：类型、负载、时间 |

写入时强制校验：`origin` ∈ `cron | a2a | subagent | manual`；
`coordination` ∈ `single | multi`；
`status` ∈ `pending | running | done | failed | cancelled | blocked`。
所有时间戳统一归一化为 ISO 8601 UTC。

## 快速开始

```bash
git clone https://github.com/gu-reni/meshdispatch
cd meshdispatch
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'

# 登记一个任务
meshdispatch add --title "每晚数据库备份" --origin cron --assignee backup-agent

# 登记一个跨服务器的多 agent 协作任务
meshdispatch add --title "跨服务器同步" --origin a2a --coordination multi \
  --participants "server-a,server-b"

meshdispatch list
meshdispatch show md-20261002-a3f19c
```

也支持模块方式调用：`python -m meshdispatch list`。

## 当前状态

**早期开发中。** 第 1 期（任务模型、存储、登记器、CLI）已实现并有测试覆盖。
尚未完成：各类来源适配器、带实时推送的 Web 面板、认证。见下方路线图。

| 期 | 范围 | 状态 |
|---|---|---|
| 1 | 任务模型、存储、登记器、CLI | ✅ 已完成 |
| 2 | 适配器（cron / A2A / 子代理）+ 对话采集 | 🚧 计划中 |
| 3 | Web 面板（SSE 实时推送）+ 认证 | 🚧 计划中 |
| 4 | 跨服务器接入、文档、打包 | 🚧 计划中 |

## 许可证

MIT —— 见 [LICENSE](LICENSE)。
