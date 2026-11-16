# Docs index

按用途分类。**Superseded** 的文档保留作历史记录,不要当作现行规格读。

## 决策(ADR)

| 文档 | 状态 | 一句话 |
|---|---|---|
| [ADR-001](ADR-001-architecture-direction.md) | superseded by ADR-004 | 最初的 MCP 手架构 |
| [ADR-002](ADR-002-youkai-brain-architecture.md) | 部分仍然有效 | 四样证据、档位模型、人批门的原始来源 |
| [ADR-003](ADR-003-platform-pivot.md) | 现行 | 单操作员、无 RBAC、只听 loopback 的边界 |
| [ADR-004](ADR-004-monolith-absorb.md) | **现行(架构基线)** | 吸收 Fairy/Verdex 成一个 Go 单体;纪律脊柱是唯一出口 |

## 规格(DEVPLAN)

| 文档 | 状态 |
|---|---|
| [DEVPLAN-v0.1](DEVPLAN-v0.1.md) | superseded by v0.2 |
| [DEVPLAN-v0.2](DEVPLAN-v0.2.md) | 现行(单体化与能力基线) |
| [DEVPLAN-v0.4](DEVPLAN-v0.4.md) | 已实现 |
| [DEVPLAN-v0.5](DEVPLAN-v0.5.md) | 已实现 |
| [DEVPLAN-v0.6](DEVPLAN-v0.6.md) | 已实现 |
| [DEVPLAN-v0.7](DEVPLAN-v0.7.md) | 已实现 |
| [DEVPLAN-v0.8](DEVPLAN-v0.8.md) | 已实现 |
| [DEVPLAN-v0.9](DEVPLAN-v0.9.md) | 已实现 |
| [DEVPLAN-v0.10](DEVPLAN-v0.10.md) | 已实现 |
| [DEVPLAN-v0.11](DEVPLAN-v0.11.md) | 已实现 |
| [DEVPLAN-v0.12](DEVPLAN-v0.12.md) | 已实现 |
| [DEVPLAN-v0.13](DEVPLAN-v0.13.md) | 已实现 |
| [DEVPLAN-v0.14](DEVPLAN-v0.14.md) | 已实现 |
| [DEVPLAN-v0.15](DEVPLAN-v0.15.md) | 部分实现 |
| [DEVPLAN-v0.16](DEVPLAN-v0.16.md) | 部分实现 |
| [DEVPLAN-v0.17](DEVPLAN-v0.17.md) | 部分实现 |
| [DEVPLAN-v0.18](DEVPLAN-v0.18-backfill.md) | 已实现(A/B/C) |
| [DEVPLAN-v0.19](DEVPLAN-v0.19.md) | 已实现(1-4) |
| [DEVPLAN-v0.20](DEVPLAN-v0.20.md) | 已实现 |
| [DEVPLAN-v0.21](DEVPLAN-v0.21.md) | 已实现(1-4) |
| [DEVPLAN-v0.22](DEVPLAN-v0.22.md) | 已实现(1-3) |
| [DEVPLAN-v0.23](DEVPLAN-v0.23.md) | 已实现(1-4) |

## 进度(IMPL-STATUS)

| 文档 | 状态 | 覆盖 |
|---|---|---|
| [IMPL-STATUS-v0.1](IMPL-STATUS-v0.1.md) | superseded by v0.2 | v0.1 的 MCP 手原型 |
| [IMPL-STATUS-v0.2](IMPL-STATUS-v0.2.md) | superseded by v0.3 | 单体化的第一批能力 |
| [IMPL-STATUS-v0.3](IMPL-STATUS-v0.3.md) | 现行(历史价值) | 账号层、CDP 浏览器闸门 |
| [IMPL-STATUS-v0.4](IMPL-STATUS-v0.4.md) | 现行 | 配置面(LLM / 护照 / 审计) |
| [IMPL-STATUS-v0.5](IMPL-STATUS-v0.5.md) | 现行 | 四样证据、快照、SARIF、披露包 |
| [IMPL-STATUS-v0.6](IMPL-STATUS-v0.6.md) | 现行 | 登录态浏览器(闸内注入) |
| [IMPL-STATUS-v0.7](IMPL-STATUS-v0.7.md) | 现行 | 过程记忆(trace 检索) |
| [IMPL-STATUS-v0.8](IMPL-STATUS-v0.8.md) | 现行 | 工程化(CI / 许可 / 基准) |
| [IMPL-STATUS-v0.9](IMPL-STATUS-v0.9.md) | 现行 | 检测覆盖(API 文档 / GraphQL / JWT / OAuth) |
| [IMPL-STATUS-v0.10](IMPL-STATUS-v0.10.md) | 现行 | 极简向导式 UX(只问网址) |
| [IMPL-STATUS-v0.11](IMPL-STATUS-v0.11.md) | 现行 | 对话式 + 人签委托书自治 |
| [IMPL-STATUS-v0.12](IMPL-STATUS-v0.12.md) | 现行 | 拆签名墙(UI 点头)+ 对话历史 + 点头卡 |
| [IMPL-STATUS-v0.13](IMPL-STATUS-v0.13.md) | 现行 | 白盒源码分析(代码线索指导黑盒验证) |
| [IMPL-STATUS-v0.14](IMPL-STATUS-v0.14.md) | 现行 | 五类新探针(SSRF/穿越/命令注入/XXE/上传),全部只判存在 |
| [IMPL-STATUS-v0.15-17](IMPL-STATUS-v0.15-17.md) | 现行 | JWT 深度 + 反致盲 + 证据加权排序 |
| [IMPL-STATUS-v0.18](IMPL-STATUS-v0.18.md) | 现行 | 反致盲闭环 + 多步链 + 认证补齐 |
| [IMPL-STATUS-v0.19](IMPL-STATUS-v0.19.md) | 现行 | 多链型 + 结果复盘 + 推理式提案 |
| [IMPL-STATUS-v0.20](IMPL-STATUS-v0.20.md) | 现行 | 对话直接开工的闭环修复(三个真因) |
| [IMPL-STATUS-v0.21](IMPL-STATUS-v0.21.md) | 现行 | 实时步骤流(看得见 agent 每一步) |
| [IMPL-STATUS-v0.22](IMPL-STATUS-v0.22.md) | 现行 | 托管自动续跑到真停止点 + 一条时间线 |
| [IMPL-STATUS-v0.23](IMPL-STATUS-v0.23.md) | 现行 | 利用方案文本 + 修复建议 |
| [ADR-006](ADR-006-approve-not-sign.md) | 生效 | 档 2 默认 UI 点头,签名降级为可选(取代 ADR-005 的委托书) |
| [ADR-005](ADR-005-conversational-and-mandate.md) | 部分被覆盖 | 对话面板保留;委托书改为 opt-in |

## 验证

| 文档 | 状态 |
|---|---|
| [GAPS-v0.2](GAPS-v0.2.md) | 已闭合(v0.3) |
| [E2E-VALIDATION-v0.5](E2E-VALIDATION-v0.5.md) | 剧本(可重放) |
| [E2E-RESULT-v0.5](E2E-RESULT-v0.5.md) | 2026-11-14 真机结果 + 6 个修复 |
| [bench/README](../bench/README.md) | 本机基准的口径与结果 |

## 读的顺序

新读者:`README` → `ADR-004`(为什么是单体)→ `IMPL-STATUS-v0.8`(现在到哪了)→
`E2E-RESULT-v0.5`(真机怎么验的)。要动手改代码前读 `CONTRIBUTING.md` 的
「Adding a capability」一节。
