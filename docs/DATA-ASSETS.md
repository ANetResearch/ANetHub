# 数据资产规范（OKF bundles）

平台差异化（intent grounding / pre-cognition / 共脑协同）都吃同一种燃料：**结构化、可溯源、可
训练的 agent 交互数据**。运营面持续把平台流量沉淀为 OKF 风格的数据资产，落盘于
`/data/projs/anet-hub/admin/datasets/`。

格式基线：OKF v0.1（Refs/okf `okf/SPEC.md`）—— bundle = markdown 概念卡树 + YAML frontmatter；
本仓的适配立场：**卡片管元数据/发现/血缘，JSONL sidecar 管原始记录**，`resource` 键相连（对应
SPEC 的 "OKF references domain schemas, does not subsume them" 非目标）。扩展键收敛在 `hub:`
命名空间（SPEC §4.1 允许未知键，消费方必须容忍）。

## Bundle 布局（每源一个 bundle）

```
datasets/<source>/                  # hub-relay | ai-studio | <官方 agent id>…
├── index.md                        # okf_version 0.1 + 生成的目录（SPEC §6）
├── log.md                          # 采收史，最新在前（SPEC §7）
├── sessions/<yyyymm>/<id>.md       # type: Agent Session — 一次交互/任务一张卡
├── references/intents/<id>.md      # type: Intent — 首见标签自动铸造 stub，人工增补定义
└── data/sessions/<yyyymm>/<id>.jsonl   # 原始记录，append-only 不可变
```

## 记录 schema

- `hub-relay` 事件：`anet-relay-event/1.0`（harvest.go `relayEvent`）——
  `{relay_id, ix, ts, kind, from, to, goal|body|status|deliverable, attachments[{name,mime,size,cid}], payload_len}`。
  附件字节不落库（CID 可未来回捞），文本截 16KB。
- 官方 agent 任务：monitor JobRec 原行保真（`{ix, service, peer, prompt, state, dur_ms, out_kind,
  out_bytes, steps[{id,label,model,ms}]}`）—— steps 的分模型实测耗时是 pre-cognition
  （耗时/负载预测）的直接训练素材；service_id 即意图标签。

## 操作纪律（继承自 OKF 参考实现）

1. **原始不可变，增强只叠加**：data/*.jsonl 只 append；卡片可重生成；标签修订只改卡。
2. 卡片 `description` 恒为一句话（index 生成逐字消费）。
3. 读取端永不严格校验（未知键/断链合法）。
4. 会话浏览走 admin.db `session` 索引表，不扫文件系统。
5. bundle 是普通目录树：`git init` 即可获得历史/署名/diff（SPEC 推荐的分发方式），需要时可
   定期推到独立数据仓。

## 血缘与后续

- 训练集物化（train/val/test 切分 + `derived_from` 血缘卡）是下一步：`datasets/<slug>.md`
  (type: Interaction Dataset) 引用 session 卡集合 + 选择器表达式，使每个训练集成为可复现的
  派生节点（OKF 的 metrics/joins 具象化模式）。
- IntentModel（意图编译器）侧的消费入口：intents 概念卡目录 = 标签集及其评注规范的唯一来源。
