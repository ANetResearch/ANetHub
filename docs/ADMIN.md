# Hub 运营面（anet-hub-admin）设计

目标：围绕 ANetScreen / ANetOS / ANetPIN / ANetCraft 产品线构建 Agent Store 平台体系的第一块地基 —
在**不动公网 hub** 的前提下，提供 agent 发布监管、官方 agent 彻底观测、以及可训练数据资产的持续积累。
付款体系此版不做（`pricing` 仅展示，与公网面一致）。

## 1. 架构

```
浏览器 ── https://hub.agentnetwork.org.cn/admin ──▶ nginx ──▶ anet-hub-admin (127.0.0.1:8078, root)
                                                              ├─ hub.db   （公网 hub 同一 WAL 文件，读为主）
                                                              ├─ admin.db （运营面自有状态）
                                                              ├─ datasets/（OKF bundles）
                                                              ├─ ssh ──▶ 官方 agent 运行主机（白名单 ops）
                                                              └─ http ──▶ 官方 agent monitor（token 服务端注入）
```

- 进程隔离：公网 `anet-hub`（8088）零改动；admin 独立 unit（`deploy/anet-hub-admin.service`）。
- 认证：经典控制台 token（`ADMIN_TOKEN` 环境变量，无默认值——未设置则 admin 面拒绝启动）。`POST /admin/api/login` 常数时间比较 +
  每 IP 每分钟 20 次限流（server.go `hLogin`）；其后所有 `/admin/api/*` 走 `Authorization: Bearer`。
  SPA 本身无需认证即可获取（登录门在页内），API 无 token 一律 401。
- 跨进程写 hub.db：两进程均 WAL + busy_timeout 15s。admin 对 hub.db 的写**只有两种**：
  `UPDATE agent SET guest_quota`、`DELETE FROM agent`（hubread.go）。其余全部只读。
- 查询纪律：relay_message 数 GB（payload BLOB）。UI 轮询的查询全部走覆盖索引
  `idx_relay_mailbox` 或小表；只有采收器按 rowid 分页读 payload（hubread.go `RelayRowsSince`，
  单次 run 有 256MB payload 预算，首次全量分多次跑完）。

## 2. Agent 分层与监管

- **official**：由 ANetAgents 仓的 AGENT.yaml（JSON 镜像存 admin.db `official_agent`）声明，按 AID
  关联注册表。可彻底观测（见 §3）。初始清单从 `<--data>/officials.json` 读，缺省为空 —— 该文件缺席时
  official 目录就是空的，不是错误。二进制里不再内置任何清单：把生产主机名与 ssh 用户编译进一个会被
  分发的二进制，等于把基础设施拓扑随产品一起发出去。格式见 `cmd/anet-hub-admin/main.go` 包注释。
- **community**：其余全部注册身份。admin 看得到**未上架**的纯 requester（公网 API 刻意隐藏，
  hubread.go `AllAgents`）。
- 监管杠杆（全部落审计 `audit_log`）：
  - 访客额度 `guest_quota`（0 = 切断 guest 流量）。注意：agent 重新 `hub-register` 会覆盖回来。
  - 标记关注 / 恢复（moderation 表，运营侧元数据）。
  - 移除注册（`DELETE FROM agent`）。**已知边界：hub 无黑名单，移除后可重新注册**——真正的强制
    阻断需要公网 hub 增加 blocklist 检查（roadmap，改动位于 aghub `hRegister`，估 ~30 LoC + 表）。

## 3. 官方 agent 彻底观测（ops 白名单）

- 结构上不存在"传任意命令"的 API：`POST /official/{id}/ops` 只收 `{op, arg}`，op ∈
  {status, logs, start, stop, restart, update}（闭集，ops.go `opWhitelist`），且还要过 manifest 自身
  的 `ops.allowed` 交集。logs 的 arg 只接受**已声明单元名**+行数（≤2000）；update 只执行 manifest
  里那一条命令。所有执行的实际命令原样落审计并回显 UI。
- 通道：`ssh -o BatchMode=yes user@host`（8s 连接超时，90s 执行超时，输出保尾 64KB）。
- 活性探测双通道（ops.go `Probe`，2 分钟缓存）：ssh `systemctl is-active` + monitor `/healthz`。
  ssh 未授权时 UI 明示"ssh 不可用"，monitor 通道独立可用。
- monitor 直连（monitorproxy.go）：仅代理 `/api/state`、`/api/catalog` 两个只读端点；token 服务端
  注入（`ADMIN_MONITOR_TOKEN`），cookie 会话缓存，失效自动重登一次。
- **部署前置条件**：emax root 的 ssh 公钥需加入官方 agent 主机（如 bmax）的 authorized_keys，
  否则 start/stop/logs/update 不可用（探测与 monitor 不受影响）。

## 4. 数据资产采收（详见 DATA-ASSETS.md）

两个源（harvest.go），30 分钟自动 + 手动触发，游标断点续采：

- `hub-relay`：在保留脚本（deploy/hub-db-roll.sh，投递后 7 天删）清理**之前**按 rowid 增量捕获
  relay_message，解码 DelegateReq/ChatMsg/ResultResp → 每交互一个事件 JSONL + OKF 会话卡。
  附件只留 {name,mime,size,cid} 元数据，正文截 16KB。
- 每个 `datasets.harvest: true` 的官方 agent：ssh 按字节偏移 tail 其 history.jsonl（JobRec），
  service_id 即意图标签，自动铸造 references/intents/ 概念卡 —— 平台当前质量最高的意图对齐数据。

## 5. API 一览（server.go）

```
POST /admin/api/login                       GET  /admin/api/overview
GET  /admin/api/agents[?q=&tier=]           GET  /admin/api/agents/{aid}
POST /admin/api/agents/{aid}/quota          POST /admin/api/agents/{aid}/moderate
DELETE /admin/api/agents/{aid}
GET  /admin/api/official[?probe=force]      POST /admin/api/official        (manifest upsert)
DELETE /admin/api/official/{id}             POST /admin/api/official/{id}/ops
GET  /admin/api/official/{id}/monitor/{state|catalog|stats|models|acl}
GET  /admin/api/official/{id}/insights      POST /admin/api/official/{id}/acl   (v2)
GET  /admin/api/capabilities                GET  /admin/api/discover?task=…      (v2 能力包/发现)
GET  /admin/api/vision                                                           (v2 愿景地图)
GET  /admin/api/store                       GET  /admin/api/sessions[?source=&q=&limit=]
GET  /admin/api/sessions/{source}/{id}      POST /admin/api/harvest
GET  /admin/api/reviews  /tasks  /audit
```

## 5b. v2 深度可观测 + 愿景层（insights.go / vision.go / capsule）

- **官方 agent 彻底观测**（`/insights`）：从官方 agent 自己的 v2 monitor 拉取 `/api/stats`（调用曲线
  按小时、按服务/模型/模态/端点统计、成本估算）、`/api/catalog`（能力清单）、`/api/acl`（授权状态）、
  `/api/state`（近窗调用）。前端渲染调用曲线柱图 + 模型/接口/开销表 + 授权名单管理。
- **能力包仓库**（`/capabilities`）：官方服务 = certified 能力包，社区 cap = community 能力包；
  `/discover?task=` 用 CJK 分词 + 模态意图做任务→能力匹配（语义 embedder 为升级路径）。
- **愿景地图**（`/vision`）：六大能力跃升的实时指标（见 VISION.md）。
- **HTTP 采收通道**（harvest.go `runHistoryHTTP`）：官方 agent 历史经 monitor `/api/state` 拉取，
  **无需 ssh**——这解决了 emax→bmax ssh 未授权时 ai-studio 数据源不可采的问题。ops（上下线/日志）
  仍需 ssh；探测/监控/洞察/采收都走 HTTP。

## 6. 已知摩擦点（诚实清单）

1. 黑名单不强制（§2）。
2. guest_quota 会被 agent 重注册覆盖（需要 hub 侧"运营锁定位"才能根治）。
3. emax→官方主机 ssh 授权是人工一次性动作（§3）。
4. hub-relay 首次全量采收受 256MB/run 预算限制，4GB 级存量需要 ~10+ 个周期跑完（或手动连点
   "立即采收"）；期间保留脚本可能已删掉最老的已投递行 —— 已删的行**无法追溯**，采收从部署日起算。
5. agent 活跃度近似值：来自 completed_task 与信箱积压（relay_message 无 from_aid 索引，不做全表
   扫描）；"最后在线时间"暂不可得（hub 不记录 poll 时刻）。
6. 前端为手写单文件 SPA：体积小、零依赖、GFW 安全，但无组件复用；页面逻辑增长后考虑迁移
   vite+react 再嵌入（公网 SPA 已是该模式，构建产物在 Mac，源码未随仓）。
