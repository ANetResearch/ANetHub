# Hub 运营面（anet-hub-admin）设计

目标：在**不动公网 hub** 的前提下，为运营者提供注册表监管（上下架、移除与恢复）、官方 agent 登记与
全部管理操作的审计。付款体系此版不做（`pricing` 仅展示，与公网面一致）。

运营面不持有任务内容，也没有读取任务内容的通道（A2A-DESIGN §0 决定 2、§9、[C39]）。旧版本的
中继采收、官方 agent 任务记录采收、ssh 运维、monitor 代理、调用洞察与 ACL 写入均已删除，见 §4。

## 1. 架构

```
浏览器 ── https://hub.agentnetwork.org.cn/admin ──▶ nginx ──▶ anet-hub-admin (127.0.0.1:8078)
                                                              ├─ hub.db   （公网 hub 同一 WAL 文件，读为主）
                                                              └─ admin.db （运营面自有状态）
```

- 进程隔离：公网 `anet-hub`（8088）零改动；admin 独立 unit（`deploy/anet-hub-admin.service`）。
  运营面不再连接任何其他主机，因此不再需要 root 的 ssh 身份；改用 hub 自身账户运行需要调整
  `admin/` 目录属主，属于部署变更，未在 unit 文件中改动。
- 认证：`ADMIN_TOKEN` 环境变量，无默认值——未设置则拒绝启动；取值为占位符（unit 模板中的
  `CHANGE_ME` 及同类，见 `admin.PlaceholderToken`）同样拒绝启动；取值为本仓库曾发布过的默认口令时
  启动但每小时告警（`admin.WeakToken`）。`anet-hub-admin -check-token` 按同一规则检查
  `$ADMIN_TOKEN` 后退出（0 可启动，1 会被拒绝），不启动服务、不打印口令值。
  `deploy/deploy-admin.sh` 在重启前于主机上用刚部署的二进制执行该检查，未设置或为占位符则中止部署；
  口令值留在主机上，经 ssh 传回的只有检查结论。
  `POST /admin/api/login` 常数时间比较 + 每 IP 每分钟 20 次失败限流；其后所有 `/admin/api/*` 走
  `Authorization: Bearer`，Bearer 失败同样计入限流。SPA 本身无需认证即可获取（登录门在页内），
  API 无 token 一律 401；`/admin/api/` 下不存在的路由在认证后返回 JSON 404。
- 跨进程写 hub.db：两进程均 WAL + busy_timeout 15s。admin 对 hub.db 的写**只有**注册表删除
  （`DELETE FROM agent`，删除前整行归档到 admin.db）与从归档恢复（`INSERT OR IGNORE`）。
- 不读取 `relay_message` 的载荷：自 hub wire 2 起载荷为封装信封，运营面只统计行数（信箱积压）。

## 2. Agent 分层与监管

- **official**：运营面登记的官方 agent，只登记 `id / aid / hub / caps`，另有 `name / tier /
  product_line / summary / maintainer` 等展示标签（`internal/admin/manifest.go`）。清单来自
  `<--data>/officials.json` 或 `POST /admin/api/official`；含 `runtime`、`monitor`、`ops`、
  `datasets` 任一字段的清单被拒绝（文件中出现时运营面拒绝启动）。官方 agent 的运行、日志与授权
  由 hub 主机之外的独立运维工具处理（A2A-DESIGN §15）。
- **community**：其余全部注册身份。admin 看得到**未上架**的纯 requester（公网 API 刻意隐藏，
  hubread.go `AllAgents`）。
- 注册表视图的计数：收到的评价数（作为提供方）、写出的评价数（作为请求方）、信箱积压。旧版本的
  "任务 供/求"计数读自已删除的 `completed_task` 表，不再提供。
- 监管杠杆（全部落审计 `audit_log`）：
  - 标记关注 / 恢复（moderation 表，运营侧元数据）。
  - 移除注册（`DELETE FROM agent`，可在回收站恢复）。**已知边界：hub 无黑名单，移除后可重新注册**。

## 3. API 一览（server.go）

```
POST /admin/api/login                       GET  /admin/api/overview
GET  /admin/api/agents[?q=&tier=]           GET  /admin/api/agents/{aid}
POST /admin/api/agents/{aid}/moderate       DELETE /admin/api/agents/{aid}
GET  /admin/api/official                    POST /admin/api/official        (登记 upsert)
DELETE /admin/api/official/{id}
GET  /admin/api/capabilities                GET  /admin/api/discover?task=…
GET  /admin/api/vision                      GET  /admin/api/store
GET  /admin/api/sessions[?source=&q=&limit=]   GET /admin/api/sessions/{source}/{id}
POST /admin/api/harvest                     GET  /admin/api/reviews
GET  /admin/api/audit                       GET  /admin/api/deleted
POST /admin/api/deleted/{aid}/restore
```

- `/reviews` 只返回评分、评语与回执 CID，不含请求目标与交付物（hub 不持有）。
- `/sessions` 与 `/sessions/{source}/{id}` 只读展示旧版本采收留在 admin.db 的会话索引（来源、会话
  id、双方 AID、意图标签、状态、计数），不返回目标文本、会话卡与事件文件。生产清理后为空。
- `/harvest` 调用 `RunAll`，它没有任何来源，返回空列表；保留该入口与定时器，是为了让"采收不触碰
  任何源、不写 datasets"可以从外部验证（A2A-DESIGN SI-1）。
- `/capabilities` 与 `/discover`：官方登记的能力（`listed`）与社区能力（`community`），来源只有
  注册表与登记清单，不含调用数据。

已删除的路由（请求返回 404）：`POST /agents/{aid}/quota`、`POST /official/{id}/ops`、
`GET /official/{id}/monitor/{what}`、`GET /official/{id}/insights`、`POST /official/{id}/acl`、
`GET /tasks`。

## 4. 已删除的能力与原因

| 能力 | 删除原因 |
|---|---|
| hub-relay 采收（`RelayRowsSince`、解码 DelegateReq/ChatMsg/ResultResp） | 把中继内容复制出中继自身的保留期，永久存放在 hub 主机 |
| ai-studio 采收（`jobRec`、`runHistory`、`runHistoryHTTP`、`appendJob`、`Manifest.Datasets`） | 把官方 agent 的任务 prompt 汇集到 hub 主机 |
| 官方 agent ops（ssh start/stop/restart/update/logs）、探活 | hub 主机持有以 root 操作官方 agent 主机的通道 |
| monitor 代理与 insights（`MonitorProxy`、`buildInsights`，含 `state` 即近窗任务） | 经 hub 主机读取官方 agent 的任务记录 |
| ACL 写入 | 官方 agent 的授权由其自身与独立运维工具管理 |
| 访客额度 `guest_quota` | 访客模式删除 |
| `completed_task` 读取方（任务计数、最近任务） | 表已删除；`tasks_completed` 改为已公开回执数，见 DATA-ASSETS.md §3 |

旧版本留在 `admin/datasets/`、`admin.db` 的数据由 `deploy/cleanup-content-v0.2.sh` 删除（须经产品
负责人同意）。

## 5. 旧运维凭证（部署 v0.2 时的检查清单）

删除 ops/monitor 代码不会让它们用过的凭证消失（A2A-DESIGN §9 "admin 官方 agent"、§15、[C39]）。
旧版 admin 以 root 运行（unit 没有 `User=`），用该账户的默认 ssh 身份（清单 `runtime.ssh_user`，
缺省 root，不带 `-i`）登录官方 agent 主机；并以 `ADMIN_MONITOR_TOKEN` 登录官方 agent 控制台，
该变量未设置时取 `ADMIN_TOKEN` 的值。

`deploy/cleanup-content-v0.2.sh` 第 9 步报告这些凭证（默认只报告，不打印任何口令值）：清单里出现过的
`用户@主机`（在第 7 步剥掉 `runtime/monitor` 之前读取）、`--ssh-dir`（缺省 `/root/.ssh`）下的私钥及指纹、
admin unit、drop-in 及其 `EnvironmentFile` 中的 `ADMIN_MONITOR_TOKEN`。`--apply` 时删除单独成行的
`ADMIN_MONITOR_TOKEN` 赋值（与其他变量同行的只报告，需手工改），并删除以 `--ops-ssh-key` 点名的私钥
及其 `.pub`。默认身份不点名就不删：脚本无法判断该账户是否还用它做别的事。

脚本做不到、需运营者逐项完成（执行前征求产品负责人同意，属阶段 G）：

- [ ] 在报告列出的每台官方 agent 主机上，从对应用户的 `~/.ssh/authorized_keys` 删除本 hub 主机的公钥
  （按报告中的指纹核对）；hub 主机上若有专用私钥，以 `--ops-ssh-key` 点名删除。
- [ ] 轮换每个带 `monitor` 段的官方 agent 的控制台令牌。
- [ ] `ADMIN_MONITOR_TOKEN` 曾未设置或与 `ADMIN_TOKEN` 相同时，`ADMIN_TOKEN` 已发往各官方 agent 控制台：
  两者都换（新的 `ADMIN_TOKEN` 按 §1 的规则检查）。
- [ ] 改 unit 后 `systemctl daemon-reload`。
- [ ] admin 改用非 root 账户运行（调整 `admin/` 目录属主，见 `deploy/anet-hub-admin.service` 注释）。
