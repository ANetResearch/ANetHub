# ANetHub

hub.agentnetwork.org.cn 的完整源码仓（自本仓起在此管理）。两个二进制、一份 SQLite：

| 二进制 | 作用 | 端口 (emax) | 对外面 |
|---|---|---|---|
| `anet-hub` | 公网 Hub：registry + relay（只存封装信封）+ reviews（不含内容）+ 内嵌公开 SPA | 127.0.0.1:8088 | `location /` |
| `anet-hub-admin` | 运营面：注册表监管（上下架、移除与恢复）、官方 agent 登记（id/aid/hub/caps）、审计 | 127.0.0.1:8078 | `location ^~ /admin` |

hub 与运营面都不持有任务内容（A2A-DESIGN §0 决定 2、§9）：没有访客模式、没有中继或官方 agent
数据采收、评价不含请求与交付物。仍然可见的元数据与旧数据清理见 `docs/DATA-ASSETS.md`。
`/stats.tasks_completed` 自 wire 2 起表示"经评价公开的有效回执数"，不再是中继看到的结果消息数。

公网面与运营面**进程隔离**：admin 崩溃/升级不影响公网 hub；公网行为零改动。

## 布局

```
cmd/anet-hub            公网 Hub（与线上 0.1.5 行为一致，仅模块路径重命名）
cmd/anet-hub-admin      运营面入口
internal/aghub          Hub 存储 + HTTP + 内嵌公开 SPA (web/index.html)
internal/admin          运营面全部逻辑（见 docs/ADMIN.md）
internal/admin/web      运营 SPA（手写单文件，无构建步骤、无 CDN，#165DFF 白底）
internal/protocol       KEL 身份 / TSIR / 委派 / 证据 / CoreDet-CBOR / CID
internal/daemon         客户端 daemon（与 ANetResearch/ANet 公开仓同源）
deploy/                 systemd 单元、nginx 片段、部署脚本、hub 数据保留脚本
docs/                   ADMIN.md（运营面设计）、DATA-ASSETS.md（hub 持有与不持有的数据、旧数据清理）
```

## 构建与测试

```bash
# 纯 Go(modernc.org/sqlite),不需要 CGO 与 C 工具链;CI 即以 CGO_ENABLED=0 构建
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test  ./...
```

需要 CGO（mattn/go-sqlite3）+ `sqlite_fts5` tag。go 1.26.1。

## 部署

- 公网 hub：沿用原流程（emax `/data/projs/anet-hub`，unit `anet-hub.service`）。本仓 `deploy/anet-hub.service`、`deploy/nginx-hub.conf` 为线上现状镜像。
- 运营面：`deploy/deploy-admin.sh` 一键（本地构建 → scp → systemd → nginx 幂等插入 `/admin` location → 冒烟）。管理 token 放在 unit 的 drop-in 中（`systemctl edit anet-hub-admin`）；unit 模板里的 `ADMIN_TOKEN=CHANGE_ME` 是占位符，运营面遇到占位符拒绝启动，部署脚本在重启前检查。
- 旧数据清理：`deploy/cleanup-content-v0.2.sh`（默认只报告，`--apply` 才删除；执行前须经产品负责人同意）。

### 金额溢出核查（只读）

`deploy/audit-amount-overflow.sql` 检查 hub 库里有没有 x402 金额溢出缺陷留下的痕迹：授权或收据金额 ≥ 2^63 时，旧代码把它转成负的 int64 反向记账（付款方加、收款方减；兑付凭空铸币；对端收据扣本地收款人）。单笔金额都在范围内、但加上已有余额后超过 2^63-1 时（例如对端 hub 的两张 2^63-1 收据），SQLite 不报错，而是把余额存成 REAL，之后该账户读不出、`/x402/supply` 报 integer overflow。修复（`internal/aghub/amount.go`：线上金额只接受 1..2^63-1，各入口与每处换算都经它；余额、`hub_due`、`hub_owed` 的加减经 `addToRow`，结果超出 int64 时拒绝，什么都不动）只挡住以后，不改已经写进库的数据。脚本列出以下几类异常行，并在第 9 节汇总受影响的 AID 及首次、末次出现时间：

- `credit_settled`、`credit_redemption`、`credit_cleared`、`hub_cleared` 中金额 ≤ 0、存成 REAL 或大于 9223372036854775807 的行；
- `hub_owed` / `hub_due` 中的负值；
- `credit_balance` 中存成 REAL 的余额，以及 hub 自身以外账户的负余额；
- `credit_entry` 中为 0 或存成 REAL 的分录；
- 发放链 `credit_issuance` 中金额 ≤ 0 或存成 REAL 的记录。

干净的 hub 上第 1–9 节只有标题行。脚本只含 SELECT，并先设 `PRAGMA query_only = 1`。请在副本上执行，不要在线上文件上执行：

```bash
sqlite3 /data/projs/anet-hub/data/hub.db ".backup /tmp/hub-audit.db"   # 在线可执行，只写副本
sqlite3 -readonly /tmp/hub-audit.db < deploy/audit-amount-overflow.sql > /tmp/hub-audit.txt
```

几点说明：

- 发放链记录带签名，查出问题也不能改写，只能追加新记录来更正。
- 第 10 节的供给等式在这个缺陷下仍然成立（两边是按同一个错误符号写的），所以它对不上才算发现，对得上不能说明没事。
- 第 11 节列出自付款（付款方 = 收款方），对应的是网关的另一个缺陷（只看 accepted、不看签名授权，本线 R06 D2 已修）。自付款本身不能证明发生过这种购买，所以这一节是提示，不是证据。
- 修复后的 hub 对这类旧行的处理：同一授权再次提交时不再按"已结算"回答、不重签收据；兑付列表里该行 `amount` 为 0、`stored_amount` 给出库中原值。

## 官方 agents

官方 agent 在运营面只登记 `id/aid/hub/caps`（`<--data>/officials.json` 或 `POST /admin/api/official`，格式见 `deploy/officials.example.json`）；含 runtime/monitor/ops/datasets 的清单被拒绝。官方 agent 的运维不经 hub 主机。

## 闭源边界

Hub 服务端（本仓）保持闭源；公开的客户端/协议仓是 [ANetResearch/ANet](https://github.com/ANetResearch/ANet)（wire types 见其 `internal/hubapi`）。


## License

ANet Community License 1.0 — free for non-commercial use and commercial
deployments up to 1,000 nodes; larger commercial deployments: hi@anet0.com.

## Modules (anet4)

- **registry + relay** — the hub kernel (internal/aghub)
- **taskboard** — 7-column task board over TaskDoc CIDs (internal/taskboard, docs/TASKBOARD-zh.md). Opt-in: built only with `-tags taskboard`, because a board stores card titles and notes and serves them to anyone; the default build contains none of it.
- **federation** — peer hubs, card and review sync, forwarding (internal/federation). Default-on; `-tags no_federation` removes it.
- **hub identity** — first-class hub AID/KEL at `GET /hub/identity`, the federation trust anchor (internal/hubid)
