# Hub Taskboard（任务板）— C2 扩面

> anet4 A4 裁决落地：v3 kanban 的 7 列 FSM 移植到 hub 侧，卡片只是视图——
> 任务的真相是 `taskdoc_cid` 指向的 TaskDoc（D3 遗训）。orchestrator 依赖已剪断。

## 编译方式：加法 tag（默认不含）

任务板存储调用方提供的卡片标题，以及 submit / reject / block 时的备注，读取无认证，整个 hub 只有
一块板。这些都是任务内容，而 hub 默认不得持有任务内容（A2A-DESIGN §0 决定 2、§2 taskboard 行）。
因此自 hub wire 2 起任务板是**加法**编译模块：

- 默认构建（`go build ./cmd/anet-hub`）不含 `internal/taskboard` 的任何符号，`/tasks/*` 不路由，
  `/stats.modules` 不含 `taskboard`，web UI 不显示任务板。
- `go build -tags taskboard ./cmd/anet-hub` 才编入；此时 `/stats.modules` 含 `taskboard`，
  web UI 显示任务板，并注明卡片标题与备注对所有访问者公开。
- CI 的 `optin` job 验证两个方向：默认构建符号数 == 0，`-tags taskboard` 构建 > 0，并运行
  `go test -tags taskboard ./...`（默认的 `go test ./...` 看不到本包）。
- 生产主机上已有的 `data/taskboard.db`（含 `-wal`、`-shm`）由 `deploy/cleanup-content-v0.2.sh`
  删除（须经产品负责人同意）。

## 列与状态

`draft · backlog · ready(可认领) · in_progress(每人 WIP≤3) · in_review ·
done · blocked(需 blocker 说明)`；状态机 `created → claimed → submitted →
accepted`，reject 回 claimed，block/unblock 在 claimed 内横移。

## API

读开放（无认证；D44 原意为访客只读）：
- `GET /tasks/board` — 7 列全量
- `GET /tasks/cards/{id}` — 卡片 + 审计事件流

写需注册身份的 KEL 签名挑战（与 relay poll/ack 同一套 `relayauth.Preimage`，
action 命名空间 `task.*` 防跨端点重放）：

`POST /tasks/{create|move|claim|submit|accept|reject|block|unblock}`
统一携带 `{aid, ts, key_state_seq, sig}` + 各自字段（title/taskdoc_cid/
column/card_id/note）。

角色守卫：creator 才能 move/accept/reject；assignee 才能 submit；
block/unblock 限 assignee 或 creator。错误映射 400/401/403/404/409。

## 已知未竟（登记）

- 签名只绑 action+aid+ts，不绑 body（与 relay 同信任级）；加固项 = 挑战里
  纳入 body CID。
- 事件流后续镜像到 AEL；卡片事件与 hub 联邦的跨 hub 任务是 K208 F-2 之后的事。
