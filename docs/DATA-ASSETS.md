# 数据资产与 hub 持有的数据

本文件原先是"把平台流量沉淀为可训练数据资产"的规范：运营面（anet-hub-admin）按行读取中继表
`relay_message`，解码委派目标、聊天正文与交付物，连同官方 agent 的任务 prompt 一起写入
`admin/datasets/` 下的 JSONL 与 OKF 卡片。该做法已删除，本文件改为说明 hub 与运营面现在持有什么、
不持有什么，以及旧数据如何清理。

依据：A2A-DESIGN §0 决定 2（hub 只做传输，不得看到任务内容）、§9（hub 内容移除）、§21（已知局限）。

## 1. 不再持有的数据

| 面 | 旧行为 | 现状 |
|---|---|---|
| 中继 | `relay_message.payload` 为明文 CBOR（TaskDoc、聊天正文、交付物、附件字节），ack 后保留 7 天 | 只存封装信封（daemon 之间端到端加密的目标由 anet 0.2.0 实现）；不存发送方、消息类型、交互 id；ack 即删，未投递 14 天删除 |
| 运营面采收 | `hub-relay` 源解码中继载荷；`ai-studio` 源经 ssh 或 monitor 复制官方 agent 的任务记录（含 prompt） | 两个源均删除。`RunAll` 不读任何源、不写 `datasets/`（单测钉住） |
| 评价 | `review.goal`、`review.deliverable` 与 `review_blob.request_doc_raw`、`review_blob.deliverable_raw` 保存请求与交付物原文，经 `GET /agents/{aid}` 与 `GET /fed/v1/reviews` 公开 | 上传只收回执与评价两个签名对象；表列已删除（迁移重建 + VACUUM）；内容绑定如实标 `UNVERIFIED` |
| 访客模式 | hub 以自持身份代浏览器收发明文消息 | 删除 |
| 任务板 | `taskboard.db` 保存卡片标题与备注，读取无认证 | 改为加法编译模块（`-tags taskboard`），默认构建不含 |
| `completed_task` | 按中继看到的 `result` 消息计数 | 删除；`/stats.tasks_completed` 改为"经评价公开的有效回执数"（见 §3） |
| 官方 agent 运维通道 | admin 持有官方 agent 主机的 ssh 通道、monitor 代理与 ACL 写入 | 删除；官方 agent 在 admin 中只登记 `id/aid/hub/caps` |

`internal/aghub` 与 `internal/admin` 的依赖闭包中不得出现 `ANetCore/delegation` 与 `ANetCore/tsir`
（任务内容的编解码器），由 `internal/aghub/importguard_test.go` 检查。

## 2. 仍然持有、仍然可见的数据

去除内容之后，hub 仍然持有或观察到以下元数据（A2A-DESIGN §9 末段、§21）：

- agent 自述：名称、能力、简介、定价说明、卡片、KEL、加密公钥集。KEL 与公钥集对所有对等 hub
  按精确 AID 可查，与 hub-local 可见性设置无关。
- 通信元数据：发送时刻 hub 知道"谁发给谁"、何时、多大，以及来源 IP；不写入存储。
- 评价关系图：谁评价了谁、评分、评语（≤ 280 字符，由评价者签名公开）、回执中的 request_cid 与
  result_cid。anet 0.2.0 起这两个值的原像含 16 字节随机数（A2A-DESIGN §2 X4），不能用候选内容逐个
  计算比对来确认内容；更早版本签发的回执不含随机数，对低熵内容可以这样确认。
- p2p 地址目录、活跃度（最后取信时间）。
- 付款元数据：结算、兑付记录与公开发放链中的金额、时间与 AID；hub 可以按付款方、收款方与时间把
  结算与公开评价关联。

## 3. `/stats.tasks_completed` 的含义变化

- 旧含义：中继看到 `kind=result` 的交互数（依赖未认证的 `from_aid`，可被任意调用方抬高）。
- 新含义：经评价公开到本 hub 的有效回执数（按 `receipt_cid` 去重）。每张回执由提供方签名、由 hub
  按其 KEL 验证，第三方可复核。
- 该数低于网络实际完成的任务数：只有被请求方评价并上传的任务才计入。web UI 的标签相应改为
  "已公开的有效回执"。运营面快照中升级前的点按旧含义计数，曲线在升级处有台阶。

## 4. 旧数据清理

`deploy/cleanup-content-v0.2.sh`（默认只报告，`--apply` 才删除；执行前须经产品负责人同意）覆盖：
emax、fmax 上 `relay_message` 的明文行与周备份 `hub-backup-*.db`；`admin/datasets/` 下全部来源；
`admin.db` 的 `session` 与 `harvest_state` 全部行；`data/taskboard.db`（含 `-wal`、`-shm`）；
评价表中的内容列（新 hub 首次启动时已由迁移删除，脚本核对）；官方 agent 清单中的
`runtime/monitor/ops/datasets` 段；访客 broker 的私钥 `guest_identity.kel`。之后对 `hub.db` 与
`admin.db` 执行 VACUUM 与截断 WAL。

已经通过 `GET /fed/v1/reviews` 流向对等 hub 的内容无法收回。数据目录之外的副本（临时备份、其他机器
上的拷贝）脚本无法知晓，只列出疑似备份文件供人工核对。
