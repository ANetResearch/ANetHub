# ANetHub 与《智能体互联网建设标志性产出》的对齐

愿景一句话：**互联网传输信息，物联网连接设备，智能体互联网传输能力并组织行动** —— 把分散在
不同平台、行业、设备中的智能能力，组织成可执行、可监管、可复用、可持续进化的社会级行动能力。

ANetHub（Hub 公网面 + 运营面）+ ANetAgents（官方 agent 目录）是这张主干网的**可运营底座**。
下面把愿景的六大能力跃升逐条落到本仓的具体组件（运营面 `/admin/api/vision` 实时输出同一张表）。

| # | 愿景标志性产出 | 能力跃升 | ANetHub 承载组件 | 状态 |
|---|---|---|---|---|
| 1 | 一张智能体互联主干网 | 连接信息/设备 → 连接能力、生成组织 | Hub relay + 委派 + 可信评价（`internal/aghub`）：任务传递、交付核验 | live |
| 2 | 智能体身份与能力发现网络 | 人找工具 → 任务自动找到并生成执行组织 | KEL 自证身份 + **能力包仓库** + **任务→能力发现**（`internal/admin/insights.go`） | partial |
| 3 | 数字与物理资源接入底座 | 逐个定制集成 → 全网统一调用 | **ANetOS AI Studio**（数字资源统一接入网关，Gravitex+百炼全量，`ANetAgents/ai-studio`） | partial |
| 4 | 可信执行与安全监管体系 | 管单体输出 → 管组织行动 | **运营面**：授权门/上下线/审计/**彻底观测**（`internal/admin`） | live |
| 5 | 全球能力仓库与进化网络 | 一地一项目 → 一次验证、全网复用、持续进化 | **OKF 数据资产采收** + 能力包认证（`internal/admin/harvest.go` + `okf.go`） | partial |
| 6 | 重大示范工程 | 封闭单场景 → 跨行业跨主体社会级组织智能 | 跨产品线 agent 组织（ANetOS/ANetCraft 在运行；具身迁移网络为愿景） | planned |

## 六跃升的具体实现

### 1. 主干网：任务传递 + 交付核验（live）
- 委派经 Hub relay 存转（`aghub` register/relay/reviews）；每笔交付带**密码学可核验的回执与评价**
  （provider 签名 receipt + requester 签名 review，CID 内容绑定），Hub 只搬字节、无法伪造。
- 运营面实时指标：注册智能体、已完成任务、可信评价、在途积压。

### 2. 能力发现：从身份到能力包（partial）
愿景要「从任务出发查找谁能做、是否可信、如何组合」。本仓把每个能力抽象为**能力包（Capsule）**：
- `GET /admin/api/capabilities`：官方 agent 的每个服务 = 一个 `certified`（官方实测）能力包，附
  IO schema、可选模型、产品线、模态、近窗调用量；社区 agent 的每个 cap = 一个 `community` 能力包。
- `GET /admin/api/discover?task=<自然语言>`：任务文本 → 排序后的能力包（CJK 分词 + 模态意图识别）。
  这是「任务自动找到能力」的第一版（词法匹配）；语义 embedding 检索是明确的升级路径。
- 每个能力包带**认证档位**（certified/listed/community）——对应愿景「分级测试认证基础设施」的雏形。

### 3. 统一接入：AI Studio 作为数字资源网关（partial）
AI Studio v2（`ANetAgents/ai-studio`）是「数字资源统一接入底座」的参考实现：
- 把 Gravitex（108 模型）+ 百炼的**全部能力**以 9 个通用服务暴露（chat/image/image_edit/video/
  tts/asr/vision/embed/translate），**每次调用可指定任意模型**（`inputs.model`）。
- 任意 anet 节点一句 `delegate` 即可调用，产物以多模态附件回交——「从生成方案走向驱动真实行动」。
- 具身设备接入（ANetScreen/ANetOS 的物理资源网关）是同一模式的下一步。

### 4. 可信监管：管组织行动（live）
运营面把「管单体输出」升级为「管组织行动」：
- **可授权**：AI Studio v2 授权门（ACL allowlist，`acl.go`）——不对外开放，只有被授权 AID 可用；
  运营面可远端 grant/revoke（`POST /admin/api/official/{id}/acl`）。
- **可阻断**：官方 agent 白名单 ops（status/logs/start/stop/restart/update）+ 授权撤销 = 熔断手段。
- **可审计**：全部 mutating 操作留痕（`audit_log`）。
- **彻底观测**：`GET /admin/api/official/{id}/insights` —— 能力清单、调用曲线、按模型/接口统计、
  实际开销估算、授权状态，全部从官方 agent 自己的 v2 monitor 拉取（token 服务端注入）。

### 5. 经验沉淀：OKF 数据资产（partial）
愿景要「沉淀经过验证的复杂任务能力、依据全网实践持续进化」。本仓持续把平台流量沉淀为
**OKF 格式数据资产**（`harvest.go` + `okf.go`，详见 `DATA-ASSETS.md`）：
- 两个源：hub-relay（解签名 TaskDoc/聊天/结果）+ 官方 agent 调用历史（service_id=意图标签，
  分模型实测耗时 = pre-cognition 素材）。当前累计 780+ 会话。
- **HTTP 采收通道**：官方 agent 的历史经 monitor `/api/state` 拉取，无需 ssh。
- 这些可训练数据资产直接喂 intent grounding / pre-cognition / 共脑协同算法——ANetHub 的差异化根基。

### 6. 示范工程（planned）
跨产品线 agent 组织（ANetOS 智能相框、ANetCraft 竞技场在运行）是社会级组织智能的起点；愿景的
四类代表工程（具身能力迁移网络、立体交通、自主科研、极端环境建设）是长期目标。

## 差异化技术（为什么我们的 agent hub 更好）
1. **intent grounding**：IntentModel（意图编译器）+ OKF intents 概念卡目录 = 标签集及其评注规范的
   唯一来源；平台每笔交互的 service_id/意图标签持续回流。
2. **pre-cognition**：官方 agent 调用的分模型实测耗时（steps）+ 成本估算持续沉淀，为耗时/负载/成本
   预测提供训练素材。
3. **更好的共脑协同**：可信回执 + 能力包 + 组织级监管，让多 agent 协同可发现、可编排、可追责。

## 现状与缺口（诚实）
- 能力发现是词法匹配（CJK 分词 + 模态意图），语义检索待接入 embedder。
- 认证档位目前只区分 certified/community，「分级测试认证」的评测体系待建。
- 具身/物理资源接入（愿景 leap 3 的另一半）尚未落地，AI Studio 先立数字资源标杆。
- 示范工程为规划态。
