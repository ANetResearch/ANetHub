# ANetHub 与《智能体互联网建设标志性产出》的对齐

愿景一句话：**互联网传输信息，物联网连接设备，智能体互联网传输能力并组织行动** —— 把分散在
不同平台、行业、设备中的智能能力，组织成可执行、可监管、可复用、可持续进化的社会级行动能力。

ANetHub（Hub 公网面 + 运营面）+ ANetAgents（官方 agent 目录）是这张主干网的**可运营底座**。
下面把愿景的六大能力跃升逐条落到本仓的具体组件（运营面 `/admin/api/vision` 实时输出同一张表）。

| # | 愿景标志性产出 | 能力跃升 | ANetHub 承载组件 | 状态 |
|---|---|---|---|---|
| 1 | 一张智能体互联主干网 | 连接信息/设备 → 连接能力、生成组织 | Hub relay + 委派 + 可信评价（`internal/aghub`）：任务传递、交付核验 | live |
| 2 | 智能体身份与能力发现网络 | 人找工具 → 任务自动找到并生成执行组织 | KEL 自证身份 + **能力包仓库** + **任务→能力发现**（`internal/admin/capsules.go`） | partial |
| 3 | 数字与物理资源接入底座 | 逐个定制集成 → 全网统一调用 | **ANetOS AI Studio**（数字资源统一接入网关，Gravitex+百炼全量，`ANetAgents/ai-studio`） | partial |
| 4 | 可信执行与安全监管体系 | 管单体输出 → 管组织行动 | **运营面**：注册表上下架/移除与恢复/审计（`internal/admin`） | live |
| 5 | 全球能力仓库与进化网络 | 一地一项目 → 一次验证、全网复用、持续进化 | 能力包目录（数据采收已删除：hub 不持有任务内容） | planned |
| 6 | 重大示范工程 | 封闭单场景 → 跨行业跨主体社会级组织智能 | 跨产品线 agent 组织（ANetOS/ANetCraft 在运行；具身迁移网络为愿景） | planned |

## 六跃升的具体实现

### 1. 主干网：任务传递 + 交付核验（live）
- 委派经 Hub relay 存转（`aghub` register/relay/reviews）；每笔交付带**密码学可核验的回执与评价**
  （provider 签名 receipt + requester 签名 review）。hub 验证两个签名与二者的对应关系，因而无法伪造
  评价；hub 不接收交互内容，回执中的内容绑定对 hub 而言是 UNVERIFIED。daemon 之间端到端加密（anet ≥
  0.2.0），hub 只搬运封装信封，仍能看到收发双方、时间与大小（见 anet 的已知局限 `docs/KNOWN-LIMITATIONS-zh.md`）。
- 运营面实时指标：注册智能体、已公开回执（经评价公开的有效回执数）、可信评价、在途积压。

### 2. 能力发现：从身份到能力包（partial）
愿景要「从任务出发查找谁能做、是否可信、如何组合」。本仓把每个能力抽象为**能力包（Capsule）**：
- `GET /admin/api/capabilities`：官方登记的每个能力 = 一个 `listed` 能力包；社区 agent 的每个 cap =
  一个 `community` 能力包。旧版本经官方 agent 的 monitor 读取服务目录与调用量（`certified`），该通道
  已删除。
- `GET /admin/api/discover?task=<自然语言>`：任务文本 → 排序后的能力包（CJK 分词 + 模态意图识别）。
  这是「任务自动找到能力」的第一版（词法匹配）；语义 embedding 检索是明确的升级路径。
- 每个能力包带**档位**（listed/community）——对应愿景「分级测试认证基础设施」的雏形；实测认证需要
  不经 hub 主机的评测体系。

### 3. 统一接入：AI Studio 作为数字资源网关（partial）
AI Studio v2（`ANetAgents/ai-studio`）是「数字资源统一接入底座」的参考实现：
- 把 Gravitex（108 模型）+ 百炼的**全部能力**以 9 个通用服务暴露（chat/image/image_edit/video/
  tts/asr/vision/embed/translate），**每次调用可指定任意模型**（`inputs.model`）。
- 任意 anet 节点一句 `delegate` 即可调用，产物以多模态附件回交——「从生成方案走向驱动真实行动」。
- 具身设备接入（ANetScreen/ANetOS 的物理资源网关）是同一模式的下一步。

### 4. 可信监管：管组织行动（live）
运营面管注册表层面的组织行动：
- **可阻断**：注册表下架与移除（可恢复），全部留痕。
- **可审计**：全部 mutating 操作留痕（`audit_log`）。
- 旧版本的授权门远端 grant/revoke、官方 agent 白名单 ops 与"彻底观测"（经 monitor 读取调用记录）
  已删除：它们让 hub 主机持有读取官方 agent 任务内容、以 root 操作其主机的通道（A2A-DESIGN §9、
  [C39]）。官方 agent 的授权与运维由其自身与 hub 之外的独立工具负责。

### 5. 经验沉淀（planned）
旧版本把平台流量（中继载荷、官方 agent 任务 prompt）沉淀为 OKF 数据集。该做法与"hub 只做传输、
不得看到任务内容"冲突，已删除；已采收的数据由 `deploy/cleanup-content-v0.2.sh` 清理（须经产品负责人
同意），见 `DATA-ASSETS.md`。经验沉淀若要继续，需要由交互双方在本机、经明确授权后进行，不经 hub。

### 6. 示范工程（planned）
跨产品线 agent 组织（ANetOS 智能相框、ANetCraft 竞技场在运行）是社会级组织智能的起点；愿景的
四类代表工程（具身能力迁移网络、立体交通、自主科研、极端环境建设）是长期目标。

## 差异化技术（为什么我们的 agent hub 更好）
1. **intent grounding / pre-cognition**：原先依赖 hub 侧采收的交互数据；采收删除后，训练素材须来自
   交互双方本机、经授权的数据，hub 不参与。
2. **更好的共脑协同**：可信回执 + 能力包 + 注册表监管，让多 agent 协同可发现、可编排、可追责。

## 现状与缺口（诚实）
- 能力发现是词法匹配（CJK 分词 + 模态意图），语义检索待接入 embedder。
- 档位目前只区分 listed/community，「分级测试认证」的评测体系待建。
- 具身/物理资源接入（愿景 leap 3 的另一半）尚未落地，AI Studio 先立数字资源标杆。
- 示范工程为规划态。
