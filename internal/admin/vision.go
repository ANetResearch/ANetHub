package admin

import "context"

// vision —— 把平台实况映射到《智能体互联网建设标志性产出》的六大能力跃升，让愿景可度量。
// 每个跃升给：它是什么、ANetHub 用什么组件承载、当前实况指标。这既是对外叙事，也是运营自检。

// VisionLeap 是一个能力跃升条目。
type VisionLeap struct {
	Key       string         `json:"key"`
	Title     string         `json:"title"`     // 愿景标志性产出
	Leap      string         `json:"leap"`      // 能力跃升一句话
	Component string         `json:"component"` // ANetHub 承载组件
	Metrics   map[string]any `json:"metrics"`   // 当前实况
	Status    string         `json:"status"`    // live | partial | planned
}

// VisionMap 是完整六跃升 + 总览。
type VisionMap struct {
	Headline string       `json:"headline"`
	Leaps    []VisionLeap `json:"leaps"`
}

// buildVisionMap computes the live vision map from the hub + admin state.
func (s *Server) buildVisionMap(ctx context.Context) VisionMap {
	totals, _ := s.hub.Totals()
	officials, _ := s.store.Officials()
	counts, _ := s.store.SessionCounts()
	states, _ := s.store.HarvestStates()
	caps := s.buildCapsules(ctx)

	var sessions, records int64
	for _, c := range counts {
		sessions += c["sessions"]
	}
	for _, st := range states {
		records += int64(st.Records)
	}
	certified, community := 0, 0
	for _, c := range caps {
		if c.Cert == "certified" {
			certified++
		} else {
			community++
		}
	}
	// official liveness (deeply observable ones)
	deepObservable := 0
	for _, m := range officials {
		if m.Monitor.URL != "" {
			deepObservable++
		}
	}

	return VisionMap{
		Headline: "互联网传输信息，物联网连接设备，智能体互联网传输能力并组织行动 —— ANetHub 是这张主干网的可运营底座。",
		Leaps: []VisionLeap{
			{
				Key: "backbone", Title: "一张智能体互联主干网", Component: "Hub relay + delegation（任务传递/交付核验）",
				Leap:    "从连接信息和设备，跃升为连接能力、生成组织",
				Metrics: map[string]any{"注册智能体": totals.Agents, "已完成任务": totals.TasksCompleted, "可信评价": totals.Reviews, "在途积压": totals.RelayBacklog},
				Status:  "live",
			},
			{
				Key: "discovery", Title: "智能体身份与能力发现网络", Component: "KEL 自证身份 + 能力包仓库 + 任务→能力发现",
				Leap:    "从人找工具、人工编排，跃升为任务自动找到并生成执行组织",
				Metrics: map[string]any{"能力包总数": len(caps), "已认证能力": certified, "社区能力": community, "上架提供方": totals.Listed},
				Status:  "partial",
			},
			{
				Key: "access", Title: "数字与物理资源接入底座", Component: "ANetOS AI Studio（数字资源统一接入网关，Gravitex+百炼全量）",
				Leap:    "从逐个系统定制集成，跃升为全网统一调用数字与物理资源",
				Metrics: map[string]any{"官方接入网关": len(officials), "AI Studio 模型": 108, "通用能力": 9, "具身接入": "ANetScreen/ANetOS（路线图）"},
				Status:  "partial",
			},
			{
				Key: "regulation", Title: "可信执行与安全监管体系", Component: "Admin 监管面（权限/授权门/上下线/审计/彻底观测）",
				Leap:    "从管单体输出，跃升为管组织行动：可授权、可阻断、可审计、可追责",
				Metrics: map[string]any{"深度可观测官方 agent": deepObservable, "授权门": "ACL allowlist", "审计留痕": "全量 mutating 操作", "熔断": "上下线 + 授权撤销"},
				Status:  "live",
			},
			{
				Key: "evolution", Title: "全球能力仓库与进化网络", Component: "OKF 数据资产采收 + 能力包认证（经验沉淀）",
				Leap:    "从一地一项目重复建设，跃升为一次验证、全网复用、持续进化",
				Metrics: map[string]any{"已沉淀会话": sessions, "累计交互记录": records, "采收源": len(states), "数据格式": "OKF v0.1"},
				Status:  "partial",
			},
			{
				Key: "demonstration", Title: "重大示范工程", Component: "跨产品线 agent 组织（ANetScreen/ANetOS/ANetPIN/ANetCraft）",
				Leap:    "从封闭系统单场景自动化，跃升为跨行业、跨区域、跨主体的社会级组织智能",
				Metrics: map[string]any{"产品线": "ANetOS 智能相框 · ANetCraft 竞技场（在运行）", "代表工程": "全球具身智能能力共享与迁移网络（愿景）"},
				Status:  "planned",
			},
		},
	}
}
