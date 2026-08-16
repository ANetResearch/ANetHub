package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// insights —— 官方 agent 的深度可观测：能力清单、调用曲线、模型/接口统计、实际开销、授权状态。
// 数据源是官方 agent 自己的 monitor（v2 /api/stats /api/catalog /api/acl /api/state），经
// MonitorProxy 拉取（token 服务端注入）。这实现「官方提供的 agent 能被彻底观测」。

// Insights 是一个官方 agent 的完整洞察包。
type Insights struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	OK        bool            `json:"ok"`
	Error     string          `json:"error,omitempty"`
	Catalog   json.RawMessage `json:"catalog,omitempty"` // {lines, services} —— 能力清单
	Stats     json.RawMessage `json:"stats,omitempty"`   // {curve, by_service, by_model, by_modality, endpoints, total_milli}
	ACL       json.RawMessage `json:"acl,omitempty"`     // {acl:{mode,allow,notes}, rejects, reject_seen}
	Recent    json.RawMessage `json:"recent,omitempty"`  // /api/state {jobs,logs,stats}
	CostYuan  string          `json:"cost_yuan,omitempty"`
	CostMilli int             `json:"cost_milli,omitempty"`
}

// Insights pulls the four v2 monitor surfaces for an official agent and assembles the insight pack.
func (s *Server) buildInsights(ctx context.Context, m *Manifest) Insights {
	out := Insights{ID: m.ID, Name: m.Name}
	if m.Monitor.URL == "" {
		out.Error = "该 agent 未声明 monitor"
		return out
	}
	// Each pull is independent; a failure on one (e.g. an older agent without /api/stats) must not
	// blank the whole pack.
	if b, err := s.mon.Fetch(ctx, m, "catalog"); err == nil {
		out.Catalog = json.RawMessage(b)
	}
	if b, err := s.mon.Fetch(ctx, m, "stats"); err == nil {
		out.Stats = json.RawMessage(b)
		var st struct {
			TotalMilli int `json:"total_milli"`
		}
		if json.Unmarshal(b, &st) == nil {
			out.CostMilli = st.TotalMilli
			out.CostYuan = formatMilliYuan(st.TotalMilli)
		}
	}
	if b, err := s.mon.Fetch(ctx, m, "acl"); err == nil {
		out.ACL = json.RawMessage(b)
	}
	if b, err := s.mon.Fetch(ctx, m, "state"); err == nil {
		out.Recent = json.RawMessage(b)
	}
	out.OK = out.Catalog != nil || out.Stats != nil
	if !out.OK {
		out.Error = "monitor 不可达或未升级到 v2（/api/stats 缺失）"
	}
	return out
}

func formatMilliYuan(milli int) string {
	yuan := milli / 1000
	frac := (milli % 1000) / 10 // 两位小数
	return fmt.Sprintf("¥%d.%02d", yuan, frac)
}

// --- capability packages (能力包) ---
//
// 愿景「全球能力仓库」的第一步：把每个官方 agent 的服务目录抽象为可发现、可调用、带来源与
// 认证档位的「能力包」。community agent 的 caps 也纳入（作为未认证能力）。这给能力发现与经验
// 沉淀一个统一对象模型。

// Capsule 是一个能力包（capability package）。
type Capsule struct {
	Key         string   `json:"key"` // 稳定标识：<provider_id>/<service_id> 或 cap 名
	Name        string   `json:"name"`
	ProviderID  string   `json:"provider_id"` // 官方 agent id（community 为空）
	ProviderAID string   `json:"provider_aid"`
	Tier        string   `json:"tier"`     // official | community
	Line        string   `json:"line"`     // 产品线
	Modality    string   `json:"modality"` // text|image|video|audio|mixed
	Inputs      []string `json:"inputs,omitempty"`
	Outputs     []string `json:"outputs,omitempty"`
	Models      []string `json:"models,omitempty"`
	Desc        string   `json:"desc,omitempty"`
	Cert        string   `json:"cert"`            // 认证档位：certified(官方实测) | listed(已登记) | community
	Calls       int      `json:"calls"`           // 近窗调用次数（来自 stats）
	Score       float64  `json:"score,omitempty"` // 语义检索相似度（discover 时填充）
}

// serviceEntry mirrors the AI Studio catalog Service shape (subset we need).
type serviceEntry struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Line    string   `json:"line"`
	Out     string   `json:"out"`
	Desc    string   `json:"desc"`
	Inputs  []string `json:"inputs"`
	Outputs []string `json:"outputs"`
	Models  []string `json:"models"`
}

// buildCapsules assembles the capability-package catalog: official agents contribute one capsule per
// catalog service (certified), community listed agents contribute one capsule per cap (community tier).
func (s *Server) buildCapsules(ctx context.Context) []Capsule {
	var out []Capsule
	officials, _ := s.store.Officials()
	callsByService := map[string]int{}
	for _, m := range officials {
		// call counts from stats (best-effort)
		if b, err := s.mon.Fetch(ctx, m, "stats"); err == nil {
			var st struct {
				ByService []struct {
					Key   string `json:"key"`
					Calls int    `json:"calls"`
				} `json:"by_service"`
			}
			if json.Unmarshal(b, &st) == nil {
				for _, e := range st.ByService {
					callsByService[m.ID+"/"+e.Key] = e.Calls
				}
			}
		}
		b, err := s.mon.Fetch(ctx, m, "catalog")
		if err != nil {
			continue
		}
		var cat struct {
			Services []serviceEntry `json:"services"`
		}
		if json.Unmarshal(b, &cat) != nil {
			continue
		}
		for _, sv := range cat.Services {
			out = append(out, Capsule{
				Key: m.ID + "/" + sv.ID, Name: sv.Name, ProviderID: m.ID, ProviderAID: m.AID,
				Tier: "official", Line: sv.Line, Modality: modalityOfOut(sv.Out),
				Inputs: sv.Inputs, Outputs: sv.Outputs, Models: sv.Models, Desc: sv.Desc,
				Cert: "certified", Calls: callsByService[m.ID+"/"+sv.ID],
			})
		}
	}
	// community capsules from listed agents' caps
	officialAIDs := map[string]bool{}
	for _, m := range officials {
		if m.AID != "" {
			officialAIDs[m.AID] = true
		}
	}
	agents, _ := s.hub.AllAgents("")
	for _, a := range agents {
		if !a.Listed || officialAIDs[a.AID] {
			continue
		}
		for _, c := range a.Caps {
			out = append(out, Capsule{
				Key: a.AID + "/" + c, Name: c, ProviderAID: a.AID, Tier: "community",
				Modality: modalityOfCap(c), Cert: "community", Desc: a.Summary,
			})
		}
	}
	return out
}

func modalityOfOut(out string) string {
	switch strings.ToLower(out) {
	case "image":
		return "image"
	case "video":
		return "video"
	case "music":
		return "audio"
	case "album":
		return "mixed"
	default:
		return "text"
	}
}

func modalityOfCap(cap string) string {
	c := strings.ToLower(cap)
	switch {
	case strings.Contains(c, "image"), strings.Contains(c, "art"), strings.Contains(c, "photo"):
		return "image"
	case strings.Contains(c, "video"):
		return "video"
	case strings.Contains(c, "tts"), strings.Contains(c, "asr"), strings.Contains(c, "voice"), strings.Contains(c, "audio"), strings.Contains(c, "music"):
		return "audio"
	default:
		return "text"
	}
}

// discoverCapsules ranks capsules against a free-text task (lexical match with CJK-aware tokenization —
// the vision's "任务自动找到能做的能力" first cut; a semantic embedder is the upgrade path). Chinese has
// no word spaces, so we also index/query character bigrams, and map a few intent keywords to modalities.
func discoverCapsules(caps []Capsule, task string, limit int) []Capsule {
	if limit <= 0 {
		limit = 20
	}
	terms := tokenize(task)
	// Intent keyword → modality hints (Chinese + English), a light boost when the capsule matches.
	wantMod := taskModalityHint(task)
	type scored struct {
		c     Capsule
		score int
	}
	var ranked []scored
	for _, c := range caps {
		hayTokens := c.tokenSet()
		score := 0
		for t := range terms {
			if hayTokens[t] {
				score += 3
			}
		}
		if wantMod != "" && c.Modality == wantMod {
			score += 4
		}
		if c.Cert == "certified" {
			score++
		}
		score += minInt(c.Calls/5, 3)
		if score > 0 {
			ranked = append(ranked, scored{c, score})
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool { return ranked[i].score > ranked[j].score })
	out := make([]Capsule, 0, limit)
	for i, r := range ranked {
		if i >= limit {
			break
		}
		out = append(out, r.c)
	}
	return out
}

// tokenize lowercases and splits into ASCII words + CJK character bigrams (and singletons).
func tokenize(s string) map[string]bool {
	s = strings.ToLower(s)
	out := map[string]bool{}
	var ascii strings.Builder
	var cjk []rune
	flushASCII := func() {
		if ascii.Len() >= 2 {
			out[ascii.String()] = true
		}
		ascii.Reset()
	}
	for _, r := range s {
		switch {
		case r >= 0x4e00 && r <= 0x9fff: // CJK ideographs
			flushASCII()
			cjk = append(cjk, r)
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			ascii.WriteRune(r)
		default:
			flushASCII()
		}
	}
	flushASCII()
	// CJK bigrams (and singletons as a weaker fallback).
	for i := 0; i < len(cjk); i++ {
		out[string(cjk[i])] = true
		if i+1 < len(cjk) {
			out[string(cjk[i:i+2])] = true
		}
	}
	return out
}

// tokenSet builds the searchable token set for a capsule (cached would be nicer; capsule sets are small).
func (c Capsule) tokenSet() map[string]bool {
	return tokenize(c.Name + " " + c.Desc + " " + c.Line + " " + c.Modality + " " +
		strings.Join(c.Inputs, " ") + " " + strings.Join(c.Outputs, " ") + " " + strings.Join(c.Models, " "))
}

// taskModalityHint maps common intent words to a target modality.
func taskModalityHint(task string) string {
	t := strings.ToLower(task)
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(t, s) {
				return true
			}
		}
		return false
	}
	switch {
	case has("视频", "短片", "动画", "video"):
		return "video"
	case has("语音", "音频", "转成文字", "识别", "转写", "配音", "朗读", "tts", "asr", "audio", "voice", "音乐", "歌"):
		return "audio"
	case has("图", "画", "海报", "照片", "image", "photo", "picture"):
		return "image"
	case has("翻译", "写", "对话", "文本", "总结", "问答", "chat", "text", "translate"):
		return "text"
	}
	return ""
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
