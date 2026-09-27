package admin

import (
	"context"
	"sort"
	"strings"
)

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
	Cert        string   `json:"cert"`            // 认证档位：listed(官方 manifest 登记) | community；certified(官方实测)已不再产生
	Calls       int      `json:"calls"`           // 近窗调用次数；来源(官方 agent monitor)已删除，恒为 0
	Score       float64  `json:"score,omitempty"` // 语义检索相似度（discover 时填充）
}

// buildCapsules assembles the capability-package catalog from the registry: official agents
// contribute one capsule per capability their manifest declares, community listed agents one per
// capability they registered.
//
// The official branch used to read each agent's service catalog and call counts through the
// agent's monitor. That channel is removed (A2A-DESIGN §9 row admin 官方 agent): the admin plane
// registers official agents by id, AID, hub and capabilities only, and reaches no host. An
// official capsule is therefore "listed" (declared in the manifest), not "certified" (measured),
// and carries no call count.
func (s *Server) buildCapsules(ctx context.Context) []Capsule {
	var out []Capsule
	officials, _ := s.store.Officials()
	officialAIDs := map[string]bool{}
	for _, m := range officials {
		if m.AID != "" {
			officialAIDs[m.AID] = true
		}
		for _, c := range m.Caps {
			out = append(out, Capsule{
				Key: m.ID + "/" + c, Name: c, ProviderID: m.ID, ProviderAID: m.AID,
				Tier: "official", Line: m.ProductLine, Modality: modalityOfCap(c),
				Desc: m.Summary, Cert: "listed",
			})
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
