package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// vecsvc —— 语义向量服务客户端（anet-vec：fastembed 多语小模型 + ChromaDB，跑在 emax 本地 docker
// 127.0.0.1:8600）。它把「任务→能力发现」从词法匹配升级为语义检索（愿景 leap 2）。服务不可用时
// 调用方回退到 insights.go 的词法匹配，功能不中断。
type VecClient struct {
	base string
	hc   *http.Client

	mu          sync.Mutex
	lastIndexed time.Time
	indexedN    int
	ok          bool
}

const capsuleCollection = "capabilities"

// NewVecClient returns a client for the vector service at base ("" disables it).
func NewVecClient(base string) *VecClient {
	return &VecClient{base: strings.TrimRight(base, "/"), hc: &http.Client{Timeout: 20 * time.Second}}
}

// Enabled reports whether a base URL is configured.
func (v *VecClient) Enabled() bool { return v != nil && v.base != "" }

func (v *VecClient) post(ctx context.Context, path string, body any, out any) error {
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.base+path, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("vec %s: http %d", path, resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Health checks the service and records availability.
func (v *VecClient) Health(ctx context.Context) bool {
	if !v.Enabled() {
		return false
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, v.base+"/health", nil)
	resp, err := v.hc.Do(req)
	ok := err == nil && resp != nil && resp.StatusCode == 200
	if resp != nil {
		resp.Body.Close()
	}
	v.mu.Lock()
	v.ok = ok
	v.mu.Unlock()
	return ok
}

// vecItem is one document to index.
type vecItem struct {
	ID       string         `json:"id"`
	Text     string         `json:"text"`
	Metadata map[string]any `json:"metadata"`
}

// capsuleText builds the embedding text for a capsule. Community capsules often carry only a terse
// English cap name (e.g. "photo-display"), which embeds poorly against Chinese task queries, so we
// inject Chinese modality keywords to anchor the vector in the right semantic neighborhood.
func capsuleText(c Capsule) string {
	parts := []string{c.Name, c.Desc, c.Line, modalityKeywords(c.Modality)}
	parts = append(parts, c.Inputs...)
	parts = append(parts, c.Outputs...)
	parts = append(parts, c.Models...)
	return strings.Join(filterEmpty(parts), " ")
}

// modalityKeywords maps a modality to Chinese+English anchor words for embedding.
func modalityKeywords(mod string) string {
	switch mod {
	case "image":
		return "图像 图片 生图 画 海报 image picture"
	case "video":
		return "视频 短片 动画 影片 video"
	case "audio":
		return "语音 音频 声音 朗读 配音 音乐 audio voice speech"
	case "text":
		return "文本 文字 对话 翻译 问答 text"
	case "mixed":
		return "多模态 图文 mixed"
	}
	return mod
}

func filterEmpty(in []string) []string {
	out := in[:0]
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// IndexCapsules (re)indexes the capability packages into the vector service, throttled so it does not
// re-embed on every call. force bypasses the throttle.
func (v *VecClient) IndexCapsules(ctx context.Context, caps []Capsule, force bool) error {
	if !v.Enabled() {
		return fmt.Errorf("vec disabled")
	}
	v.mu.Lock()
	fresh := !force && time.Since(v.lastIndexed) < 10*time.Minute && v.indexedN == len(caps)
	v.mu.Unlock()
	if fresh {
		return nil
	}
	items := make([]vecItem, 0, len(caps))
	for _, c := range caps {
		items = append(items, vecItem{ID: c.Key, Text: capsuleText(c), Metadata: map[string]any{
			"name": c.Name, "tier": c.Tier, "cert": c.Cert, "modality": c.Modality,
			"provider_id": c.ProviderID, "provider_aid": c.ProviderAID, "line": c.Line,
		}})
	}
	// Chroma upsert handles large batches; chunk to keep request bodies modest.
	for i := 0; i < len(items); i += 256 {
		end := i + 256
		if end > len(items) {
			end = len(items)
		}
		if err := v.post(ctx, "/index", map[string]any{"collection": capsuleCollection, "items": items[i:end]}, nil); err != nil {
			return err
		}
	}
	v.mu.Lock()
	v.lastIndexed = time.Now()
	v.indexedN = len(caps)
	v.ok = true
	v.mu.Unlock()
	return nil
}

// VecMatch is one semantic search hit.
type VecMatch struct {
	ID       string         `json:"id"`
	Score    float64        `json:"score"`
	Document string         `json:"document"`
	Metadata map[string]any `json:"metadata"`
}

// Search runs a semantic query over the capability collection.
func (v *VecClient) Search(ctx context.Context, query string, n int) ([]VecMatch, error) {
	var out struct {
		Matches []VecMatch `json:"matches"`
	}
	err := v.post(ctx, "/search", map[string]any{"collection": capsuleCollection, "query": query, "n": n}, &out)
	return out.Matches, err
}

// discoverSemantic ranks capsules by semantic similarity to task, falling back to lexical on any error.
func (s *Server) discoverSemantic(ctx context.Context, caps []Capsule, task string, limit int) ([]Capsule, string) {
	if s.vec == nil || !s.vec.Enabled() {
		return discoverCapsules(caps, task, limit), "lexical"
	}
	if err := s.vec.IndexCapsules(ctx, caps, false); err != nil {
		return discoverCapsules(caps, task, limit), "lexical"
	}
	// Over-fetch so the modality rerank + dedup has candidates to work with.
	matches, err := s.vec.Search(ctx, task, limit*3)
	if err != nil || len(matches) == 0 {
		return discoverCapsules(caps, task, limit), "lexical"
	}
	byKey := map[string]Capsule{}
	for _, c := range caps {
		byKey[c.Key] = c
	}
	// Hybrid rerank: semantic similarity + a modality-intent bonus + a small certified bonus. Pure
	// semantic over terse community-cap text under-ranks the right modality; the intent hint fixes that.
	wantMod := taskModalityHint(task)
	var ranked []scoredCapsule
	for _, m := range matches {
		c, ok := byKey[m.ID]
		if !ok {
			continue
		}
		c.Score = m.Score
		combined := m.Score
		if wantMod != "" && c.Modality == wantMod {
			combined += 0.35
		}
		if c.Cert == "certified" {
			combined += 0.05
		}
		ranked = append(ranked, scoredCapsule{c, combined})
	}
	if len(ranked) == 0 {
		return discoverCapsules(caps, task, limit), "lexical"
	}
	sortStableByCombined(ranked)
	// Dedup by capability name (many community agents expose the same cap) — keep the best-scoring one.
	seen := map[string]bool{}
	out := make([]Capsule, 0, limit)
	for _, r := range ranked {
		if seen[r.c.Name] {
			continue
		}
		seen[r.c.Name] = true
		out = append(out, r.c)
		if len(out) >= limit {
			break
		}
	}
	return out, "semantic"
}

// scoredCapsule pairs a capsule with its hybrid (semantic + intent) score.
type scoredCapsule struct {
	c        Capsule
	combined float64
}

func sortStableByCombined(r []scoredCapsule) {
	// insertion sort keeps it dependency-free and stable for the small candidate set.
	for i := 1; i < len(r); i++ {
		for j := i; j > 0 && r[j].combined > r[j-1].combined; j-- {
			r[j], r[j-1] = r[j-1], r[j]
		}
	}
}
