package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"youkai/internal/ledger"
	"youkai/internal/planner"
)

// handleChat is the conversational entry point.
//
// The request carries a message; the response carries words and PROPOSALS. Nothing
// here executes anything: the cards are rendered by the UI, and the operator's
// click is what calls the ordinary endpoints (create engagement, queue intents,
// activate a signed mandate). That is why this handler needs no gate of its own -
// it cannot widen anything, only describe.
func (s *Server) handleChat(w http.ResponseWriter, r *http.Request, eng ledger.Engagement) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var body struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "无法解析请求:%v", err)
		return
	}
	msg := strings.TrimSpace(body.Message)
	if msg == "" {
		writeErr(w, http.StatusBadRequest, "说点什么")
		return
	}
	if s.cfg.Planner == nil || !s.cfg.Planner.Enabled() {
		writeErr(w, http.StatusServiceUnavailable, "AI 还没配置:去「设置」填一个模型 key(不配也能用向导和内置规则)")
		return
	}

	ctx := s.chatContext(r, eng)
	reply, err := s.cfg.Planner.Chat(r.Context(), planner.ChatRequest{
		EngagementID: eng.ID, Message: msg, Context: ctx,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, "AI 没有回答:%v", err)
		return
	}
	s.trace(r, eng.ID, "chat turn archived as planner_call:"+strconv.FormatInt(reply.Archived, 10))
	writeJSON(w, http.StatusOK, reply)
}

// chatContext builds the model's view: normalised facts and states only.
//
// Deliberately absent: response bodies, headers, cookies, tokens. A target can put
// "ignore your rules" in a page title; nothing from the page reaches the model
// except what youkai itself decided the fact says.
func (s *Server) chatContext(r *http.Request, eng ledger.Engagement) string {
	var b strings.Builder
	fmt.Fprintf(&b, "engagement:%s (id=%d)\n", eng.Name, eng.ID)

	var scope map[string]any
	if err := json.Unmarshal(eng.Scope, &scope); err == nil {
		fmt.Fprintf(&b, "授权范围:%v\n", scope)
	}
	g, err := s.cfg.Store.Graph(r.Context(), eng.ID)
	if err != nil {
		return b.String()
	}
	fmt.Fprintf(&b, "账本:资产 %d、事实 %d、发现 %d(已确认 %d)\n",
		len(g.Assets), len(g.Facts), len(g.Findings), countVerified(g.Findings))

	if len(g.Findings) > 0 {
		b.WriteString("发现(标题):\n")
		for i, f := range g.Findings {
			if i >= 12 {
				break
			}
			fmt.Fprintf(&b, "- [%s] %s\n", f.Severity, f.Title)
		}
	}
	if len(g.Intents) > 0 {
		b.WriteString("步骤状态:\n")
		for i, it := range g.Intents {
			if i >= 15 {
				break
			}
			fmt.Fprintf(&b, "- %s:%s\n", it.Capability, it.Status)
		}
	}
	if m, err := s.cfg.Store.ActiveMandate(r.Context(), eng.ID); err == nil {
		used, _ := s.cfg.Store.MandateUsage(r.Context(), eng.Name, m.ActivatedAt)
		fmt.Fprintf(&b, "在效委托书:动作类 %v、上限 %d、已用 %d、到期 %s\n",
			m.Classes, m.MaxRequests, used, m.ExpiresAt.Format("2006-01-02 15:04"))
	} else {
		b.WriteString("在效委托书:无\n")
	}
	b.WriteString("注意:以上是 youkai 归一后的摘要,不含任何响应正文。")
	return b.String()
}

func countVerified(fs []ledger.Finding) int {
	n := 0
	for _, f := range fs {
		if f.State == "verified" {
			n++
		}
	}
	return n
}
