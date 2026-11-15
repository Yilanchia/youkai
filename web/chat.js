/* ---- chat: the operator talks, the AI proposes, the human clicks -------------
 *
 * Division of labour (ADR-006): the agent runs read-only work by itself, stops at
 * anything risky, and asks for one click. /api/chat returns words and cards; a card
 * does nothing until its button calls the ordinary endpoint. approve/execute are
 * called from THIS file only when the operator clicks - never by the model.
 */

function chatState() {
  if (!state.chat) state.chat = { key: null, messages: [], pending: [] };
  return state.chat;
}

function parkedIntents() {
  return (state.intents || [])
    .map((row) => row.intent || row)
    .filter((it) => it.status === "needs_approval");
}

function renderChat(host) {
  const cs = chatState();
  const log = el("div", { class: "chat-log" });

  // ---- the always-visible state line -----------------------------------
  const st = (state.graph && state.graph.stats) || {};
  const parked = parkedIntents();
  const runs = state.runs || [];
  const lastRun = runs[0];
  // The engine's own review notes: "what changed after the last step". This is the
  // closest thing to "what is it thinking" the UI can honestly show.
  const reflections = ((state.graph && state.graph.facts) || [])
    .filter((f) => (f.tags || []).includes("reflection"))
    .map((f) => f.statement);
  const lastReflection = reflections.length ? reflections[reflections.length - 1] : "";
  const statusLine = (function () {
    if (parked.length) {
      return { kind: "wait", text: `停在第 ${parked.length} 个动作前,等你点头` };
    }
    if (lastRun && lastRun.status === "running") return { kind: "busy", text: "正在自主跑只读检查…" };
    if ((st.audit_allowed || 0) === 0) return { kind: "idle", text: "还没开始:说一句话,或点「开始扫描」" };
    const base = `这一轮跑完了:${st.audit_allowed || 0} 次请求、${st.findings || 0} 条发现`;
    return { kind: "done", text: lastReflection ? base + " · " + lastReflection : base };
  })();
  host.appendChild(el("div", { class: "run-state " + statusLine.kind }, statusLine.text));

  // ---- approval cards: the whole point of "stop at risk" -----------------
  for (const it of parked) {
    const what = el("div", { class: "approve-card" },
      el("strong", {}, "需要你点头"),
      el("p", {}, `要做什么:${it.capability}${it.rationale ? " — " + it.rationale : ""}`),
      el("p", { class: "hint" }, `对哪个目标:${it.args && (it.args.url || it.args.target || it.args.login_url) || "(见详情)"}`),
      el("p", { class: "hint" }, `为什么停:${it.gate_reason || "需要人确认的高风险动作"}`),
      el("p", { class: "hint" }, "批准后只执行这一个动作,执行完这次批准就用掉了。"));
    const ok = el("button", { class: "primary tiny-btn" }, "批准并执行");
    const no = el("button", { class: "ghost tiny-btn" }, "拒绝");
    ok.addEventListener("click", async () => {
      ok.disabled = true;
      try {
        await api(`/api/engagements/${state.current.id}/intents/${it.id}/approve`, {
          method: "POST", body: JSON.stringify({ operator: "operator", basis: "operator approved in the UI @ " + new Date().toISOString() }),
        });
        await api(`/api/engagements/${state.current.id}/intents/${it.id}/execute`, {
          method: "POST", body: JSON.stringify({ operator: "operator" }),
        });
        banner(`已执行 ${it.capability}。`, "ok");
      } catch (e) { banner("执行失败:" + e.message); ok.disabled = false; return; }
      await refresh();
    });
    no.addEventListener("click", async () => {
      no.disabled = true;
      try {
        await api(`/api/engagements/${state.current.id}/intents/${it.id}/reject`, {
          method: "POST", body: JSON.stringify({ operator: "operator", reason: "UI 拒绝" }),
        });
        banner("已拒绝这一步。", "ok");
      } catch (e) { banner("拒绝失败:" + e.message); no.disabled = false; return; }
      await refresh();
    });
    what.appendChild(el("div", { class: "actions" }, ok, no));
    host.appendChild(what);
  }

  // ---- history ----------------------------------------------------------
  const paintHistory = (messages) => {
    log.replaceChildren();
    if (!messages.length) {
      log.appendChild(el("div", { class: "empty" },
        "还没有对话。可以直接说:帮我看看这个站有没有暴露的敏感文件。"));
      return;
    }
    for (const m of messages) {
      log.appendChild(el("div", { class: "bubble " + (m.role === "user" ? "me" : "ai") }, m.content));
      const cards = Array.isArray(m.cards) ? m.cards : [];
      for (const c of cards) log.appendChild(renderChatCard(c));
    }
    log.scrollTop = log.scrollHeight;
  };

  // ---- composer ---------------------------------------------------------
  const input = el("textarea", {
    placeholder: "用大白话说:想测什么、现在卡在哪、该不该开某个开关…(Enter 发送,Shift+Enter 换行)",
    rows: "3",
  });
  const send = el("button", { class: "primary" }, "发送");

  const submit = async () => {
    const text = input.value.trim();
    if (!text) return;
    if (!state.current) return banner("先建一个任务:对话要有一个上下文");
    const cs2 = chatState();
    cs2.messages.push({ role: "user", content: text, cards: [] });
    paintHistory(cs2.messages);
    input.value = "";
    const thinking = el("div", { class: "bubble ai muted" }, "…");
    log.appendChild(thinking);
    log.scrollTop = log.scrollHeight;
    try {
      const r = await api(`/api/engagements/${state.current.id}/chat`, {
        method: "POST", body: JSON.stringify({ message: text }),
      });
      thinking.remove();
      cs2.messages.push({ role: "assistant", content: r.reply || "(空)", cards: r.cards || [] });
      paintHistory(cs2.messages);
      if ((r.rejected || []).length) {
        log.appendChild(el("p", { class: "hint" },
          "有 " + r.rejected.length + " 条建议被丢弃(不在允许的动作清单里):" + r.rejected.join(";")));
      }
    } catch (e) {
      thinking.textContent = "没能回答:" + e.message;
    }
    await refresh();
  };

  send.addEventListener("click", submit);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); }
  });

  const status = el("span", { class: "llm-light" });
  llmStatus().then((r) => { status.dataset.state = r.state; status.textContent = r.text; });

  host.appendChild(el("div", { class: "card" },
    el("div", { class: "actions", style: "justify-content:space-between" },
      el("h3", {}, "对话"),
      status),
    el("p", { class: "hint" },
      "你说想干什么,AI 把它翻译成一张待确认的卡片;需要冒险的动作会停下来等你点「批准」。" +
      "AI 只有嘴:它改不了授权范围、批准不了动作、也盖不了「已确认」。"),
    log,
    el("div", { class: "chat-input" }, input, send)));

  // First visit for this engagement: pull the stored conversation.
  const key = state.current ? String(state.current.id) : "none";
  if (cs.key !== key) {
    cs.key = key;
    paintHistory([]);
    if (state.current) {
      api(`/api/engagements/${state.current.id}/chat?limit=200`)
        .then((r) => {
          cs.messages = (r.messages || []).map((m) => ({
            role: m.role, content: m.content,
            cards: Array.isArray(m.cards) ? m.cards : [],
          }));
          paintHistory(cs.messages);
        })
        .catch(() => paintHistory([]));
    }
  } else {
    paintHistory(cs.messages);
  }
}

// renderChatCard draws one proposal. The buttons call ordinary endpoints; the
// model's text never becomes an action by itself.
function renderChatCard(card) {
  const box = el("div", { class: "card chat-card" });
  const titles = {
    note: "说明", scope_draft: "建议的授权范围",
    mandate_draft: "建议的委托书(要你签)", plan: "建议的下一步",
  };
  box.appendChild(el("h3", {}, titles[card.type] || card.type));
  if (card.why) box.appendChild(el("p", { class: "hint" }, card.why));

  if (card.type === "note") {
    box.appendChild(el("p", {}, card.text || ""));
    return box;
  }

  if (card.type === "scope_draft") {
    const sc = card.scope || {};
    box.appendChild(el("p", {}, "目标:" + ((sc.include || []).join(", ") || "—")));
    box.appendChild(el("p", { class: "hint" },
      "方法:" + ((sc.methods || ["GET", "HEAD", "OPTIONS"]).join("/")) + " · 高风险开关:默认全关"));
    const go = el("button", { class: "primary tiny-btn" }, "按这个范围建任务");
    go.addEventListener("click", async () => {
      try {
        await api("/api/engagements", {
          method: "POST",
          body: JSON.stringify({
            name: card.name || "chat-" + new Date().toISOString().slice(5, 16),
            scope: Object.assign({
              basis: "操作员在对话中确认有权测试该目标",
              operator: "operator", max_requests: 2000, rps: 5,
            }, sc),
          }),
        });
        banner("任务已创建。", "ok");
        await loadEngagements();
        setView("runs");
      } catch (e) { banner("创建失败:" + e.message); }
    });
    box.appendChild(el("div", { class: "actions" }, go));
    return box;
  }

  if (card.type === "plan") {
    const list = el("ol", { class: "steps-list" });
    for (const st of card.steps || []) {
      list.appendChild(el("li", {}, el("code", {}, st.capability),
        st.why ? el("span", { class: "hint" }, " — " + st.why) : ""));
    }
    box.appendChild(list);
    box.appendChild(el("p", { class: "hint" },
      "只排只读步骤。其中任何需要你点头的动作,仍然会停下来等你批。"));
    const go = el("button", { class: "primary tiny-btn" }, "把这些步骤排进队列");
    go.addEventListener("click", async () => {
      if (!state.current) return banner("先建一个任务,再排步骤");
      let ok = 0;
      for (const st of card.steps || []) {
        try {
          await api(`/api/engagements/${state.current.id}/intents`, {
            method: "POST",
            body: JSON.stringify({ capability: st.capability, args: st.args || {}, rationale: st.why || "from chat" }),
          });
          ok++;
        } catch (e) { banner("排入失败:" + e.message); break; }
      }
      if (ok) { banner(`已排入 ${ok} 个步骤。点「开始」继续。`, "ok"); await refresh(); }
    });
    box.appendChild(el("div", { class: "actions" }, go));
    return box;
  }

  if (card.type === "mandate_draft") {
    // Advanced and opt-in since ADR-006: the default path is one click per step.
    box.appendChild(el("p", { class: "hint" },
      "这是高级用法,只在服务端开了 require-high-auth 时才生效;默认不需要它 —— 每个动作点一次「批准」就行。"));
    box.appendChild(el("p", {}, "目标:" + ((card.assets || []).join(", ") || "当前授权范围")));
    box.appendChild(el("p", {}, `动作类:${(card.classes || []).join(", ")} · 上限 ${card.max_requests} 次 · ${card.expires_hours} 小时`));
    return box;
  }
  return box;
}

// llmStatus is the one source of truth for the status light.
async function llmStatus() {
  const llm = (state.config && state.config.llm) || {};
  if (!llm.key_present && !llm.key_from_env) {
    return { state: "off", text: "● AI 未配置(不影响使用)" };
  }
  if (state.llmTest && state.llmTest.ok) {
    return { state: "ok", text: `● ${llm.model || "模型"} · ${state.llmTest.latency_ms} ms` };
  }
  if (state.llmTest && state.llmTest.error) {
    return { state: "bad", text: "● 连不上:" + state.llmTest.error };
  }
  return { state: "unknown", text: "● 已配置,未测试" };
}

// testLLM runs the probe and remembers the answer.
async function testLLM() {
  const llm = (state.config && state.config.llm) || {};
  try {
    const r = await api("/api/config/llm/test", {
      method: "POST",
      body: JSON.stringify({ base_url: llm.base_url, model: llm.model, timeout_s: 20 }),
    });
    state.llmTest = r.ok ? { ok: true, latency_ms: r.latency_ms } : { error: r.error || "未知错误" };
  } catch (e) {
    state.llmTest = { error: e.message };
  }
  return state.llmTest;
}
