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
  if (state.current && !runStreamState().loaded) {
    runStreamState().loaded = true;
    loadStream().then(() => { if (state.view === "chat") render(); });
  }
  const log = el("div", { class: "chat-log timeline" });

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
  // The header is the harness bar: what it is doing, plus "停下".
  host.appendChild(el("div", { id: "activity-slot" }, renderActivityBar()));

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
        // Approving is not the end of the chain: whatever was waiting on this step
        // should start now. Resume the run so the operator does not have to go and
        // press "start" in another panel.
        let resumed = false;
        try {
          const intents = await api(`/api/engagements/${state.current.id}/intents`);
          const waiting = (intents || []).some((row) => {
            const x = row.intent || row;
            return x.status === "todo" && (x.deps || []).includes(it.id);
          });
          if (waiting) {
            await api(`/api/engagements/${state.current.id}/runs`, {
              method: "POST", body: JSON.stringify({ max_steps: 12 }),
            });
            resumed = true;
          }
        } catch { /* resuming is best effort; the operator can still press start */ }
        banner(`已执行 ${it.capability}${resumed ? ",后续步骤继续跑了" : ""}。`, "ok");
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

  // ---- history: ONE timeline (messages + steps merged by time) ----------
  const paintHistory = (messages) => {
    const merged = renderTimeline(messages, runStreamState().steps);
    log.replaceChildren(...merged.childNodes);
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
    // v0.20 fix: a first-time operator has no task yet. The conversation is the
    // entry point, so the first message creates a draft task to hold the context
    // (chat is bound to an engagement on the backend) instead of refusing. No
    // scope is granted here - the task starts with an empty passport, so nothing
    // can be sent at a target until the operator confirms a scope_draft card.
    if (!state.current) {
      try {
        const draft = await api("/api/engagements", {
          method: "POST",
          body: JSON.stringify({ name: "chat-" + new Date().toISOString().slice(5, 16) }),
        });
        await loadEngagements();
        await selectEngagement(draft.id);
      } catch (e) {
        return banner("没能开一个对话任务:" + e.message);
      }
    }
    const cs2 = chatState();
    cs2.messages.push({ role: "user", content: text, cards: [], created_at: new Date().toISOString() });
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

  const problem = (state.config && state.config.problem) || "";
  host.appendChild(el("div", { class: "card" },
    el("div", { class: "actions", style: "justify-content:space-between" },
      el("h3", {}, "对话"),
      status),

    problem ? el("div", { class: "problem" }, "配置有问题:" + problem) : document.createComment("ok"),
    el("p", { class: "hint" },
      "你说想干什么,AI 把它翻译成一张待确认的卡片;需要冒险的动作会停下来等你点「批准」。" +
      "AI 只有嘴:它改不了授权范围、批准不了动作、也盖不了「已确认」。"),
    log,
    el("div", { class: "chat-input" }, input, send,
      el("button", {
        class: "ghost tiny-btn",
        onclick: () => openTaskWizard("new"),
        title: "不配 AI 也能用:走向导填一个网址,内置规则会自己跑只读检查",
      }, "用向导直接开工")),
    el("p", { class: "hint" }, "不想配 AI?点「用向导直接开工」:填一个网址 + 确认授权,内置规则会自己跑只读检查。")));

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
            created_at: m.created_at || "",
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
    const go = el("button", { class: "primary tiny-btn" }, "确认开工");
    go.addEventListener("click", async () => {
      go.disabled = true;
      try {
        const scopeBody = Object.assign({
          basis: "操作员在对话中确认有权测试该目标",
          operator: "operator", max_requests: 2000, rps: 5,
        }, sc);
        // If the conversation is already held by a draft task (the one the first
        // message created), give THAT task the scope. Creating a second task would
        // move the run - and the report - into an engagement the chat history is
        // not attached to, so the operator would be watching a different task.
        const draft = draftTask();
        let targetID;
        if (draft) {
          await api(`/api/engagements/${draft.id}/scope`, {
            method: "PUT", body: JSON.stringify({ scope: scopeBody, updated_by: "operator" }),
          });
          await loadEngagements();
          await selectEngagement(draft.id);
          targetID = draft.id;
        } else {
          const created = await api("/api/engagements", {
            method: "POST",
            body: JSON.stringify({
              name: card.name || "chat-" + new Date().toISOString().slice(5, 16),
              scope: scopeBody,
            }),
          });
          await loadEngagements();
          await selectEngagement(created.id);
          targetID = created.id;
        }
        // The click is the human act: the scope is set AND the read-only run starts,
        // so "confirmed" actually means "it is working now".
        await api(`/api/engagements/${targetID}/runs`, {
          method: "POST", body: JSON.stringify({ max_steps: 12 }),
        });
        banner("开工了:只读检查会自己跑,遇到要冒险的动作会停下来问你。", "ok");
        await refresh();
      } catch (e) { banner("开工失败:" + e.message); go.disabled = false; }
    });
    box.appendChild(el("div", { class: "actions" }, go,
      el("span", { class: "hint" }, "确认后立刻开始只读扫描。")));
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
      "只排只读步骤,排完我直接开跑。其中任何需要你点头的动作,仍然会停下来等你批。"));
    const go = el("button", { class: "primary tiny-btn" }, "排进去,开跑");
    go.addEventListener("click", async () => {
      if (!state.current) return banner("先建一个任务,再排步骤");
      go.disabled = true;
      let ok = 0;
      for (const st of card.steps || []) {
        try {
          await api(`/api/engagements/${state.current.id}/intents`, {
            method: "POST",
            body: JSON.stringify({ capability: st.capability, args: st.args || {}, rationale: st.why || "from chat" }),
          });
          ok++;
        } catch (e) { banner("排入失败:" + e.message); go.disabled = false; break; }
      }
      if (ok) {
        // Do not make the operator hunt for a separate "start" button: queueing the
        // steps and starting the supervised run is one intent, so it is one click.
        try {
          await api(`/api/engagements/${state.current.id}/runs`, {
            method: "POST", body: JSON.stringify({ max_steps: 12 }),
          });
          banner(`排了 ${ok} 个步骤,已经开跑 —— 步骤会在下面实时出现,遇到要你拍板的会停下。`, "ok");
        } catch (e) { banner("排好了但没能自动开跑:" + e.message); }
        await refresh();
      }
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
  // A key that no longer decrypts is not "not configured": say what happened and
  // what to do, instead of quietly running without a planner.
  if (state.config && state.config.problem) {
    return { state: "bad", text: "● 模型配置没生效:" + state.config.problem };
  }
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
// draftTask returns the current task if it is still a draft (no authorised target
// yet). The first chat message creates one so the conversation has somewhere to
// live; confirming a scope should fill that task, not create a second one.
function draftTask() {
  const cur = state.current;
  if (!cur) return null;
  const include = (cur.scope && cur.scope.include) || [];
  if (include.length > 0) return null;
  return cur;
}