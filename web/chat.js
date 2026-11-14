/* ---- chat: the operator talks, the AI proposes, the human clicks -------------
 *
 * The division of labour is the whole design: /api/chat returns WORDS and CARDS,
 * and a card does nothing until its confirm button calls the ordinary endpoint
 * (create engagement, queue intents, activate a signed mandate). There is no code
 * path here that changes state on the model's say-so.
 */

function renderChat(host) {
  const log = el("div", { class: "chat-log" });
  if (!state.chat) state.chat = [];

  const status = el("span", { class: "llm-light" });
  const paintStatus = async () => {
    const r = await llmStatus();
    status.dataset.state = r.state;
    status.textContent = r.text;
  };

  const input = el("textarea", {
    placeholder: "用大白话说:想测什么、现在卡在哪、该不该开某个开关…(Enter 发送,Shift+Enter 换行)",
    rows: "3",
  });
  const send = el("button", { class: "primary" }, "发送");

  const addBubble = (who, text) => {
    const b = el("div", { class: "bubble " + who }, text);
    log.appendChild(b);
    log.scrollTop = log.scrollHeight;
    return b;
  };

  const addCard = (card) => {
    const box = el("div", { class: "card chat-card" });
    const title = el("h3", {}, {
      note: "说明",
      scope_draft: "建议的授权范围",
      mandate_draft: "建议的委托书(要你签)",
      plan: "建议的下一步",
    }[card.type] || card.type);
    box.appendChild(title);
    if (card.why) box.appendChild(el("p", { class: "hint" }, card.why));

    if (card.type === "note") {
      box.appendChild(el("p", {}, card.text || ""));
      return box;
    }

    if (card.type === "scope_draft") {
      const sc = card.scope || {};
      box.appendChild(el("p", {}, "目标:" + ((sc.include || []).join(", ") || "—")));
      box.appendChild(el("p", { class: "hint" },
        "方法:" + ((sc.methods || ["GET", "HEAD", "OPTIONS"]).join("/")) +
        " · 高风险开关:默认全关"));
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
          banner("任务已创建(按对话里那份授权范围)。", "ok");
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
        list.appendChild(el("li", {},
          el("code", {}, st.capability), st.why ? el("span", { class: "hint" }, " — " + st.why) : ""));
      }
      box.appendChild(list);
      box.appendChild(el("p", { class: "hint" },
        "只排只读步骤。其中任何需要你点头的动作,仍然会停在「待办审批」。"));
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
        if (ok) { banner(`已排入 ${ok} 个步骤。点「开始扫描」继续。`, "ok"); await refresh(); }
      });
      box.appendChild(el("div", { class: "actions" }, go));
      return box;
    }

    if (card.type === "mandate_draft") {
      const classes = card.classes || [];
      const cn = { param: "参数存在性探测(SQL/模板注入)", waf: "WAF 行为观察", seeding: "自动创建测试对象", registration: "注册测试账号" };
      box.appendChild(el("p", {}, "你将授权 youkai 在 " +
        ((card.assets || []).join(", ") || "当前授权范围") + " 上自动执行:"));
      box.appendChild(el("ul", {}, ...classes.map((c) => el("li", {}, cn[c] || c))));
      box.appendChild(el("p", {},
        `上限 ${card.max_requests} 次请求,${card.expires_hours} 小时后失效。` +
        "这些动作只判存在、不取数据;期间不再逐步问你,但你可以随时急停。"));
      box.appendChild(el("p", { class: "hint" },
        "youkai 不会替你签:这把钥匙在你手里。下面这条命令在你自己机器上跑,签完把文件贴回来。"));

      const draft = el("textarea", { rows: "6", readonly: "readonly" }, JSON.stringify({
        tier: "highest",
        basis: card.basis || "操作员在对话中确认授权",
        approver: "operator",
        assets: card.assets || [],
        actions: ["read-only"].concat(classes.map((c) => "tier2:" + c)),
        max_requests: card.max_requests,
        issued_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + (card.expires_hours || 24) * 3600 * 1000).toISOString(),
        nonce: Math.random().toString(36).slice(2),
      }, null, 2));
      const file = el("textarea", { rows: "6", placeholder: "签好的记录(youkai-sign 输出的 JSON)贴这里" });
      const go = el("button", { class: "primary tiny-btn" }, "激活这份委托书");
      go.addEventListener("click", async () => {
        if (!state.current) return banner("先建一个任务");
        let rec;
        try { rec = JSON.parse(file.value); } catch { return banner("贴进来的不是合法 JSON"); }
        try {
          const r = await api(`/api/engagements/${state.current.id}/mandate/activate`, {
            method: "POST", body: JSON.stringify(rec),
          });
          banner(`委托书已生效:${(r.classes || []).join("/")},剩余 ${r.remaining} 次请求。急停随时可用。`, "ok");
          await refresh();
        } catch (e) { banner("激活失败:" + e.message); }
      });
      box.append(
        el("p", { class: "label" }, "① 存成 mandate.json,然后在你机器上跑"),
        el("pre", { class: "mono small" }, "youkai-sign -draft mandate.json -out mandate.signed.json"),
        draft,
        el("p", { class: "label" }, "② 把签好的 mandate.signed.json 内容贴到这里"),
        file,
        el("div", { class: "actions" }, go));
      return box;
    }
    return box;
  };

  const submit = async () => {
    const text = input.value.trim();
    if (!text) return;
    if (!state.current) return banner("先建一个任务:对话要有一个上下文");
    addBubble("me", text);
    input.value = "";
    const thinking = addBubble("ai muted", "…");
    try {
      const r = await api(`/api/engagements/${state.current.id}/chat`, {
        method: "POST", body: JSON.stringify({ message: text }),
      });
      thinking.textContent = r.reply || "(空)";
      thinking.classList.remove("muted");
      for (const c of r.cards || []) log.appendChild(addCard(c));
      if ((r.rejected || []).length) {
        log.appendChild(el("p", { class: "hint" },
          "有 " + r.rejected.length + " 条建议被丢弃(不在允许的动作清单里):" + r.rejected.join(";")));
      }
      log.scrollTop = log.scrollHeight;
      state.chat.push({ me: text, reply: r.reply });
    } catch (e) {
      thinking.textContent = "没能回答:" + e.message;
    }
    paintStatus();
  };

  send.addEventListener("click", submit);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); }
  });

  const header = el("div", { class: "card" },
    el("div", { class: "actions", style: "justify-content:space-between" },
      el("h3", {}, "对话"),
      status),
    el("p", { class: "hint" },
      "你说想干什么,AI 把它翻译成一张待确认的卡片;卡片不点确认就不会发生任何事。" +
      "AI 只有嘴,没有手:它改不了授权范围、批准不了动作、也盖不了「已确认」。"),
    el("p", { class: "hint" },
      "它能看见的是 youkai 归一后的摘要(发现标题、步骤状态、在效委托书),**不含目标响应正文** —— 页面里的内容可能是攻击者写的。"),
    log,
    el("div", { class: "chat-input" }, input, send));

  host.appendChild(header);
  paintStatus();
}

// llmStatus is the one source of truth for the status light: unconfigured, ok, or
// configured-but-failing, with the real error.
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

// testLLM runs the same probe the settings panel uses and remembers the answer.
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
