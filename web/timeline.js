/* ---- timeline: one scrollback for the whole session ------------------------
 *
 * v0.22. A harness window is ONE timeline: what you said, what the agent said,
 * what it ran, what came back - in the order it happened. Before this file, chat
 * bubbles and the step stream lived in two panels, which reads like two tools
 * rather than one agent.
 *
 * The merge key is time. Steps carry `at` (RFC3339, server clock); messages carry
 * `created_at`. Ties are broken by a stable rank (a message that triggered a step
 * comes before it), then by seq/id, so a reload reproduces the same order.
 */

function timelineItems(messages, steps) {
  const items = [];
  (messages || []).forEach((m, i) => {
    items.push({
      kind: "msg",
      t: parseTime(m.created_at),
      rank: 0,
      order: i,
      msg: m,
    });
  });
  (steps || []).forEach((s) => {
    items.push({
      kind: "step",
      t: parseTime(s.at),
      rank: 1,
      order: s.seq || 0,
      step: s,
    });
  });
  items.sort((a, b) => {
    if (a.t !== b.t) return a.t - b.t;
    if (a.rank !== b.rank) return a.rank - b.rank;
    return a.order - b.order;
  });
  return items;
}

/* renderTimeline paints the merged scrollback. Steps render exactly like the
 * v0.21 stream (same icons, same sanitised fields); they are simply inline now. */
function renderTimeline(messages, steps) {
  const box = el("div", { class: "chat-log timeline" });
  const items = timelineItems(messages, steps);
  if (!items.length) {
    box.appendChild(el("div", { class: "empty" },
      "还没有对话。可以直接说:帮我看看这个站有没有暴露的敏感文件。"));
    return box;
  }
  for (const item of items) {
    if (item.kind === "msg") {
      box.appendChild(el("div", { class: "bubble " + (item.msg.role === "user" ? "me" : "ai") }, item.msg.content));
      const cards = Array.isArray(item.msg.cards) ? item.msg.cards : [];
      for (const c of cards) box.appendChild(renderChatCard(c));
      continue;
    }
    box.appendChild(renderStepRow(item.step));
  }
  return box;
}

/* renderActivityBar is the harness header: what it is doing right now, and a way
 * to take the wheel back. */
function renderActivityBar() {
  const s = runStreamState();
  const steps = s.steps || [];
  const parked = steps.filter((x) => x.status === "parked");
  const busyRun = (state.runs || []).find((r) => r.status === "running");
  const last = steps.length ? steps[steps.length - 1] : null;

  const head = (function () {
    if (parked.length) return { cls: "wait", text: `停在 ${parked.length} 个动作前,等你拍板` };
    if (busyRun) {
      const n = steps.filter((x) => x.phase === "exec").length;
      return { cls: "busy", text: `托管中(第 ${n} 步)…` };
    }
    if (last && last.phase === "stop") {
      if (last.stop === "max_steps") return { cls: "wait", text: "已达本次托管预算" };
      if (last.stop === "cancelled") return { cls: "done", text: "已按你的要求停下" };
      return { cls: "done", text: "这一程结束了" };
    }
    if (steps.length) return { cls: "done", text: "上一程已结束" };
    return { cls: "idle", text: "还没开工" };
  })();

  const bar = el("div", { class: "activity-bar " + head.cls },
    el("span", { class: "activity-dot" }, "●"),
    el("span", { class: "activity-text" }, head.text));

  if (busyRun) {
    const stop = el("button", { class: "ghost tiny-btn" }, "停下");
    stop.addEventListener("click", async () => {
      stop.disabled = true;
      try {
        await api(`/api/engagements/${state.current.id}/runs/${busyRun.id}/cancel`, {
          method: "POST", body: JSON.stringify({}),
        });
        banner("已喊停:它会在当前这一步之后收手。", "ok");
        await refresh();
      } catch (e) { banner("停下失败:" + e.message); stop.disabled = false; }
    });
    bar.appendChild(stop);
  }
  return bar;
}
// parseTime reads the timestamps we actually emit. "+08" (no minutes) is not valid
// ISO for JS, and a failed parse used to silently sort the message to the top.
function parseTime(s) {
  if (!s) return 0;
  let v = String(s).trim();
  if (/[+-]\d{2}$/.test(v)) v += ":00";
  const t = Date.parse(v);
  return Number.isNaN(t) ? 0 : t;
}