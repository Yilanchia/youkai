/* ---- run-stream: watch the agent work, step by step ------------------------
 *
 * v0.21. The engine emits a sanitised StepEvent for every step it finishes
 * (derive / exec / reflect / stop). This module renders that stream as a live
 * transcript, like watching an agent in a terminal:
 *
 *   ▸ 扫描  127.0.0.1:18080            tier1  ✓ 得到 3 条事实
 *   ▸ 探测  /search?q=…                tier1  ✓ 2 条候选  R0007
 *   ⏸ 探测  /item?id=…                 tier2  等你批准  [批准] [拒绝]
 *   ↳ 命中确认了"参数反射"假设
 *
 * Security boundary: the event carries only capability/target/tier/summary/
 * request id. There is no body, cookie or credential in it, so there is nothing to
 * hide here - and the renderer must never add one.
 */

const CAP_LABEL = {
  scan: "扫描", crawl: "爬取", probe: "探测", fingerprint: "识别", headers: "看响应头",
  api_spec: "读 API 文档", cors: "看 CORS", jwt_audit: "审 JWT", oauth_audit: "审 OAuth",
  param: "参数探测", compare: "双身份比对", role_matrix: "权限矩阵", canary: "回连验证",
  code_ingest: "读源码", whitebox: "白盒线索", accounts_provision: "登录测试身份",
  session_probe: "会话检查", binary_scan: "二进制检查", binflow: "二进制数据流",
  blind_screen: "反致盲检查", git_check: "查 .git", openapi: "读接口定义",
};

function capLabel(cap) {
  return CAP_LABEL[cap] || cap || "步骤";
}

function stepState(ev) {
  switch (ev.status) {
    case "ok": return { icon: "▸", cls: "ok", word: "完成" };
    case "miss": return { icon: "▸", cls: "miss", word: "未命中" };
    case "failed": return { icon: "✗", cls: "bad", word: "失败" };
    case "parked": return { icon: "⏸", cls: "wait", word: "等你批准" };
    default: return { icon: "·", cls: "info", word: "" };
  }
}

function runStreamState() {
  if (!state.stream) state.stream = { steps: [], lastSeq: 0, loading: false };
  return state.stream;
}

// loadStream fills the transcript from the database: a refresh must not lose what
// already happened.
async function loadStream() {
  const s = runStreamState();
  if (!state.current) { s.steps = []; s.lastSeq = 0; return; }
  s.loading = true;
  try {
    const steps = (await api(`/api/engagements/${state.current.id}/run-steps?since=0`)) || [];
    s.steps = steps;
    s.lastSeq = steps.length ? steps[steps.length - 1].seq : 0;
  } catch { /* an empty stream is a fine state */ }
  s.loading = false;
}

// pushSteps appends live events, ignoring duplicates from a reconnect.
function pushSteps(incoming) {
  const s = runStreamState();
  let added = false;
  for (const ev of incoming) {
    if (!ev || (ev.seq && ev.seq <= s.lastSeq)) continue;
    s.steps.push(ev);
    if (ev.seq) s.lastSeq = ev.seq;
    added = true;
  }
  if (s.steps.length > 400) s.steps = s.steps.slice(-400);
  if (!added) return;
  // Patch only the stream slot: re-rendering the whole chat would throw away
  // whatever the operator is typing.
  const slot = document.querySelector("#run-stream-slot");
  if (slot) {
    slot.replaceChildren(renderRunStream());
  } else if (state.view === "chat") {
    render();
  }
}

// renderRunStream draws the transcript plus the one-line activity header.
function renderRunStream() {
  const s = runStreamState();
  const box = el("div", { class: "run-stream" });

  const last = s.steps.length ? s.steps[s.steps.length - 1] : null;
  const busy = (state.runs || []).some((r) => r.status === "running");
  const parked = s.steps.filter((x) => x.status === "parked");
  const header = (function () {
    if (parked.length) return { cls: "wait", text: `停在 ${parked.length} 个动作前,等你点头` };
    if (busy) {
      const n = s.steps.filter((x) => x.phase === "exec").length;
      return { cls: "busy", text: `正在跑(第 ${n} 步)…` };
    }
    if (last && last.phase === "stop") {
      return { cls: "done", text: last.stop === "needs_approval" ? "等你点头后继续" : `这一轮结束:${last.reason || last.stop}` };
    }
    if (s.steps.length) return { cls: "done", text: "上一轮已结束" };
    return { cls: "idle", text: "还没有运行记录" };
  })();
  box.appendChild(el("div", { class: "stream-head " + header.cls }, header.text));

  if (!s.steps.length) {
    box.appendChild(el("p", { class: "hint" },
      "开工后,它每扫一下、每发现一点、每要冒险一步,都会在这里实时出现。"));
    return box;
  }

  const list = el("div", { class: "stream-list" });
  for (const ev of s.steps) {
    list.appendChild(renderStepRow(ev));
  }
  box.appendChild(list);
  return box;
}

function renderStepRow(ev) {
  const st = stepState(ev);
  const row = el("div", { class: "stream-row " + st.cls });

  if (ev.phase === "reflect") {
    row.classList.add("reflect");
    row.appendChild(el("span", { class: "stream-icon" }, "↳"));
    row.appendChild(el("span", { class: "stream-text" }, ev.summary || ""));
    return row;
  }
  if (ev.phase === "stop") {
    row.appendChild(el("span", { class: "stream-icon" }, "■"));
    row.appendChild(el("span", { class: "stream-text" },
      (ev.stop === "needs_approval" ? "停下等你:" : "结束:") + (ev.reason || ev.stop)));
    return row;
  }
  if (ev.phase === "derive") {
    row.appendChild(el("span", { class: "stream-icon" }, "＋"));
    row.appendChild(el("span", { class: "stream-text" }, ev.summary || "推出新步骤"));
    return row;
  }

  row.appendChild(el("span", { class: "stream-icon" }, st.icon));
  row.appendChild(el("span", { class: "stream-cap" }, capLabel(ev.capability)));
  if (ev.target) row.appendChild(el("span", { class: "stream-target" }, ev.target));
  if (ev.tier) row.appendChild(el("span", { class: "stream-tier" }, "tier" + ev.tier));
  if (ev.summary) row.appendChild(el("span", { class: "stream-sum" }, ev.summary));
  if (ev.reason && ev.status !== "ok") {
    row.appendChild(el("span", { class: "stream-reason" }, ev.reason));
  }
  if (ev.request_id) {
    row.appendChild(el("span", { class: "stream-rid", title: "审计流水号(可去审计页搜)" }, ev.request_id));
  }

  // The parked row is where the human acts: the same approve → execute → resume
  // path the approval card uses, just inline.
  if (ev.status === "parked" && ev.intent_id) {
    const yes = el("button", { class: "primary tiny-btn" }, "批准");
    const no = el("button", { class: "ghost tiny-btn" }, "拒绝");
    yes.addEventListener("click", async () => {
      yes.disabled = true; no.disabled = true;
      try {
        await approveAndRun(ev.intent_id);
      } catch (e) { banner("批准失败:" + e.message); yes.disabled = false; no.disabled = false; }
    });
    no.addEventListener("click", async () => {
      yes.disabled = true; no.disabled = true;
      try {
        await api(`/api/engagements/${state.current.id}/intents/${ev.intent_id}/reject`, {
          method: "POST", body: JSON.stringify({ operator: "operator", reason: "operator declined in the run stream" }),
        });
        banner("已拒绝这一步。它不会执行。", "ok");
        await refresh();
      } catch (e) { banner("拒绝失败:" + e.message); yes.disabled = false; no.disabled = false; }
    });
    row.appendChild(el("span", { class: "stream-actions" }, yes, no));
  }
  return row;
}

// approveAndRun is the one human act of the whole flow: approve the parked intent,
// execute it once, then let whatever depended on it continue.
async function approveAndRun(intentID) {
  await api(`/api/engagements/${state.current.id}/intents/${intentID}/approve`, {
    method: "POST",
    body: JSON.stringify({ operator: "operator", basis: "operator approved this step in the run stream" }),
  });
  await api(`/api/engagements/${state.current.id}/intents/${intentID}/execute`, {
    method: "POST", body: JSON.stringify({ operator: "operator" }),
  });
  // Steps that were waiting on this one can go now.
  let resumed = false;
  try {
    const intents = await api(`/api/engagements/${state.current.id}/intents`);
    const waiting = (intents || []).some((row) => {
      const x = row.intent || row;
      return x.status === "todo" && (x.deps || []).includes(intentID);
    });
    if (waiting) {
      await api(`/api/engagements/${state.current.id}/runs`, {
        method: "POST", body: JSON.stringify({ max_steps: 12 }),
      });
      resumed = true;
    }
  } catch { /* best effort; the start panel still works */ }
  banner(resumed ? "已执行,后续步骤继续跑了。" : "已执行这一步。", "ok");
  await refresh();
}
