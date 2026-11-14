/* youkai control plane — hand-written SPA, no framework, no build step.
 *
 * Rules that shape this file:
 *   - the approval workbench is the primary view; it can approve ONE step at a
 *     time and never offers a batch action
 *   - nothing here can execute tier-2 work on its own: every path requires an
 *     operator approval AND (for network targets) a high-auth record on disk
 *   - the UI renders evidence, it never invents it
 */
"use strict";

const state = {
  token: "",
  engagements: [],
  current: null,
  view: "approvals",
  graph: null,
  intents: [],
  runs: [],
  audit: [],
  config: null,
  health: null,
  es: null,
};

/* ---- tiny helpers -------------------------------------------------------- */

const $ = (sel, root = document) => root.querySelector(sel);
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined) continue;
    n.appendChild(typeof kid === "string" ? document.createTextNode(kid) : kid);
  }
  return n;
};
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const short = (s, n = 160) => (s && s.length > n ? s.slice(0, n) + "…" : s || "");

function banner(msg, kind = "warn") {
  const b = $("#banner");
  if (!msg) { b.classList.add("hidden"); b.textContent = ""; return; }
  b.className = "banner";
  if (kind === "ok") { b.style.borderColor = "#24503a"; b.style.background = "#0f2418"; b.style.color = "#b8f0cf"; }
  else { b.style.borderColor = ""; b.style.background = ""; b.style.color = ""; }
  b.textContent = msg;
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      "X-Youkai-Token": state.token,
      ...(opts.headers || {}),
    },
  });
  const text = await res.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = { raw: text }; }
  if (!res.ok) {
    // A rejected token is not a failed action: the operator cannot fix it by
    // editing the form. Send them to the gate with an explanation instead of
    // stringing "missing or invalid token" through every panel (found in
    // hands-on use: the page had been opened without the #token= fragment).
    if (res.status === 401) {
      showGate("令牌无效或已过期:请从 youkaid 启动窗口复制完整地址(含 #token=…)重新打开,或在这里粘贴令牌");
    }
    const msg = (body && body.error) || res.status + " " + res.statusText;
    throw new Error(msg);
  }
  return body;
}

function openModal(...kids) {
  const body = $("#modal-body");
  body.replaceChildren(...kids);
  $("#modal").classList.remove("hidden");
}
function closeModal() { $("#modal").classList.add("hidden"); }


/* ---- wording -------------------------------------------------------------
 * Mirrors internal/wording so the UI and the API describe a step identically.
 * If these ever disagree, the panel is lying about what will be sent.
 */
const WORDING = {
  probe: { impact: "一次只读 HTTP 请求,不改变状态", stop: "状态码/正文能回答问题即停,不重复探测同一 URL" },
  scan: { impact: "一轮只读检测(头/CORS/Cookie/暴露面/反射),不注入载荷", stop: "拿到候选清单即停" },
  crawl: { impact: "同源只读爬取,受页数上限约束", stop: "达到页数上限即停" },
  compare: { impact: "每账号各一次只读 GET,只比对标记可见性", stop: "标记是否跨账号可见一旦确定即停" },
  role_matrix: { impact: "多账号只读 GET,只比对状态与长度", stop: "差异一旦定位即停" },
  proof: { impact: "一次只读请求 + DOM 上下文判定", stop: "上下文分类完成即停" },
  fingerprint: { impact: "一次只读请求读指纹", stop: "拿到指纹即停" },
  param: { impact: "仅存在性:单个参数少量标记请求;不取数据、不 UNION、不盲注、不落持久化", stop: "首次命中即停;不枚举、不提取、不升级为利用" },
  param_adaptive: { impact: "仅存在性:少量编码变体探测单一参数", stop: "首次命中即停" },
  waf: { impact: "语法形态标记请求,观察拦截行为;不套利用载荷、不绕过", stop: "画像完成即停" },
  login: { impact: "用操作员提供的测试账号登录一次;不爆破、不换字典", stop: "单次尝试后即停" },
  artifact_identify: { impact: "本地静态识别,不联网、不执行", stop: "格式确定即停" },
  checksec: { impact: "本地静态解析缓解措施", stop: "解析完成即停" },
  strings: { impact: "本地只读字符串提取", stop: "提取完成即停" },
  secrets: { impact: "本地只读扫描,凭据一律掩码", stop: "扫描完成即停" },
  decompile: { impact: "本地反编译(需后端),不执行样本", stop: "产出文本即停" },
  download: { impact: "把样本下载到隔离目录(需要人批)", stop: "下载完成即停" },
};

function argURL(a) {
  if (!a) return "";
  if (typeof a.url === "string") return a.url;
  if (Array.isArray(a.urls) && a.urls.length) return String(a.urls[0]);
  if (typeof a.path === "string") return a.path;
  return "";
}

function exactRequest(it) {
  const a = it.args || {};
  const target = argURL(a);
  switch (it.capability) {
    case "param":
    case "param_adaptive":
      return `active existence probe on ${target}, param="${a.param ?? ""}" (SQL error signature / boolean diff; SSTI {{7*7}})`;
    case "waf":
      return `WAF fingerprinting markers on ${target}, param="${a.param ?? ""}"`;
    case "login":
      return `one login attempt at ${target} (single try, no retry, no wordlist)`;
    case "probe":
      return `${(a.method || "GET").toUpperCase()} ${target}`;
    case "download":
      return `download ${a.url || ""} into the isolated artifact directory`;
    default:
      return target ? `${it.capability} ${target}` : it.capability;
  }
}

function minImpact(it) {
  return (WORDING[it.capability] && WORDING[it.capability].impact) || "未知档位动作:按至少证明级影响对待";
}

function stopCondition(it) {
  return (WORDING[it.capability] && WORDING[it.capability].stop) || "首次可观察效果即停";
}

/* Surface render errors in the banner instead of leaving a blank panel. */
window.addEventListener("error", (e) => {
  banner("界面渲染出错:" + (e.message || e.error));
});
window.addEventListener("unhandledrejection", (e) => {
  const r = e.reason;
  banner("界面出错:" + ((r && (r.message || r)) || "unknown"));
  console.error(r);
});
/* ---- token gate ---------------------------------------------------------- */

function initToken() {
  const hash = location.hash.replace(/^#/, "");
  if (hash.startsWith("token=")) {
    state.token = decodeURIComponent(hash.slice(6));
    sessionStorage.setItem("youkai_token", state.token);
    history.replaceState(null, "", location.pathname); // keep the token out of the URL bar
  } else {
    state.token = sessionStorage.getItem("youkai_token") || "";
  }
}

async function boot() {
  initToken();
  if (!state.token) return showGate("请输入令牌");
  try {
    state.health = await api("/api/health");
    state.config = await api("/api/config");
  } catch (e) {
    sessionStorage.removeItem("youkai_token");
    return showGate("令牌无效或被拒绝:" + e.message);
  }
  $("#gate").classList.add("hidden");
  $("#app").classList.remove("hidden");
  $("#health").textContent = `v${state.health.version} · ${state.health.highauth ? "high-auth 已配置" : "high-auth 未配置"}`;
  bindChrome();
  await loadEngagements();
}

function showGate(msg) {
  $("#app").classList.add("hidden");
  $("#gate").classList.remove("hidden");
  $("#gate-err").textContent = msg || "";
  $("#gate-token").focus();
}

/* ---- chrome -------------------------------------------------------------- */

function bindChrome() {
  $("#gate-form").addEventListener("submit", (e) => {
    e.preventDefault();
    state.token = $("#gate-token").value.trim();
    sessionStorage.setItem("youkai_token", state.token);
    boot();
  });
  $("#logout").addEventListener("click", () => {
    sessionStorage.removeItem("youkai_token");
    state.token = "";
    location.reload();
  });
  $("#engagement").addEventListener("change", (e) => selectEngagement(Number(e.target.value)));
  $("#new-engagement").addEventListener("click", () => openScopeModal("new"));
  document.querySelectorAll(".nav").forEach((btn) =>
    btn.addEventListener("click", () => setView(btn.dataset.view))
  );
  $("#modal").addEventListener("click", (e) => { if (e.target.id === "modal") closeModal(); });
}

function setView(view) {
  state.view = view;
  document.querySelectorAll(".nav").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  const titles = {
    approvals: "审批台", evidence: "证据 · 报告", runs: "任务台",
    graph: "探索图", accounts: "账号 · 归属", config: "配置 · 隔离墙", audit: "审计日志",
  };
  $("#view-title").textContent = titles[view] || view;
  render();
}

/* ---- data ---------------------------------------------------------------- */

async function loadEngagements() {
  state.engagements = (await api("/api/engagements")) || [];
  const sel = $("#engagement");
  sel.replaceChildren();
  if (state.engagements.length === 0) {
    sel.appendChild(el("option", { value: "" }, "（还没有作业）"));
    state.current = null;
    render();
    return;
  }
  for (const e of state.engagements) sel.appendChild(el("option", { value: e.id }, e.name));
  const keep = state.current && state.engagements.find((x) => x.id === state.current.id);
  await selectEngagement(keep ? keep.id : state.engagements[0].id);
}

async function selectEngagement(id) {
  const found = state.engagements.find((x) => x.id === id);
  if (!found) return;
  state.current = found;
  $("#engagement").value = String(id);
  await refresh();
  connectSSE();
}

async function refresh() {
  if (!state.current) { render(); return; }
  const base = `/api/engagements/${state.current.id}`;
  const [graph, intents, runs, audit] = await Promise.all([
    api(base + "/graph").catch(() => null),
    api(base + "/intents").catch(() => []),
    api(base + "/runs").catch(() => []),
    api(base + "/audit?limit=300").catch(() => []),
  ]);
  state.graph = graph;
  state.intents = intents || [];
  state.runs = runs || [];
  state.audit = audit || [];
  render();
}

function connectSSE() {
  if (state.es) { state.es.close(); state.es = null; }
  if (!state.current) return;
  const url = `/api/engagements/${state.current.id}/events?token=${encodeURIComponent(state.token)}`;
  const es = new EventSource(url);
  state.es = es;
  es.addEventListener("snapshot", (ev) => {
    try {
      const data = JSON.parse(ev.data);
      if (data.graph) {
        state.graph = data.graph;
        renderChips();
        if (state.view === "approvals" || state.view === "graph") render();
      }
      if (data.running_run_id && state.view === "runs") render();
    } catch { /* ignore malformed frame */ }
  });
  es.onerror = () => { /* EventSource retries on its own */ };
}

/* ---- render -------------------------------------------------------------- */

function render() {
  renderChips();
  const host = $("#view");
  host.replaceChildren();
  try {
    if (!state.current) {
      host.appendChild(el("div", { class: "empty" },
        "先建一个作业:给它名字和一个授权护照(scope)。没有护照,youkai 一个请求都不会发。"));
      return;
    }
    switch (state.view) {
      case "approvals": return renderApprovals(host);
      case "evidence": return renderEvidence(host);
      case "runs": return renderRuns(host);
      case "graph": return renderGraph(host);
    case "accounts": return renderAccounts(host);
      case "config": return renderConfig(host);
      case "audit": return renderAudit(host);
    }
  } catch (err) {
    // A render bug must never look like "there is nothing to approve".
    console.error(err);
    host.appendChild(el("div", { class: "banner" }, "界面渲染出错:" + (err && err.message ? err.message : err)));
  }
}

function renderChips() {
  const s = (state.graph && state.graph.stats) || {};
  const chips = [
    ["资产", s.assets], ["事实", s.facts], ["发现", s.findings],
    ["待确认", s.candidates], ["已确认", s.verified],
    ["请求允许", s.audit_allowed], ["请求阻断", s.audit_blocked],
  ];
  const host = $("#chips");
  host.replaceChildren();
  for (const [label, value] of chips) {
    host.appendChild(el("span", { class: "chip" }, label + " ", el("b", {}, String(value ?? 0))));
  }
  const pending = pendingIntents().length;
  const badge = $("#badge-approvals");
  badge.textContent = String(pending);
  badge.classList.toggle("hidden", pending === 0);
}

function pendingIntents() {
  return state.intents
    .map((row) => row.intent || row)
    .filter((it) => it.status === "needs_approval" || (it.tier >= 2 && it.status === "todo"));
}

function tierTag(tier) {
  if (tier >= 3) return el("span", { class: "tag" }, "tier 3 · 永不执行");
  if (tier === 2) return el("span", { class: "tag t2" }, "tier 2 · 需人批");
  return el("span", { class: "tag t1" }, "tier 1 · 只读");
}

/* ---- approvals ----------------------------------------------------------- */

function renderApprovals(host) {
  const pending = pendingIntents();
  // The pending notice belongs INSIDE this view. It must not go through banner():
  // render() runs on every stream tick, and a banner written here would wipe the
  // error message an operator is still reading (found by the v0.5 E2E walkthrough).
  if (pending.length) {
    host.appendChild(el("p", { class: "hint" },
      "有 " + pending.length + " 个动作停在门口。youkai 不会批准、也不会执行它们 —— 只有你能。"));
  }

  if (pending.length === 0) {
    host.appendChild(el("div", { class: "empty" },
      "门口是空的。自治循环只跑 tier 1;需要人批的动作会出现在这里,一次一个。"));
  }

  for (const it of pending) {
    const card = el("div", { class: "card door" },
      el("h3", {},
        el("span", { class: "mono" }, "#" + it.id),
        el("code", {}, it.capability),
        tierTag(it.tier),
        el("span", { class: "state candidate" }, it.status)),
      el("dl", { class: "kv" },
        el("dt", {}, "会发的确切请求"),
        el("dd", { class: "mono" }, exactRequest(it)),
        el("dt", {}, "最小影响"),
        el("dd", {}, minImpact(it)),
        el("dt", {}, "停止点"),
        el("dd", {}, stopCondition(it)),
        el("dt", {}, "为什么停在这"),
        el("dd", {}, it.gate_reason || "proof-grade action"),
        el("dt", {}, "指纹"),
        el("dd", { class: "mono" }, it.fingerprint)),
      evidenceList(it),
      approveControls(it));
    host.appendChild(card);
  }
}

function evidenceList(it) {
  const facts = (state.graph && state.graph.facts) || [];
  const anchored = facts.filter((f) =>
    f.statement && it.args && JSON.stringify(f).includes(String(it.args.param || "\u0000")) === false
      ? false
      : f.statement && it.args && it.args.param && f.statement.includes("param: " + it.args.param));
  const list = anchored.length ? anchored : facts.slice(-3);
  if (!list.length) return el("p", { class: "hint" }, "暂无关联事实(证据只来自账本,不编造)。");
  return el("ul", { class: "evidence" },
    ...list.map((f) => el("li", {}, `#${f.id} ${short(f.statement, 120)}` +
      (f.evidence && f.evidence.request_id ? ` (request_id=${f.evidence.request_id})` : ""))));
}

function approveControls(it) {
  const operator = el("input", { type: "text", placeholder: "操作员", value: "operator" });
  const basis = el("input", { type: "text", placeholder: "授权依据(≥8 字)" });
  const highAuth = el("input", { type: "text", placeholder: "high-auth 记录路径(网络目标必填)" });
  const status = el("span", { class: "hint" });
  const approveBtn = el("button", { class: "primary" }, "批准这一步");
  const execBtn = el("button", { class: "ghost" }, "执行这一步（一次性）");
  // Derive the button state from the ledger, not from what was clicked here: the
  // stream re-renders this card every few seconds, and a local "I just approved"
  // flag would reset the execute button while the approval still stands (found by
  // the v0.5 E2E walkthrough: you approve, and then cannot execute).
  execBtn.disabled = !it.approved;
  approveBtn.disabled = !!it.approved;
  if (it.approved) status.textContent = "已批准(未执行)。执行一次后即被消费。";

  approveBtn.addEventListener("click", async () => {
    banner("");
    try {
      await api(`/api/engagements/${state.current.id}/intents/${it.id}/approve`, {
        method: "POST",
        body: JSON.stringify({
          operator: operator.value.trim(),
          basis: basis.value.trim(),
          high_auth_path: highAuth.value.trim(),
        }),
      });
      execBtn.disabled = false;
      approveBtn.disabled = true;
      status.textContent = "已批准。执行一次后该批准即被消费,下一步需要新的批准。";
      banner("批准已记录。它只对这一个动作、这一次执行有效。", "ok");
    } catch (e) {
      banner("批准被拒绝:" + e.message);
    }
  });

  execBtn.addEventListener("click", () => {
    openModal(
      el("h3", {}, "执行这一步?"),
      el("p", { class: "muted" }, "这会发出一次真实请求。批准将被立即消费,且不会自动重试。"),
      el("dl", { class: "kv" },
        el("dt", {}, "请求"), el("dd", { class: "mono" }, exactRequest(it)),
        el("dt", {}, "停止点"), el("dd", {}, stopCondition(it))),
      el("div", { class: "actions" },
        el("button", { class: "primary", onclick: async () => {
          closeModal();
          try {
            const r = await api(`/api/engagements/${state.current.id}/intents/${it.id}/execute`, {
              method: "POST",
              body: JSON.stringify({ operator: operator.value.trim(), high_auth_path: highAuth.value.trim() }),
            });
            banner(`已执行 #${it.id} ${it.capability}:事实 +${r.facts},发现 +${r.findings}。批准已消费。`, "ok");
            await refresh();
          } catch (e) {
            banner("执行被拒绝:" + e.message);
            await refresh();
          }
        } }, "确认执行"),
        el("button", { class: "ghost", onclick: closeModal }, "取消")));
  });

  return el("div", { class: "actions" }, operator, basis, highAuth, approveBtn, execBtn, status);
}

/* ---- evidence: the report, snapshots, SARIF, disclosure ------------------- */

async function renderEvidence(host) {
  let b;
  try {
    b = await api(`/api/engagements/${state.current.id}/report`);
  } catch (e) {
    host.appendChild(el("div", { class: "empty" }, "读取报告失败:" + e.message));
    return;
  }
  const findings = b.findings || [];
  const cov = b.coverage || {};

  const actions = el("div", { class: "actions" },
    el("button", { class: "primary", onclick: () => snapshotReport() }, "出快照报告"),
    el("button", { class: "ghost", onclick: () => openWithToken("sarif") }, "导出 SARIF"),
    el("button", { class: "ghost", onclick: () => openWithToken("disclosure", "md") }, "披露包 (md)"),
    el("button", { class: "ghost", onclick: () => openWithToken("disclosure", "html") }, "披露包 (html)"),
    el("button", { class: "ghost", onclick: () => downloadReport("md") }, "下载 markdown"),
    el("button", { class: "ghost", onclick: () => downloadReport("html") }, "下载 HTML"));
  host.appendChild(actions);

  host.appendChild(el("div", { class: "card" },
    el("h3", {}, "覆盖声明"),
    el("p", {}, cov.statement || "—"),
    el("p", { class: "hint" },
      "覆盖数字来自审计表(实际发出的请求),不是来自护照(允许去的地方)。未列出的资产不在报告范围内。")));

  if ((b.incomplete || []).length) {
    host.appendChild(el("div", { class: "card warn" },
      el("h3", {}, "证据不完整"),
      el("p", { class: "hint" }, "以下发现缺四样证据中至少一样,已排除在披露包之外:"),
      el("ul", {}, ...b.incomplete.map((s) => el("li", { class: "mono" }, s)))));
  }

  host.appendChild(el("div", { class: "sec" }, `发现 (${findings.length},已确认 ${b.stats ? b.stats.verified : 0})`));
  if (!findings.length) {
    host.appendChild(el("div", { class: "empty" }, "还没有发现。只读取证跑完后会出现在这里。"));
  }
  for (const f of findings) {
    const ev = f.evidence_block || {};
    const four = el("ul", { class: "four" });
    const evLines = el("ul", {});
    if (!(ev.request_ids || []).length) {
      evLines.appendChild(el("li", {}, "缺失:没有任何 request_id"));
    }
    for (const id of (ev.request_ids || [])) {
      const row = (ev.audit || []).find((a) => a.request_id === id);
      evLines.appendChild(el("li", { class: "mono" },
        id + (row ? ` — ${row.method} ${short(row.url, 90)} → ${row.status} [${row.verdict}]` : " — 审计表里找不到")));
    }
    four.appendChild(el("li", {}, el("b", {}, "① 证据"), evLines));
    four.appendChild(el("li", {}, el("b", {}, "② 最小影响"), ":", f.min_impact || "—"));
    four.appendChild(el("li", {}, el("b", {}, "③ 停止点"), ":", f.stop_condition || "—"));
    four.appendChild(el("li", {}, el("b", {}, "④ 反证说明"), ":", f.counter || "—"));

    host.appendChild(el("div", { class: "card" },
      el("h3", {},
        el("span", { class: "tag" }, f.severity),
        f.title,
        el("span", { class: "state " + f.state }, f.state),
        f.disclosable ? el("span", { class: "tag ok" }, "可披露") : null),
      el("p", { class: "mono" }, "位置:" + short(f.where, 300)),
      (f.evidence && f.evidence.session)
        ? el("p", { class: "hint" }, "会话:" + f.evidence.session + (f.evidence.owner ? " · 对象属于 " + f.evidence.owner : ""))
        : null,
      four,
      f.detail ? el("p", { class: "muted" }, f.detail) : null,
      (f.incomplete || []).length
        ? el("p", { class: "warn" }, "证据不完整:缺 " + f.incomplete.join("、"))
        : null,
      f.state === "candidate"
        ? el("div", { class: "actions" }, el("button", { class: "ghost", onclick: () => verdictModal(f) }, "确认 verified…"))
        : el("p", { class: "hint" }, "已由操作员确认。")));
  }

  host.appendChild(el("div", { class: "sec" }, "历史快照"));
  const listHost = el("div", {});
  host.appendChild(listHost);
  await renderSnapshots(listHost);
}

async function renderSnapshots(host) {
  let snaps = [];
  try { snaps = await api(`/api/engagements/${state.current.id}/reports`); } catch (e) { snaps = []; }
  if (!snaps.length) {
    host.appendChild(el("div", { class: "empty" }, "还没有快照。点「出快照报告」把当前投影固化下来(append-only,带 sha256)。"));
    return;
  }
  host.appendChild(simpleTable(["#", "时间", "sha256(前 8)", "读回"],
    snaps.map((s) => [String(s.id), new Date(s.created_at).toLocaleString(), s.content_sha256.slice(0, 8),
      "下载"])));
  host.appendChild(el("p", { class: "hint" },
    "快照表在数据库层是 append-only:UPDATE / DELETE 会被触发器拒绝。披露与复核都以快照哈希为锚。"));
}

async function snapshotReport() {
  banner("");
  try {
    const r = await api(`/api/engagements/${state.current.id}/reports`, { method: "POST" });
    banner(`已出快照 #${r.snapshot.id} · sha256=${(r.sha256 || "").slice(0, 8)}…` +
      (r.artifact ? " · HTML: " + r.artifact : ""), "ok");
    await refresh();
  } catch (e) { banner("出快照失败:" + e.message); }
}

// openWithToken opens a report sub-resource with the token in the fragment-free
// query (the API accepts ?token= for downloads).
function openWithToken(kind, format) {
  const q = format ? `?format=${format}&token=` : "?token=";
  window.open(`/api/engagements/${state.current.id}/${kind}${q}${encodeURIComponent(state.token)}`, "_blank");
}

async function verdictModal(f) {
  const note = el("input", { type: "text", placeholder: "操作员的判定依据" });
  const confirm = el("input", { type: "checkbox" });
  openModal(
    el("h3", {}, "确认这条发现?"),
    el("p", { class: "muted" }, "candidate → verified 只能在操作员明确确认后发生;youkai 永不自动升级。"),
    el("dl", { class: "kv" },
      el("dt", {}, "发现"), el("dd", {}, f.title),
      el("dt", {}, "位置"), el("dd", { class: "mono" }, short(f.where, 240))),
    el("p", {}, el("label", {}, confirm, " 我确认这条发现成立")),
    note,
    el("div", { class: "actions" },
      el("button", { class: "primary", onclick: async () => {
        if (!confirm.checked) return banner("必须先勾选确认。");
        try {
          await api(`/api/engagements/${state.current.id}/findings/${f.id}/verdict`, {
            method: "POST",
            body: JSON.stringify({ operator: "operator", note: note.value.trim(), confirm: true }),
          });
          closeModal();
          banner("发现已置为 verified。", "ok");
          await refresh();
        } catch (e) { banner("判定被拒绝:" + e.message); }
      } }, "确认"),
      el("button", { class: "ghost", onclick: closeModal }, "取消")));
}

function downloadReport(format) {
  const url = `/api/engagements/${state.current.id}/report?format=${format}&token=${encodeURIComponent(state.token)}`;
  window.open(url, "_blank");
}
/* ---- runs ---------------------------------------------------------------- */

function renderRuns(host) {
  const seeds = el("input", { type: "text", placeholder: "可选:额外种子 URL(逗号分隔)" });
  const steps = el("input", { type: "text", placeholder: "max_steps", value: "10" });
  host.appendChild(el("div", { class: "card" },
    el("h3", {}, "跑一轮只读取证"),
    el("p", { class: "hint" },
      "自治循环只执行 tier 1。遇到需要人批的动作就停下,回到审批台。"),
    el("div", { class: "actions" }, seeds, steps,
      el("button", { class: "primary", onclick: async () => {
        banner("");
        try {
          const seedList = seeds.value.split(",").map((s) => s.trim()).filter(Boolean);
          const r = await api(`/api/engagements/${state.current.id}/runs`, {
            method: "POST",
            body: JSON.stringify({ seed_urls: seedList, max_steps: Number(steps.value) || 10 }),
          });
          banner(`已启动 run #${r.run_id}。`, "ok");
          await refresh();
        } catch (e) { banner("启动失败:" + e.message); }
      } }, "开始"))));

  host.appendChild(el("div", { class: "sec" }, `运行记录 (${state.runs.length})`));
  if (!state.runs.length) {
    host.appendChild(el("div", { class: "empty" }, "还没有运行记录。"));
    return;
  }
  const tbody = el("tbody");
  for (const r of state.runs) {
    tbody.appendChild(el("tr", {},
      el("td", { class: "mono" }, "#" + r.id),
      el("td", {}, el("span", { class: "state " + (r.status === "error" ? "blocked" : "allowed") }, r.status)),
      el("td", {}, r.stop_reason || "—"),
      el("td", { class: "mono" }, String(r.steps)),
      el("td", { class: "mono" }, r.started_at ? new Date(r.started_at).toLocaleString() : "—"),
      el("td", {}, r.ended_at ? new Date(r.ended_at).toLocaleTimeString() : "运行中…")));
  }
  host.appendChild(el("table", {}, el("thead", {}, el("tr", {},
    ...["run", "状态", "停止原因", "步数", "开始", "结束"].map((h) => el("th", {}, h)))), tbody));
}

/* ---- graph --------------------------------------------------------------- */

function renderGraph(host) {
  const g = state.graph;
  if (!g) { host.appendChild(el("div", { class: "empty" }, "暂无数据。")); return; }
  host.appendChild(el("div", { class: "sec" }, `资产 (${g.assets.length})`));
  host.appendChild(simpleTable(["id", "kind", "value"],
    g.assets.map((a) => [a.id, a.kind, short(a.value, 90)])));
  host.appendChild(el("div", { class: "sec" }, `事实 (${g.facts.length})`));
  host.appendChild(simpleTable(["id", "statement", "request_id"],
    g.facts.map((f) => [f.id, short(f.statement, 130), (f.evidence && f.evidence.request_id) || "—"])));
  // Process memory: what each executed step did, and how much of each host
  // is already covered. Read-only projection of intents.trace (v0.7).
  const doneIntents = g.intents.filter((i) => i.trace);
  if (doneIntents.length) {
    const byHost = {};
    for (const i of doneIntents) {
      const u = (i.args && i.args.url) || "";
      const m = u.match(/^https?:\/\/([^/]+)/i);
      const host = m ? m[1] : "(无目标)";
      byHost[host] = (byHost[host] || 0) + 1;
    }
    host.appendChild(el("p", { class: "hint" },
      "已执行步骤按目标:" + Object.entries(byHost).map(([h, n]) => h + " × " + n).join(" · ")));
  }
  host.appendChild(simpleTable(["id", "capability", "tier", "status", "rationale"],
    g.intents.map((i) => [i.id, i.capability, i.tier, i.status, short(i.rationale, 90)])));
  if (doneIntents.length) {
    host.appendChild(el("div", { class: "sec" }, `已执行步骤 (${doneIntents.length})`));
    host.appendChild(simpleTable(["id", "capability", "trace"],
      doneIntents.map((i) => [i.id, i.capability, short(i.trace, 160)])));
    host.appendChild(el("p", { class: "hint" },
      "这些 trace 会被检索后喂给规划器(同目标已做的检查不再重复派生);账本里只有能力名、计数与 request_id。"));
  }
  host.appendChild(el("div", { class: "sec" }, `血缘边 (${g.edges.length})`));
  host.appendChild(simpleTable(["from", "rel", "to"],
    g.edges.slice(0, 200).map((e) => [`${e.from_kind}#${e.from_id}`, e.rel, `${e.to_kind}#${e.to_id}`])));
}

function simpleTable(headers, rows) {
  if (!rows.length) return el("div", { class: "empty" }, "（空）");
  const tbody = el("tbody");
  for (const r of rows) {
    tbody.appendChild(el("tr", {}, ...r.map((c, i) =>
      el("td", { class: i === 0 ? "mono" : "" }, String(c ?? "—")))));
  }
  return el("table", {},
    el("thead", {}, el("tr", {}, ...headers.map((h) => el("th", {}, h)))), tbody);
}


/* ---- accounts ------------------------------------------------------------ */

async function renderAccounts(host) {
  let view;
  try {
    view = await api(`/api/engagements/${state.current.id}/accounts`);
  } catch (e) {
    host.appendChild(el("div", { class: "empty" }, "读取账号层失败:" + e.message));
    return;
  }
  const accounts = view.accounts || [];
  const pairs = view.bola_pairs || [];

  banner("");
  host.appendChild(el("p", { class: "hint" },
    "账号层是 BOLA/IDOR 的燃料:身份来自清单,归属由操作员声明或由账号自建。登录与播种都是档 2,只能在审批台一步一批。"));

  for (const w of (view.warnings || [])) {
    host.appendChild(el("div", { class: "banner" }, w));
  }

  host.appendChild(el("div", { class: "sec" }, `身份 (${accounts.length})`));
  if (!accounts.length) {
    host.appendChild(el("div", { class: "empty" },
      "还没有身份。由授权人写一份 " + (view.path || ".youkai/accounts.json") +
      "(YoukaiAccounts/v1);密码只走 password_env 环境变量。"));
  } else {
    host.appendChild(simpleTable(["name", "role", "owns", "session"],
      accounts.map((a) => [a.name, a.role, (a.owns || []).join(", ") || "—", a.session_ready ? "ready" : "未登录"])));
  }

  const actions = el("div", { class: "actions" },
    el("button", { class: "ghost", onclick: () => deriveIntent("accounts_provision", {}, "为清单里每个账号登录一次并保存会话(档 2)") },
      "派生 provision 意图(档 2)"),
    el("button", { class: "ghost", onclick: () => deriveIntent("accounts_seed", { confirm: true }, "每账号创建一个最小对象作为归属真值(档 2)") },
      "派生 seed 意图(档 2)"),
    el("button", { class: "ghost", onclick: () => deriveIntent("accounts_show", {}, "只读刷新账号视图") },
      "派生 accounts_show 意图(只读)"));
  host.appendChild(actions);
  host.appendChild(el("p", { class: "hint" },
    "派生出来的档 2 意图会停在审批台,需要你逐条批准(并且登录/播种还要求 scope 里对应的开关)。"));

  // Render a page as one of these identities. The form never holds a
  // credential: it names a session, and the dispatcher attaches the cookie
  // inside the Fetch gate, only for that identity's own host.
  const renderURL = el("input", { type: "text", placeholder: "要以某个身份渲染的 URL" });
  const renderSession = el("select", {},
    el("option", { value: "" }, "匿名(不带会话)"),
    ...accounts.map((a) => el("option", { value: a.name }, a.name)));
  host.appendChild(el("div", { class: "card" },
    el("h3", {}, "以会话渲染"),
    el("p", { class: "hint" },
      "档 1 只读渲染。会话 header 在 Fetch 闸内、按 host 注入到已被 guard 放行的请求上;账本只记会话名。"),
    el("div", { class: "actions" }, renderURL, renderSession,
      el("button", { class: "ghost", onclick: () => {
        const url = renderURL.value.trim();
        if (!url) return banner("先填要渲染的 URL");
        const intentArgs = { url };
        if (renderSession.value) intentArgs.session = renderSession.value;
        deriveIntent("browser", intentArgs,
          renderSession.value ? "以已登录身份 " + renderSession.value + " 只读渲染" : "匿名只读渲染");
      } }, "派生 browser 意图(只读)"))));
  host.appendChild(el("div", { class: "sec" }, `BOLA 配对 (${pairs.length})`));
  if (!pairs.length) {
    host.appendChild(el("div", { class: "empty" }, "还没有归属关系,所以没有可比的配对。"));
  } else {
    host.appendChild(simpleTable(["owner", "viewer", "marker", "compared url"],
      pairs.map((p) => [p.owner, p.viewer, p.marker, short(p.url, 90)])));
    host.appendChild(el("p", { class: "hint" },
      "配对的 compare 是档 1(两次只读 GET),引擎可以自走。"));
  }
}

async function deriveIntent(capability, args, rationale) {
  try {
    const r = await api(`/api/engagements/${state.current.id}/intents`, {
      method: "POST",
      body: JSON.stringify({ capability, args, rationale, expected_fact: "" }),
    });
    const created = r.created ? "已创建" : "已存在";
    banner(`意图 #${r.intent.id} ${created}(${capability},tier ${r.gate.tier})。` +
      (r.gate.tier >= 2 ? "它停在审批台,等你批准。" : "没有可领的只读步骤时引擎会自己跑它。"), "ok");
    await refresh();
  } catch (e) {
    banner("派生意图失败:" + e.message);
  }
}
/* ---- config: editable LLM + passport -------------------------------------- */

async function renderConfig(host) {
  let cfg = state.config || {};
  try { cfg = await api("/api/config"); state.config = cfg; } catch (e) { banner("读取配置失败:" + e.message); }

  const llm = cfg.llm || {};
  const provider = cfg.provider || {};
  const ha = cfg.highauth || {};

  /* -------- LLM: editable -------- */
  const enabled = el("input", { type: "checkbox" });
  enabled.checked = !!llm.enabled;
  const baseURL = el("input", { type: "text", placeholder: "https://api.example/v1", value: llm.base_url || "" });
  const model = el("input", { type: "text", placeholder: "模型名,如 deepseek-chat", value: llm.model || "" });
  const temp = el("input", { type: "text", placeholder: "0", value: String(llm.temperature ?? 0) });
  const timeout = el("input", { type: "text", placeholder: "120", value: String(llm.timeout_s || 120) });
  const maxTokens = el("input", { type: "text", placeholder: "1200", value: String(llm.max_tokens || 1200) });

  const keyModeEnv = el("input", { type: "radio", name: "keymode", value: "env" });
  const keyModeRaw = el("input", { type: "radio", name: "keymode", value: "raw" });
  if (llm.key_from_env || llm.key_source) keyModeEnv.checked = true; else keyModeRaw.checked = true;
  const envName = el("input", { type: "text", placeholder: "环境变量名,如 YOUKAI_LLM_API_KEY", value: llm.key_from_env || "" });
  const rawKey = el("input", { type: "password", placeholder: "直接填 key(加密保存,永不回显)", autocomplete: "off" });

  const saveBtn = el("button", { class: "primary" }, "保存配置");
  const testBtn = el("button", { class: "ghost" }, "测试连接");
  const status = el("span", { class: "hint" });

  const keyLine = el("p", { class: "hint" },
    `密钥状态:${llm.key_present ? "已配置" : "未配置"}` +
    (llm.key_source ? ` · 来源 ${llm.key_source}` : "") +
    (llm.can_store_secrets ? "" : " · 本站未设置会话密钥,只能使用环境变量引用"));

  const collect = () => {
    const body = {
      enabled: enabled.checked,
      base_url: baseURL.value.trim(),
      model: model.value.trim(),
      temperature: Number(temp.value || 0),
      timeout_s: Number(timeout.value || 120),
      max_tokens: Number(maxTokens.value || 1200),
      updated_by: "operator",
    };
    if (keyModeEnv.checked) {
      body.key_from_env = envName.value.trim();
    } else if (rawKey.value.trim() !== "") {
      body.key = rawKey.value.trim();
    }
    // An empty raw key with the "raw" mode selected and a stored secret present
    // is left untouched: clearing is an explicit action, not a side effect.
    return body;
  };

  saveBtn.addEventListener("click", async () => {
    banner("");
    try {
      const view = await api("/api/config/llm", { method: "PUT", body: JSON.stringify(collect()) });
      rawKey.value = "";
      status.textContent = `已保存 · ${view.source}`;
      banner("配置已保存并热生效(新作业使用新配置,不用重启)。", "ok");
      await renderConfig(currentHost());
    } catch (e) { banner("保存失败:" + e.message); }
  });
  testBtn.addEventListener("click", async () => {
    banner("");
    status.textContent = "测试中…";
    try {
      const r = await api("/api/config/llm/test", { method: "POST", body: JSON.stringify(collect()) });
      if (r.ok) status.textContent = `连通正常 · ${r.latency_ms} ms`;
      else status.textContent = "连接失败:" + (r.error || "未知错误");
    } catch (e) { status.textContent = "测试失败:" + e.message; }
  });

  host.appendChild(el("div", { class: "card" },
    el("h3", {}, "LLM 补位规划器"),
    el("p", { class: "hint" },
      "模型怎么连在这里配;保存后热生效。key 永不回显:要么引用环境变量(推荐),要么加密保存。"),
    el("p", {}, el("label", {}, enabled, " 启用(未启用时确定性循环照跑)")),
    el("div", { class: "field" }, el("span", { class: "label" }, "base_url"), baseURL),
    el("div", { class: "field" }, el("span", { class: "label" }, "model"), model),
    el("div", { class: "grid2" },
      el("div", { class: "field" }, el("span", { class: "label" }, "temperature"), temp),
      el("div", { class: "field" }, el("span", { class: "label" }, "timeout (秒)"), timeout),
      el("div", { class: "field" }, el("span", { class: "label" }, "max_tokens"), maxTokens)),
    el("p", {}, el("label", {}, keyModeEnv, " 用环境变量"), "  ", el("label", {}, keyModeRaw, " 直接填 key")),
    el("div", { class: "field" }, el("span", { class: "label" }, "环境变量名"), envName),
    el("div", { class: "field" }, el("span", { class: "label" }, "API key(不回显)"), rawKey),
    keyLine,
    el("div", { class: "actions" }, saveBtn, testBtn, status)));

  /* -------- passport: current + edit -------- */
  const scope = (state.current && state.current.scope) || {};
  const switches = [
    ["allow_active_probes", "主动探针(param/waf 档 2)"],
    ["allow_waf_probe", "WAF 画像(档 2)"],
    ["allow_object_seeding", "对象播种(档 2)"],
    ["allow_account_provisioning", "账号注册(档 2)"],
    ["allow_private", "私有/环回地址"],
  ].filter(([k]) => scope[k]);
  host.appendChild(el("div", { class: "card" },
    el("h3", {}, "授权护照"),
    el("dl", { class: "kv" },
      el("dt", {}, "include"), el("dd", { class: "mono" }, (scope.include || []).join(", ") || "—"),
      el("dt", {}, "exclude"), el("dd", { class: "mono" }, (scope.exclude || []).join(", ") || "—"),
      el("dt", {}, "methods"), el("dd", { class: "mono" }, (scope.methods || []).join(", ") || "—"),
      el("dt", {}, "放开的开关"), el("dd", {}, switches.map(([, label]) => label).join(" · ") || "无(全只读)"),
      el("dt", {}, "请求预算"), el("dd", { class: "mono" }, String(scope.max_requests || "—")),
      el("dt", {}, "限速 rps"), el("dd", { class: "mono" }, String(scope.rps || "—")),
      el("dt", {}, "过期"), el("dd", { class: "mono" }, scope.expires_at || "—"),
      el("dt", {}, "授权依据"), el("dd", {}, scope.basis || "—")),
    el("div", { class: "actions" },
      el("button", { class: "ghost", onclick: () => openScopeModal("edit") }, "编辑护照…"),
      el("button", { class: "ghost", onclick: () => openScopeModal("new") }, "+ 新建作业…")),
    el("p", { class: "hint" }, "放宽护照(加目标/加写方法/开档 2 开关)会写一条审计;它改变的是「能看哪里」,不是「能做什么」。")));

  /* -------- the wall: read-only, no switches -------- */
  host.appendChild(el("div", { class: "card" },
    el("h3", {}, "隔离墙(只读)"),
    el("dl", { class: "kv" },
      el("dt", {}, "利用提供者"),
      el("dd", { class: "state " + (provider.available ? "blocked" : "verified") }, provider.reason || "—"),
      el("dt", {}, "构建"), el("dd", {}, "OSS(无 youkai_full)"),
      el("dt", {}, "high-auth"), el("dd", {}, ha.configured ? "已配置 " + ha.env : "未配置 " + ha.env)),
    el("p", { class: "hint" }, "这不是可配项:档 3 不在本仓库,档 2 永远要人批。配置面碰不到它们。")));

  const tiers = cfg.tiers || {};
  const rows = (tiers.read_only || []).map((c) => [c, "tier 1 · 自治"]);
  (tiers.proof || []).forEach((c) => rows.push([c, "tier 2 · 人批"]));
  host.appendChild(el("div", { class: "sec" }, "能力分档"));
  host.appendChild(simpleTable(["capability", "档位"], rows));
}

function currentHost() { return document.querySelector("#view"); }

/* ---- passport editor (new + edit) ---------------------------------------- */

function openScopeModal(mode) {
  const editing = mode === "edit" && state.current;
  const scope = (editing && state.current.scope) || {};
  const name = el("input", { type: "text", placeholder: "作业名,如 lab-demo", value: editing ? state.current.name : "" });
  const include = el("input", { type: "text", placeholder: "127.0.0.1:8080, https://lab.example", value: (scope.include || []).join(", ") });
  const exclude = el("input", { type: "text", placeholder: "admin.lab.example(排除优先)", value: (scope.exclude || []).join(", ") });
  const basis = el("input", { type: "text", placeholder: "授权依据(≥8 字)", value: scope.basis || "" });
  const operator = el("input", { type: "text", placeholder: "操作员", value: scope.operator || "operator" });
  const maxReq = el("input", { type: "text", placeholder: "2000", value: String(scope.max_requests || 2000) });
  const rps = el("input", { type: "text", placeholder: "5", value: String(scope.rps || 5) });
  const expires = el("input", { type: "text", placeholder: "2026-12-31T00:00:00Z", value: scope.expires_at || "" });

  const methodList = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];
  const methodBoxes = {};
  for (const m of methodList) {
    const cb = el("input", { type: "checkbox" });
    cb.checked = (scope.methods || ["GET", "HEAD", "OPTIONS"]).includes(m);
    methodBoxes[m] = cb;
  }

  const switchDefs = [
    ["allow_private", "私有/环回地址(自建靶场)"],
    ["allow_active_probes", "主动探针 param/waf(档 2)"],
    ["allow_waf_probe", "WAF 画像(档 2)"],
    ["allow_object_seeding", "对象播种(档 2)"],
    ["allow_account_provisioning", "账号注册(档 2)"],
  ];
  const switchBoxes = {};
  for (const [k] of switchDefs) {
    const cb = el("input", { type: "checkbox" });
    cb.checked = !!scope[k];
    switchBoxes[k] = cb;
  }

  const writeMethodWarn = el("p", { class: "hint" },
    "勾选写方法或档 2 开关只是「允许 it 发生」:param/waf/登录/播种仍然停在审批台,一步一批。");

  const save = el("button", { class: "primary" }, editing ? "保存护照" : "创建作业");
  save.addEventListener("click", async () => {
    banner("");
    const body = {
      project: (include.value.split(",")[0] || "").trim(),
      include: include.value.split(",").map((s) => s.trim()).filter(Boolean),
      exclude: exclude.value.split(",").map((s) => s.trim()).filter(Boolean),
      methods: methodList.filter((m) => methodBoxes[m].checked),
      basis: basis.value.trim(),
      operator: operator.value.trim(),
      max_requests: Number(maxReq.value || 2000),
      rps: Number(rps.value || 5),
    };
    const exp = normExpiry(expires.value);
    if (exp) body.expires_at = exp;   // empty means "no expiry": omit rather than send ""
    for (const [k] of switchDefs) body[k] = switchBoxes[k].checked;
    try {
      if (editing) {
        await api(`/api/engagements/${state.current.id}/scope`, {
          method: "PUT",
          body: JSON.stringify({ scope: body, updated_by: operator.value.trim() || "operator" }),
        });
        closeModal();
        await loadEngagements();
        banner("护照已更新并记入审计。", "ok");
        return;
      }
      const created = await api("/api/engagements", {
        method: "POST",
        body: JSON.stringify({ name: name.value.trim(), scope: body }),
      });
      closeModal();
      await loadEngagements();
      const warns = (created && created.warnings) || [];
      banner(warns.length ? "作业已创建,但护照会拦断自己的目标:" + warns.join(";") : "作业已创建。",
        warns.length ? "warn" : "ok");
    } catch (e) {
      banner("保存失败:" + e.message);
    }
  });

  openModal(
    el("h3", {}, editing ? "编辑授权护照" : "新建作业"),
    el("p", { class: "muted" }, "护照决定 youkai 能看哪里。非法护照(空 include / * / *.tld / basis 太短 / 已过期)会被拒绝保存。"),
    editing ? null : el("div", { class: "field" }, el("span", { class: "label" }, "名称"), name),
    el("div", { class: "field" }, el("span", { class: "label" }, "include(授权目标)"), include),
    el("div", { class: "field" }, el("span", { class: "label" }, "exclude(排除优先)"), exclude),
    el("div", { class: "field" }, el("span", { class: "label" }, "methods"), el("div", { class: "row" },
      ...methodList.map((m) => el("label", {}, methodBoxes[m], " " + m)))),
    el("div", { class: "field" }, el("span", { class: "label" }, "档 2 开关"), el("div", {},
      ...switchDefs.map(([k, label]) => el("label", { style: "display:block" }, switchBoxes[k], " " + label)))),
    writeMethodWarn,
    el("div", { class: "grid2" },
      el("div", { class: "field" }, el("span", { class: "label" }, "请求预算"), maxReq),
      el("div", { class: "field" }, el("span", { class: "label" }, "限速 rps"), rps),
      el("div", { class: "field" }, el("span", { class: "label" }, "过期(RFC3339)"), expires)),
    el("div", { class: "field" }, el("span", { class: "label" }, "授权依据"), basis),
    el("div", { class: "field" }, el("span", { class: "label" }, "操作员"), operator),
    el("div", { class: "actions" }, save, el("button", { class: "ghost", onclick: closeModal }, "取消")));
}

// normExpiry turns a UI datetime into RFC3339; empty stays empty (server default).
function normExpiry(v) {
  const raw = (v || "").trim();
  if (!raw) return "";
  const d = new Date(raw);
  if (isNaN(d.getTime())) return raw; // let the server reject it with a clear message
  return d.toISOString();
}


function renderAudit(host) {
  if (!state.audit.length) {
    host.appendChild(el("div", { class: "empty" }, "还没有审计记录。"));
    return;
  }
  const tbody = el("tbody");
  for (const a of state.audit) {
    tbody.appendChild(el("tr", {},
      el("td", { class: "mono" }, a.request_id),
      el("td", {}, a.ts ? new Date(a.ts).toLocaleTimeString() : "—"),
      el("td", { class: "mono" }, a.method),
      el("td", { class: "mono" }, short(a.url, 70)),
      el("td", { class: "mono" }, String(a.status || "—")),
      el("td", {}, el("span", { class: "state " + a.verdict }, a.verdict)),
      el("td", {}, short(a.reason || a.purpose, 60))));
  }
  host.appendChild(el("table", {}, el("thead", {}, el("tr", {},
    ...["request_id", "时间", "方法", "URL", "状态", "判定", "原因"].map((h) => el("th", {}, h)))), tbody));
  host.appendChild(el("p", { class: "hint" }, "审计表在数据库层是 append-only:UPDATE / DELETE 会被触发器拒绝。"));
}


boot();
