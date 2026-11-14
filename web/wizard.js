/* ---- wizard: create a task by answering one question ---------------------
 *
 * The old form asked for a passport before the operator understood what a
 * passport was. This one asks "which URL" and derives a legal, conservative
 * scope from the answer. Everything else lives behind "高级选项", where each
 * knob explains what it unlocks in plain language.
 *
 * Security defaults are unchanged - the wizard only fills them in:
 * read-only methods, every high-risk switch off, a 7-day expiry, a request budget.
 */

const LLM_PRESETS = [
  { key: "deepseek", label: "DeepSeek", base: "https://api.deepseek.com/v1", model: "deepseek-chat" },
  { key: "openai", label: "OpenAI 兼容", base: "https://api.openai.com/v1", model: "gpt-4o-mini" },
  { key: "custom", label: "自定义", base: "", model: "" },
];

function isLoopbackHost(host) {
  return /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|localhost$|\[::1\]$)/i.test(host);
}

// normaliseTarget returns { url, host } or null. It refuses anything that is not
// an http(s) URL, because that is what the passport can even express.
function normaliseTarget(raw) {
  let v = (raw || "").trim();
  if (!v) return null;
  if (!/^https?:\/\//i.test(v)) v = "https://" + v.replace(/^\/+/, "");
  let u;
  try { u = new URL(v); } catch { return null; }
  if (!u.hostname) return null;
  return { url: u.origin + (u.pathname === "/" ? "" : u.pathname), host: u.host };
}

function openTaskWizard(mode) {
  const editing = mode === "edit" && state.current;
  const scope = (editing && state.current.scope) || {};
  const existingHosts = (scope.include || []);
  const firstTarget = editing ? normaliseTarget(existingHosts[0] || "") : null;

  const target = el("input", {
    type: "text",
    placeholder: "https://你的站点  或  http://127.0.0.1:8080",
    value: firstTarget ? firstTarget.url : (existingHosts[0] || ""),
  });
  const name = el("input", {
    type: "text", placeholder: "任务名(留空自动取域名)",
    value: editing ? state.current.name : "",
  });
  const confirm = el("input", { type: "checkbox" });
  confirm.checked = !!editing;

  const advanced = el("details", { class: "advanced" });
  advanced.appendChild(el("summary", {}, "高级选项(一般不用动)"));

  // ---- advanced fields --------------------------------------------------
  const exclude = el("input", { type: "text", placeholder: "例如 admin.example.com", value: (scope.exclude || []).join(", ") });
  const basis = el("input", { type: "text", placeholder: "写清授权来源,≥8 字", value: scope.basis || "" });
  const operator = el("input", { type: "text", placeholder: "你的名字", value: scope.operator || "operator" });
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
    ["allow_private", "允许打本机/内网地址",
      "给自建靶场和本机开发服务用。公网站点不需要;开了也只意味着允许连这些地址。"],
    ["allow_active_probes", "允许主动探针(SQL / 模板注入的存在性检查)",
      "会让 youkai 向目标发送少量带载荷形状的请求。每一次仍然要你在待办审批里单独点批准。"],
    ["allow_waf_probe", "允许 WAF 行为探测",
      "只观察对方拦不拦、怎么拦,不做绕过。同样是每次都要你批准。"],
    ["allow_object_seeding", "允许自动创建测试对象",
      "为了做越权验证而创建一个最小对象(例如一条订单)。会写数据,每次都要你批准。"],
    ["allow_account_provisioning", "允许注册测试账号",
      "自助注册一个测试账号。会写数据、可能触发验证码,遇到验证码会停下等你。"],
  ];
  const switchBoxes = {};
  const switchRows = [];
  for (const [k, label, why] of switchDefs) {
    const cb = el("input", { type: "checkbox" });
    cb.checked = !!scope[k];
    switchBoxes[k] = cb;
    switchRows.push(el("label", { class: "switch-row" }, cb, el("span", {}, label, el("em", {}, " " + why))));
  }

  const privateNote = el("p", { class: "hint" }, "");
  const syncPrivateNote = () => {
    const t = normaliseTarget(target.value);
    if (!t) { privateNote.textContent = ""; return; }
    if (!isLoopbackHost(t.host.split(":")[0])) { privateNote.textContent = ""; return; }
    // Say it out loud: the checkbox lives under 高级, and silently flipping a
    // switch the operator cannot see is worse than making them read one line.
    privateNote.textContent = switchBoxes.allow_private.checked
      ? "识别为本机/内网地址,已自动允许(否则安全边界会拦下每一个请求)。"
      : "这是本机/内网地址,但没有允许 —— 所有请求都会被安全边界拦下。";
  };
  target.addEventListener("input", () => {
    const t = normaliseTarget(target.value);
    if (t && isLoopbackHost(t.host.split(":")[0])) switchBoxes.allow_private.checked = true;
    syncPrivateNote();
  });

  advanced.append(
    el("div", { class: "field" }, el("span", { class: "label" }, "额外允许的目标(逗号分隔)"), target),
    el("div", { class: "field" }, el("span", { class: "label" }, "排除(这些不碰)"), exclude),
    el("div", { class: "field" }, el("span", { class: "label" }, "允许的请求方法"),
      el("div", { class: "row" }, ...methodList.map((m) => el("label", {}, methodBoxes[m], " " + m)))),
    el("p", { class: "hint" }, "默认只有 GET/HEAD/OPTIONS。勾 POST 是给“登录/写操作”用的,那些动作仍然每次都要你批准。"),
    el("div", { class: "field" }, el("span", { class: "label" }, "高风险开关"), el("div", {}, ...switchRows)),
    el("div", { class: "grid2" },
      el("div", { class: "field" }, el("span", { class: "label" }, "请求上限"), maxReq),
      el("div", { class: "field" }, el("span", { class: "label" }, "每秒请求数"), rps),
      el("div", { class: "field" }, el("span", { class: "label" }, "到期时间(RFC3339,留空=7 天后)"), expires)),
    el("div", { class: "field" }, el("span", { class: "label" }, "授权依据(留空自动记录向导确认)"), basis),
    el("div", { class: "field" }, el("span", { class: "label" }, "操作员"), operator));

  const save = el("button", { class: "primary" }, editing ? "保存授权范围" : "创建任务");
  save.addEventListener("click", async () => {
    banner("");
    const t = normaliseTarget(target.value);
    if (!t) return banner("先填一个网址,形如 https://example.com 或 http://127.0.0.1:8080");
    if (!confirm.checked) return banner("请先勾选“我确认有权测试这个目标”");
    const hostName = t.host.replace(/^www\./, "");
    const body = {
      project: hostName,
      include: [t.url],
      exclude: exclude.value.split(",").map((s) => s.trim()).filter(Boolean),
      methods: methodList.filter((m) => methodBoxes[m].checked),
      basis: basis.value.trim() || `向导确认:操作员声明有权测试 ${t.host} @ ${new Date().toISOString()}`,
      operator: operator.value.trim() || "operator",
      max_requests: Number(maxReq.value || 2000),
      rps: Number(rps.value || 5),
    };
    const exp = normExpiry(expires.value) || new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
    if (exp) body.expires_at = exp;
    for (const [k] of switchDefs) body[k] = switchBoxes[k].checked;

    try {
      if (editing) {
        await api(`/api/engagements/${state.current.id}/scope`, {
          method: "PUT", body: JSON.stringify({ scope: body, updated_by: body.operator }),
        });
        closeModal();
        await loadEngagements();
        banner("授权范围已更新并记入审计。", "ok");
        return;
      }
      const created = await api("/api/engagements", {
        method: "POST",
        body: JSON.stringify({ name: name.value.trim() || hostName, scope: body }),
      });
      closeModal();
      await loadEngagements();
      const warns = (created && created.warnings) || [];
      banner(warns.length ? "任务已创建,但授权范围会拦断自己的目标:" + warns.join(";")
        : "任务已创建。点“开始扫描”就能跑只读检查。", warns.length ? "warn" : "ok");
      setView("runs");
    } catch (e) { banner("保存失败:" + e.message); }
  });

  openModal(
    el("h3", {}, editing ? "编辑授权范围" : "新建任务"),
    !editing && el("p", { class: "muted" }, "只填一个网址。其余都是安全默认值,想调再展开“高级选项”。"),
    el("div", { class: "field" }, el("span", { class: "label" }, "要测试的网址"), target),
    privateNote,
    !editing && el("div", { class: "field" }, el("span", { class: "label" }, "任务名(可留空)"), name),
    el("label", { class: "confirm-row" }, confirm,
      el("span", {}, "我确认有权测试这个目标(自建靶场 / 我拥有 / 已获书面授权)")),
    advanced,
    el("div", { class: "actions" }, save, el("button", { class: "ghost", onclick: closeModal }, "取消")));
  syncPrivateNote();
}

/* ---- onboarding + the always-visible next step ---------------------------- */

function llmConfigured() {
  const llm = (state.config && state.config.llm) || {};
  return !!llm.key_present && !!llm.enabled;
}

function hasTask() { return (state.engagements || []).length > 0; }

function hasRun() {
  if ((state.runs || []).length > 0) return true;
  const s = (state.graph && state.graph.stats) || {};
  return (s.audit_allowed || 0) > 0;
}

// The first question is "what do I scan", not "do you have an API key": AI is an
// optional upgrade, so a skipped step 1 must not keep nagging (it is marked done
// as soon as the operator gets past it by creating a task).
function onboardingStep() {
  if (!hasTask()) return 1;
  if (!hasRun()) return 2;
  return 0;
}

function renderNextStep() {
  const box = $("#next-step");
  const steps = onboardingStep();
  const pending = pendingIntents().length;
  let text = "";
  let action = null;
  if (steps === 1) {
    text = "第一步:新建一个任务,告诉 youkai 要测哪个网址。";
    action = { label: "新建任务", run: () => openTaskWizard("new") };
  } else if (steps === 2) {
    text = "点「开始扫描」,youkai 会自己跑只读检查,遇到需要你点头的动作会停下。";
    action = { label: "去开始", run: () => setView("runs") };
  } else if (pending > 0) {
    text = `有 ${pending} 个动作在等你批准。`;
    action = { label: "去待办审批", run: () => setView("approvals") };
  } else {
    const s = (state.graph && state.graph.stats) || {};
    text = `这一轮结束了:${s.audit_allowed || 0} 次请求、${s.findings || 0} 条发现。可以去「结果」看看报告。`;
    action = { label: "看结果", run: () => setView("evidence") };
  }
  box.replaceChildren();
  box.appendChild(el("span", {}, text));
  if (action) box.appendChild(el("button", { class: "ghost tiny-btn", onclick: action.run }, action.label));
  box.classList.remove("hidden");
}

function renderOnboarding() {
  const host = $("#onboarding");
  host.replaceChildren();
  const step = onboardingStep();
  // The three-step card is for the first run; once the loop is going, the one-line
  // "next step" bar below is enough.
  if (step === 0) { host.classList.add("hidden"); return; }
  host.classList.remove("hidden");

  const steps = [
    { n: 1, title: "配 AI(可选)", done: llmConfigured() || hasTask(),
      note: "不配也能用:youkai 内置确定性规则会自己跑。配了之后它能规划得更聪明。" },
    { n: 2, title: "新建任务", done: hasTask(), note: "告诉 youkai 要测哪个网址;授权范围自动按安全默认填好。" },
    { n: 3, title: "开始扫描", done: hasRun(), note: "只读检查自己跑;需要你点头的动作会停在「待办审批」。" },
  ];
  host.appendChild(el("div", { class: "steps" }, ...steps.map((s) =>
    el("div", { class: "step" + (s.done ? " done" : "") + (s.n === step ? " current" : "") },
      el("span", { class: "num" }, s.done ? "✓" : String(s.n)),
      el("div", {},
        el("strong", {}, s.title),
        el("div", { class: "muted tiny" }, s.note))))));

  if (step === 1) {
    host.appendChild(el("div", { class: "actions" },
      el("button", { class: "primary", onclick: () => openTaskWizard("new") }, "新建任务(只需一个网址)")));
    host.appendChild(llmQuickCard());
  }
}

function llmQuickCard() {
  const llm = (state.config && state.config.llm) || {};
  const provider = el("select", {}, ...LLM_PRESETS.map((p) => el("option", { value: p.key }, p.label)));
  const baseURL = el("input", { type: "text", placeholder: "接口地址,如 https://api.deepseek.com/v1", value: llm.base_url || "" });
  const model = el("input", { type: "text", placeholder: "模型名,如 deepseek-chat", value: llm.model || "" });
  const key = el("input", { type: "password", placeholder: "API key(加密保存,永不回显)", autocomplete: "off" });
  const status = el("span", { class: "hint" });

  provider.addEventListener("change", () => {
    const p = LLM_PRESETS.find((x) => x.key === provider.value);
    if (p && p.base) { baseURL.value = p.base; model.value = p.model; }
  });

  const save = el("button", { class: "primary" }, "保存并测试连接");
  save.addEventListener("click", async () => {
    banner("");
    status.textContent = "保存中…";
    const body = {
      enabled: true,
      base_url: baseURL.value.trim(),
      model: model.value.trim(),
      temperature: Number(llm.temperature || 0),
      timeout_s: Number(llm.timeout_s || 120),
      max_tokens: Number(llm.max_tokens || 1200),
      updated_by: "wizard",
    };
    if (key.value.trim()) body.key = key.value.trim();
    else if (llm.key_from_env) body.key_from_env = llm.key_from_env;
    try {
      await api("/api/config/llm", { method: "PUT", body: JSON.stringify(body) });
      key.value = "";
      status.textContent = "已保存,测试中…";
      const t = await api("/api/config/llm/test", {
        method: "POST",
        body: JSON.stringify({ base_url: body.base_url, model: body.model, timeout_s: 20 }),
      });
      if (t.ok) {
        status.textContent = `连通正常 · ${t.latency_ms} ms`;
        banner("AI 已配置好 —— 现在可以新建任务了。", "ok");
        state.config = await api("/api/config");
        render();
      } else {
        status.textContent = "连接失败:" + (t.error || "未知错误");
      }
    } catch (e) { status.textContent = "保存失败:" + e.message; }
  });

  return el("div", { class: "card quick-llm" },
    el("h3", {}, "第 1 步 · 配一个模型(可选)"),
    el("p", { class: "hint" }, "key 只用于让 youkai 规划下一步,不会发到目标;加密保存,界面上只显示“已配置”。"),
    el("div", { class: "actions" }, provider,
      el("button", { class: "ghost tiny-btn", onclick: () => setView("config") }, "打开完整设置")),
    el("div", { class: "field" }, el("span", { class: "label" }, "接口地址"), baseURL),
    el("div", { class: "field" }, el("span", { class: "label" }, "模型"), model),
    el("div", { class: "field" }, el("span", { class: "label" }, "API key"), key),
    el("div", { class: "actions" }, save, status));
}
