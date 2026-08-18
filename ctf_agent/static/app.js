(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const icon = (name) => `<svg aria-hidden="true"><use href="#i-${name}"></use></svg>`;
  const escapeHTML = (value) => String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
  const clamp = (value, min = 0, max = 100) => Math.min(max, Math.max(min, Number(value) || 0));
  const number = (value) => new Intl.NumberFormat("th-TH").format(Number(value) || 0);
  const compact = (value) => new Intl.NumberFormat("th-TH", { notation: "compact", maximumFractionDigits: 1 }).format(Number(value) || 0);
  const formatBytes = (bytes) => {
    const value = Number(bytes) || 0;
    if (value < 1024) return `${value} B`;
    if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`;
    return `${(value / 1024 ** 2).toFixed(1)} MB`;
  };
  const formatTime = (value) => {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.valueOf()) ? escapeHTML(value) : date.toLocaleString("th-TH", { dateStyle: "short", timeStyle: "short" });
  };
  const ago = (value) => {
    const date = new Date(value || 0);
    if (Number.isNaN(date.valueOf())) return "เมื่อสักครู่";
    const seconds = Math.max(0, Math.round((Date.now() - date.valueOf()) / 1000));
    if (seconds < 60) return `${seconds} วินาที`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} นาที`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} ชั่วโมง`;
    return `${Math.floor(seconds / 86400)} วัน`;
  };

  const STATUS_LABELS = {
    queued: "รอ Triage", ready: "พร้อมทำ", running: "กำลังทำ", paused: "พักไว้",
    stopped: "หยุดแล้ว", solved: "Solved", rejected: "Rejected", blocked: "Blocked",
  };
  const CATEGORY_GLYPHS = {
    web: "WEB", pwn: "PWN", reverse: "REV", crypto: "CRY", forensics: "FOR",
    osint: "OSI", hardware: "HW", stego: "STG", misc: "MSC",
  };
  const ACTION_LABELS = {
    triage: "เริ่ม Triage", solve: "ทำรอบถัดไป", pause: "พัก Agent",
    resume: "ทำงานต่อ", stop: "หยุดเส้นทาง", verify: "ตรวจ Candidate",
  };

  const KNOWLEDGE = [
    {
      id: "jwt-trust", category: "web", title: "JWT trust boundary",
      summary: "แยกการ decode ออกจากการ verify และตรวจ algorithm/key source ฝั่ง server",
      signal: "role/alg/kid ถูกใช้ก่อน signature ผ่าน", uses: 4,
      checks: ["หา code path ที่ verify signature", "ตรวจ alg confusion และ key lookup", "ยืนยัน authorization ฝั่ง server"],
      command: "rg -n \"jwt|verify|decode|authorization|role\" .",
    },
    {
      id: "png-tail", category: "forensics", title: "PNG trailing data",
      summary: "ข้อมูลหลัง IEND มักเป็น clue ที่ตรวจได้ด้วย deterministic tools",
      signal: "ขนาดไฟล์ใหญ่ผิดปกติหรือ binwalk พบ offset หลังภาพ", uses: 7,
      checks: ["เก็บ SHA-256 ของ original", "หา IEND และวัด trailing bytes", "แยกข้อมูลลง working copy"],
      command: "file image.png && xxd -l 64 image.png",
    },
    {
      id: "binary-first-pass", category: "reverse", title: "Binary first pass",
      summary: "จำกัด context ด้วย format, sections, imports และ strings ที่มีสัญญาณสูง",
      signal: "ได้รับ ELF/PE โดยยังไม่รู้ input-to-check path", uses: 9,
      checks: ["hash และ file type", "mitigations/sections/imports", "targeted strings ก่อน decompile"],
      command: "file chall && sha256sum chall && strings -n 6 chall | head -200",
    },
    {
      id: "nonce-reuse", category: "crypto", title: "Nonce & parameter reuse",
      summary: "normalize parameters แล้วตรวจค่าที่ซ้ำก่อนเลือก attack ที่แพงกว่า",
      signal: "มี ciphertext/signature หลายชุดภายใต้ key เดียวกัน", uses: 5,
      checks: ["normalize encoding/endianness", "ตรวจ nonce/r/e ซ้ำ", "เขียน verifier ที่ย้อน relation เดิม"],
      command: "python3 solve/check_parameters.py",
    },
  ];

  const state = {
    data: null,
    offline: false,
    loading: true,
    selectedChallenge: null,
    selectedFiles: [],
    knowledgeId: KNOWLEDGE[0].id,
    settingsDirty: false,
    confirmCallback: null,
    lastKey: "",
  };
  // Keep one request per identical operation in flight.  This prevents a slow
  // provider from being called again when an operator double-clicks or retries
  // while the first request is still finishing.
  const pendingRequests = new Map();

  function fallbackData() {
    return {
      app: { name: "CTF Agent", version: "0.1.0", mode: "offline", notice: "Local API unavailable; no data is shown." },
      stats: { total: 0, active: 0, queued: 0, paused: 0, solved: 0, token_spent: 0, global_budget: 500000, reserve_tokens: 100000, spendable_remaining: 400000 },
      challenges: [],
      scopes: [],
      settings: { global_token_budget: 500000, per_challenge_token_budget: 50000, reserve_percent: 20, max_iterations: 12, max_large_model_calls: 2, max_tool_output_bytes: 64000, max_context_tokens: 12000, max_model_output_tokens: 1200, provider: "mock", network_enabled: false, tier_models: { tool: "deterministic", luna: "gpt-5.6-luna", terra: "gpt-5.6-terra", sol: "gpt-5.6-sol" }, budget: { global_spent: 0, reserve_tokens: 100000, spendable_remaining: 400000, reserve_protected: true } },
      audit: [],
    };
  }

  function normalizeData(raw) {
    const fallback = fallbackData();
    const data = raw && typeof raw === "object" ? raw : fallback;
    data.app = { ...fallback.app, ...(data.app || {}) };
    data.settings = { ...fallback.settings, ...(data.settings || {}), tier_models: { ...fallback.settings.tier_models, ...(data.settings?.tier_models || {}) }, budget: { ...fallback.settings.budget, ...(data.settings?.budget || {}) } };
    data.challenges = Array.isArray(data.challenges) ? data.challenges.map(normalizeChallenge) : [];
    data.scopes = Array.isArray(data.scopes) ? data.scopes : [];
    data.audit = Array.isArray(data.audit) ? data.audit : [];
    const counts = data.challenges.reduce((acc, challenge) => { acc[challenge.status] = (acc[challenge.status] || 0) + 1; return acc; }, {});
    const spent = data.challenges.reduce((sum, item) => sum + (Number(item.budget.spent) || 0), 0);
    data.stats = {
      total: data.challenges.length, active: counts.running || 0,
      queued: (counts.queued || 0) + (counts.ready || 0), paused: counts.paused || 0,
      solved: counts.solved || 0, token_spent: spent,
      global_budget: data.settings.global_token_budget,
      reserve_tokens: data.settings.budget.reserve_tokens ?? Math.ceil(data.settings.global_token_budget * data.settings.reserve_percent / 100),
      spendable_remaining: Math.max(0, data.settings.global_token_budget - (data.settings.budget.reserve_tokens || 0) - spent),
      ...(data.stats || {}),
    };
    return data;
  }

  function normalizeChallenge(raw) {
    const item = raw && typeof raw === "object" ? raw : {};
    const allocated = Number(item.budget?.allocated) || 50000;
    const spent = Number(item.budget?.spent) || 0;
    return {
      id: String(item.id || "unknown"), title: String(item.title || "Untitled challenge"),
      description: String(item.description || ""), category: String(item.category || "misc"),
      category_confidence: Number(item.category_confidence) || 0, status: String(item.status || "queued"),
      target: String(item.target || ""), scope_authorized: item.scope_authorized ?? null,
      flag_format: String(item.flag_format || "CTF{...}"), candidate_flag: item.candidate_flag || null,
      created_at: item.created_at, updated_at: item.updated_at,
      burn_score: clamp(item.burn_score, 0, 1), injection_signals: Array.isArray(item.injection_signals) ? item.injection_signals : [],
      artifact_count: Number(item.artifact_count ?? item.artifacts?.length) || 0,
      artifacts: Array.isArray(item.artifacts) ? item.artifacts : [],
      budget: { allocated, spent, remaining: Number(item.budget?.remaining ?? Math.max(0, allocated - spent)), percent_used: Number(item.budget?.percent_used ?? (allocated ? spent * 100 / allocated : 0)) },
      routing: { tier: "tool", model: "deterministic", reason: "deterministic_first", ...(item.routing || {}) },
      state: { objective: "", known_facts: [], observations: [], hypotheses: [], discarded_hypotheses: [], completed_actions: [], failed_actions: [], next_candidate_actions: [], verification: { status: "not_started" }, circuit: { iterations: 0, no_progress_count: 0, large_model_calls: 0, tripped: false }, ...(item.state || {}) },
      security: { hostile_prompt: Number(item.burn_score) >= .6, large_model_escalation_blocked: Number(item.burn_score) >= .6, raw_artifacts_sent_to_models: false, ...(item.security || {}) },
      untrusted_data: true,
    };
  }

  async function api(path, options = {}) {
    const method = options.method || "GET";
    const body = options.body ? JSON.stringify(options.body) : "";
    const dedupe = options.dedupe !== false;
    const key = dedupe ? `${method}:${path}:${body}` : "";
    if (key && pendingRequests.has(key)) return pendingRequests.get(key);
    // Solver/provider calls can legitimately take longer than a normal read.
    // The old fixed 15s timeout caused the UI to report a failure while the
    // server was still working, encouraging duplicate expensive retries.
    const timeoutMs = Number(options.timeoutMs) || (method === "POST" ? 45_000 : 12_000);
    const request = (async () => {
      const response = await fetch(path, {
        method,
        headers: options.body ? { "Content-Type": "application/json" } : {},
        body: options.body ? body : undefined,
        signal: AbortSignal.timeout(timeoutMs),
      });
      let payload;
      try { payload = await response.json(); } catch { payload = {}; }
      if (!response.ok) {
        const error = new Error(payload?.error?.message || `HTTP ${response.status}`);
        error.code = payload?.error?.code || "request_failed";
        error.details = payload?.error?.details;
        throw error;
      }
      return payload;
    })();
    if (key) pendingRequests.set(key, request);
    try {
      return await request;
    } finally {
      if (key && pendingRequests.get(key) === request) pendingRequests.delete(key);
    }
  }

  async function loadBootstrap({ quiet = false } = {}) {
    if (!quiet) setLoading(true);
    try {
      const raw = await api("/api/bootstrap");
      state.data = normalizeData(raw);
      state.offline = false;
    } catch (error) {
      state.data = normalizeData(fallbackData());
      state.offline = true;
      if (!quiet) toast("ใช้งานแบบ Offline", "เชื่อมต่อ local API ไม่สำเร็จ จึงไม่แสดงข้อมูลและไม่สามารถบันทึกได้", "warning");
    } finally {
      setLoading(false);
      renderShell();
      route();
    }
  }

  function setLoading(isLoading) {
    state.loading = isLoading;
    const health = $("#systemHealthText");
    if (health) health.textContent = isLoading ? "กำลังเชื่อมต่อ…" : state.offline ? "OFFLINE" : "พร้อมใช้งาน";
  }

  function renderShell() {
    if (!state.data) return;
    const { app, stats, settings, challenges, scopes } = state.data;
    $("#offlineBanner").hidden = !state.offline;
    $("#systemHealthText").textContent = state.offline ? "OFFLINE" : "พร้อมใช้งาน";
    $("#systemHealthDot").className = `system-health__dot${state.offline ? "" : " is-online"}`;
    $("#eventName").textContent = state.offline ? "CTF Agent · Offline" : "CTF Agent · Active Event";
    $("#eventCountdown").textContent = settings.provider === "mock" ? "LOCAL • MOCK" : "LOCAL • LIVE";
    $("#topTokenText").textContent = `${compact(stats.spendable_remaining)} เหลือ`;
    $("#topScopeText").textContent = settings.network_enabled ? `${scopes.filter((s) => s.enabled).length} allowlisted` : "Network locked";
    $("#networkDot").className = `live-dot ${settings.network_enabled ? "is-warning" : "is-safe"}`;
    $("#challengeNavCount").textContent = challenges.length;
    const active = challenges.some((item) => item.status === "running");
    $("#agentPresence").hidden = !active;
    const hostile = challenges.filter((item) => item.security.hostile_prompt).length;
    $("#securityNavWarning").hidden = hostile === 0;
    const notifications = buildNotifications();
    $("#notificationDot").hidden = notifications.length === 0;
    $("#notificationList").innerHTML = notifications.length ? notifications.map((item) => `
      <div class="notification-item"><span class="notification-item__icon">${icon(item.icon)}</span><div><strong>${escapeHTML(item.title)}</strong><p>${escapeHTML(item.body)}</p><time>${escapeHTML(item.time)}</time></div></div>
    `).join("") : `<div class="empty-inline">ไม่มีการแจ้งเตือนที่ต้องจัดการ</div>`;
  }

  function buildNotifications() {
    const list = [];
    state.data.challenges.forEach((challenge) => {
      if (challenge.security.hostile_prompt) list.push({ icon: "shield", title: `AI trap · ${challenge.title}`, body: "ระบบแยกคำสั่งไม่พึงประสงค์และปิด large-model escalation แล้ว", time: ago(challenge.updated_at) });
      if (challenge.state.verification?.status === "needs_evidence") list.push({ icon: "flag", title: `รอหลักฐาน · ${challenge.title}`, body: "รูปแบบ flag ผ่าน แต่ต้องมี independent reproduction evidence", time: ago(challenge.updated_at) });
      if (challenge.state.circuit?.tripped) list.push({ icon: "alert", title: `Circuit breaker · ${challenge.title}`, body: challenge.state.circuit.trip_reason || "solver path ถูกหยุดอัตโนมัติ", time: ago(challenge.updated_at) });
    });
    return list.slice(0, 12);
  }

  function currentRoute() {
    const hash = location.hash.replace(/^#\/?/, "") || "overview";
    const [page, id] = hash.split("/").filter(Boolean);
    return { page: page || "overview", id: id ? decodeURIComponent(id) : null };
  }

  function route() {
    if (!state.data) return;
    const { page, id } = currentRoute();
    const known = ["overview", "challenges", "challenge", "agents", "budget", "knowledge", "security", "settings"];
    const activePage = known.includes(page) ? page : "overview";
    $$(".page").forEach((section) => {
      const visible = section.dataset.page === activePage;
      section.hidden = !visible;
      section.classList.toggle("is-active", visible);
    });
    $$(".nav-item").forEach((item) => item.classList.toggle("is-active", item.dataset.route === (activePage === "challenge" ? "challenges" : activePage)));
    closeMobileMenu();
    if (activePage === "overview") renderOverview();
    if (activePage === "challenges") renderChallenges();
    if (activePage === "challenge") openChallenge(id);
    if (activePage === "agents") renderAgents();
    if (activePage === "budget") renderBudget();
    if (activePage === "knowledge") renderKnowledge();
    if (activePage === "security") renderSecurity();
    if (activePage === "settings") renderSettings();
    $("#mainContent").focus({ preventScroll: true });
    window.scrollTo({ top: 0, behavior: "auto" });
  }

  function metricCard(label, value, meta, iconName, color = "cyan", unit = "") {
    return `<article class="metric-card" style="--metric-color:var(--${color});--metric-glow:var(--${color}-soft)"><div class="metric-card__top"><span>${escapeHTML(label)}</span><span class="metric-card__icon">${icon(iconName)}</span></div><div class="metric-card__value">${escapeHTML(value)}${unit ? `<small>${escapeHTML(unit)}</small>` : ""}</div><p class="metric-card__meta">${escapeHTML(meta)}</p></article>`;
  }

  function statusBadge(status) {
    return `<span class="status-badge status-${escapeHTML(status)}">${escapeHTML(STATUS_LABELS[status] || status)}</span>`;
  }

  function progress(value, color = "cyan") {
    return `<div class="progress-track"><span style="--value:${clamp(value)}%;--bar:var(--${color})"></span></div>`;
  }

  function emptyState(title, body, iconName = "info", action = "") {
    return `<div class="empty-state__content"><span class="empty-state__icon">${icon(iconName)}</span><h3>${escapeHTML(title)}</h3><p>${escapeHTML(body)}</p>${action}</div>`;
  }

  function renderOverview() {
    const { stats, challenges, audit, settings } = state.data;
    const hostile = challenges.filter((item) => item.security.hostile_prompt).length;
    $("#overviewMetrics").innerHTML = [
      metricCard("SOLVED", stats.solved, `${stats.total} challenges ทั้งหมด`, "flag", "green"),
      metricCard("ACTIVE AGENTS", stats.active, stats.active ? "กำลังสร้าง progress" : "ยังไม่มี agent ทำงาน", "bot", "cyan"),
      metricCard("CHALLENGES", stats.total, challenges.length ? "ข้อมูลจาก operator" : "ยังไม่มี challenge", "target", "blue"),
      metricCard("TOKEN SPENT", compact(stats.token_spent), `${compact(stats.spendable_remaining)} ใช้ได้ก่อน reserve`, "coins", "purple"),
      metricCard("SECURITY ALERTS", hostile, hostile ? "Large-model ถูก block ตาม policy" : "ไม่พบ hostile prompt", "shield", hostile ? "red" : "green"),
    ].join("");
    const active = challenges.filter((item) => ["running", "ready", "queued", "paused"].includes(item.status)).slice(0, 5);
    $("#activeChallenges").innerHTML = active.length ? active.map(challengeRow).join("") : `<div class="empty-inline">ยังไม่มี challenge ในคิว</div>`;

    const attention = [];
    challenges.forEach((challenge) => {
      if (challenge.security.hostile_prompt) attention.push({ danger: true, title: challenge.title, body: `AI burn ${(challenge.burn_score * 100).toFixed(0)}% · ${challenge.injection_signals.join(", ")}`, id: challenge.id });
      if (challenge.status === "paused") attention.push({ title: challenge.title, body: "Challenge ถูกพักไว้ รอเลือก alternate path หรือ resume", id: challenge.id });
      if (challenge.state.verification?.status === "needs_evidence") attention.push({ title: challenge.title, body: "Candidate flag ต้องมี reproduction evidence", id: challenge.id });
    });
    $("#attentionCount").textContent = attention.length;
    $("#attentionList").innerHTML = attention.length ? attention.slice(0, 5).map((item) => `<button class="attention-item" type="button" data-challenge-id="${escapeHTML(item.id)}"><span class="attention-item__icon${item.danger ? " is-danger" : ""}">${icon(item.danger ? "shield" : "alert")}</span><span><strong>${escapeHTML(item.title)}</strong><p>${escapeHTML(item.body)}</p></span><time>เปิด →</time></button>`).join("") : `<div class="empty-inline">ไม่มีรายการที่ต้องตัดสินใจ</div>`;
    $("#recentActivity").innerHTML = audit.length ? audit.slice(0, 6).map(auditTimeline).join("") : `<div class="empty-inline">ยังไม่มีกิจกรรม</div>`;
    const budget = settings.global_token_budget;
    const spentPct = budget ? stats.token_spent * 100 / budget : 0;
    const reservePct = settings.reserve_percent || 20;
    $("#budgetForecast").innerHTML = `<div class="budget-gauge"><div class="budget-gauge__numbers"><strong>${compact(stats.spendable_remaining)}</strong><span>spendable tokens</span></div>${progress(spentPct, spentPct > 70 ? "amber" : "cyan")}<div class="budget-legend"><div><span>ใช้แล้ว</span><strong>${compact(stats.token_spent)}</strong></div><div><span>Reserve ${reservePct}%</span><strong>${compact(stats.reserve_tokens)}</strong></div><div><span>Provider</span><strong>${escapeHTML(settings.provider)}</strong></div></div></div>`;
  }

  function challengeRow(challenge) {
    const percent = challenge.budget.percent_used;
    return `<button class="challenge-row" type="button" data-challenge-id="${escapeHTML(challenge.id)}"><span class="challenge-row__name"><span class="category-glyph">${escapeHTML(CATEGORY_GLYPHS[challenge.category] || "CTF")}</span><span class="challenge-row__copy"><strong>${escapeHTML(challenge.title)}</strong><small>${escapeHTML(challenge.id)}</small></span></span>${statusBadge(challenge.status)}<span class="challenge-row__agent">${escapeHTML(challenge.routing.tier === "tool" ? "Deterministic tools" : `${challenge.category} agent · ${challenge.routing.tier}`)}</span><span class="challenge-row__budget">${progress(percent, percent > 80 ? "amber" : "cyan")}<small>${compact(challenge.budget.spent)} / ${compact(challenge.budget.allocated)}</small></span><span>${icon("chevron")}</span></button>`;
  }

  function auditTimeline(item) {
    const warning = ["warning", "error", "critical"].includes(item.severity);
    const details = summarizeDetails(item.details);
    return `<div class="timeline-item"><span class="timeline-item__marker${warning ? " danger-text" : ""}">${icon(warning ? "alert" : "check")}</span><div class="timeline-item__body"><div class="timeline-item__meta"><strong>${escapeHTML(humanEvent(item.event))}</strong><span>${escapeHTML(item.challenge_id || "system")}</span></div><p>${escapeHTML(details)}</p></div><time>${escapeHTML(ago(item.created_at))}</time></div>`;
  }

  function summarizeDetails(details) {
    if (!details || typeof details !== "object") return "บันทึกเหตุการณ์เรียบร้อย";
    const entries = Object.entries(details).filter(([, value]) => ["string", "number", "boolean"].includes(typeof value)).slice(0, 4);
    return entries.length ? entries.map(([key, value]) => `${key}: ${value}`).join(" · ") : "Structured audit event";
  }

  function humanEvent(event) {
    return String(event || "event").replaceAll("_", " ").replace(/\b\w/g, (char) => char.toUpperCase());
  }

  function renderChallenges() {
    const categorySelect = $("#categoryFilter");
    const statusSelect = $("#statusFilter");
    if (categorySelect.options.length === 1) {
      [...new Set(state.data.challenges.map((item) => item.category))].sort().forEach((category) => categorySelect.add(new Option(category, category)));
    }
    if (statusSelect.options.length === 1) {
      Object.entries(STATUS_LABELS).forEach(([status, label]) => statusSelect.add(new Option(label, status)));
    }
    const query = $("#challengeSearch").value.trim().toLowerCase();
    const category = categorySelect.value;
    const status = statusSelect.value;
    const filtered = state.data.challenges.filter((item) => {
      const matchesText = !query || `${item.title} ${item.id} ${item.category}`.toLowerCase().includes(query);
      return matchesText && (category === "all" || item.category === category) && (status === "all" || item.status === status);
    });
    $("#filterResult").textContent = `${filtered.length} รายการ`;
    $("#challengeTableBody").innerHTML = filtered.map((challenge) => `<tr data-challenge-id="${escapeHTML(challenge.id)}" tabindex="0"><td><div class="table-primary"><span class="category-glyph">${escapeHTML(CATEGORY_GLYPHS[challenge.category] || "CTF")}</span><div><strong>${escapeHTML(challenge.title)}</strong><small>${escapeHTML(challenge.id)}</small></div></div></td><td><span class="category-badge">${escapeHTML(challenge.category)}</span></td><td>${statusBadge(challenge.status)}</td><td><span class="table-agent"><span class="agent-dot${challenge.status === "running" ? " is-running" : ""}"></span>${escapeHTML(challenge.routing.tier)}</span></td><td><div class="challenge-row__budget">${progress(challenge.budget.percent_used, challenge.budget.percent_used > 80 ? "amber" : "cyan")}<small>${compact(challenge.budget.spent)} / ${compact(challenge.budget.allocated)}</small></div></td><td class="mono">—</td><td><button class="icon-button small" type="button" data-challenge-id="${escapeHTML(challenge.id)}" aria-label="เปิด ${escapeHTML(challenge.title)}">${icon("chevron")}</button></td></tr>`).join("");
    $("#challengeMobileList").innerHTML = filtered.map((challenge) => `<button class="mobile-challenge-card" type="button" data-challenge-id="${escapeHTML(challenge.id)}"><span class="mobile-challenge-card__top"><span class="mobile-challenge-card__title"><span class="category-glyph">${escapeHTML(CATEGORY_GLYPHS[challenge.category] || "CTF")}</span><span><strong>${escapeHTML(challenge.title)}</strong><small>${escapeHTML(challenge.id)}</small></span></span>${statusBadge(challenge.status)}</span><span class="mobile-challenge-card__bottom">${progress(challenge.budget.percent_used)}<span class="mono">${compact(challenge.budget.spent)}</span></span></button>`).join("");
    $("#challengeEmpty").hidden = filtered.length !== 0;
    $("#challengeEmpty").innerHTML = emptyState("ไม่พบ Challenge", "ลองล้างตัวกรองหรือเพิ่ม challenge ใหม่", "search", `<button class="button button--primary" type="button" data-open-add>${icon("plus")}เพิ่ม Challenge</button>`);
  }

  async function openChallenge(id) {
    if (!id) { location.hash = "#/challenges"; return; }
    let challenge = state.data.challenges.find((item) => item.id === id);
    if (!challenge) {
      $("#challengeCockpit").innerHTML = `<div class="empty-state">${emptyState("ไม่พบ Challenge", "รายการนี้อาจถูกลบหรือ ID ไม่ถูกต้อง", "alert", `<a class="button button--secondary" href="#/challenges">กลับไป Challenges</a>`)}</div>`;
      return;
    }
    state.selectedChallenge = challenge;
    renderCockpit(challenge);
    if (!state.offline) {
      try {
        const payload = await api(`/api/challenges/${encodeURIComponent(id)}`);
        challenge = normalizeChallenge(payload.challenge);
        state.selectedChallenge = challenge;
        const index = state.data.challenges.findIndex((item) => item.id === id);
        if (index >= 0) state.data.challenges[index] = challenge;
        renderCockpit(challenge);
      } catch (error) {
        toast("โหลดรายละเอียดไม่สำเร็จ", error.message, "error");
      }
    }
  }

  function renderCockpit(challenge) {
    const statusIndex = { queued: 0, ready: 1, running: 2, paused: 2, stopped: 2, rejected: 3, solved: 4 }[challenge.status] ?? 0;
    const pipeline = ["Ingest", "Triage", "Analyze", "Verify", "Solved"].map((label, index) => `<span class="pipeline-step ${index < statusIndex ? "is-complete" : index === statusIndex ? "is-current" : ""}"><span class="pipeline-step__dot">${index < statusIndex ? icon("check") : index + 1}</span><span>${label}</span></span>`).join("");
    const canRun = !["paused", "stopped", "solved", "rejected"].includes(challenge.status);
    const mainAction = challenge.status === "queued" ? "triage" : canRun ? "solve" : ["paused", "stopped"].includes(challenge.status) ? "resume" : null;
    const hostile = challenge.security.hostile_prompt;
    const signals = challenge.injection_signals;
    const injection = signals.length ? `<div class="injection-banner${hostile ? " is-critical" : ""}" role="alert"><span class="injection-banner__icon">${icon("shield")}</span><div><strong>${hostile ? "Adversarial instruction ถูกแยกออกแล้ว" : "พบข้อความน่าสงสัยใน Challenge data"}</strong><p>${escapeHTML(signals.join(" · "))} — เนื้อหาถูกจัดเป็นข้อมูลและไม่มีสิทธิ์เปลี่ยน policy</p></div><span class="burn-score"><span>AI Burn</span><strong>${Math.round(challenge.burn_score * 100)}%</strong></span></div>` : "";
    const tabs = ["overview", "evidence", "hypotheses", "artifacts", "runs", "writeup"];
    const labels = { overview: "Overview", evidence: "Evidence", hypotheses: "Hypotheses", artifacts: `Artifacts (${challenge.artifact_count})`, runs: "Runs", writeup: "Write-up" };
    $("#challengeCockpit").innerHTML = `
      <header class="cockpit-header"><div class="cockpit-header__main"><div class="cockpit-title"><span class="category-glyph">${escapeHTML(CATEGORY_GLYPHS[challenge.category] || "CTF")}</span><div class="cockpit-title__copy"><h1 id="cockpitTitle">${escapeHTML(challenge.title)}</h1><div class="cockpit-meta">${statusBadge(challenge.status)}<span class="category-badge">${escapeHTML(challenge.category)} · ${Math.round(challenge.category_confidence * 100)}%</span><span>${icon("clock")} ${escapeHTML(ago(challenge.updated_at))}</span></div></div></div><div class="cockpit-actions">${mainAction ? `<button class="button button--primary" type="button" data-run-action="${mainAction}">${icon(mainAction === "resume" ? "play" : mainAction === "triage" ? "target" : "play")}<span>${escapeHTML(ACTION_LABELS[mainAction])}</span></button>` : ""}${["queued", "ready", "running"].includes(challenge.status) ? `<button class="button button--secondary" type="button" data-run-action="pause">${icon("pause")}พัก</button>` : ""}${!["solved", "stopped"].includes(challenge.status) ? `<button class="button button--danger-subtle" type="button" data-run-action="stop">${icon("stop")}หยุด</button>` : ""}</div></div><div class="pipeline">${pipeline}</div></header>
      ${injection}
      <div class="cockpit-layout"><section class="cockpit-main"><div class="tab-list" role="tablist">${tabs.map((tab, index) => `<button class="tab-button${index === 0 ? " is-active" : ""}" type="button" role="tab" aria-selected="${index === 0}" data-cockpit-tab="${tab}">${escapeHTML(labels[tab])}</button>`).join("")}</div>${tabs.map((tab, index) => `<div class="tab-panel" data-tab-panel="${tab}"${index ? " hidden" : ""}>${cockpitPanel(tab, challenge)}</div>`).join("")}</section><aside class="cockpit-side">${cockpitControls(challenge)}</aside></div>`;
  }

  function cockpitPanel(tab, challenge) {
    const solver = challenge.state;
    const facts = [...(solver.known_facts || []), ...(solver.observations || [])];
    const hypotheses = solver.hypotheses || [];
    if (tab === "overview") return `<div class="overview-layout"><div><section class="section-block"><div class="section-heading"><h3>Objective</h3><span class="model-badge">CTF_CHALLENGE_DATA</span></div><div class="objective-card"><p>${escapeHTML(solver.objective || challenge.description || "ยังไม่มี objective")}</p></div></section><section class="section-block"><div class="section-heading"><h3>Next best action</h3><span class="eyebrow">VALUE / COST</span></div><div class="next-action"><span class="next-action__index">01</span><div><strong>${escapeHTML((solver.next_candidate_actions || [])[0] || "Run deterministic triage")}</strong><p>เริ่มจาก action ที่ให้ข้อมูลใหม่โดยใช้ต้นทุนต่ำที่สุด</p></div></div></section><section class="section-block"><div class="section-heading"><h3>Known facts</h3><span class="count-badge">${facts.length}</span></div>${facts.length ? `<ul class="facts-list">${facts.slice(0, 8).map((fact) => `<li class="fact-item">${icon("check")}<span>${escapeHTML(typeof fact === "string" ? fact : JSON.stringify(fact))}</span></li>`).join("")}</ul>` : `<div class="empty-inline">ยังไม่มี facts — เริ่ม triage ก่อน</div>`}</section></div><aside><section class="section-block"><div class="section-heading"><h3>Leading hypothesis</h3></div>${hypotheses.length ? hypothesisCard(hypotheses.at(-1)) : `<div class="empty-inline">ยังไม่มี hypothesis</div>`}</section><section class="section-block">${verificationCard(challenge)}</section></aside></div>`;
    if (tab === "evidence") return `<div class="section-heading"><h3>Evidence & observations</h3><span class="model-badge">BOUNDED OUTPUT</span></div>${facts.length ? `<ul class="facts-list">${facts.map((fact) => `<li class="fact-item">${icon("eye")}<span>${escapeHTML(typeof fact === "string" ? fact : JSON.stringify(fact))}</span></li>`).join("")}</ul>` : `<div class="empty-state">${emptyState("ยังไม่มี Evidence", "Triage จะบันทึกเฉพาะข้อมูลที่ตรวจสอบย้อนกลับได้", "eye")}</div>`}`;
    if (tab === "hypotheses") return `<div class="section-heading"><h3>Ranked hypotheses</h3><span class="count-badge">${hypotheses.length}</span></div><div class="hypothesis-list">${hypotheses.length ? hypotheses.map(hypothesisCard).join("") : `<div class="empty-state">${emptyState("ยังไม่มี Hypothesis", "ระบบจะสร้างหลัง deterministic triage และจัดลำดับตาม evidence/cost", "target")}</div>`}</div>`;
    if (tab === "artifacts") return challenge.artifacts.length ? `<div class="artifact-grid">${challenge.artifacts.map(artifactCard).join("")}</div>` : `<div class="empty-state">${emptyState("ไม่มี Artifact", "เพิ่มไฟล์โจทย์ผ่าน Challenge ingestion", "file")}</div>`;
    if (tab === "runs") {
      const records = state.data.audit.filter((item) => item.challenge_id === challenge.id);
      const completed = solver.completed_actions || [];
      return `<div class="log-viewer"><div class="log-toolbar"><span>STRUCTURED RUN LOG · raw output collapsed</span><span>${records.length + completed.length} events</span></div><div class="log-content">${escapeHTML(records.map((item) => `[${item.created_at}] ${humanEvent(item.event)} · ${summarizeDetails(item.details)}`).concat(completed.map((item) => `[state] ${typeof item === "string" ? item : JSON.stringify(item)}`)).join("\n") || "No run events yet.")}</div></div>`;
    }
    if (tab === "writeup") return `<div class="writeup"><h3>สถานะการบันทึกผล</h3><p>${challenge.status === "solved" ? "Challenge ผ่านการ verify แล้ว พร้อมกลั่นเป็น solution.md" : "Write-up จะ finalize หลัง candidate มี reproduction evidence และ independent verification"}</p><h3>Decisive evidence</h3><p>${escapeHTML(facts.at(-1) || "ยังไม่มี decisive evidence")}</p><h3>Reproduction</h3><pre>${escapeHTML(challenge.status === "solved" ? "VERIFIED · review solve artifacts and minimal steps" : "PENDING · solve → reproduce → verify")}</pre><h3>Knowledge distillation</h3><p>บันทึกเฉพาะเทคนิคที่ใช้ซ้ำได้ ไม่สร้าง skill ใหม่ต่อหนึ่งโจทย์</p></div>`;
    return "";
  }

  function hypothesisCard(hypothesis) {
    const value = typeof hypothesis === "string" ? { text: hypothesis, confidence: .5, tier: "unknown" } : hypothesis;
    return `<article class="hypothesis-card"><div class="hypothesis-card__top"><strong>${escapeHTML(value.text || value.hypothesis || "Untitled hypothesis")}</strong><span class="confidence">${Math.round((Number(value.confidence) || 0) * 100)}%</span></div><p>Tier ${escapeHTML(value.tier || "unknown")} · ${escapeHTML(value.created_at ? ago(value.created_at) : "state")}</p>${value.evidence ? `<span class="evidence-chip">${escapeHTML(value.evidence)}</span>` : ""}</article>`;
  }

  function artifactCard(artifact) {
    return `<article class="artifact-card"><div class="artifact-card__top"><span class="artifact-card__icon">${icon("file")}</span><div class="artifact-card__name"><strong title="${escapeHTML(artifact.name)}">${escapeHTML(artifact.name)}</strong><span>${escapeHTML(artifact.kind || "artifact")} · ${formatBytes(artifact.size)}</span></div></div><div class="artifact-card__meta"><span title="${escapeHTML(artifact.sha256)}">SHA ${escapeHTML(String(artifact.sha256 || "—").slice(0, 12))}…</span><span>${escapeHTML(artifact.media_type || "unknown")}</span></div></article>`;
  }

  function verificationCard(challenge) {
    const verify = challenge.state.verification || { status: "not_started" };
    if (challenge.candidate_flag) return `<div class="candidate-card"><div class="candidate-card__header"><strong>Candidate · ${escapeHTML(verify.status)}</strong>${statusBadge(verify.status === "verified" ? "solved" : verify.status === "rejected" ? "rejected" : "ready")}</div><div class="flag-value"><code>${escapeHTML(challenge.candidate_flag)}</code><button class="icon-button" type="button" data-copy-flag="${escapeHTML(challenge.candidate_flag)}" aria-label="คัดลอก flag">${icon("copy")}</button></div><p class="control-note">${escapeHTML(verify.reason || "ต้อง replay หลักฐานจาก artifact ก่อน")}</p>${verify.status !== "verified" ? `<button class="button button--green" type="button" data-verify-candidate="${escapeHTML(challenge.candidate_flag)}">${icon("check")}Replay artifact verification</button>` : ""}</div>`;
    return `<form class="verify-form" data-verify-form><label class="field"><span>Candidate flag</span><input name="candidate_flag" placeholder="${escapeHTML(challenge.flag_format)}" autocomplete="off" required></label><label class="toggle-row"><span><strong>Reproduction note</strong><p>บันทึกได้ แต่จะไม่ถือว่า verified หากระบบ replay หลักฐานจาก artifact ไม่ได้</p></span><label class="toggle"><input name="reproduced" type="checkbox"><span></span></label></label><label class="field"><span>Reproduction note</span><input name="evidence" placeholder="เช่น solve.py + artifact hash"></label><button class="button button--green" type="submit">${icon("check")}Verify candidate</button></form>`;
  }

  function cockpitControls(challenge) {
    const route = challenge.routing;
    const circuit = challenge.state.circuit || {};
    return `<section class="control-card"><div class="control-card__header"><h3>Token budget</h3>${icon("coins")}</div><div class="budget-gauge__numbers"><strong>${compact(challenge.budget.remaining)}</strong><span>remaining</span></div>${progress(challenge.budget.percent_used, challenge.budget.percent_used > 80 ? "amber" : "cyan")}<div class="control-row"><span>ใช้แล้ว</span><strong class="mono">${number(challenge.budget.spent)} / ${number(challenge.budget.allocated)}</strong></div></section><section class="control-card"><div class="control-card__header"><h3>Model routing</h3>${icon("bot")}</div><div class="control-row"><span>Tier</span><strong class="${route.tier === "sol" ? "warning-text" : "safe-text"}">${escapeHTML(String(route.tier).toUpperCase())}</strong></div><div class="control-row"><span>Model</span><strong class="mono">${escapeHTML(route.model)}</strong></div><div class="control-note"><strong>เหตุผล:</strong> ${escapeHTML(route.reason)}</div></section><section class="control-card"><div class="control-card__header"><h3>Scope & network</h3>${icon("network")}</div><div class="control-row"><span>Target</span><strong>${escapeHTML(challenge.target || "Offline artifact")}</strong></div><div class="control-row"><span>Allowlist</span><strong class="${challenge.scope_authorized === true ? "safe-text" : challenge.scope_authorized === false ? "danger-text" : ""}">${challenge.scope_authorized === true ? "AUTHORIZED" : challenge.scope_authorized === false ? "DENIED" : "NOT REQUIRED"}</strong></div><div class="control-row"><span>Network</span><strong>${state.data.settings.network_enabled ? "Enabled by operator" : "LOCKED"}</strong></div></section><section class="control-card"><div class="control-card__header"><h3>Circuit breaker</h3>${icon("shield")}</div><div class="control-row"><span>State</span><strong class="${circuit.tripped ? "danger-text" : "safe-text"}">${circuit.tripped ? "TRIPPED" : "HEALTHY"}</strong></div><div class="control-row"><span>Iterations</span><strong>${number(circuit.iterations)} / ${number(state.data.settings.max_iterations)}</strong></div><div class="control-row"><span>No progress</span><strong>${number(circuit.no_progress_count)} / 3</strong></div>${circuit.trip_reason ? `<div class="control-note danger-text">${escapeHTML(circuit.trip_reason)}</div>` : ""}</section>`;
  }

  function renderAgents() {
    const challenges = state.data.challenges;
    const active = challenges.filter((item) => item.status === "running");
    const roster = [
      { name: "Triage", tier: "LUNA · LOW", role: "Deterministic metadata & classification", status: challenges.some((c) => c.status === "queued") ? "running" : "idle" },
      ...["web", "pwn", "reverse", "crypto", "forensics"].map((category) => ({ name: `${category[0].toUpperCase()}${category.slice(1)} Agent`, tier: "TERRA", role: `Bounded ${category} hypothesis`, status: active.some((c) => c.category === category) ? "running" : "idle" })),
      { name: "Verifier", tier: "TERRA · CLEAN CONTEXT", role: "Independent candidate verification", status: challenges.some((c) => c.state.verification?.status === "needs_evidence") ? "waiting" : "idle" },
      { name: "Deep Solver", tier: "SOL · ULTRA", role: "Final escalation only", status: challenges.some((c) => c.routing.tier === "sol" && c.status === "running") ? "running" : "locked" },
    ];
    $("#agentSummary").innerHTML = `<div class="summary-strip"><span>ACTIVE</span><strong>${active.length}</strong></div><div class="summary-strip"><span>AVAILABLE</span><strong>${roster.length}</strong></div><div class="summary-strip"><span>SOL ESCALATIONS</span><strong>${challenges.filter((c) => c.routing.tier === "sol").length}</strong></div><div class="summary-strip"><span>MAX CONCURRENCY</span><strong>4</strong></div>`;
    $("#agentGrid").innerHTML = roster.map((agent) => { const assigned = active.find((c) => agent.name.toLowerCase().startsWith(c.category)); return `<article class="agent-card"><header class="agent-card__header"><div class="agent-identity"><span class="agent-avatar">${icon("bot")}<span class="agent-dot${agent.status === "running" ? " is-running" : ""}"></span></span><div><strong>${escapeHTML(agent.name)}</strong><small>${escapeHTML(agent.tier)}</small></div></div><span class="model-badge">${escapeHTML(agent.status)}</span></header><div class="agent-task"><span>Current task</span><p>${escapeHTML(assigned ? assigned.title : agent.role)}</p></div><div class="agent-stats"><div><span>Token</span><strong>${assigned ? compact(assigned.budget.spent) : "0"}</strong></div><div><span>Runs</span><strong>${assigned ? assigned.state.circuit?.iterations || 0 : 0}</strong></div><div><span>Scope</span><strong>${assigned?.scope_authorized === false ? "DENY" : "SAFE"}</strong></div></div></article>`; }).join("");
  }

  function renderBudget() {
    const { stats, settings, challenges } = state.data;
    const budget = Number(settings.global_token_budget) || 1;
    const spentPct = clamp(stats.token_spent * 100 / budget);
    const reservePct = clamp(settings.reserve_percent);
    const counts = { tool: 0, luna: 0, terra: 0, sol: 0 };
    challenges.forEach((item) => { if (counts[item.routing.tier] !== undefined) counts[item.routing.tier] += 1; });
    const totalRoutes = Math.max(1, Object.values(counts).reduce((sum, value) => sum + value, 0));
    $("#budgetPageContent").innerHTML = `<div class="budget-hero"><section class="budget-total"><div class="budget-total__top"><div><p class="eyebrow">GLOBAL BUDGET</p><div class="budget-total__value">${compact(stats.spendable_remaining)} <small>spendable</small></div></div><span class="model-badge">${escapeHTML(settings.provider.toUpperCase())}</span></div><div class="budget-stack"><span class="budget-stack__spent" style="width:${spentPct}%"></span><span class="budget-stack__reserved" style="width:${reservePct}%"></span></div><div class="budget-legend"><div><span>ใช้จริง</span><strong>${number(stats.token_spent)}</strong></div><div><span>Protected reserve</span><strong>${number(stats.reserve_tokens)}</strong></div><div><span>Global cap</span><strong>${number(budget)}</strong></div></div></section><section class="budget-stat-card"><span class="budget-stat-card__icon">${icon("lock")}</span><div><span>Reserve policy</span><strong>${reservePct}%</strong></div></section><section class="budget-stat-card"><span class="budget-stat-card__icon">${icon("chart")}</span><div><span>Sol calls / challenge</span><strong>≤ ${number(settings.max_large_model_calls)}</strong></div></section></div><div class="budget-page-grid"><section class="panel"><div class="panel__header"><div><p class="eyebrow">ROUTING MIX</p><h2>Cheapest adequate tier</h2></div></div><div class="tier-list">${Object.entries(counts).map(([tier, count]) => `<div class="tier-row"><span class="tier-name"><strong>${escapeHTML(tier.toUpperCase())}</strong><span>${escapeHTML(settings.tier_models[tier] || "—")}</span></span>${progress(count * 100 / totalRoutes, tier === "sol" ? "purple" : tier === "tool" ? "green" : "cyan")}<span class="tier-value">${count} challenges</span></div>`).join("")}</div></section><section class="panel"><div class="panel__header"><div><p class="eyebrow">RECENT DECISIONS</p><h2>เหตุผลการ route</h2></div></div><div class="routing-list">${challenges.slice(0, 6).map((challenge) => `<button class="routing-item" type="button" data-challenge-id="${escapeHTML(challenge.id)}"><span class="routing-item__tier">${escapeHTML(String(challenge.routing.tier).slice(0, 1).toUpperCase())}</span><span><strong>${escapeHTML(challenge.title)}</strong><p>${escapeHTML(challenge.routing.reason)}</p></span><time>${escapeHTML(ago(challenge.updated_at))}</time></button>`).join("")}</div></section></div>`;
  }

  function renderKnowledge() {
    const categorySelect = $("#knowledgeCategory");
    if (categorySelect.options.length === 1) [...new Set(KNOWLEDGE.map((item) => item.category))].sort().forEach((category) => categorySelect.add(new Option(category, category)));
    const query = $("#knowledgeSearch").value.trim().toLowerCase();
    const category = categorySelect.value;
    const filtered = KNOWLEDGE.filter((item) => (!query || `${item.title} ${item.summary} ${item.signal}`.toLowerCase().includes(query)) && (category === "all" || item.category === category));
    if (!filtered.some((item) => item.id === state.knowledgeId)) state.knowledgeId = filtered[0]?.id || null;
    $("#knowledgeList").innerHTML = filtered.length ? filtered.map((item) => `<button class="knowledge-item${item.id === state.knowledgeId ? " is-active" : ""}" type="button" data-knowledge-id="${escapeHTML(item.id)}"><span class="knowledge-item__top"><strong>${escapeHTML(item.title)}</strong><span class="category-badge">${escapeHTML(item.category)}</span></span><p>${escapeHTML(item.summary)}</p><span class="knowledge-item__meta"><span>reused ${item.uses}×</span><span>reviewed playbook</span></span></button>`).join("") : `<div class="empty-inline">ไม่พบ knowledge ที่ค้นหา</div>`;
    const selected = KNOWLEDGE.find((item) => item.id === state.knowledgeId);
    $("#knowledgeDetail").innerHTML = selected ? `<p class="eyebrow">${escapeHTML(selected.category)} PLAYBOOK</p><h2>${escapeHTML(selected.title)}</h2><div class="knowledge-detail__meta"><span class="category-badge">reviewed</span><span class="model-badge">deterministic-first</span></div><section class="knowledge-section"><h3>เมื่อใดควรใช้</h3><p>${escapeHTML(selected.signal)}</p></section><section class="knowledge-section"><h3>Checklist</h3><ul>${selected.checks.map((check) => `<li>${escapeHTML(check)}</li>`).join("")}</ul></section><section class="knowledge-section"><h3>Bounded first pass</h3><div class="command-block">${escapeHTML(selected.command)}</div></section><section class="knowledge-section"><h3>หมายเหตุ</h3><p>${escapeHTML(selected.summary)} ข้อมูลจาก challenge ยังคงเป็น untrusted data และผลลัพธ์ต้องมีหลักฐานก่อนนำไปใช้ต่อ</p></section>` : `<div class="empty-state">${emptyState("เลือก Knowledge", "เลือก playbook ทางซ้ายเพื่อดูรายละเอียด", "book")}</div>`;
  }

  function renderSecurity() {
    const { challenges, scopes, audit, settings } = state.data;
    const hostile = challenges.filter((item) => item.security.hostile_prompt).length;
    const denied = challenges.filter((item) => item.scope_authorized === false).length;
    const blocked = audit.filter((item) => /blocked|denied|injection|error/.test(`${item.event} ${item.severity}`)).length;
    $("#securityPageContent").innerHTML = `<div class="security-summary"><div class="summary-strip"><span>HOSTILE INPUTS</span><strong class="${hostile ? "danger-text" : "safe-text"}">${hostile}</strong></div><div class="summary-strip"><span>ACTIVE SCOPES</span><strong>${scopes.filter((item) => item.enabled).length}</strong></div><div class="summary-strip"><span>BLOCKED EVENTS</span><strong>${blocked}</strong></div><div class="summary-strip"><span>NETWORK</span><strong class="${settings.network_enabled ? "warning-text" : "safe-text"}">${settings.network_enabled ? "ENABLED" : "LOCKED"}</strong></div></div><div class="security-grid"><section class="panel"><div class="panel__header"><div><p class="eyebrow">ALLOWLIST</p><h2>Authorized CTF targets</h2></div><span class="count-badge">${scopes.length}</span></div><form class="form-grid" data-scope-form style="margin-top:0"><label class="field field--span-2"><span>Host, IP หรือ CIDR</span><input name="pattern" required placeholder="challenge.ctf.example"></label><button class="button button--primary field--span-2" type="submit">${icon("plus")}เพิ่ม Scope</button></form><div class="scope-list" style="margin-top:12px">${scopes.length ? scopes.map((scope) => `<div class="scope-item"><span class="scope-item__icon">${icon("network")}</span><span><strong>${escapeHTML(scope.pattern)}</strong><span>${escapeHTML(scope.kind)} · ${scope.enabled ? "enabled" : "disabled"}</span></span><button class="icon-button small" type="button" data-delete-scope="${escapeHTML(scope.id)}" aria-label="ลบ ${escapeHTML(scope.pattern)}">${icon("x")}</button></div>`).join("") : `<div class="empty-inline">ยังไม่มี target ที่ได้รับอนุญาต</div>`}</div><div class="control-note"><strong>Fail closed:</strong> target ที่ไม่อยู่ในรายการนี้จะใช้งาน network ไม่ได้ (${denied} challenge denied)</div></section><section class="panel"><div class="panel__header"><div><p class="eyebrow">IMMUTABLE TRAIL</p><h2>Audit events</h2></div><span class="model-badge">NO SECRETS</span></div><div class="audit-list">${audit.length ? audit.slice(0, 60).map((item) => `<div class="audit-item"><time>${escapeHTML(formatTime(item.created_at))}</time><span class="audit-item__source">${escapeHTML(item.challenge_id || "system")}</span><span class="audit-item__event"><strong>${escapeHTML(humanEvent(item.event))}</strong><p>${escapeHTML(summarizeDetails(item.details))}</p></span><span class="severity-badge severity-${escapeHTML(item.severity)}">${escapeHTML(item.severity)}</span></div>`).join("") : `<div class="empty-inline">ยังไม่มี audit event</div>`}</div></section></div>`;
  }

  function renderSettings() {
    const settings = state.data.settings;
    $("#settingsPageContent").innerHTML = `<div class="settings-grid"><section class="settings-section"><header class="settings-section__header"><span class="settings-section__icon">${icon("coins")}</span><div><h2>Token firewall</h2><p>Global, per-challenge และ protected reserve</p></div></header><div class="field-list"><label class="field"><span>Global token budget</span><input name="global_token_budget" type="number" min="1000" max="100000000" value="${escapeHTML(settings.global_token_budget)}"></label><label class="field"><span>Budget ต่อ Challenge</span><input name="per_challenge_token_budget" type="number" min="100" max="10000000" value="${escapeHTML(settings.per_challenge_token_budget)}"></label><label class="field"><span>Protected reserve (%)</span><input name="reserve_percent" type="number" min="20" max="80" value="${escapeHTML(settings.reserve_percent)}"><small>ระบบจะไม่ใช้ reserve อัตโนมัติ</small></label><label class="field"><span>Max iterations</span><input name="max_iterations" type="number" min="1" max="100" value="${escapeHTML(settings.max_iterations)}"></label><label class="field"><span>Sol calls ต่อ Challenge</span><input name="max_large_model_calls" type="number" min="0" max="20" value="${escapeHTML(settings.max_large_model_calls)}"></label></div></section><section class="settings-section"><header class="settings-section__header"><span class="settings-section__icon">${icon("bot")}</span><div><h2>Provider & model tiers</h2><p>Mock เป็นค่าเริ่มต้นและไม่เรียก API</p></div></header><div class="field-list"><label class="field"><span>Provider</span><select name="provider"><option value="mock"${settings.provider === "mock" ? " selected" : ""}>Mock · local safe default</option><option value="openai"${settings.provider === "openai" ? " selected" : ""}>OpenAI · explicit opt-in</option></select><small>OpenAI ยังต้องตั้ง env gate + API key ที่ server</small></label>${["luna", "terra", "sol"].map((tier) => `<label class="field"><span>${tier.toUpperCase()} model</span><input name="model_${tier}" value="${escapeHTML(settings.tier_models[tier])}" maxlength="100"></label>`).join("")}</div></section><section class="settings-section"><header class="settings-section__header"><span class="settings-section__icon">${icon("shield")}</span><div><h2>Execution policy</h2><p>ค่า default จะ fail closed</p></div></header><div class="toggle-row"><span><strong>Network execution</strong><p>ยังต้องผ่าน allowlist แยกทุก target</p></span><label class="toggle"><input name="network_enabled" type="checkbox"${settings.network_enabled ? " checked" : ""}><span></span></label></div><div class="control-note"><strong>CTF-only:</strong> Challenge content อธิบาย action ได้ แต่ไม่สามารถอนุญาต action, model escalation หรือ secret access ได้</div></section><section class="settings-section"><header class="settings-section__header"><span class="settings-section__icon">${icon("terminal")}</span><div><h2>Output caps</h2><p>จำกัด context และ tool noise</p></div></header><div class="field-list"><label class="field"><span>Tool output bytes</span><input name="max_tool_output_bytes" type="number" min="1024" max="10000000" value="${escapeHTML(settings.max_tool_output_bytes)}"></label><label class="field"><span>Context tokens</span><input name="max_context_tokens" type="number" min="512" max="1000000" value="${escapeHTML(settings.max_context_tokens)}"></label><label class="field"><span>Model output tokens</span><input name="max_model_output_tokens" type="number" min="64" max="32000" value="${escapeHTML(settings.max_model_output_tokens)}"></label></div></section></div>`;
    state.settingsDirty = false;
    updateSettingsDirty();
  }

  function updateSettingsDirty() {
    $("#saveSettingsButton").disabled = !state.settingsDirty || state.offline;
    $("#settingsDirtyText").textContent = state.offline ? "Offline · บันทึกไม่ได้" : state.settingsDirty ? "มีการเปลี่ยนแปลงที่ยังไม่บันทึก" : "ยังไม่มีการเปลี่ยนแปลง";
  }

  async function runChallengeAction(action, body = {}) {
    const challenge = state.selectedChallenge;
    if (!challenge) return;
    if (state.offline) {
      toast("ดำเนินการไม่ได้", "Local API ไม่พร้อมใช้งาน จึงไม่มีการจำลองผลการทำงาน", "warning");
      return;
    }
    setActionBusy(true);
    try {
      const payload = await api(`/api/challenges/${encodeURIComponent(challenge.id)}/actions/${action}`, { method: "POST", body });
      const updated = normalizeChallenge(payload.challenge);
      mergeChallenge(updated);
      recalculateStats();
      state.selectedChallenge = updated;
      renderCockpit(updated);
      renderShell();
      toast(`${ACTION_LABELS[action] || action} สำเร็จ`, action === "verify" ? verificationMessage(updated) : `${updated.title} · ${STATUS_LABELS[updated.status] || updated.status}`, updated.status === "solved" ? "success" : "info");
      // Refresh the shell without holding the action button busy.  The action
      // response already contains the authoritative challenge state.
      void refreshDataInBackground();
    } catch (error) {
      toast("ดำเนินการไม่สำเร็จ", error.message, "error");
    } finally { setActionBusy(false); }
  }

  function verificationMessage(challenge) {
    const verify = challenge.state.verification;
    return verify.status === "verified" ? "VERIFIED · พร้อมให้ operator copy และ submit เอง" : verify.status === "needs_evidence" ? "รูปแบบผ่าน แต่ยังต้องมี reproduction evidence" : verify.reason || verify.status;
  }

  function mergeChallenge(challenge) {
    const index = state.data.challenges.findIndex((item) => item.id === challenge.id);
    if (index >= 0) state.data.challenges[index] = challenge;
    else state.data.challenges.unshift(challenge);
  }

  async function refreshDataInBackground() {
    try {
      const fresh = normalizeData(await api("/api/bootstrap"));
      state.data = fresh;
      const selected = fresh.challenges.find((item) => item.id === state.selectedChallenge?.id);
      if (selected) state.selectedChallenge = selected;
      renderShell();
    } catch { /* retain the successful local response */ }
  }

  function setActionBusy(busy) {
    $$('[data-run-action], [data-verify-form] button, [data-verify-candidate]').forEach((button) => { button.disabled = busy; });
  }

  async function createChallenge(event) {
    event.preventDefault();
    if (state.offline) {
      toast("นำเข้าไม่ได้", "Local API ไม่พร้อมใช้งาน จึงไม่มีการสร้าง challenge จำลอง", "warning");
      return;
    }
    const form = event.currentTarget;
    const button = $("#createChallengeButton");
    button.disabled = true;
    button.innerHTML = `<span class="spinner"></span>กำลังนำเข้า…`;
    try {
      const data = new FormData(form);
      const files = await Promise.all(state.selectedFiles.map(fileToPayload));
      const body = {
        title: String(data.get("name") || "").trim(), description: String(data.get("description") || ""),
        target: String(data.get("target") || "").trim(), budget: Number(data.get("token_budget")) || state.data.settings.per_challenge_token_budget,
        files,
      };
      const category = String(data.get("category") || "auto");
      if (category !== "auto") body.category = category;
      const created = await api("/api/challenges", { method: "POST", body });
      let challenge = normalizeChallenge(created.challenge);
      const triaged = await api(`/api/challenges/${encodeURIComponent(challenge.id)}/actions/triage`, { method: "POST", body: {} });
      challenge = normalizeChallenge(triaged.challenge);
      mergeChallenge(challenge);
      recalculateStats();
      state.selectedChallenge = challenge;
      state.selectedFiles = [];
      form.reset();
      renderSelectedFiles();
      $("#addChallengeDialog").close();
      toast("นำเข้า Challenge แล้ว", "Deterministic triage เสร็จและยังไม่มีการเรียกโมเดลใหญ่", "success");
      location.hash = `#/challenge/${encodeURIComponent(challenge.id)}`;
      void refreshDataInBackground();
    } catch (error) {
      toast("นำเข้าไม่สำเร็จ", error.message, "error");
    } finally {
      button.disabled = false;
      button.innerHTML = `${icon("upload")}เพิ่มและเริ่ม Triage`;
    }
  }

  function fileToPayload(file) {
    if (file.size > 4 * 1024 * 1024) return Promise.reject(new Error(`${file.name} ใหญ่เกิน 4 MB`));
    return file.arrayBuffer().then((buffer) => {
      const bytes = new Uint8Array(buffer);
      let binary = "";
      const chunk = 0x8000;
      for (let index = 0; index < bytes.length; index += chunk) binary += String.fromCharCode(...bytes.subarray(index, index + chunk));
      return { name: file.name, media_type: file.type || "application/octet-stream", content_base64: btoa(binary) };
    });
  }

  function selectFiles(files) {
    const selected = [...files].slice(0, 16);
    const total = selected.reduce((sum, file) => sum + file.size, 0);
    if (selected.some((file) => file.size > 4 * 1024 * 1024) || total > 12 * 1024 * 1024) {
      toast("ไฟล์เกินขีดจำกัด", "สูงสุด 4 MB ต่อไฟล์ และรวมไม่เกิน 12 MB", "error");
      return;
    }
    state.selectedFiles = selected;
    renderSelectedFiles();
    if (!$("#challengeNameInput").value && selected[0]) $("#challengeNameInput").value = selected[0].name.replace(/\.[^.]+$/, "");
  }

  function renderSelectedFiles() {
    $("#selectedFiles").innerHTML = state.selectedFiles.map((file) => `<span class="file-chip" title="${escapeHTML(file.name)}">${escapeHTML(file.name)} · ${formatBytes(file.size)}</span>`).join("");
  }

  function recalculateStats() {
    const challenges = state.data.challenges;
    const counts = challenges.reduce((result, item) => { result[item.status] = (result[item.status] || 0) + 1; return result; }, {});
    state.data.stats = {
      ...state.data.stats,
      total: challenges.length,
      active: counts.running || 0,
      queued: (counts.queued || 0) + (counts.ready || 0),
      paused: counts.paused || 0,
      solved: counts.solved || 0,
      token_spent: challenges.reduce((sum, item) => sum + item.budget.spent, 0),
    };
    state.data.stats.spendable_remaining = Math.max(0, state.data.stats.global_budget - state.data.stats.reserve_tokens - state.data.stats.token_spent);
  }

  function toast(title, message, type = "info") {
    const node = document.createElement("div");
    node.className = `toast toast--${type}`;
    node.innerHTML = `<span class="toast__icon">${icon(type === "success" ? "check" : type === "error" || type === "warning" ? "alert" : "info")}</span><div><strong>${escapeHTML(title)}</strong><p>${escapeHTML(message)}</p></div><button class="icon-button" type="button" data-dismiss-toast aria-label="ปิด">${icon("x")}</button>`;
    $("#toastRegion").append(node);
    window.setTimeout(() => node.remove(), 6500);
  }

  function askConfirm({ title, message, details = "", label = "ยืนยัน", danger = true, callback }) {
    $("#confirmTitle").textContent = title;
    $("#confirmMessage").textContent = message;
    $("#confirmDetails").innerHTML = details ? `<div class="confirm-detail-box">${escapeHTML(details)}</div>` : "";
    const button = $("#confirmActionButton");
    button.textContent = label;
    button.className = `button ${danger ? "button--danger" : "button--primary"}`;
    state.confirmCallback = callback;
    $("#confirmDialog").showModal();
  }

  async function pauseAll() {
    if (state.offline) {
      toast("ดำเนินการไม่ได้", "Local API ไม่พร้อมใช้งาน จึงไม่มีการเปลี่ยนสถานะจำลอง", "warning");
      return;
    }
    const targets = state.data.challenges.filter((item) => ["queued", "ready", "running"].includes(item.status));
    if (!targets.length) { toast("ไม่มี Agent ที่ต้องหยุด", "ทุก challenge อยู่ในสถานะปลอดภัยแล้ว", "info"); return; }
    try {
      await Promise.all(targets.map((item) => api(`/api/challenges/${encodeURIComponent(item.id)}/actions/pause`, { method: "POST", body: {} })));
      state.data = normalizeData(await api("/api/bootstrap"));
      recalculateStats();
      renderShell();
      route();
      toast("หยุด Agent แล้ว", `${targets.length} challenge ถูก pause`, "success");
    } catch (error) { toast("หยุด Agent ไม่ครบ", error.message, "error"); }
  }

  async function addScope(form) {
    const pattern = String(new FormData(form).get("pattern") || "").trim();
    if (!pattern) return;
    if (state.offline) {
      toast("เพิ่ม Scope ไม่ได้", "Local API ไม่พร้อมใช้งาน จึงไม่มีการเพิ่ม scope จำลอง", "warning");
      return;
    }
    try {
      const payload = await api("/api/scopes", { method: "POST", body: { pattern } });
      state.data.scopes.push(payload.scope);
      form.reset();
      renderShell();
      renderSecurity();
      toast("เพิ่ม Scope แล้ว", `${pattern} พร้อมใช้เมื่อ operator เปิด network`, "success");
    } catch (error) { toast("เพิ่ม Scope ไม่สำเร็จ", error.message, "error"); }
  }

  async function deleteScope(id) {
    if (state.offline) {
      toast("ลบ Scope ไม่ได้", "Local API ไม่พร้อมใช้งาน", "warning");
      return;
    }
    try {
      await api(`/api/scopes/${encodeURIComponent(id)}`, { method: "DELETE" });
      state.data.scopes = state.data.scopes.filter((item) => String(item.id) !== String(id));
      renderShell();
      renderSecurity();
      toast("ลบ Scope แล้ว", "คำขอ network ไปยัง target นี้จะถูกปฏิเสธ", "success");
    } catch (error) { toast("ลบ Scope ไม่สำเร็จ", error.message, "error"); }
  }

  async function saveSettings(event) {
    event.preventDefault();
    if (state.offline) return;
    const data = new FormData(event.currentTarget);
    const intKeys = ["global_token_budget", "per_challenge_token_budget", "reserve_percent", "max_iterations", "max_large_model_calls", "max_tool_output_bytes", "max_context_tokens", "max_model_output_tokens"];
    const body = {};
    intKeys.forEach((key) => { body[key] = Number(data.get(key)); });
    body.provider = String(data.get("provider"));
    body.network_enabled = data.get("network_enabled") === "on";
    body.tier_models = { luna: String(data.get("model_luna")), terra: String(data.get("model_terra")), sol: String(data.get("model_sol")) };
    const save = async () => {
      const button = $("#saveSettingsButton");
      button.disabled = true;
      try {
        const payload = await api("/api/settings", { method: "PATCH", body });
        state.data.settings = { ...state.data.settings, ...payload.settings };
        state.settingsDirty = false;
        updateSettingsDirty();
        renderShell();
        toast("บันทึก Policy แล้ว", "การ route ครั้งถัดไปจะใช้ค่าใหม่", "success");
      } catch (error) { toast("บันทึกไม่สำเร็จ", error.message, "error"); state.settingsDirty = true; updateSettingsDirty(); }
    };
    if (body.network_enabled && !state.data.settings.network_enabled) askConfirm({ title: "เปิด Network execution?", message: "แม้เปิด network ทุก target ยังต้องอยู่ใน allowlist และควรใช้เฉพาะ CTF VM", details: `${state.data.scopes.length} scope currently allowlisted`, label: "เปิด Network", callback: save });
    else if (body.provider === "openai" && state.data.settings.provider !== "openai") askConfirm({ title: "เปลี่ยนเป็น OpenAI provider?", message: "การตั้งค่านี้อาจใช้ token จริงเมื่อ env gate และ API key พร้อม", details: "CTF_AGENT_ENABLE_OPENAI=1 ต้องถูกตั้งอย่างชัดเจนที่ server", label: "เปลี่ยน Provider", danger: false, callback: save });
    else await save();
  }

  function exportAudit() {
    const content = JSON.stringify({ exported_at: new Date().toISOString(), notice: "Secrets must not be stored in audit output.", audit: state.data.audit }, null, 2);
    const url = URL.createObjectURL(new Blob([content], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `ctf-agent-audit-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
    toast("Export audit แล้ว", "บันทึกเป็น JSON ในโฟลเดอร์ดาวน์โหลด", "success");
  }

  function openMobileMenu() {
    $("#sidebar").classList.add("is-open");
    $("#drawerScrim").classList.add("is-open");
    $("#menuButton").setAttribute("aria-expanded", "true");
  }

  function closeMobileMenu() {
    $("#sidebar").classList.remove("is-open");
    $("#drawerScrim").classList.remove("is-open");
    $("#menuButton").setAttribute("aria-expanded", "false");
  }

  function toggleNotifications(force) {
    const drawer = $("#notificationDrawer");
    const open = typeof force === "boolean" ? force : !drawer.classList.contains("is-open");
    drawer.classList.toggle("is-open", open);
    drawer.setAttribute("aria-hidden", String(!open));
  }

  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("ctf-agent-theme", theme); } catch { /* storage unavailable */ }
  }

  function bindEvents() {
    window.addEventListener("hashchange", route);
    $("#menuButton").addEventListener("click", openMobileMenu);
    $("#drawerScrim").addEventListener("click", closeMobileMenu);
    $("#themeButton").addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));
    $("#notificationButton").addEventListener("click", () => toggleNotifications());
    $("#closeNotifications").addEventListener("click", () => toggleNotifications(false));
    $("#shortcutButton").addEventListener("click", () => $("#shortcutsDialog").showModal());
    $("#budgetQuickButton").addEventListener("click", () => { location.hash = "#/budget"; });
    $("#scopeQuickButton").addEventListener("click", () => { location.hash = "#/security"; });
    $("#challengeBackButton").addEventListener("click", () => { location.hash = "#/challenges"; });
    $("#retryApiButton").addEventListener("click", () => loadBootstrap());
    $("#refreshOverviewButton").addEventListener("click", () => loadBootstrap());
    $("#activityRefreshButton").addEventListener("click", () => loadBootstrap({ quiet: true }));
    $("#refreshAgentsButton").addEventListener("click", () => loadBootstrap({ quiet: true }));
    $("#pauseAllButton").addEventListener("click", () => askConfirm({ title: "หยุด Agent ทุกตัว?", message: "Challenge ที่ queued, ready และ running จะถูก pause โดยไม่ลบ state", details: "ใช้เป็น emergency stop เมื่อเห็น loop, scope หรือ budget ผิดปกติ", label: "หยุดทุก Agent", callback: pauseAll }));
    $("#exportAuditButton").addEventListener("click", exportAudit);
    $("#addChallengeForm").addEventListener("submit", createChallenge);
    $("#settingsForm").addEventListener("submit", saveSettings);
    $("#settingsForm").addEventListener("input", () => { state.settingsDirty = true; updateSettingsDirty(); });
    $("#challengeSearch").addEventListener("input", renderChallenges);
    $("#categoryFilter").addEventListener("change", renderChallenges);
    $("#statusFilter").addEventListener("change", renderChallenges);
    $("#resetFiltersButton").addEventListener("click", () => { $("#challengeSearch").value = ""; $("#categoryFilter").value = "all"; $("#statusFilter").value = "all"; renderChallenges(); });
    $("#knowledgeSearch").addEventListener("input", renderKnowledge);
    $("#knowledgeCategory").addEventListener("change", renderKnowledge);
    $("#challengeFiles").addEventListener("change", (event) => selectFiles(event.target.files));
    $("#challengeDropZone").addEventListener("click", () => $("#challengeFiles").click());
    $("#challengeDropZone").addEventListener("keydown", (event) => { if (["Enter", " "].includes(event.key)) { event.preventDefault(); $("#challengeFiles").click(); } });
    ["dragenter", "dragover"].forEach((name) => $("#challengeDropZone").addEventListener(name, (event) => { event.preventDefault(); event.currentTarget.classList.add("is-dragover"); }));
    ["dragleave", "drop"].forEach((name) => $("#challengeDropZone").addEventListener(name, (event) => { event.preventDefault(); event.currentTarget.classList.remove("is-dragover"); if (name === "drop") selectFiles(event.dataTransfer.files); }));
    $("#confirmActionButton").addEventListener("click", async () => {
      const callback = state.confirmCallback;
      state.confirmCallback = null;
      $("#confirmDialog").close();
      if (callback) await callback();
    });
    document.addEventListener("click", handleClick);
    document.addEventListener("submit", handleDynamicSubmit);
    document.addEventListener("keydown", handleKeyboard);
  }

  function handleClick(event) {
    const close = event.target.closest("[data-close-dialog]");
    if (close) { close.closest("dialog")?.close(); return; }
    const add = event.target.closest("[data-open-add]");
    if (add) { $("#addChallengeDialog").showModal(); return; }
    const dismiss = event.target.closest("[data-dismiss-toast]");
    if (dismiss) { dismiss.closest(".toast")?.remove(); return; }
    const challengeLink = event.target.closest("[data-challenge-id]");
    if (challengeLink) { location.hash = `#/challenge/${encodeURIComponent(challengeLink.dataset.challengeId)}`; return; }
    const action = event.target.closest("[data-run-action]");
    if (action) {
      const name = action.dataset.runAction;
      if (name === "stop") askConfirm({ title: "หยุด Solver path?", message: "State และ evidence จะถูกเก็บ แต่ agent จะไม่ทำรอบถัดไป", details: state.selectedChallenge?.title || "", label: "หยุดเส้นทาง", callback: () => runChallengeAction(name) });
      else runChallengeAction(name);
      return;
    }
    const tab = event.target.closest("[data-cockpit-tab]");
    if (tab) {
      $$('[data-cockpit-tab]').forEach((button) => { const active = button === tab; button.classList.toggle("is-active", active); button.setAttribute("aria-selected", String(active)); });
      $$('[data-tab-panel]').forEach((panel) => { panel.hidden = panel.dataset.tabPanel !== tab.dataset.cockpitTab; });
      return;
    }
    const copy = event.target.closest("[data-copy-flag]");
    if (copy) navigator.clipboard.writeText(copy.dataset.copyFlag).then(() => toast("คัดลอก Candidate แล้ว", "ตรวจสอบ platform และ submit ด้วยตัวเอง", "success"), () => toast("คัดลอกไม่สำเร็จ", "เลือกข้อความแล้วคัดลอกด้วยตนเอง", "error"));
    const verifyCandidate = event.target.closest("[data-verify-candidate]");
    if (verifyCandidate) { runChallengeAction("verify", { candidate_flag: verifyCandidate.dataset.verifyCandidate }); return; }
    const knowledge = event.target.closest("[data-knowledge-id]");
    if (knowledge) { state.knowledgeId = knowledge.dataset.knowledgeId; renderKnowledge(); return; }
    const removeScope = event.target.closest("[data-delete-scope]");
    if (removeScope) {
      const scope = state.data.scopes.find((item) => String(item.id) === removeScope.dataset.deleteScope);
      askConfirm({ title: "ลบ Target scope?", message: "Network access ไปยัง target นี้จะถูกปฏิเสธทันที", details: scope?.pattern || "", label: "ลบ Scope", callback: () => deleteScope(removeScope.dataset.deleteScope) });
    }
  }

  function handleDynamicSubmit(event) {
    const verify = event.target.closest("[data-verify-form]");
    if (verify) {
      event.preventDefault();
      const data = new FormData(verify);
      const evidence = String(data.get("evidence") || "").trim();
      runChallengeAction("verify", { candidate_flag: String(data.get("candidate_flag") || "").trim(), reproduced: data.get("reproduced") === "on", evidence: evidence ? [evidence] : [] });
      return;
    }
    const scope = event.target.closest("[data-scope-form]");
    if (scope) { event.preventDefault(); addScope(scope); }
  }

  function handleKeyboard(event) {
    const typing = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName);
    if (event.key === "Escape") { toggleNotifications(false); $$("dialog[open]").forEach((dialog) => dialog.close()); closeMobileMenu(); return; }
    if (typing) return;
    if (event.key === "/") { event.preventDefault(); location.hash = "#/challenges"; window.setTimeout(() => $("#challengeSearch").focus(), 80); return; }
    const key = event.key.toLowerCase();
    if (state.lastKey === "g") {
      const routes = { o: "overview", c: "challenges", b: "budget", s: "security" };
      if (routes[key]) { event.preventDefault(); location.hash = `#/${routes[key]}`; }
      state.lastKey = "";
      return;
    }
    if (key === "g") { state.lastKey = "g"; window.setTimeout(() => { state.lastKey = ""; }, 900); return; }
    if (key === "?" || (event.shiftKey && key === "/")) { event.preventDefault(); $("#shortcutsDialog").showModal(); return; }
    if (key === "p" && currentRoute().page === "challenge" && ["queued", "ready", "running"].includes(state.selectedChallenge?.status)) runChallengeAction("pause");
    if (key === "v" && currentRoute().page === "challenge") $('[data-verify-form] input[name="candidate_flag"]')?.focus();
  }

  async function init() {
    try { setTheme(localStorage.getItem("ctf-agent-theme") || "dark"); } catch { setTheme("dark"); }
    bindEvents();
    await loadBootstrap();
  }

  init();
})();
