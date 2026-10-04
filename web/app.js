"use strict";

/* CyberSentinel X — Agent Workspace client.
 * Architecture notes:
 *  - The frontend is an untrusted client. Every mission state, evidence record,
 *    finding, and activity item rendered here originates from server responses.
 *  - No session or token material is stored in the browser: owner sessions live
 *    in HttpOnly cookies scoped to /api/public.
 *  - All transport goes through api() so a future desktop shell can supply a
 *    different transport origin via window.CYBERSENTINEL_API_BASE.
 *  - The composer input is natural language only. There are no predefined
 *    command buttons and no client-side text-to-command mappings.
 */

const API_BASE = String(window.CYBERSENTINEL_API_BASE || "").replace(/\/+$/, "");

const state = {
  csrfToken: "",
  sessionPromise: null,
  ownerAuthenticated: false,
  ownerUsername: "",
  conversationId: "",
  missions: [],
  selectedMissionId: "",
  selectedMission: null,
  missionViews: { timeline: [], evidence: [], artifacts: [], logs: [], effects: [] },
  filePath: ".",
  activeView: "overview",
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);

function apiUrl(path) {
  return API_BASE + path;
}

/* ── API layer ──────────────────────────────────────────── */

async function ensureSession() {
  if (state.csrfToken) return state.csrfToken;
  if (!state.sessionPromise) {
    state.sessionPromise = fetch(apiUrl("/api/public/session"), {
      method: "POST",
      credentials: "include",
      headers: { Accept: "application/json" },
    })
      .then(async (response) => {
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
        state.csrfToken = data.session?.csrf_token || "";
        if (!state.csrfToken) throw new Error("public session was not issued");
        return state.csrfToken;
      })
      .catch((error) => {
        state.sessionPromise = null;
        throw error;
      });
  }
  return state.sessionPromise;
}

async function api(path, options = {}) {
  const isPublicApi = path.startsWith("/api/public/");
  const needsCsrf = isPublicApi && path !== "/api/public/session";
  const makeHeaders = async () => {
    const headers = { Accept: "application/json", ...(options.headers || {}) };
    if (options.body) headers["Content-Type"] = "application/json";
    if (needsCsrf) headers["X-CSRF-Token"] = await ensureSession();
    return headers;
  };
  let response = await fetch(apiUrl(path), { ...options, credentials: "include", headers: await makeHeaders() });
  const method = String(options.method || "GET").toUpperCase();
  if (isPublicApi && method === "GET" && path !== "/api/public/session" && response.status === 401) {
    state.csrfToken = "";
    state.sessionPromise = null;
    response = await fetch(apiUrl(path), { ...options, credentials: "include", headers: await makeHeaders() });
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

function errorText(error) {
  const messages = {
    invalid_credentials: "بيانات الدخول غير صحيحة.",
    owner_authorization_required: "يلزم تسجيل الدخول بحساب المالك.",
    "owner authentication required": "انتهت الجلسة؛ سجّل الدخول مرة أخرى.",
    public_boundary_disabled: "واجهة المتصفح معطلة في إعدادات الخدمة.",
    unknown_mission: "المهمة غير موجودة أو غير متاحة لهذا الحساب.",
    not_found: "المورد غير موجود أو محجوب بسياسة مساحة العمل.",
  };
  return messages[error.message] || `تعذر إكمال الطلب: ${error.message || "خطأ غير معروف"}`;
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;",
  }[character]));
}

function showJson(value) {
  const pre = document.createElement("pre");
  pre.className = "result json-view";
  pre.textContent = JSON.stringify(value, null, 2);
  return pre;
}

function setNotice(message, kind = "") {
  const notice = $("#workspaceNotice");
  if (!notice) return;
  notice.textContent = message;
  notice.className = `notice${kind ? ` ${kind}` : ""}`;
}

/* ── Connection / runtime state ──────────────────────────── */

async function status() {
  try {
    const [health, auth] = await Promise.all([
      api("/api/public/health"),
      api("/api/public/auth/session"),
    ]);
    updateAuthUI(auth);
    const runtime = $("#runtimeState");
    runtime.classList.remove("offline");
    runtime.textContent = health.ok === true
      ? `● ${health.service || "الخدمة"} · ${health.version || "الإصدار غير متاح"}`
      : "? حالة الخدمة غير مؤكدة";
  } catch (error) {
    const runtime = $("#runtimeState");
    runtime.classList.add("offline");
    runtime.textContent = "○ تعذر الوصول إلى الخدمة";
    $("#authState").textContent = "تعذر التحقق من الجلسة";
  }
}

function updateAuthUI(data) {
  const nextAuthenticated = data.authenticated === true;
  const nextUsername = nextAuthenticated ? String(data.username || "") : "";
  if (state.ownerAuthenticated && (!nextAuthenticated || (state.ownerUsername && nextUsername && state.ownerUsername !== nextUsername))) {
    resetWorkspaceState();
  }
  state.ownerAuthenticated = nextAuthenticated;
  state.ownerUsername = nextUsername;
  const label = state.ownerAuthenticated
    ? `مسجل الدخول: ${state.ownerUsername || "المالك"}`
    : "غير مسجل الدخول";
  $("#authState").textContent = label;
  $("#authStateSide").textContent = label;
  $("#loginForm").classList.toggle("hidden", state.ownerAuthenticated);
  $("#logoutButton").classList.toggle("hidden", !state.ownerAuthenticated);
  $("#authMessage").textContent = "";
}

function resetWorkspaceState() {
  state.conversationId = "";
  state.selectedMissionId = "";
  state.selectedMission = null;
  state.missionViews = { timeline: [], evidence: [], artifacts: [], logs: [], effects: [] };
  state.missions = [];
  $("#messages").replaceChildren();
  $("#missionHeader").classList.add("hidden");
  $("#missionTools").classList.add("hidden");
  $("#missionList").innerHTML = '<p class="muted">سجّل الدخول لعرض المهام.</p>';
  renderMissionView("overview");
  $("#missionTabs .tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.view === "overview"));
  state.activeView = "overview";
  updateSideLinks();
}

/* ── Activity panel (real server events only) ───────────── */

function activityPlaceholder(text) {
  const list = $("#activityList");
  list.replaceChildren();
  const empty = document.createElement("p");
  empty.className = "muted";
  empty.textContent = text;
  list.appendChild(empty);
}

function pushActivity(text, kind = "") {
  const list = $("#activityList");
  const placeholder = list.querySelector("p.muted");
  if (placeholder) placeholder.remove();
  const row = document.createElement("div");
  row.className = `activity-item${kind ? ` ${kind}` : ""}`;
  const time = document.createElement("time");
  time.textContent = new Date().toISOString().slice(11, 19);
  const body = document.createElement("span");
  body.textContent = text;
  row.append(time, body);
  list.appendChild(row);
  list.scrollTop = list.scrollHeight;
}

function renderActivityFromTimeline(timeline) {
  const entries = Array.isArray(timeline) ? timeline : [];
  if (!entries.length) {
    activityPlaceholder("لا توجد أحداث نشاط من الخادم لهذه المهمة.");
    return;
  }
  const list = $("#activityList");
  list.replaceChildren();
  entries.slice(-80).forEach((entry) => {
    const row = document.createElement("div");
    row.className = "activity-item";
    const time = document.createElement("time");
    time.textContent = String(entry?.timestamp || entry?.time || "");
    const body = document.createElement("span");
    const label = entry?.event || entry?.type || entry?.step_id || entry?.action || "حدث";
    const detail = entry?.detail || entry?.status ? ` · ${entry.detail || entry.status}` : "";
    body.textContent = `${label}${detail}`;
    row.append(time, body);
    list.appendChild(row);
  });
}

/* ── Composer: natural language only ─────────────────────── */

function bubble(who, text, kind = "") {
  const element = document.createElement("div");
  element.className = `msg ${who}${kind ? ` ${kind}` : ""}`;
  const wrap = document.createElement("div");
  const whoLabel = document.createElement("div");
  whoLabel.className = "who";
  whoLabel.textContent = who === "user" ? "أنت" : "CyberSentinel X";
  const body = document.createElement("div");
  body.className = "bubble";
  body.textContent = text;
  wrap.append(whoLabel, body);
  element.appendChild(wrap);
  $("#messages").appendChild(element);
  $("#messages").scrollTop = 1e9;
  return element;
}

async function send(text) {
  text = text.trim();
  if (!text) return;
  showView("conversation");
  if (!state.ownerAuthenticated) {
    bubble("bot", "سجّل الدخول بحساب المالك لاستخدام المحادثة.");
    return;
  }
  bubble("user", text);
  $("#composerInput").value = "";
  const button = $("#composerForm button[type=submit]");
  button.disabled = true;
  const loading = bubble("bot", "جارٍ إرسال الطلب إلى الخادم...", "loading");
  try {
    const data = await api("/api/public/chat", {
      method: "POST",
      body: JSON.stringify({ text, conversation_id: state.conversationId || undefined }),
    });
    loading.remove();
    state.conversationId = String(data.conversation_id || "");
    (Array.isArray(data.activity) ? data.activity : []).forEach((item) => {
      pushActivity(
        `أداة: ${item.name || item.type || "غير محددة"} · الحالة: ${item.status || "غير متاحة"}${item.request_id ? ` · ${item.request_id}` : ""}`,
        item.status === "failed" ? "error" : "ok",
      );
    });
    const answer = typeof data.answer === "string" && data.answer.trim()
      ? data.answer
      : `لم يقدّم الخادم إجابة نصية. حالة المهمة: ${data.mission?.status || "غير متاحة"}.`;
    bubble("bot", answer);
  } catch (error) {
    loading.remove();
    bubble("bot", errorText(error));
    if (error.message === "owner_authorization_required") updateAuthUI({ authenticated: false });
  } finally {
    button.disabled = false;
  }
  await refreshAfterInteraction();
}

/* ── Missions ────────────────────────────────────────────── */

function missionStatusLabel(mission) {
  const status = mission?.status || "unknown";
  const queue = mission?.queue?.state;
  return `${status}${queue ? ` · queue: ${queue}` : ""}`;
}

function renderMissions() {
  const target = $("#missionList");
  target.replaceChildren();
  if (!state.ownerAuthenticated) {
    target.innerHTML = '<p class="muted">سجّل الدخول لعرض المهام.</p>';
    return;
  }
  if (!state.missions.length) {
    target.innerHTML = '<p class="muted">لا توجد مهام محفوظة لهذا الحساب.</p>';
    return;
  }
  const groups = [
    { title: "نشطة", match: (m) => !["GOAL_COMPLETED", "CANCELLED", "FAILED_RETRY_EXHAUSTED", "SCOPE_BLOCKED", "SAFETY_BLOCKED"].includes(m.status) },
    { title: "مكتملة (بتحقق الخادم)", match: (m) => m.status === "GOAL_COMPLETED" },
    { title: "منتهية لأسباب أخرى", match: () => true },
  ];
  const seen = new Set();
  groups.forEach((group) => {
    const items = state.missions.filter((m) => !seen.has(m.mission_id) && group.match(m));
    items.forEach((m) => seen.add(m.mission_id));
    if (!items.length) return;
    const heading = document.createElement("div");
    heading.className = "mission-group";
    heading.textContent = group.title;
    target.appendChild(heading);
    items.forEach((mission) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `mission-item${mission.mission_id === state.selectedMissionId ? " selected" : ""}`;
      button.innerHTML = `<strong>${esc(mission.objective || mission.owner_request || mission.mission_id)}</strong><span>${esc(missionStatusLabel(mission))}</span><small>${esc(mission.request_id || "Request ID غير متاح")}</small>`;
      button.addEventListener("click", () => selectMission(mission.mission_id));
      target.appendChild(button);
    });
  });
}

async function loadMissions() {
  if (!state.ownerAuthenticated) {
    setNotice("سجّل الدخول بحساب المالك لعرض المهام.", "warn");
    renderMissions();
    return;
  }
  try {
    const data = await api("/api/public/missions?limit=100");
    state.missions = Array.isArray(data.missions) ? data.missions : [];
    renderMissions();
    if (state.selectedMissionId && state.missions.some((item) => item.mission_id === state.selectedMissionId)) {
      await loadMission(state.selectedMissionId);
    } else if (state.missions.length && !state.selectedMissionId) {
      await selectMission(state.missions[0].mission_id);
    }
  } catch (error) {
    $("#missionList").textContent = errorText(error);
    setNotice(errorText(error), "error");
  }
}

function missionEndpoint(action) {
  return `/api/public/missions/${encodeURIComponent(state.selectedMissionId)}/${encodeURIComponent(action)}`;
}

async function selectMission(missionId) {
  state.selectedMissionId = String(missionId || "");
  state.filePath = ".";
  renderMissions();
  await loadMission(state.selectedMissionId);
}

async function loadMission(missionId = state.selectedMissionId) {
  if (!missionId || !state.ownerAuthenticated) return;
  state.selectedMissionId = String(missionId);
  try {
    const [statusData, timelineData, evidenceData, artifactsData, logsData, effectsData] = await Promise.all([
      api(missionEndpoint("status")),
      api(missionEndpoint("timeline")),
      api(missionEndpoint("evidence")),
      api(missionEndpoint("artifacts")),
      api(missionEndpoint("logs")),
      api(missionEndpoint("effects")).catch((error) => ({ effects: [], error: error.message })),
    ]);
    state.selectedMission = statusData.status || null;
    state.missionViews = {
      timeline: timelineData.timeline ?? [],
      evidence: evidenceData.evidence ?? [],
      artifacts: artifactsData.artifacts ?? [],
      logs: logsData.logs ?? [],
      effects: effectsData.effects ?? [],
      effectsError: effectsData.error || "",
    };
    renderMissionHeader();
    renderActivityFromTimeline(state.missionViews.timeline);
    renderMissionView(state.activeView === "conversation" ? "conversation" : state.activeView);
  } catch (error) {
    state.selectedMission = null;
    $("#missionDetail").textContent = errorText(error);
    setNotice(errorText(error), "error");
  }
}

function renderMissionHeader() {
  const selectedMission = state.selectedMission;
  if (!selectedMission) return;
  $("#missionHeader").classList.remove("hidden");
  $("#missionTools").classList.remove("hidden");
  const verification = selectedMission.verification_state || {};
  const complete = selectedMission.status === "GOAL_COMPLETED" && verification.verified === true && !!selectedMission.completion_proof;
  const phase = selectedMission.status === "PAUSED" ? "متوقفة مؤقتًا" : (selectedMission.status || "غير متاح");
  $("#missionDetail").innerHTML = `<div class="detail-title"><div><h1>${esc(selectedMission.objective || selectedMission.owner_request || "مهمة")}</h1><small>Mission ID: ${esc(selectedMission.mission_id || state.selectedMissionId)} · Request ID: ${esc(selectedMission.request_id || "غير متاح")}</small></div><span class="status-chip">${esc(phase)}</span></div>
    <div class="kv"><div class="card">حالة التنفيذ<b class="small-value">${esc(selectedMission.queue?.state || "لا توجد حالة طابور")}</b></div><div class="card">التحقق<b class="small-value">${verification.verified === true ? "متحقق حسب الخادم" : "غير متحقق"}</b></div><div class="card">الاكتمال<b class="small-value">${complete ? "مكتمل بدليل موقّع" : "غير مثبت"}</b></div><div class="card">إعادة المحاولة<b class="small-value">${esc(selectedMission.retry_count ?? "غير متاح")}</b></div></div>`;
  updateSideLinks();
}

function renderMissionView(view) {
  const target = $("#missionView");
  target.replaceChildren();
  const mission = state.selectedMission;
  if (view === "conversation") return;
  if (!mission) {
    const empty = document.createElement("div");
    empty.className = "welcome";
    empty.innerHTML = '<div class="hero">CS</div><h1>CyberSentinel X</h1><p>اختر مهمة من القائمة الجانبية أو صف هدفًا جديدًا في حقل الإدخال أسفل الشاشة.</p>';
    target.appendChild(empty);
    return;
  }
  if (view === "overview") {
    const step = mission.plan?.steps?.[mission.current_step] || null;
    const verification = mission.verification_state || {};
    const missing = Array.isArray(verification.missing_criteria) ? verification.missing_criteria : [];
    const authSnapshot = mission.authorization_snapshot?.authorization_hash ? "لقطة التفويض موجودة" : "لا توجد لقطة تفويض";
    const block = document.createElement("div");
    block.className = "result";
    block.textContent = `تعليمات المالك\n${mission.owner_instruction || mission.owner_request || "غير متاحة"}\n\nالمرحلة / العملية الحالية\n${step ? `${step.step_id || ""} · ${step.action || "عملية غير محددة"}` : "لا توجد خطوة حالية في الخطة"}\n\nالتفويض\n${authSnapshot}\n\nسبب الإخفاق / التوقف\n${mission.error || "لا يوجد سبب مسجل"}\n\nنقاط الاستعادة\n${JSON.stringify(mission.checkpoint || {}, null, 2)}\n\nمعايير التحقق المفقودة\n${missing.length ? missing.join(", ") : (verification.verified === true ? "لا توجد معايير مفقودة وفق الخادم" : "غير محددة")}`;
    target.appendChild(block);
    if (mission.status === "RECOVERY_REQUIRED" && ["in_flight", "in_flight_parallel"].includes(mission.checkpoint?.status)) {
      const notice = document.createElement("div");
      notice.className = "notice warn";
      notice.textContent = "توقّف التنفيذ عند أثر خارجي غير محسوم. تحقّق من النظام الخارجي وأدخل مرجعًا يمكن مراجعته؛ قرار المالك لا يُستخدم كدليل اكتمال.";
      const pending = (state.missionViews.effects || []).filter((effect) =>
        effect && effect.requires_reconciliation === true
        && ["DISPATCHED", "AMBIGUOUS", "UNKNOWN", "RECOVERY_REQUIRED"].includes(String(effect.state))
      );
      target.appendChild(notice);
      if (!pending.length) {
        const unavailable = document.createElement("p");
        unavailable.className = "muted";
        unavailable.textContent = state.missionViews.effectsError
          ? "تعذر تحميل سجل الأثر؛ لا يمكن إرسال قرار مصالحة بلا أثر محدد."
          : "لا يوجد أثر محدد يتطلب مصالحة في سجل الخادم؛ لن يُنشأ قرار عام.";
        target.appendChild(unavailable);
        return;
      }
      const controls = document.createElement("div");
      controls.className = "result reconciliation-controls";
      const label = document.createElement("label");
      label.textContent = "الأثر المطلوب مراجعته";
      const select = document.createElement("select");
      select.id = "reconciliationEffect";
      pending.forEach((effect) => {
        const option = document.createElement("option");
        option.value = String(effect.effect_id || "");
        option.textContent = `${effect.effect_id || "أثر بلا معرّف"} · ${effect.operation || "عملية"} · ${effect.state || "حالة غير معروفة"}`;
        select.appendChild(option);
      });
      label.appendChild(select);
      const evidenceLabel = document.createElement("label");
      evidenceLabel.textContent = "مرجع الدليل الخارجي (حتى 512 محرفًا)";
      const evidenceInput = document.createElement("input");
      evidenceInput.id = "reconciliationEvidenceReference";
      evidenceInput.type = "text";
      evidenceInput.maxLength = 512;
      evidenceInput.autocomplete = "off";
      evidenceInput.placeholder = "معرّف سجل/إيصال/تذكرة من النظام الخارجي";
      evidenceLabel.appendChild(evidenceInput);
      const actions = document.createElement("div");
      actions.className = "action-row";
      const applied = document.createElement("button");
      applied.type = "button";
      applied.textContent = "تأكيد المالك: الأثر نُفّذ";
      applied.addEventListener("click", () => reconcileMission(
        select.value, "OWNER_CONFIRM_APPLIED", evidenceInput.value.trim(),
      ));
      const noEffect = document.createElement("button");
      noEffect.type = "button";
      noEffect.className = "danger";
      noEffect.textContent = "تأكيد المالك: لا أثر خارجي";
      noEffect.addEventListener("click", () => reconcileMission(
        select.value, "OWNER_CONFIRM_NO_EFFECT", evidenceInput.value.trim(),
      ));
      actions.append(applied, noEffect);
      controls.append(label, evidenceLabel, actions);
      target.appendChild(controls);
    }
    return;
  }
  const values = view === "evidence" ? state.missionViews.evidence
    : view === "timeline" ? state.missionViews.timeline
      : view === "artifacts" ? state.missionViews.artifacts
        : view === "logs" ? state.missionViews.logs : null;
  if (values !== null) {
    if (!Array.isArray(values) || !values.length) {
      const empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = view === "evidence" ? "لا توجد سجلات أدلة من الخادم لهذه المهمة." : "لا توجد سجلات من الخادم لهذه اللوحة.";
      target.appendChild(empty);
      return;
    }
    values.forEach((item) => {
      const card = document.createElement("article");
      card.className = "result record-card";
      card.appendChild(showJson(item));
      target.appendChild(card);
    });
    return;
  }
  if (view === "findings") {
    const records = state.missionViews.evidence.filter((item) => item && typeof item === "object" && item.system_evidence);
    const heading = document.createElement("p");
    heading.className = "muted";
    heading.textContent = "هذه اللوحة تعرض سجلات معايير موقّعة من الخادم فقط؛ لا ينشئ النظام سجل نتائج مستقلًا ولا يعامل نص النموذج كنتيجة أمنية مؤكدة.";
    target.appendChild(heading);
    if (!records.length) {
      const empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = "لا توجد نتائج مرتبطة بدليل نظام موقّع لهذه المهمة.";
      target.appendChild(empty);
      return;
    }
    records.forEach((record) => {
      const card = document.createElement("article");
      card.className = "result record-card";
      const title = document.createElement("b");
      title.textContent = `معيار: ${record.criterion_id || "غير محدد"} · المصدر: ${record.source || "غير محدد"}`;
      const link = document.createElement("p");
      link.className = "muted";
      link.textContent = `معرّف الإجراء: ${record.provenance?.action_id || "غير متاح"} · مرجع التحقق: ${record.provenance?.verification || "غير متاح"}`;
      card.append(title, link, showJson(record));
      target.appendChild(card);
    });
    return;
  }
  if (view === "files") {
    renderFiles();
    return;
  }
  if (view === "git") {
    renderGit();
  }
}

async function runMissionAction(action) {
  if (!state.selectedMissionId || !state.ownerAuthenticated) return;
  if (action === "cancel" && !window.confirm("هل تريد إلغاء هذه المهمة؟ لن تُعرض بوصفها مكتملة.")) return;
  setNotice("جارٍ إرسال الإجراء إلى الخادم...", "warn");
  try {
    await api(missionEndpoint(action), { method: "POST", body: "{}" });
    setNotice("استجاب الخادم؛ جارٍ إعادة تحميل الحالة المحفوظة.", "ok");
    await loadMissions();
    await loadMission(state.selectedMissionId);
  } catch (error) {
    setNotice(errorText(error), "error");
  }
}

async function reconcileMission(effectId, outcome, evidenceReference) {
  if (!effectId || !evidenceReference || evidenceReference.length > 512) {
    setNotice("اختر أثرًا محددًا وأدخل مرجع دليل خارجي لا يتجاوز 512 محرفًا.", "warn");
    return;
  }
  const applied = outcome === "OWNER_CONFIRM_APPLIED";
  const warning = applied
    ? "هل راجعت المرجع الخارجي وتؤكد أن هذا الأثر المحدد نُفّذ؟ سيُسجل قرار المالك فقط، ولن يُعامل كدليل اكتمال."
    : "هل راجعت المرجع الخارجي وتؤكد أن هذا الأثر المحدد لم يُنفّذ؟ قد يسمح ذلك بإعادة المحاولة، والاختيار الخاطئ قد يكرر أثرًا خارجيًا.";
  if (!window.confirm(warning)) return;
  setNotice("جارٍ حفظ قرار الاستعادة وإعادة التحقق من تفويض المالك...", "warn");
  try {
    const path = `/api/public/missions/${encodeURIComponent(state.selectedMissionId)}/effects/${encodeURIComponent(effectId)}/reconcile`;
    await api(path, { method: "POST", body: JSON.stringify({ outcome, evidence_reference: evidenceReference }) });
    setNotice("سُجل قرار الاستعادة من الخادم؛ لا يعني ذلك اكتمال المهمة.", "ok");
    await loadMissions();
    await loadMission(state.selectedMissionId);
  } catch (error) {
    setNotice(errorText(error), "error");
  }
}

/* ── Workspace files / git (read-only, mission-scoped) ───── */

function renderFiles() {
  const target = $("#missionView");
  target.innerHTML = `<div class="file-controls"><label for="filePath">مسار نسبي داخل المستودع</label><input id="filePath" value="${esc(state.filePath)}" maxlength="1024"><button id="listFiles" type="button">استعراض</button></div><div id="fileEntries" class="file-list"></div><pre id="fileContent" class="result file-content">اختر ملفًا للقراءة فقط.</pre>`;
  $("#listFiles").onclick = () => browseFiles($("#filePath").value.trim() || ".");
  browseFiles(state.filePath);
}

async function browseFiles(path) {
  state.filePath = path;
  const entries = $("#fileEntries");
  if (!entries) return;
  entries.textContent = "جارٍ تحميل قائمة الملفات المسموح بها...";
  $("#fileContent").textContent = "اختر ملفًا للقراءة فقط.";
  try {
    const query = new URLSearchParams({ path });
    const data = await api(`/api/public/workspace/${encodeURIComponent(state.selectedMissionId)}/files?${query}`);
    entries.replaceChildren();
    const up = document.createElement("button");
    up.type = "button";
    up.textContent = ".. / المستوى الأعلى";
    up.addEventListener("click", () => {
      const parent = path === "." ? "." : path.split("/").slice(0, -1).join("/") || ".";
      browseFiles(parent);
    });
    entries.appendChild(up);
    (Array.isArray(data.files) ? data.files : []).forEach((item) => {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = `${item.directory ? "مجلد" : "ملف"} · ${item.name}${item.directory ? "/" : ""}`;
      button.addEventListener("click", () => {
        const next = path === "." ? item.name : `${path.replace(/\/$/, "")}/${item.name}`;
        if (item.directory) browseFiles(next);
        else readFile(next);
      });
      entries.appendChild(button);
    });
    $("#filePath").value = path;
  } catch (error) {
    entries.textContent = errorText(error);
  }
}

async function readFile(path) {
  $("#fileContent").textContent = "جارٍ قراءة الملف من الخادم...";
  try {
    const query = new URLSearchParams({ path });
    const data = await api(`/api/public/workspace/${encodeURIComponent(state.selectedMissionId)}/file?${query}`);
    $("#fileContent").textContent = data.content ?? "لم يُرجع الخادم محتوى نصيًا.";
  } catch (error) {
    $("#fileContent").textContent = errorText(error);
  }
}

function renderGit() {
  const target = $("#missionView");
  const labels = { status: "الحالة", branch: "الفرع", log: "السجل", diff: "الفروق", repository: "المستودع", head: "HEAD", remote: "المصدر البعيد" };
  target.innerHTML = `<div class="action-row git-actions">${Object.keys(labels).map((name) => `<button type="button" data-git="${name}">${labels[name]}</button>`).join("")}</div><pre id="gitOutput" class="result file-content">اختر عملية Git للقراءة فقط.</pre><p class="muted">هذه الواجهة للقراءة فقط؛ لا تنفّذ commit أو push.</p>`;
  $$("[data-git]").forEach((button) => button.addEventListener("click", () => readGit(button.dataset.git)));
}

async function readGit(operation) {
  $("#gitOutput").textContent = "جارٍ قراءة Git من مساحة العمل المرتبطة بالمهمة...";
  try {
    const query = new URLSearchParams({ operation });
    const data = await api(`/api/public/workspace/${encodeURIComponent(state.selectedMissionId)}/git?${query}`);
    $("#gitOutput").textContent = data.output || data.error_output || `Exit code: ${data.exit_code}`;
  } catch (error) {
    $("#gitOutput").textContent = errorText(error);
  }
}

/* ── Truthful info panels (no invented backend) ──────────── */

function showInfoPanel(nodes) {
  showView("info");
  const panel = $("#infoPanel");
  panel.replaceChildren();
  (Array.isArray(nodes) ? nodes : [nodes]).forEach((node) => panel.appendChild(node));
}

function toolsPanel() {
  const box = document.createElement("div");
  box.className = "result";
  box.textContent = "لا تعرض واجهة المالك العامة قائمة أدوات. تُقيد الأدوات الفعلية بميزانية المالك المصرّح بها على الخادم عند إنشاء المهمة، ولا يمكن للواجهة أن تضيف أداة أو تفويضًا.";
  const note = document.createElement("p");
  note.className = "muted";
  note.textContent = "عقد مفقود: لا يوجد مسار عام لعرض الأدوات المتاحة لحساب المالك. عُرضت حالة عدم توفر صادقة بدل بيانات ملفقة.";
  showInfoPanel([box, note]);
}

async function settingsPanel() {
  const box = document.createElement("div");
  box.className = "result";
  let healthText = "تعذر قراءة حالة الخدمة.";
  try {
    const health = await api("/api/public/health");
    healthText = `استجابة HTTP: ${health.ok === true ? "OK" : "غير مؤكدة"}\nالخدمة: ${health.service || "غير متاح"}\nالإصدار: ${health.version || "غير متاح"}`;
  } catch (error) {
    healthText = `تعذر قراءة حالة الخدمة: ${errorText(error)}`;
  }
  let providerText = "حالة المزودين متاحة بعد تسجيل دخول المالك.";
  try {
    const data = await api("/api/public/providers");
    const providers = Array.isArray(data.providers) ? data.providers : [];
    providerText = providers.length
      ? providers.map((provider) => {
        const caps = provider.capabilities || {};
        const enabled = Object.entries(caps).filter(([, active]) => active === true).map(([name]) => name);
        return `${provider.name || "مزود"}: ${provider.configured ? "مهيأ" : "غير مهيأ"} · إخفاقات مرصودة: ${provider.failure_count || 0} · قدرات: ${enabled.length ? enabled.join(", ") : "غير معلنة"}`;
      }).join("\n")
      : "لا يوجد مزود نموذج مهيأ.";
  } catch (error) {
    providerText = `تعذر قراءة حالة المزود: ${errorText(error)}`;
  }
  box.textContent = `حالة الخدمة\n${healthText}\n\nحالة مزود النموذج\n${providerText}\n\nحالة الإعداد تعكس التهيئة فقط ولا تثبت أن المزود متصل أو أن طلبًا نجح. لا تُعرض عناوين المزودين أو المفاتيح أو نصوص الأخطاء.\n\nلا توجد إعدادات تُدار من المتصفح. الإعدادات والتشريعات تُدار من الخادم وفق تعليمات المالك، ولا يملك العميل أي سلطة تعديل.`;
  showInfoPanel(box);
}

/* ── View switching ──────────────────────────────────────── */

function showView(view) {
  state.activeView = view;
  $$("#missionTabs .tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.view === view));
  const isConversation = view === "conversation";
  const isInfo = view === "info";
  $("#missionView").classList.toggle("hidden", isConversation || isInfo);
  $("#transcript").classList.toggle("hidden", !isConversation);
  $("#infoPanel").classList.toggle("hidden", !isInfo);
  $("#missionTabs").classList.toggle("hidden", isInfo);
  if (!isConversation && !isInfo) renderMissionView(view);
}

async function refreshAfterInteraction() {
  await status();
  if (state.ownerAuthenticated) await loadMissions();
}

async function refreshConnection() {
  await status();
  if (state.ownerAuthenticated && state.selectedMissionId && !document.hidden) {
    await loadMission(state.selectedMissionId);
  }
}

/* ── Wiring ──────────────────────────────────────────────── */

$("#composerForm").onsubmit = (event) => { event.preventDefault(); send($("#composerInput").value); };
$("#composerInput").onkeydown = (event) => {
  if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); send(event.target.value); }
};
$("#reload").onclick = refreshConnection;
$("#sidebarToggle").onclick = () => $("#sidebar").classList.toggle("open");
$("#activityToggle").onclick = () => {
  const panel = $("#activityPanel");
  const open = panel.classList.toggle("open");
  $("#activityToggle").setAttribute("aria-expanded", String(open));
};
$("#toolsLink").onclick = toolsPanel;
$("#settingsLink").onclick = settingsPanel;
$("#refreshMissions")?.addEventListener("click", loadMissions);

$("#missionForm").onsubmit = async (event) => {
  event.preventDefault();
  if (!state.ownerAuthenticated) { setNotice("سجّل الدخول بحساب المالك أولاً.", "warn"); return; }
  const button = $("#createMission");
  button.disabled = true;
  setNotice("جارٍ إنشاء المهمة وتسجيلها في طابور التنفيذ...", "warn");
  try {
    const data = await api("/api/public/missions", {
      method: "POST",
      body: JSON.stringify({ objective: $("#missionObjective").value.trim() }),
    });
    $("#missionObjective").value = "";
    state.selectedMissionId = data.mission_id || data.mission?.mission_id || "";
    setNotice(`أُنشئت المهمة من الخادم. الحالة الحالية: ${data.mission?.status || "غير متاحة"} · ${data.queue?.state || "حالة الطابور غير متاحة"}`, "ok");
    pushActivity(`أُنشئت مهمة: ${state.selectedMissionId || "معرّف غير متاح"}`, "ok");
    await loadMissions();
    if (state.selectedMissionId) { await loadMission(state.selectedMissionId); showView("overview"); }
  } catch (error) {
    setNotice(errorText(error), "error");
  } finally {
    button.disabled = false;
  }
};

$$("[data-mission-action]").forEach((button) => button.addEventListener("click", () => runMissionAction(button.dataset.missionAction)));

$$("#missionTabs .tab").forEach((button) => button.addEventListener("click", () => showView(button.dataset.view)));

$$("[data-side-view]").forEach((button) => button.addEventListener("click", () => {
  if (!state.selectedMissionId) return;
  showView(button.dataset.sideView);
}));

$("#loginForm").onsubmit = async (event) => {
  event.preventDefault();
  const button = $("#loginButton");
  button.disabled = true;
  $("#authMessage").textContent = "جارٍ التحقق...";
  try {
    const data = await api("/api/public/auth/login", {
      method: "POST",
      body: JSON.stringify({ username: $("#loginUsername").value.trim(), password: $("#loginPassword").value }),
    });
    $("#loginPassword").value = "";
    updateAuthUI(data);
    await status();
    if (state.ownerAuthenticated) await loadMissions();
  } catch (error) {
    $("#authMessage").textContent = errorText(error);
  } finally {
    button.disabled = false;
  }
};

$("#logoutButton").onclick = async () => {
  try {
    await api("/api/public/auth/logout", { method: "POST", body: "{}" });
    updateAuthUI({ authenticated: false });
    resetWorkspaceState();
    renderMissions();
    activityPlaceholder("لا يوجد نشاط حالي من الخادم.");
    await status();
  } catch (error) {
    $("#authMessage").textContent = errorText(error);
  }
};

/* Reconnect behavior: the browser may lose connectivity; mission state is
 * always re-fetched from the server rather than kept only in memory. */
window.addEventListener("online", refreshConnection);
document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshConnection(); });
setInterval(refreshConnection, 15000);

/* Keep sidebar project shortcuts enabled only when a mission is selected. */
function updateSideLinks() {
  $("[data-side-view]").forEach((button) => { button.disabled = !state.selectedMissionId; });
}

status().then(() => { if (state.ownerAuthenticated) loadMissions(); });
