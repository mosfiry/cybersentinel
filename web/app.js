"use strict";

/* CyberSentinel X — Agent Workspace client.
 * Architecture notes:
 *  - The frontend is an untrusted client. Every mission state, evidence record,
 *    finding, and activity item rendered here originates from server responses.
 *  - No credential or session-token material is stored in the browser: owner
 *    sessions live in HttpOnly cookies and only a non-secret conversation pointer
 *    is retained for server-authorized transcript restoration.
 *  - All transport goes through api() so a future desktop shell can supply a
 *    different transport origin via window.CYBERSENTINEL_API_BASE.
 *  - The composer input is natural language only. There are no predefined
 *    command buttons and no client-side text-to-command mappings.
 */

const API_BASE = String(window.CYBERSENTINEL_API_BASE || "").replace(/\/+$/, "");
const CONVERSATION_STORAGE_KEY = "cybersentinel.lastConversation";
const MAX_SCOPE_ASSETS = 32;
const MAX_SCOPE_TARGETS = 32;
const MAX_SCOPE_PORTS = 20;
const MAX_SCOPE_PATHS = 32;
const MAX_SCOPE_METHODS = 9;
const MAX_SCOPE_EXPIRATION_DAYS = 365;
const SCOPE_IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SCOPE_HTTP_METHODS = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"];

const state = {
  csrfToken: "",
  sessionPromise: null,
  ownerAuthenticated: false,
  ownerUsername: "",
  conversationId: "",
  conversationTasks: [],
  connectionAvailable: false,
  modelPreferences: [],
  selectedModelPreference: "balanced",
  continueSelectedMission: false,
  missions: [],
  scopeSnapshotSubmitting: false,
  selectedMissionId: "",
  selectedMission: null,
  missionViews: { timeline: [], evidence: [], artifacts: [], logs: [] },
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
  if (isPublicApi && path !== "/api/public/session" && response.status === 401) {
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
    invalid_model_id: "خيار النموذج غير صالح؛ حدّث الصفحة وحاول مجددًا.",
    invalid_model_preference: "تفضيل التنسيق غير صالح؛ اختر أحد الخيارات المعروضة.",
    model_id_and_preference_are_mutually_exclusive: "اختر إما ملفًا محددًا عبر API أو تفضيل التنسيق، لا كليهما.",
    selected_model_unavailable: "النموذج المختار لم يعد مُعدًا على الخادم.",
    selected_model_configuration_changed: "تغيّر إعداد النموذج المحفوظ؛ اختر نموذجًا جديدًا أو استخدم التلقائي.",
    mission_not_resumable: "المهمة المكتملة لا يمكن استئنافها؛ أرسل طلبًا جديدًا لبدء مهمة جديدة.",
    mission_busy: "المهمة قيد التنفيذ حاليًا؛ انتظر انتهاء العامل قبل إرسال متابعة أخرى.",
    only_model_id_is_accepted: "يُقبل معرّف النموذج من القائمة فقط.",
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
    const wasAvailable = state.connectionAvailable;
    const [health, auth] = await Promise.all([
      api("/api/public/health"),
      api("/api/public/auth/session"),
    ]);
    updateAuthUI(auth);
    loadModelPreferences();
    state.connectionAvailable = health.ok === true;
    const runtime = $("#runtimeState");
    runtime.classList.remove("offline");
    runtime.textContent = health.ok === true
      ? `● ${health.service || "الخدمة"} · ${health.version || "الإصدار غير متاح"}`
      : "? حالة الخدمة غير مؤكدة";
    return { connected: state.connectionAvailable, reconnected: state.connectionAvailable && !wasAvailable };
  } catch (error) {
    state.connectionAvailable = false;
    const runtime = $("#runtimeState");
    runtime.classList.add("offline");
    runtime.textContent = "○ تعذر الوصول إلى الخدمة";
    $("#authState").textContent = "تعذر التحقق من الجلسة";
    return { connected: false, reconnected: false };
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
  updateScopeSnapshotAuthUI();
}

const MODEL_PREFERENCES = [
  { id: "fast", label: "سريع · ملف واحد وأقل كمون" },
  { id: "balanced", label: "متوازن · تحليل ومراجعة عند التهيئة" },
  { id: "deep", label: "متعمق · تعاون نماذج أوسع ضمن الميزانية" },
  { id: "local", label: "محلي/خاص فقط · لا يتجاوز نقطة نهاية خاصة مُعلنة" },
];
const RESUMABLE_MISSION_STATUSES = new Set([
  "CREATED", "PLANNING", "READY", "RUNNING", "OBSERVING", "VERIFYING",
  "REPLANNING", "PAUSED", "RECOVERY_REQUIRED", "OWNER_INPUT_REQUIRED", "AUTHORIZATION_BLOCKED",
]);

function resetModelPreferences(message = "اختر تفضيل التنسيق؛ لا يُكشف ملف المزوّد أو طرازه في المتصفح.") {
  state.modelPreferences = MODEL_PREFERENCES;
  state.selectedModelPreference = "balanced";
  const select = $("#modelPreference");
  if (select) {
    select.replaceChildren(...MODEL_PREFERENCES.map((item) => new Option(item.label, item.id)));
    select.value = "balanced";
    select.disabled = !state.ownerAuthenticated;
  }
  const note = $("#modelPreferenceNote");
  if (note) note.textContent = message;
}

function loadModelPreferences() {
  const select = $("#modelPreference");
  if (!select) return;
  const previous = select.value || state.selectedModelPreference || "balanced";
  if (!select.options.length || !MODEL_PREFERENCES.some((item) => item.id === select.options[0]?.value)) {
    select.replaceChildren(...MODEL_PREFERENCES.map((item) => new Option(item.label, item.id)));
  }
  select.value = MODEL_PREFERENCES.some((item) => item.id === previous) ? previous : "balanced";
  select.disabled = !state.ownerAuthenticated;
  state.modelPreferences = MODEL_PREFERENCES;
  updateModelPreferenceNote();
}

function updateModelPreferenceNote() {
  const note = $("#modelPreferenceNote");
  const select = $("#modelPreference");
  if (!note || !select) return;
  const selected = MODEL_PREFERENCES.find((item) => item.id === select.value) || MODEL_PREFERENCES[1];
  state.selectedModelPreference = selected.id;
  note.textContent = selected.id === "local"
    ? "لا يستخدم هذا الخيار إلا ملفات صرّح الخادم بأن نقطة نهايتها خاصة/loopback؛ لا يثبت وحده أن المزود محلي أصليًا."
    : "يختار الخادم النماذج والأدوار من القدرات المهيأة؛ حدود المالك والتنفيذ والأدلة لا تتغير بهذا التفضيل.";
}

function resetWorkspaceState() {
  state.conversationId = "";
  state.conversationTasks = [];
  state.selectedMissionId = "";
  state.selectedMission = null;
  state.missionViews = { timeline: [], evidence: [], artifacts: [], logs: [] };
  state.missions = [];
  state.continueSelectedMission = false;
  resetManualScopeForm();
  resetModelPreferences();
  $("#messages").replaceChildren();
  $("#missionHeader").classList.add("hidden");
  $("#missionTools").classList.add("hidden");
  $("#missionList").innerHTML = '<p class="muted">سجّل الدخول لعرض المهام.</p>';
  showView("overview");
  updateSideLinks();
}

function rememberConversation(conversationId) {
  if (!state.ownerAuthenticated || !state.ownerUsername || !conversationId) return;
  try {
    localStorage.setItem(CONVERSATION_STORAGE_KEY, JSON.stringify({ owner: state.ownerUsername, conversation_id: String(conversationId) }));
  } catch (_) { /* The server remains authoritative if browser storage is unavailable. */ }
}

function forgetConversation() {
  try { localStorage.removeItem(CONVERSATION_STORAGE_KEY); } catch (_) { /* Storage can be disabled by browser policy. */ }
}

async function restoreConversation() {
  if (!state.ownerAuthenticated || !state.ownerUsername) return;
  let saved;
  try { saved = JSON.parse(localStorage.getItem(CONVERSATION_STORAGE_KEY) || "null"); } catch (_) { saved = null; }
  if (!saved || typeof saved.conversation_id !== "string") {
    state.conversationTasks = [];
    renderMissions();
    return;
  }
  if (saved.owner !== state.ownerUsername || !/^[A-Za-z0-9_-]{1,128}$/.test(saved.conversation_id)) {
    forgetConversation();
    state.conversationTasks = [];
    renderMissions();
    return;
  }
  try {
    const response = await api(`/api/public/conversations/${encodeURIComponent(saved.conversation_id)}`);
    const conversation = response.conversation;
    if (!conversation || conversation.conversation_id !== saved.conversation_id || !Array.isArray(conversation.messages)) throw new Error("unknown_conversation");
    state.conversationId = conversation.conversation_id;
    state.conversationTasks = Array.isArray(conversation.tasks)
      ? conversation.tasks.filter((task) => task && typeof task === "object" && task.conversation_id === conversation.conversation_id && typeof task.task_id === "string")
      : [];
    renderMissions();
    const messages = $("#messages");
    messages.replaceChildren();
    conversation.messages.forEach((message) => {
      if (message?.role === "user") bubble("user", String(message.content || ""));
      else if (message?.role === "assistant") bubble("bot", String(message.content || ""));
    });
    if (conversation.messages.length || state.conversationTasks.length) showView("conversation");
  } catch (error) {
    if (error.message === "unknown_conversation") {
      forgetConversation();
      state.conversationTasks = [];
      renderMissions();
    }
  }
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

function pushActivity(text, kind = "", timestamp = "") {
  const list = $("#activityList");
  const placeholder = list.querySelector("p.muted");
  if (placeholder) placeholder.remove();
  const row = document.createElement("div");
  row.className = `activity-item${kind ? ` ${kind}` : ""}`;
  const time = document.createElement("time");
  time.textContent = String(timestamp || "");
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
    const selectedMissionId = state.continueSelectedMission
      && RESUMABLE_MISSION_STATUSES.has(String(state.selectedMission?.status || ""))
      ? state.selectedMissionId : undefined;
    const data = await api("/api/public/chat", {
      method: "POST",
      body: JSON.stringify({ text,
        conversation_id: state.conversationId || undefined,
        mission_id: selectedMissionId,
        model_preference: $("#modelPreference")?.value || state.selectedModelPreference || "balanced",
      }),
    });
    loading.remove();
    state.conversationId = String(data.conversation_id || "");
    const returnedMissionId = String(data.mission_id || "");
    if (returnedMissionId) {
      state.selectedMissionId = returnedMissionId;
      state.continueSelectedMission = RESUMABLE_MISSION_STATUSES.has(String(data.mission?.status || ""));
    }
    rememberConversation(state.conversationId);
    (Array.isArray(data.activity) ? data.activity : []).forEach((item) => {
      const label = item.event || item.type || item.tool || item.name || "حدث من الخادم";
      const statusText = item.status ? ` · الحالة: ${item.status}` : "";
      pushActivity(`حدث: ${label}${statusText}`, item.status === "failed" ? "error" : "", item.timestamp || item.time || "");
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
  if (!state.missions.length && !state.conversationTasks.length) {
    target.innerHTML = '<p class="muted">لا توجد مهام محفوظة لهذا الحساب.</p>';
    return;
  }
  const activeStatuses = new Set(["CREATED", "PLANNING", "READY", "RUNNING", "OBSERVING", "VERIFYING", "REPLANNING", "PAUSED"]);
  const groups = [
    { title: "نشطة", match: (m) => activeStatuses.has(m.status) },
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
      button.addEventListener("click", () => selectMission(mission.mission_id, { explicit: true }));
      target.appendChild(button);
    });
  });
  if (state.conversationTasks.length) {
    const heading = document.createElement("div");
    heading.className = "mission-group";
    heading.textContent = "مهام محفوظة في المحادثة";
    target.appendChild(heading);
    state.conversationTasks.forEach((task) => {
      const card = document.createElement("div");
      card.className = "mission-item conversation-task";
      const title = document.createElement("strong");
      title.textContent = String(task.objective || task.task_id || "مهمة محفوظة");
      const status = document.createElement("span");
      status.textContent = String(task.status || "حالة غير متاحة");
      const id = document.createElement("small");
      id.textContent = String(task.task_id || "");
      card.append(title, status, id);
      target.appendChild(card);
    });
  }
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

async function selectMission(missionId, { explicit = false } = {}) {
  state.continueSelectedMission = explicit;
  state.selectedMissionId = String(missionId || "");
  state.filePath = ".";
  renderMissions();
  await loadMission(state.selectedMissionId);
}

async function loadMission(missionId = state.selectedMissionId) {
  if (!missionId || !state.ownerAuthenticated) return;
  state.selectedMissionId = String(missionId);
  try {
    const [statusData, timelineData, evidenceData, artifactsData, logsData] = await Promise.all([
      api(missionEndpoint("status")),
      api(missionEndpoint("timeline")),
      api(missionEndpoint("evidence")),
      api(missionEndpoint("artifacts")),
      api(missionEndpoint("logs")),
    ]);
    state.selectedMission = statusData.status || null;
    state.missionViews = {
      timeline: timelineData.timeline ?? [],
      evidence: evidenceData.evidence ?? [],
      artifacts: artifactsData.artifacts ?? [],
      logs: logsData.logs ?? [],
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
    if (!new Set(["GOAL_COMPLETED", "CANCELLED", "FAILED_RETRY_EXHAUSTED", "SCOPE_BLOCKED", "SAFETY_BLOCKED"]).has(mission.status) && ["in_flight", "in_flight_parallel"].includes(mission.checkpoint?.status)) {
      const notice = document.createElement("div");
      notice.className = "notice warn";
      notice.textContent = "توقّف التنفيذ عند عملية ذات نتيجة غير محسومة. راجع الحالة الخارجية بنفسك؛ لن تُستخدم إفادتك كدليل اكتمال.";
      const controls = document.createElement("div");
      controls.className = "action-row";
      const yes = document.createElement("button");
      yes.type = "button";
      yes.textContent = "تأكدت: العملية نُفذت";
      yes.addEventListener("click", () => reconcileMission(true));
      const no = document.createElement("button");
      no.type = "button";
      no.className = "danger";
      no.textContent = "تأكدت: العملية لم تُنفذ";
      no.addEventListener("click", () => reconcileMission(false));
      controls.append(yes, no);
      target.append(notice, controls);
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

async function reconcileMission(executed) {
  const warning = executed
    ? "هل تحققت من أن العملية الخارجية نُفذت بالفعل؟ سيتم تسجيل قرار الاستعادة فقط؛ ولن يُعامل كدليل اكتمال."
    : "هل تحققت من أن العملية الخارجية لم تُنفذ؟ سيُسمح للمهمة بمحاولة العملية مرة أخرى، وقد يسبب اختيار خاطئ تكرار أثر خارجي.";
  if (!window.confirm(warning)) return;
  setNotice("جارٍ حفظ قرار الاستعادة وإعادة التحقق من تفويض المالك...", "warn");
  try {
    await api(missionEndpoint("reconcile"), { method: "POST", body: JSON.stringify({ executed }) });
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
  note.textContent = "scoped_http_probe: أداة GET واحدة محدودة النطاق، لا تتبع التحويلات، ولا ترسل بيانات اعتماد أو تعرض نص الاستجابة. لا يظهر زر تنفيذ عام؛ لا تُتاح إلا لمهمة يصرح بها المالك ضمن نطاق محفوظ.";
  const contract = document.createElement("p");
  contract.className = "muted";
  contract.textContent = "عقد مفقود: لا يوجد مسار عام لعرض قائمة الأدوات المتاحة لحساب المالك.";
  showInfoPanel([box, note, contract]);
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
  box.textContent = `حالة الخدمة\n${healthText}\n\nلا توجد إعدادات تُدار من المتصفح. الإعدادات والتشريعات تُدار من الخادم وفق تعليمات المالك، ولا يملك العميل أي سلطة تعديل.`;
  showInfoPanel(box);
}

/* ── View switching ──────────────────────────────────────── */

function showView(view) {
  state.activeView = view;
  $$("#missionTabs .tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.view === view));
  const isConversation = view === "conversation";
  const isInfo = view === "info";
  const isScopeSnapshot = view === "scope-snapshot";
  $("#missionView").classList.toggle("hidden", isConversation || isInfo || isScopeSnapshot);
  $("#scopeSnapshotView").classList.toggle("hidden", !isScopeSnapshot);
  $("#transcript").classList.toggle("hidden", !isConversation);
  $("#infoPanel").classList.toggle("hidden", !isInfo);
  $("#missionTabs").classList.toggle("hidden", isInfo);
  if (!isConversation && !isInfo && !isScopeSnapshot) renderMissionView(view);
}

async function refreshAfterInteraction() {
  await status();
  if (state.ownerAuthenticated) await loadMissions();
}

async function refreshConnection() {
  const connection = await status();
  if (state.ownerAuthenticated && !document.hidden) {
    await loadMissions();
    if (connection?.reconnected) await restoreConversation();
  }
}

/* ── Owner manual Scope Snapshot ──────────────────────────── */

const SCOPE_ROW_CONFIG = {
  "in-scope": { template: "#inScopeAssetTemplate", container: "#inScopeAssetRows", add: "#addInScopeAsset", max: MAX_SCOPE_ASSETS, minimum: 1 },
  "out-of-scope": { template: "#outOfScopeAssetTemplate", container: "#outOfScopeAssetRows", add: "#addOutOfScopeAsset", max: MAX_SCOPE_ASSETS, minimum: 0 },
  target: { template: "#scopeTargetTemplate", container: "#scopeTargetRows", add: "#addScopeTarget", max: MAX_SCOPE_TARGETS, minimum: 1 },
};

function scopeRows(kind) {
  const config = SCOPE_ROW_CONFIG[kind];
  return config ? Array.from($(config.container).querySelectorAll(".scope-row")) : [];
}

function updateScopeRowControls(kind) {
  const config = SCOPE_ROW_CONFIG[kind];
  if (!config) return;
  const rows = scopeRows(kind);
  const canEdit = state.ownerAuthenticated && !state.scopeSnapshotSubmitting;
  const addButton = $(config.add);
  addButton.disabled = !canEdit || rows.length >= config.max;
  rows.forEach((row) => {
    const removeButton = row.querySelector(".remove-scope-row");
    removeButton.disabled = !canEdit || rows.length <= config.minimum;
  });
}

function addScopeRow(kind) {
  const config = SCOPE_ROW_CONFIG[kind];
  if (!config) return;
  const container = $(config.container);
  if (container.querySelectorAll(".scope-row").length >= config.max) return;
  container.appendChild($(config.template).content.cloneNode(true));
  const row = container.lastElementChild;
  row.dataset.scopeKind = kind;
  row.querySelector(".remove-scope-row").addEventListener("click", () => {
    if (scopeRows(kind).length <= config.minimum) return;
    row.remove();
    updateScopeRowControls(kind);
  });
  updateScopeRowControls(kind);
}

function updateScopeSnapshotAuthUI() {
  const authenticated = state.ownerAuthenticated;
  const canEdit = authenticated && !state.scopeSnapshotSubmitting;
  const fields = $("#scopeSnapshotFields");
  if (fields) fields.disabled = !canEdit;
  const submitButton = $("#createScopeSnapshot");
  if (submitButton) submitButton.disabled = !canEdit;
  const authNotice = $("#scopeSnapshotAuthNotice");
  if (authNotice) {
    authNotice.textContent = authenticated
      ? "أنت مسجل الدخول بحساب المالك؛ الإرسال لا يحدث إلا عند اختيار حفظ تصريح النطاق."
      : "سجّل الدخول بحساب المالك لتعبئة النموذج وحفظ التصريح.";
    authNotice.className = `notice ${authenticated ? "ok" : "warn"}`;
  }
  Object.keys(SCOPE_ROW_CONFIG).forEach(updateScopeRowControls);
}

function resetManualScopeForm() {
  state.scopeSnapshotSubmitting = false;
  const form = $("#scopeSnapshotForm");
  if (!form) return;
  form.reset();
  const defaultExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  defaultExpiry.setSeconds(0, 0);
  const localExpiry = new Date(defaultExpiry.getTime() - defaultExpiry.getTimezoneOffset() * 60 * 1000);
  $("#scopeExpiresAt").value = localExpiry.toISOString().slice(0, 16);
  Object.values(SCOPE_ROW_CONFIG).forEach(({ container }) => $(container).replaceChildren());
  addScopeRow("in-scope");
  addScopeRow("target");
  $("#scopeSnapshotMessage").textContent = "";
  $("#scopeSnapshotMessage").className = "notice";
  $("#scopeSnapshotResult").replaceChildren();
  updateScopeSnapshotAuthUI();
}

function scopeIdentifier(value, field) {
  const text = String(value ?? "").trim();
  if (!SCOPE_IDENTIFIER_RE.test(text)) throw new Error(`invalid_${field}`);
  return text;
}

function scopeHost(value, field, allowWildcard = false) {
  const host = String(value ?? "");
  const wildcard = host.startsWith("*.");
  if (!host || host !== host.trim() || host.length > 253 || host.includes("://") || /[\/@]/.test(host)) {
    throw new Error(`invalid_${field}`);
  }
  if (host.includes("*") && (!allowWildcard || !wildcard || (host.match(/\*/g) || []).length !== 1)) {
    throw new Error(`invalid_${field}`);
  }
  return host;
}

function scopePaths(value, field, minimum, maximum) {
  const paths = String(value ?? "").split(/\r?\n/).map((path) => path.trim()).filter(Boolean);
  if (paths.length < minimum || paths.length > maximum || new Set(paths).size !== paths.length) {
    throw new Error(`invalid_${field}`);
  }
  if (paths.some((path) => path.length > 256 || !path.startsWith("/") || path.startsWith("//")
    || /[?#\\\x00-\x1f\x7f]/.test(path) || path.split("/").some((part) => part === "." || part === "..")
    || /%(?:2e|2f|5c)/i.test(path))) {
    throw new Error(`invalid_${field}`);
  }
  return paths;
}

function scopePorts(value, field) {
  const text = String(value ?? "").trim();
  const values = text ? text.split(",").map((part) => part.trim()) : [];
  if (!values.length || values.length > MAX_SCOPE_PORTS || values.some((part) => !/^\d+$/.test(part))) {
    throw new Error(`invalid_${field}`);
  }
  const ports = values.map(Number);
  if (ports.some((port) => !Number.isInteger(port) || port < 1 || port > 65535) || new Set(ports).size !== ports.length) {
    throw new Error(`invalid_${field}`);
  }
  return ports;
}

function scopeRowValue(row, field) {
  return row.querySelector(`[data-field="${field}"]`)?.value ?? "";
}

function scopeRowsCounted(kind, minimum, maximum) {
  const rows = scopeRows(kind);
  if (rows.length < minimum || rows.length > maximum) throw new Error(`invalid_${kind.replaceAll("-", "_")}`);
  return rows;
}

function buildManualScopePayload() {
  const programId = scopeIdentifier($("#scopeProgramId").value, "program_id");
  const platform = scopeIdentifier($("#scopePlatform").value, "platform");
  const scopeVersion = scopeIdentifier($("#scopeVersion").value, "scope_version");

  const inScopeAssets = scopeRowsCounted("in-scope", 1, MAX_SCOPE_ASSETS).map((row) => {
    const schemes = Array.from(row.querySelectorAll('[data-field="scheme"]:checked')).map((item) => item.value);
    if (!schemes.length || schemes.length > 2 || schemes.some((scheme) => !["http", "https"].includes(scheme))) {
      throw new Error("invalid_asset_schemes");
    }
    return {
      host: scopeHost(scopeRowValue(row, "host"), "in_scope_host", true),
      schemes,
      ports: scopePorts(scopeRowValue(row, "ports"), "asset_ports"),
      paths: scopePaths(scopeRowValue(row, "paths"), "asset_paths", 1, MAX_SCOPE_PATHS),
    };
  });

  const outOfScopeAssets = scopeRowsCounted("out-of-scope", 0, MAX_SCOPE_ASSETS).map((row) => {
    const asset = { host: scopeHost(scopeRowValue(row, "host"), "out_of_scope_host", true) };
    const paths = scopePaths(scopeRowValue(row, "paths"), "out_of_scope_paths", 0, MAX_SCOPE_PATHS);
    if (paths.length) asset.paths = paths;
    return asset;
  });

  const targets = scopeRowsCounted("target", 1, MAX_SCOPE_TARGETS).map((row) => {
    const target = {
      target_id: scopeIdentifier(scopeRowValue(row, "target_id"), "target_id"),
      host: scopeHost(scopeRowValue(row, "host"), "target_host"),
      allowed_ports: scopePorts(scopeRowValue(row, "allowed_ports"), "target_ports"),
      allowed_paths: scopePaths(scopeRowValue(row, "allowed_paths"), "target_paths", 1, MAX_SCOPE_PATHS),
    };
    for (const field of ["asset_type", "environment"]) {
      const value = String(scopeRowValue(row, field)).trim();
      if (value) target[field] = scopeIdentifier(value, field);
    }
    const excludedPaths = scopePaths(scopeRowValue(row, "excluded_paths"), "target_excluded_paths", 0, MAX_SCOPE_PATHS);
    if (excludedPaths.length) target.excluded_paths = excludedPaths;
    return target;
  });

  const allowedMethods = Array.from(document.querySelectorAll('input[name="scopeAllowedMethods"]:checked')).map((item) => item.value);
  const prohibitedMethods = Array.from(document.querySelectorAll('input[name="scopeProhibitedMethods"]:checked')).map((item) => item.value);
  if (!allowedMethods.length || allowedMethods.length > MAX_SCOPE_METHODS || prohibitedMethods.length > MAX_SCOPE_METHODS
    || [...allowedMethods, ...prohibitedMethods].some((method) => !SCOPE_HTTP_METHODS.includes(method))
    || new Set(allowedMethods).size !== allowedMethods.length || new Set(prohibitedMethods).size !== prohibitedMethods.length
    || allowedMethods.some((method) => prohibitedMethods.includes(method))) {
    throw new Error("invalid_methods");
  }

  const expirationInput = $("#scopeExpiresAt").value;
  const expiration = new Date(expirationInput);
  const now = Date.now();
  if (!expirationInput || !Number.isFinite(expiration.getTime()) || expiration.getTime() <= now
    || expiration.getTime() > now + MAX_SCOPE_EXPIRATION_DAYS * 24 * 60 * 60 * 1000) {
    throw new Error("invalid_expires_at");
  }
  const rateValue = $("#scopeRateLimit").value.trim();
  let rateLimits = {};
  if (rateValue) {
    const requestsPerMinute = Number(rateValue);
    if (!/^\d+$/.test(rateValue) || !Number.isInteger(requestsPerMinute) || requestsPerMinute < 1 || requestsPerMinute > 1000) {
      throw new Error("invalid_requests_per_minute");
    }
    rateLimits = { requests_per_minute: requestsPerMinute };
  }

  return {
    program_id: programId,
    platform,
    scope_version: scopeVersion,
    in_scope_assets: inScopeAssets,
    out_of_scope_assets: outOfScopeAssets,
    targets,
    allowed_methods: allowedMethods,
    prohibited_methods: prohibitedMethods,
    rate_limits: rateLimits,
    expires_at: expiration.toISOString(),
  };
}

function renderScopeSnapshotSummary(snapshot) {
  if (!snapshot || typeof snapshot !== "object") throw new Error("invalid_snapshot_summary");
  const result = $("#scopeSnapshotResult");
  result.replaceChildren();
  const heading = document.createElement("h2");
  heading.textContent = "ملخص اللقطة المحفوظة من الخادم";
  const grid = document.createElement("dl");
  grid.className = "scope-summary-grid";
  const methodText = (value) => Array.isArray(value) && value.every((method) => SCOPE_HTTP_METHODS.includes(method))
    ? (value.join("، ") || "لا يوجد") : "غير متاح";
  const countText = (value) => Number.isInteger(value) && value >= 0 ? String(value) : "غير متاح";
  const rateText = Number.isInteger(snapshot.rate_limits?.requests_per_minute)
    ? `${snapshot.rate_limits.requests_per_minute} طلب/دقيقة` : "غير محدد";
  const entries = [
    ["معرّف اللقطة", snapshot.snapshot_id, true],
    ["البرنامج", snapshot.program_id, true],
    ["المنصة", snapshot.platform, true],
    ["إصدار النطاق", snapshot.scope_version, true],
    ["عدد الموارد داخل النطاق", countText(snapshot.in_scope_asset_count), false],
    ["عدد الموارد خارج النطاق", countText(snapshot.out_of_scope_asset_count), false],
    ["عدد الأهداف", countText(snapshot.target_count), false],
    ["الطرق المسموح بها", methodText(snapshot.allowed_methods), true],
    ["الطرق المحظورة", methodText(snapshot.prohibited_methods), true],
    ["حد الطلبات", rateText, false],
    ["وقت الإنشاء", snapshot.created_at, true],
    ["انتهاء الصلاحية", snapshot.expires_at, true],
  ];
  entries.forEach(([label, value, leftToRight]) => {
    const item = document.createElement("div");
    item.className = "scope-summary-item";
    const term = document.createElement("dt");
    term.textContent = label;
    const description = document.createElement("dd");
    description.textContent = typeof value === "string" && value ? value : "غير متاح";
    if (leftToRight) description.dir = "ltr";
    item.append(term, description);
    grid.appendChild(item);
  });
  result.append(heading, grid);
}

function scopeAuthorizationErrorText(error) {
  const messages = {
    owner_authorization_required: "يلزم تسجيل الدخول بحساب المالك لحفظ تصريح النطاق.",
    "invalid csrf token": "انتهت جلسة الحماية؛ أعد تحميل الصفحة وسجّل الدخول مجددًا.",
    invalid_methods: "اختر طريقة مسموحًا بها واحدة على الأقل، ولا تكرر الطريقة نفسها ضمن المحظورات.",
    invalid_expires_at: "اختر وقت انتهاء في المستقبل وبمدة لا تتجاوز 365 يومًا.",
    target_outside_in_scope_assets: "يجب أن تقع أهدافك ضمن المضيفين والمنافذ والمسارات المعلنة داخل النطاق.",
    allowed_and_prohibited_methods_overlap: "لا يمكن إدراج الطريقة نفسها في المسموح والمحظور.",
  };
  return messages[error?.message] || "تعذر حفظ تصريح النطاق؛ راجع الحقول وحدود النطاق ثم حاول مرة أخرى.";
}

function setScopeSnapshotMessage(message, kind = "") {
  const notice = $("#scopeSnapshotMessage");
  notice.textContent = message;
  notice.className = `notice${kind ? ` ${kind}` : ""}`;
}

function initializeScopeSnapshotForm() {
  $("#addInScopeAsset").addEventListener("click", () => addScopeRow("in-scope"));
  $("#addOutOfScopeAsset").addEventListener("click", () => addScopeRow("out-of-scope"));
  $("#addScopeTarget").addEventListener("click", () => addScopeRow("target"));
  resetManualScopeForm();

  $("#scopeSnapshotForm").onsubmit = async (event) => {
    event.preventDefault();
    if (!state.ownerAuthenticated) {
      setScopeSnapshotMessage("سجّل الدخول بحساب المالك أولاً.", "warn");
      return;
    }
    const form = $("#scopeSnapshotForm");
    if (!form.reportValidity()) return;
    state.scopeSnapshotSubmitting = true;
    updateScopeSnapshotAuthUI();
    $("#scopeSnapshotResult").replaceChildren();
    setScopeSnapshotMessage("جارٍ حفظ تصريح النطاق يدويًا؛ لن يبدأ هذا الإجراء اختبارات.", "warn");
    try {
      const payload = buildManualScopePayload();
      const data = await api("/api/public/program-authorizations", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      if (data.ok !== true) throw new Error("invalid_snapshot_summary");
      renderScopeSnapshotSummary(data.snapshot);
      setScopeSnapshotMessage("حُفظ التصريح. لم تُشغّل اختبارات ولم تتغير صلاحيات الأدوات.", "ok");
    } catch (error) {
      if (error.message === "owner_authorization_required") updateAuthUI({ authenticated: false });
      setScopeSnapshotMessage(scopeAuthorizationErrorText(error), "error");
    } finally {
      state.scopeSnapshotSubmitting = false;
      updateScopeSnapshotAuthUI();
    }
  };
}

initializeScopeSnapshotForm();

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
  $("#modelPreference")?.addEventListener("change", updateModelPreferenceNote);

$("#missionForm").onsubmit = async (event) => {
  event.preventDefault();
  if (!state.ownerAuthenticated) { setNotice("سجّل الدخول بحساب المالك أولاً.", "warn"); return; }
  const button = $("#createMission");
  button.disabled = true;
  setNotice("جارٍ إنشاء المهمة وتسجيلها في طابور التنفيذ...", "warn");
  try {
    const data = await api("/api/public/missions", {
      method: "POST",
      body: JSON.stringify({ objective: $("#missionObjective").value.trim(), model_preference: $("#modelPreference")?.value || "balanced" }),
    });
    $("#missionObjective").value = "";
    state.selectedMissionId = data.mission_id || data.mission?.mission_id || "";
    setNotice(`أُنشئت المهمة من الخادم. الحالة الحالية: ${data.mission?.status || "غير متاحة"} · ${data.queue?.state || "حالة الطابور غير متاحة"}`, "ok");
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
    if (state.ownerAuthenticated) await Promise.all([loadMissions(), restoreConversation()]);
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
  $$("[data-side-view]").forEach((button) => { button.disabled = !state.selectedMissionId; });
}

status().then(() => { if (state.ownerAuthenticated) return Promise.all([loadMissions(), restoreConversation()]); });
