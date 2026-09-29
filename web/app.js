let conversationId = "";
let csrfToken = "";
let sessionPromise = null;
let ownerAuthenticated = false;
let ownerUsername = "";
let selectedMissionId = "";
let selectedMission = null;
let missionViews = { timeline: [], evidence: [], artifacts: [], logs: [] };
let filePath = ".";

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);

async function ensureSession() {
  if (csrfToken) return csrfToken;
  if (!sessionPromise) {
    sessionPromise = fetch("/api/public/session", {
      method: "POST",
      credentials: "include",
      headers: { Accept: "application/json" },
    })
      .then(async (response) => {
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
        csrfToken = data.session?.csrf_token || "";
        if (!csrfToken) throw new Error("public session was not issued");
        return csrfToken;
      })
      .catch((error) => {
        sessionPromise = null;
        throw error;
      });
  }
  return sessionPromise;
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
  let response = await fetch(path, { ...options, credentials: "include", headers: await makeHeaders() });
  if (isPublicApi && path !== "/api/public/session" && response.status === 401) {
    csrfToken = "";
    sessionPromise = null;
    response = await fetch(path, { ...options, credentials: "include", headers: await makeHeaders() });
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

function updateAuthUI(data) {
  const nextAuthenticated = data.authenticated === true;
  const nextUsername = nextAuthenticated ? String(data.username || "") : "";
  if (ownerAuthenticated && (!nextAuthenticated || (ownerUsername && nextUsername && ownerUsername !== nextUsername))) {
    conversationId = "";
    selectedMissionId = "";
    selectedMission = null;
    missionViews = { timeline: [], evidence: [], artifacts: [], logs: [] };
    if ($("#messages")) {
      $("#messages").replaceChildren();
      const welcome = document.createElement("div");
      welcome.className = "welcome";
      welcome.innerHTML = '<div class="hero">CS</div><h1>CyberSentinel X</h1><p>المحادثات مرتبطة بحساب المالك الحالي ولا تُستعاد من التخزين المحلي.</p>';
      $("#messages").appendChild(welcome);
    }
    if ($("#missionList")) $("#missionList").innerHTML = '<p class="muted">سجّل الدخول لعرض المهام.</p>';
    if ($("#missionDetail")) $("#missionDetail").innerHTML = '<h2>تفاصيل المهمة</h2><p class="muted">اختر مهمة من القائمة لعرض بيانات الخادم.</p>';
    $("#missionTools")?.classList.add("hidden");
  }
  ownerAuthenticated = nextAuthenticated;
  ownerUsername = nextUsername;
  $("#authState").textContent = ownerAuthenticated
    ? `مسجل الدخول: ${ownerUsername || "المالك"}`
    : "غير مسجل الدخول";
  $("#loginForm").classList.toggle("hidden", ownerAuthenticated);
  $("#logoutButton").classList.toggle("hidden", !ownerAuthenticated);
  $("#authMessage").textContent = "";
}

function errorText(error) {
  const messages = {
    invalid_credentials: "بيانات الدخول غير صحيحة.",
    owner_authorization_required: "يلزم تسجيل الدخول بحساب المالك.",
    "owner authentication required": "انتهت الجلسة؛ سجّل الدخول مرة أخرى.",
    public_boundary_disabled: "واجهة المتصفح معطلة في إعدادات الخدمة.",
    unknown_mission: "المهمة غير موجودة أو غير متاحة لهذا الحساب.",
    "not_found": "المورد غير موجود أو محجوب بسياسة مساحة العمل.",
  };
  return messages[error.message] || `تعذر إكمال الطلب: ${error.message || "خطأ غير معروف"}`;
}

function bubble(who, text, kind = "") {
  const element = document.createElement("div");
  element.className = `msg ${who}${kind ? ` ${kind}` : ""}`;
  element.innerHTML = `<div><div class="who">${who === "user" ? "أنت" : "CyberSentinel X"}</div><div class="bubble"></div></div>`;
  element.querySelector(".bubble").textContent = text;
  $("#messages").appendChild(element);
  $("#messages").scrollTop = 1e9;
  return element;
}

function activity(items) {
  (Array.isArray(items) ? items : []).forEach((item) => bubble(
    "bot",
    `أداة: ${item.name || item.type || "غير محددة"}\nالحالة: ${item.status || "غير متاحة"}${item.request_id ? `\nRequest: ${item.request_id}` : ""}`,
    "activity",
  ));
}

async function send(text) {
  text = text.trim();
  if (!text) return;
  if (!ownerAuthenticated) {
    bubble("bot", "سجّل الدخول بحساب المالك لاستخدام المحادثة.");
    return;
  }
  $(".welcome")?.remove();
  bubble("user", text);
  $("#input").value = "";
  const loading = bubble("bot", "جارٍ إرسال الطلب إلى الخادم...", "loading");
  try {
    const data = await api("/api/public/chat", {
      method: "POST",
      body: JSON.stringify({ text, conversation_id: conversationId || undefined }),
    });
    loading.remove();
    conversationId = String(data.conversation_id || "");
    activity(data.activity);
    const answer = typeof data.answer === "string" && data.answer.trim()
      ? data.answer
      : `لم يقدّم الخادم إجابة نصية. حالة المهمة: ${data.mission?.status || "غير متاحة"}.`;
    bubble("bot", answer);
  } catch (error) {
    loading.remove();
    bubble("bot", errorText(error));
    if (error.message === "owner_authorization_required") updateAuthUI({ authenticated: false });
  }
  status();
}

async function status() {
  try {
    const health = await api("/api/public/health");
    const auth = await api("/api/public/auth/session");
    updateAuthUI(auth);
    $("#conn").textContent = health.ok === true ? `● ${health.service || "الخدمة"} · ${health.version || "الإصدار غير متاح"}` : "? حالة الخدمة غير مؤكدة";
    $("#statusOut").innerHTML = `<div class="kv"><div class="card">استجابة HTTP<b>${health.ok === true ? "OK" : "غير مؤكدة"}</b></div><div class="card">الإصدار<b>${esc(health.version || "غير متاح")}</b></div><div class="card">المصادقة<b>${auth.authenticated === true ? "Owner" : "مطلوب تسجيل الدخول"}</b></div></div><div class="result">${auth.authenticated === true ? "الجلسة موثقة بحساب المالك وفق استجابة الخادم." : "الجلسة العامة لا تمنح صلاحيات المالك؛ سجّل الدخول قبل استخدام الأدوات."}</div>`;
  } catch (error) {
    $("#conn").textContent = "○ تعذر الوصول إلى الخدمة";
    $("#authState").textContent = "تعذر التحقق من الجلسة";
    $("#statusOut").textContent = errorText(error);
  }
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
  notice.textContent = message;
  notice.className = `notice${kind ? ` ${kind}` : ""}`;
}

function missionStatusLabel(mission) {
  const status = mission?.status || "unknown";
  const queue = mission?.queue?.state;
  return `${status}${queue ? ` · queue: ${queue}` : ""}`;
}

async function loadMissions() {
  if (!ownerAuthenticated) {
    setNotice("سجّل الدخول بحساب المالك لعرض المهام.", "warn");
    return;
  }
  $("#missionList").textContent = "جارٍ تحميل المهام المحفوظة...";
  try {
    const data = await api("/api/public/missions?limit=100");
    const missions = Array.isArray(data.missions) ? data.missions : [];
    $("#missionList").replaceChildren();
    if (!missions.length) {
      $("#missionList").innerHTML = '<p class="muted">لا توجد مهام محفوظة لهذا الحساب.</p>';
    } else {
      missions.forEach((mission) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = `mission-item${mission.mission_id === selectedMissionId ? " selected" : ""}`;
        button.innerHTML = `<strong>${esc(mission.objective || mission.owner_request || mission.mission_id)}</strong><span>${esc(missionStatusLabel(mission))}</span><small>${esc(mission.request_id || "Request ID غير متاح")}</small>`;
        button.addEventListener("click", () => selectMission(mission.mission_id));
        $("#missionList").appendChild(button);
      });
    }
    setNotice(`تم تحميل ${missions.length} مهمة من الخادم.`, "ok");
    if (selectedMissionId && missions.some((item) => item.mission_id === selectedMissionId)) await loadMission(selectedMissionId);
    else if (missions.length && !selectedMissionId) await selectMission(missions[0].mission_id);
  } catch (error) {
    $("#missionList").textContent = errorText(error);
    setNotice(errorText(error), "error");
  }
}

async function selectMission(missionId) {
  selectedMissionId = String(missionId || "");
  filePath = ".";
  $$(".mission-item").forEach((item) => item.classList.remove("selected"));
  await loadMission(selectedMissionId);
}

function missionEndpoint(action) {
  return `/api/public/missions/${encodeURIComponent(selectedMissionId)}/${encodeURIComponent(action)}`;
}

async function loadMission(missionId = selectedMissionId) {
  if (!missionId || !ownerAuthenticated) return;
  selectedMissionId = String(missionId);
  $("#missionDetail").textContent = "جارٍ تحميل الحالة المحفوظة...";
  $("#missionTools").classList.remove("hidden");
  try {
    const [statusData, timelineData, evidenceData, artifactsData, logsData] = await Promise.all([
      api(missionEndpoint("status")),
      api(missionEndpoint("timeline")),
      api(missionEndpoint("evidence")),
      api(missionEndpoint("artifacts")),
      api(missionEndpoint("logs")),
    ]);
    selectedMission = statusData.status || null;
    missionViews = {
      timeline: timelineData.timeline ?? [],
      evidence: evidenceData.evidence ?? [],
      artifacts: artifactsData.artifacts ?? [],
      logs: logsData.logs ?? [],
    };
    renderMissionOverview();
    renderMissionView(document.querySelector(".tab.active")?.dataset.view || "overview");
  } catch (error) {
    selectedMission = null;
    $("#missionDetail").textContent = errorText(error);
    $("#missionView").textContent = "تعذر قراءة بيانات هذه المهمة.";
    setNotice(errorText(error), "error");
  }
}

function renderMissionOverview() {
  const mission = selectedMission;
  if (!mission) return;
  const step = mission.plan?.steps?.[mission.current_step] || null;
  const verification = mission.verification_state || {};
  const complete = mission.status === "GOAL_COMPLETED" && verification.verified === true && !!mission.completion_proof;
  const missing = Array.isArray(verification.missing_criteria) ? verification.missing_criteria : [];
  const authSnapshot = mission.authorization_snapshot?.authorization_hash ? "لقطة التفويض موجودة" : "لا توجد لقطة تفويض";
  const phase = mission.status === "PAUSED" ? "متوقفة مؤقتًا" : (mission.status || "غير متاح");
  $("#missionDetail").innerHTML = `<div class="detail-title"><div><h2>${esc(mission.objective || mission.owner_request || "مهمة")}</h2><small>Mission ID: ${esc(mission.mission_id || selectedMissionId)}</small></div><span class="status-chip">${esc(phase)}</span></div>
    <div class="kv"><div class="card">Request ID<b class="small-value">${esc(mission.request_id || "غير متاح")}</b></div><div class="card">التنفيذ<b class="small-value">${esc(mission.queue?.state || "لا توجد حالة طابور")}</b></div><div class="card">التحقق<b class="small-value">${verification.verified === true ? "متحقق حسب الخادم" : "غير متحقق"}</b></div><div class="card">الاكتمال<b class="small-value">${complete ? "مكتمل بدليل موقّع" : "غير مثبت"}</b></div></div>
    <div class="result"><b>تعليمات المالك</b>\n${esc(mission.owner_instruction || mission.owner_request || "غير متاحة")}\n\n<b>المرحلة / العملية الحالية</b>\n${esc(step ? `${step.step_id || ""} · ${step.action || "عملية غير محددة"}` : "لا توجد خطوة حالية في الخطة")}\n\n<b>التفويض</b>\n${esc(authSnapshot)}\n\n<b>سبب الإخفاق / التوقف</b>\n${esc(mission.error || "لا يوجد سبب مسجل")}\n\n<b>إعادة المحاولة</b>\n${esc(mission.retry_count ?? "غير متاح")}\n\n<b>نقاط الاستعادة</b>\n${esc(JSON.stringify(mission.checkpoint || {}, null, 2))}\n\n<b>معايير التحقق المفقودة</b>\n${esc(missing.length ? missing.join(", ") : (verification.verified === true ? "لا توجد معايير مفقودة وفق الخادم" : "غير محددة"))}</div>`;
}

function renderMissionView(view) {
  const target = $("#missionView");
  target.replaceChildren();
  if (!selectedMission) {
    target.textContent = "اختر مهمة لعرض بياناتها.";
    return;
  }
  if (view === "overview") {
    target.innerHTML = `<div class="result"><b>الحالة المحفوظة</b>\n${esc(selectedMission.status || "غير متاحة")}\n\n<b>حالة التنفيذ</b>\n${esc(selectedMission.queue?.state || "لا يوجد عنصر طابور")}\n\n<b>حالة الأدلة</b>\n${esc(Array.isArray(selectedMission.evidence) ? `${selectedMission.evidence.length} سجل/سجلات من الخادم` : "غير متاحة")}\n\n<b>حالة التحقق</b>\n${selectedMission.verification_state?.verified === true ? "متحقق" : "غير متحقق"}\n\n<b>حالة الاكتمال</b>\n${selectedMission.status === "GOAL_COMPLETED" && !!selectedMission.completion_proof ? "دليل اكتمال موقّع موجود" : "لا يوجد دليل اكتمال موقّع"}</div>`;
    if (!new Set(["GOAL_COMPLETED", "CANCELLED", "FAILED_RETRY_EXHAUSTED", "SCOPE_BLOCKED", "SAFETY_BLOCKED"]).has(selectedMission.status) && ["in_flight", "in_flight_parallel"].includes(selectedMission.checkpoint?.status)) {
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
  const values = view === "evidence" ? missionViews.evidence
    : view === "timeline" ? missionViews.timeline
      : view === "artifacts" ? missionViews.artifacts
        : view === "logs" ? missionViews.logs : null;
  if (values !== null) {
    if (!Array.isArray(values) || !values.length) {
      target.innerHTML = `<p class="muted">${view === "evidence" ? "لا توجد سجلات أدلة من الخادم لهذه المهمة." : "لا توجد سجلات من الخادم لهذه اللوحة."}</p>`;
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
    const records = missionViews.evidence.filter((item) => item && typeof item === "object" && item.system_evidence);
    const heading = document.createElement("p");
    heading.className = "muted";
    heading.textContent = "هذه اللوحة تعرض سجلات معايير موقّعة من الخادم فقط؛ لا ينشئ النظام سجل Findings مستقلًا.";
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
      card.appendChild(title);
      const link = document.createElement("p");
      link.className = "muted";
      link.textContent = `معرّف الإجراء: ${record.provenance?.action_id || "غير متاح"} · مرجع التحقق: ${record.provenance?.verification || "غير متاح"}`;
      card.appendChild(link);
      card.appendChild(showJson(record));
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
  if (!selectedMissionId || !ownerAuthenticated) return;
  if (action === "cancel" && !window.confirm("هل تريد إلغاء هذه المهمة؟ لن تُعرض بوصفها مكتملة.")) return;
  setNotice("جارٍ إرسال الإجراء إلى الخادم...", "warn");
  try {
    await api(missionEndpoint(action), { method: "POST", body: "{}" });
    setNotice("استجاب الخادم؛ جارٍ إعادة تحميل الحالة المحفوظة.", "ok");
    await loadMissions();
    await loadMission(selectedMissionId);
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
    await loadMission(selectedMissionId);
  } catch (error) {
    setNotice(errorText(error), "error");
  }
}

function renderFiles() {
  const target = $("#missionView");
  target.innerHTML = `<div class="file-controls"><label for="filePath">مسار نسبي داخل المستودع</label><input id="filePath" value="${esc(filePath)}" maxlength="1024"><button id="listFiles" type="button">استعراض</button></div><div id="fileEntries" class="file-list"></div><pre id="fileContent" class="result file-content">اختر ملفًا للقراءة فقط.</pre>`;
  $("#listFiles").onclick = () => browseFiles($("#filePath").value.trim() || ".");
  browseFiles(filePath);
}

async function browseFiles(path) {
  filePath = path;
  const entries = $("#fileEntries");
  if (!entries) return;
  entries.textContent = "جارٍ تحميل قائمة الملفات المسموح بها...";
  $("#fileContent").textContent = "اختر ملفًا للقراءة فقط.";
  try {
    const query = new URLSearchParams({ path });
    const data = await api(`/api/public/workspace/${encodeURIComponent(selectedMissionId)}/files?${query}`);
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
      button.title = item.directory ? "فتح المجلد" : `الحجم: ${item.size ?? "غير متاح"}`;
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
    const data = await api(`/api/public/workspace/${encodeURIComponent(selectedMissionId)}/file?${query}`);
    $("#fileContent").textContent = data.content ?? "لم يُرجع الخادم محتوى نصيًا.";
  } catch (error) {
    $("#fileContent").textContent = errorText(error);
  }
}

function renderGit() {
  const target = $("#missionView");
  target.innerHTML = `<div class="action-row git-actions">${["status", "branch", "log", "diff", "repository", "head", "remote"].map((name) => `<button type="button" data-git="${name}">${({ status: "الحالة", branch: "الفرع", log: "السجل", diff: "الفروق", repository: "المستودع", head: "HEAD", remote: "المصدر البعيد" })[name]}</button>`).join("")}</div><pre id="gitOutput" class="result file-content">اختر عملية Git للقراءة فقط.</pre><p class="muted">هذه الواجهة للقراءة فقط؛ لا تنفّذ commit أو push.</p>`;
  $$('[data-git]').forEach((button) => button.addEventListener("click", () => readGit(button.dataset.git)));
}

async function readGit(operation) {
  $("#gitOutput").textContent = "جارٍ قراءة Git من مساحة العمل المرتبطة بالمهمة...";
  try {
    const query = new URLSearchParams({ operation });
    const data = await api(`/api/public/workspace/${encodeURIComponent(selectedMissionId)}/git?${query}`);
    $("#gitOutput").textContent = data.output || data.error_output || `Exit code: ${data.exit_code}`;
  } catch (error) {
    $("#gitOutput").textContent = errorText(error);
  }
}

async function loadWorkspace() {
  if (ownerAuthenticated) await loadMissions();
  else setNotice("سجّل الدخول بحساب المالك لعرض المهام.", "warn");
}

$("#form").onsubmit = (event) => { event.preventDefault(); send($("#input").value); };
$("#input").onkeydown = (event) => {
  if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); send(event.target.value); }
};
$("#reload").onclick = status;
$("#menu").onclick = () => $("#side").classList.toggle("open");
$("#refreshMissions").onclick = loadWorkspace;
$("#missionForm").onsubmit = async (event) => {
  event.preventDefault();
  if (!ownerAuthenticated) { setNotice("سجّل الدخول بحساب المالك أولاً.", "warn"); return; }
  const button = $("#createMission");
  button.disabled = true;
  setNotice("جارٍ إنشاء المهمة وتسجيلها في طابور التنفيذ...", "warn");
  try {
    const data = await api("/api/public/missions", {
      method: "POST",
      body: JSON.stringify({ objective: $("#missionObjective").value.trim() }),
    });
    $("#missionObjective").value = "";
    selectedMissionId = data.mission_id || data.mission?.mission_id || "";
    setNotice(`أُنشئت المهمة من الخادم. الحالة الحالية: ${data.mission?.status || "غير متاحة"} · ${data.queue?.state || "حالة الطابور غير متاحة"}`, "ok");
    await loadMissions();
    if (selectedMissionId) await loadMission(selectedMissionId);
  } catch (error) {
    setNotice(errorText(error), "error");
  } finally {
    button.disabled = false;
  }
};
$$("[data-mission-action]").forEach((button) => button.addEventListener("click", () => runMissionAction(button.dataset.missionAction)));
$$(".tab").forEach((button) => button.addEventListener("click", () => {
  $$(".tab").forEach((tab) => tab.classList.remove("active"));
  button.classList.add("active");
  renderMissionView(button.dataset.view);
}));
$$(`.nav`).forEach((navigation) => navigation.addEventListener("click", () => {
  $$(".nav").forEach((item) => item.classList.remove("active"));
  navigation.classList.add("active");
  $$(".page").forEach((page) => page.classList.add("hidden"));
  const action = navigation.dataset.action;
  $(`#${action}`).classList.remove("hidden");
  $("#side").classList.remove("open");
  if (action === "status") status();
  if (action === "workspace") loadWorkspace();
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
    if (ownerAuthenticated) await loadWorkspace();
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
    await status();
  } catch (error) {
    $("#authMessage").textContent = errorText(error);
  }
};
const logsTab = document.createElement("button");
logsTab.type = "button";
logsTab.className = "tab";
logsTab.dataset.view = "logs";
logsTab.textContent = "السجلات";
$(".tabs").appendChild(logsTab);
logsTab.addEventListener("click", () => {
  $$(".tab").forEach((tab) => tab.classList.remove("active"));
  logsTab.classList.add("active");
  renderMissionView("logs");
});
status();
setInterval(() => {
  status();
  if (ownerAuthenticated && selectedMissionId && !$("#workspace").classList.contains("hidden")) loadMission(selectedMissionId);
}, 15000);
