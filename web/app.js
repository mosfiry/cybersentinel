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
  projects: [],
  projectsLoaded: false,
  activeProjectId: "",
  desktopSetup: null,
  modelManager: null,
  onboardingVisible: false,
  missionViews: { timeline: [], evidence: [], artifacts: [], logs: [], effects: [], report: null },
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
  const raw = String(error?.message || "");
  if (raw.startsWith("model_not_compatible:")) return "هذا النموذج لا يلائم الذاكرة أو المساحة المتاحة على الجهاز.";
  const messages = {
    invalid_credentials: "بيانات الدخول غير صحيحة.",
    owner_authorization_required: "يلزم تسجيل الدخول بحساب المالك.",
    "owner authentication required": "انتهت الجلسة؛ سجّل الدخول مرة أخرى.",
    public_boundary_disabled: "واجهة المتصفح معطلة في إعدادات الخدمة.",
    unknown_mission: "المهمة غير موجودة أو غير متاحة لهذا الحساب.",
    not_found: "المورد غير موجود أو محجوب بسياسة مساحة العمل.",
    secure_workspace_access_unavailable: "عرض مساحة العمل غير متاح على هذا النظام لأن الوصول الآمن للمجلدات غير مدعوم.",
    model_manager_busy: "هناك عملية تنزيل أو تشغيل نموذج قيد التنفيذ؛ انتظر اكتمالها.",
    model_not_installed: "نزّل النموذج وتحقق منه قبل تفعيله.",
    model_switch_blocked_by_active_mission: "أوقف المهمة أو انتظر انتهاءها قبل تبديل النموذج.",
    owner_account_already_exists: "حساب المالك موجود بالفعل؛ سجّل الدخول بدل إنشاء حساب آخر.",
    project_folder_must_be_a_specific_directory: "اختر مجلد مشروع محددًا وليس جذر القرص.",
    project_folder_overlaps_application_data: "لا يمكن استخدام مجلد بيانات التطبيق كمجلد مشروع.",
    project_folder_already_registered: "هذا المجلد مرتبط بمشروع آخر بالفعل.",
    network_project_folder_not_supported: "اختر مجلدًا محليًا على هذا الجهاز؛ المجلدات الشبكية غير مدعومة حاليًا.",
    native_folder_selection_required: "يجب اختيار مجلد المشروع من نافذة النظام الأصلية.",
  };
  return messages[raw] || `تعذر إكمال الطلب: ${raw || "خطأ غير معروف"}`;
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
    if (window.cybersentinelDesktop?.isDesktop) {
      try { await refreshDesktopSetup(); } catch (error) { setModelNotice(errorText(error), "error"); }
    }
    if (state.ownerAuthenticated && !state.projectsLoaded) await loadProjects();
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
  state.missionViews = { timeline: [], evidence: [], artifacts: [], logs: [], effects: [], report: null };
  state.missions = [];
  state.projects = [];
  state.projectsLoaded = false;
  state.activeProjectId = "";
  $("#messages").replaceChildren();
  $("#missionHeader").classList.add("hidden");
  $("#missionTools").classList.add("hidden");
  $("#missionList").innerHTML = '<p class="muted">سجّل الدخول لعرض المهام.</p>';
  renderMissionView("overview");
  $("#missionTabs .tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.view === "overview"));
  state.activeView = "overview";
  updateSideLinks();
  renderProjects();
}

function setModelNotice(message, kind = "") {
  [$("#setupModelMessage"), $("#modelManagerNotice")].filter(Boolean).forEach((element) => {
    element.textContent = message || "";
    element.className = `notice${kind ? ` ${kind}` : ""}`;
  });
}

function formatBytes(value) {
  let size = Math.max(0, Number(value) || 0);
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
  return `${size.toFixed(unit >= 2 ? 1 : 0)} ${units[unit]}`;
}

function modelOperationLabel(operation) {
  const labels = {
    downloading: "جارٍ التنزيل",
    verifying: "جارٍ التحقق من SHA-256",
    activating: "جارٍ تشغيل النموذج",
    complete: "اكتمل",
    failed: `فشل: ${operation.error || "خطأ غير محدد"}`,
    interrupted: "توقف عند إغلاق التطبيق؛ يمكن إعادة المحاولة",
  };
  return labels[operation.status] || "لا توجد عملية جارية";
}

function renderModelCards(target) {
  if (!target) return;
  target.replaceChildren();
  const manager = state.modelManager;
  if (!manager || !Array.isArray(manager.models)) {
    target.textContent = "كتالوج النماذج غير متاح حاليًا.";
    return;
  }
  const hardware = manager.hardware || {};
  const ram = hardware.ram_gib == null ? "غير متاح" : `${hardware.ram_gib} GiB RAM`;
  const disk = hardware.free_disk_gib == null ? "مساحة القرص غير متاحة" : `${hardware.free_disk_gib} GiB متاح على القرص`;
  const hardwareLine = `الجهاز: ${hardware.os || "غير معروف"} · ${hardware.architecture || "بنية غير معروفة"} · ${ram} · ${hardware.cpu_count || "?"} نواة · ${disk} · ${hardware.gpu_acceleration_available ? "تسريع GPU متاح" : "CPU فقط"}`;
  if ($("#setupHardware")) $("#setupHardware").textContent = hardwareLine;
  const operation = manager.manager?.operation || { status: "idle", model_id: "" };
  const runtime = manager.manager?.runtime || {};
  manager.models.forEach((model) => {
    const article = document.createElement("article");
    article.className = "model-card";
    const title = document.createElement("h3");
    title.textContent = `${model.display_name || model.family} · ${model.parameter_size || ""}`;
    const description = document.createElement("p");
    description.textContent = `${model.family} · ${model.quantization} · ${model.license} · سياق ${model.context_length || 4096}`;
    const meta = document.createElement("p");
    meta.className = "model-meta";
    meta.textContent = `GGUF ${formatBytes(model.size_bytes)} · RAM حد أدنى ${model.min_ram_gib} GiB · موصى به ${model.recommended_ram_gib} GiB`;
    const recommendation = document.createElement("p");
    recommendation.className = model.compatible ? "model-recommendation" : "model-warning";
    recommendation.textContent = model.compatible
      ? (model.warnings?.length ? `متوافق مع تحذير: ${model.warnings.join(", ")}` : "ملائم وفق فحص الذاكرة والمساحة")
      : `غير ملائم حاليًا: ${(model.compatibility_reasons || []).join(", ") || "سبب غير محدد"}`;
    const button = document.createElement("button");
    button.type = "button";
    const busy = ["downloading", "verifying", "activating"].includes(operation.status);
    if (model.active && runtime.status === "ready") {
      button.textContent = "النموذج المفعّل";
      button.disabled = true;
    } else if (model.installed) {
      button.textContent = model.active ? "إعادة تشغيل النموذج" : "تشغيل / تبديل إلى هذا النموذج";
      button.dataset.modelAction = "activate";
      button.dataset.modelId = model.model_id;
      button.disabled = busy || !model.compatible;
    } else {
      button.textContent = "تنزيل وتثبيت";
      button.dataset.modelAction = "install";
      button.dataset.modelId = model.model_id;
      button.disabled = busy || !model.compatible;
    }
    const progress = document.createElement("div");
    progress.className = "model-progress";
    if (operation.model_id === model.model_id && ["downloading", "verifying", "activating", "failed", "interrupted"].includes(operation.status)) {
      const amount = operation.total_bytes ? `${formatBytes(operation.bytes_downloaded)} / ${formatBytes(operation.total_bytes)} (${operation.progress || 0}%)` : "";
      progress.textContent = `${modelOperationLabel(operation)}${amount ? ` · ${amount}` : ""}`;
    } else if (model.active) {
      progress.textContent = `Runtime: ${runtime.status || "غير معروف"}${runtime.error ? ` · ${runtime.error}` : ""}`;
    }
    article.append(title, description, meta, recommendation, button, progress);
    target.appendChild(article);
  });
  target.querySelectorAll("[data-model-action]").forEach((button) => {
    button.addEventListener("click", () => runModelAction(button.dataset.modelId, button.dataset.modelAction));
  });
}

async function refreshDesktopSetup() {
  const data = await api("/api/public/desktop/setup");
  state.desktopSetup = data;
  const canonicalUsername = String(data.owner_username || "").trim();
  const setupUsername = $("#setupOwnerUsername");
  if (setupUsername) setupUsername.textContent = canonicalUsername || "غير متاح";
  const loginUsername = $("#loginUsername");
  if (loginUsername && !loginUsername.value && canonicalUsername) loginUsername.value = canonicalUsername;
  state.modelManager = data.model_manager || null;
  renderModelCards($("#setupModelList"));
  const overlay = $("#firstRunOverlay");
  const show = Boolean(window.cybersentinelDesktop?.isDesktop && data.owner_configured === false);
  state.onboardingVisible = show;
  overlay?.classList.toggle("hidden", !show);
  const operation = state.modelManager?.manager?.operation || {};
  if (["downloading", "verifying", "activating"].includes(operation.status)) scheduleModelPoll();
}

let modelPollTimer = null;
function scheduleModelPoll() {
  if (modelPollTimer) return;
  modelPollTimer = setTimeout(async () => {
    modelPollTimer = null;
    try {
      const data = await api("/api/public/desktop/models");
      state.modelManager = data;
      renderModelCards($("#setupModelList"));
      renderModelCards($("#settingsModelList"));
      const operation = data.manager?.operation || {};
      if (operation.status === "failed") setModelNotice(modelOperationLabel(operation), "error");
      else if (["downloading", "verifying", "activating"].includes(operation.status)) {
        setModelNotice(modelOperationLabel(operation), "warn");
        scheduleModelPoll();
      } else if (operation.status === "complete") {
        setModelNotice("اكتملت العملية وتحقق الخادم من الملف المحلي.", "ok");
      }
    } catch (error) {
      setModelNotice(errorText(error), "error");
    }
  }, 1200);
}

async function runModelAction(modelId, action) {
  if (!modelId || !["install", "activate"].includes(action)) return;
  setModelNotice(action === "install" ? "بدأ التنزيل؛ سيُستأنف من الملف الجزئي ويتحقق SHA-256 قبل التثبيت." : "جارٍ إيقاف runtime السابق والتحقق من النموذج قبل التبديل.", "warn");
  try {
    const data = await api(`/api/public/desktop/models/${encodeURIComponent(modelId)}/${action}`, { method: "POST", body: "{}" });
    state.modelManager = data;
    renderModelCards($("#setupModelList"));
    renderModelCards($("#settingsModelList"));
    scheduleModelPoll();
  } catch (error) {
    setModelNotice(errorText(error), "error");
  }
}

$("#ownerSetupForm").onsubmit = async (event) => {
  event.preventDefault();
  const password = $("#ownerSetupPassword").value;
  const confirmPassword = $("#ownerSetupConfirm").value;
  const message = $("#ownerSetupMessage");
  if (password.length < 12 || password.length > 256) { message.textContent = "استخدم كلمة مرور بين 12 و256 محرفًا."; return; }
  if (password !== confirmPassword) { message.textContent = "كلمتا المرور غير متطابقتين."; return; }
  const button = $("#ownerSetupSubmit");
  button.disabled = true;
  message.textContent = "جارٍ إنشاء حساب المالك محليًا...";
  try {
    const canonicalUsername = String(state.desktopSetup?.owner_username || "").trim();
    if (!canonicalUsername) throw new Error("desktop_owner_username_unavailable");
    if (!window.cybersentinelDesktop?.createOwner) throw new Error("desktop_first_run_unavailable");
    await window.cybersentinelDesktop.createOwner(password);
    const data = await api("/api/public/auth/login", {
      method: "POST",
      body: JSON.stringify({ username: canonicalUsername, password }),
    });
    $("#ownerSetupPassword").value = "";
    $("#ownerSetupConfirm").value = "";
    updateAuthUI(data);
    await refreshDesktopSetup();
    await loadProjects();
    await loadMissions();
    setNotice("اكتمل الإعداد المحلي. يمكنك إنشاء مشروع ومهمة؛ نزّل نموذجًا متوافقًا من الإعدادات لاستخدام الاستدلال المحلي.", "ok");
  } catch (error) {
    message.textContent = errorText(error);
  } finally {
    button.disabled = false;
  }
};

function currentProject() {
  return state.projects.find((item) => item.project_id === state.activeProjectId && !item.archived) || null;
}

function renderProjects() {
  const list = $("#projectList");
  if (!list) return;
  list.replaceChildren();
  if (!state.ownerAuthenticated) {
    list.innerHTML = '<p class="muted">سجّل الدخول لعرض المشاريع.</p>';
  } else if (!state.projects.length) {
    list.innerHTML = '<p class="muted">لا توجد مشاريع بعد.</p>';
  } else {
    state.projects.forEach((project) => {
      const row = document.createElement("div");
      row.className = "project-item";
      const button = document.createElement("button");
      button.type = "button";
      button.className = `project-item${project.project_id === state.activeProjectId ? " selected" : ""}`;
      button.disabled = Boolean(project.archived);
      const name = document.createElement("span");
      name.textContent = project.name;
      const details = document.createElement("small");
      details.textContent = `${project.mission_count || 0} مهمة${project.location_kind === "selected-folder" ? " · مجلد محلي" : " · مُدار"}${project.archived ? " · مؤرشف" : ""}`;
      button.append(name, details);
      if (!project.archived) {
        button.addEventListener("click", () => selectProject(project.project_id));
        row.appendChild(button);
      } else {
        row.appendChild(button);
        const restore = document.createElement("button");
        restore.type = "button";
        restore.textContent = "استعادة";
        restore.title = `استعادة ${project.name}`;
        restore.addEventListener("click", () => updateProject(project.project_id, { action: "unarchive" }));
        row.appendChild(restore);
      }
      list.appendChild(row);
    });
  }
  const available = state.projects.filter((project) => !project.archived);
  const selector = $("#missionProject");
  if (selector) {
    const previous = state.activeProjectId;
    selector.replaceChildren();
    available.forEach((project) => {
      const option = document.createElement("option");
      option.value = project.project_id;
      option.textContent = project.name;
      selector.appendChild(option);
    });
    selector.disabled = !available.length || !state.ownerAuthenticated;
    if (available.some((project) => project.project_id === previous)) selector.value = previous;
  }
  const project = currentProject();
  $("#renameProject").disabled = !project || !state.ownerAuthenticated;
  $("#archiveProject").disabled = !project || project.is_default || !state.ownerAuthenticated;
  $("#activeProjectHint").textContent = project
    ? `السياق الحالي: ${project.name} · تُحفظ المحادثة والمهمة ضمن هذا المشروع.`
    : "اختر أو أنشئ مشروعًا قبل تسجيل المهام.";
  $("#archiveProject").textContent = "أرشفة";
}

async function loadProjects() {
  if (!state.ownerAuthenticated) {
    state.projects = [];
    state.projectsLoaded = false;
    renderProjects();
    return;
  }
  try {
    const data = await api("/api/public/projects");
    state.projects = Array.isArray(data.projects) ? data.projects : [];
    const available = state.projects.filter((project) => !project.archived);
    if (!available.some((project) => project.project_id === state.activeProjectId)) {
      state.activeProjectId = available[0]?.project_id || "";
    }
    state.projectsLoaded = true;
    renderProjects();
  } catch (error) {
    $("#projectList").textContent = errorText(error);
    $("#projectMessage").textContent = errorText(error);
  }
}

async function selectProject(projectId) {
  const project = state.projects.find((item) => item.project_id === projectId && !item.archived);
  if (!project) return;
  state.activeProjectId = projectId;
  state.selectedMissionId = "";
  state.selectedMission = null;
  $("#missionHeader").classList.add("hidden");
  $("#missionTools").classList.add("hidden");
  renderProjects();
  renderMissions();
  await loadMissions();
}

async function updateProject(projectId, payload) {
  try {
    await api(`/api/public/projects/${encodeURIComponent(projectId)}`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    $("#projectMessage").textContent = payload.action === "unarchive" ? "استُعيد المشروع." : "حُفظت تغييرات المشروع.";
    await loadProjects();
    await loadMissions();
    return true;
  } catch (error) {
    $("#projectMessage").textContent = errorText(error);
    return false;
  }
}

$("#newProjectToggle").onclick = () => {
  if (!state.ownerAuthenticated) { $("#projectMessage").textContent = "سجّل الدخول بحساب المالك أولًا."; return; }
  $("#projectForm").classList.toggle("hidden");
  $("#projectName").focus();
};
$("#cancelProjectForm").onclick = () => {
  $("#projectForm").classList.add("hidden");
  $("#projectForm").reset();
};
$("#projectForm").onsubmit = async (event) => {
  event.preventDefault();
  if (!state.ownerAuthenticated) return;
  try {
    const data = await api("/api/public/projects", {
      method: "POST",
      body: JSON.stringify({ name: $("#projectName").value.trim(), description: $("#projectDescription").value.trim() }),
    });
    $("#projectForm").reset();
    $("#projectForm").classList.add("hidden");
    state.activeProjectId = data.project?.project_id || "";
    $("#projectMessage").textContent = "أُنشئ المشروع وحُفظ مجلده المحلي.";
    await loadProjects();
    await loadMissions();
  } catch (error) {
    $("#projectMessage").textContent = errorText(error);
  }
};
$("#importProjectFolder").onclick = async () => {
  if (!state.ownerAuthenticated) { $("#projectMessage").textContent = "سجّل الدخول بحساب المالك أولًا."; return; }
  if (!window.cybersentinelDesktop?.selectProjectFolder) { $("#projectMessage").textContent = "استيراد مجلد يتطلب تطبيق Desktop."; return; }
  const name = $("#projectName").value.trim();
  if (!name) { $("#projectMessage").textContent = "أدخل اسم المشروع قبل اختيار مجلده."; $("#projectName").focus(); return; }
  const button = $("#importProjectFolder");
  button.disabled = true;
  $("#projectMessage").textContent = "اختر مجلدًا من نافذة النظام؛ سيُحفظ المسار على الجهاز فقط.";
  try {
    const csrfToken = await ensureSession();
    const result = await window.cybersentinelDesktop.selectProjectFolder({
      name,
      description: $("#projectDescription").value.trim(),
      csrfToken,
    });
    if (result.cancelled) {
      $("#projectMessage").textContent = "أُلغي اختيار المجلد.";
      return;
    }
    state.activeProjectId = result.project?.project_id || "";
    $("#projectForm").reset();
    $("#projectForm").classList.add("hidden");
    $("#projectMessage").textContent = "رُبط المجلد بالمشروع؛ نطاق المهمة سيبقى داخله.";
    await loadProjects();
    await loadMissions();
  } catch (error) {
    $("#projectMessage").textContent = errorText(error);
  } finally {
    button.disabled = false;
  }
};
$("#renameProject").onclick = () => {
  const project = currentProject();
  if (!project) return;
  $("#renameProjectName").value = project.name;
  $("#renameProjectForm").classList.remove("hidden");
  $("#renameProjectName").focus();
};
$("#cancelRenameProject").onclick = () => {
  $("#renameProjectForm").classList.add("hidden");
  $("#renameProjectForm").reset();
};
$("#renameProjectForm").onsubmit = async (event) => {
  event.preventDefault();
  const project = currentProject();
  const name = $("#renameProjectName").value.trim();
  if (!project || !name || name === project.name) {
    $("#renameProjectForm").classList.add("hidden");
    return;
  }
  if (await updateProject(project.project_id, { name })) {
    $("#renameProjectForm").classList.add("hidden");
    $("#renameProjectForm").reset();
  }
};
$("#archiveProject").onclick = async () => {
  const project = currentProject();
  if (!project || project.is_default) return;
  if (!window.confirm(`أرشفة المشروع «${project.name}»؟ ستبقى مهامه محفوظة ولن يُستخدم لمهام جديدة.`)) return;
  await updateProject(project.project_id, { action: "archive" });
};
$("#missionProject").onchange = () => {
  if ($("#missionProject").value) selectProject($("#missionProject").value);
};

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
  if (!state.activeProjectId) {
    bubble("bot", "أنشئ مشروعًا أو اختر مشروعًا نشطًا قبل إرسال المهمة.");
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
      body: JSON.stringify({ text, conversation_id: state.conversationId || undefined, project_id: state.activeProjectId || undefined }),
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
  const projectMissions = state.missions.filter((mission) => mission.project_id === state.activeProjectId);
  if (!state.activeProjectId) {
    target.innerHTML = '<p class="muted">أنشئ مشروعًا أو اختر مجلدًا محليًا أولًا.</p>';
    return;
  }
  if (!projectMissions.length) {
    target.innerHTML = '<p class="muted">لا توجد مهام محفوظة لهذا المشروع.</p>';
    return;
  }
  const groups = [
    { title: "نشطة", match: (m) => !["GOAL_COMPLETED", "CANCELLED", "FAILED_RETRY_EXHAUSTED", "SCOPE_BLOCKED", "SAFETY_BLOCKED"].includes(m.status) },
    { title: "مكتملة (بتحقق الخادم)", match: (m) => m.status === "GOAL_COMPLETED" },
    { title: "منتهية لأسباب أخرى", match: () => true },
  ];
  const seen = new Set();
  groups.forEach((group) => {
    const items = projectMissions.filter((m) => !seen.has(m.mission_id) && group.match(m));
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
    const visible = state.missions.filter((item) => item.project_id === state.activeProjectId);
    if (state.selectedMissionId && visible.some((item) => item.mission_id === state.selectedMissionId)) {
      await loadMission(state.selectedMissionId);
    } else if (visible.length) {
      await selectMission(visible[0].mission_id);
    } else {
      state.selectedMissionId = "";
      state.selectedMission = null;
      $("#missionHeader").classList.add("hidden");
      renderMissionView("overview");
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
    const [statusData, timelineData, evidenceData, artifactsData, logsData, effectsData, reportData] = await Promise.all([
      api(missionEndpoint("status")),
      api(missionEndpoint("timeline")),
      api(missionEndpoint("evidence")),
      api(missionEndpoint("artifacts")),
      api(missionEndpoint("logs")),
      api(missionEndpoint("effects")).catch((error) => ({ effects: [], error: error.message })),
      api(missionEndpoint("report")).catch((error) => ({ report: null, error: error.message })),
    ]);
    state.selectedMission = statusData.status || null;
    state.missionViews = {
      timeline: timelineData.timeline ?? [],
      evidence: evidenceData.evidence ?? [],
      artifacts: artifactsData.artifacts ?? [],
      logs: logsData.logs ?? [],
      effects: effectsData.effects ?? [],
      effectsError: effectsData.error || "",
      report: reportData.report || null,
      reportError: reportData.error || "",
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
  if (view === "agents") {
    renderAgentSubtasks(mission, target);
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
    renderReportFindings(target);
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
  if (view === "report") {
    renderMissionReport(target);
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

function renderAgentSubtasks(mission, target) {
  const plan = Array.isArray(mission.plan?.steps) ? mission.plan.steps : [];
  const queue = mission.queue || {};
  const heading = document.createElement("div");
  heading.className = "result";
  heading.textContent = `حالة mission: ${mission.status || "غير معروفة"}\nحالة العامل/الطابور: ${queue.state || "غير متاحة"}\nمعرّف العامل: ${queue.lease_owner || "لا يوجد عامل مالك للـlease حاليًا"}\nموضع مؤشر الخطة: ${Number.isInteger(mission.current_step) ? mission.current_step : "غير متاح"}\nعناصر الخطة: ${plan.length}`;
  target.appendChild(heading);
  if (!plan.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "لم يسجل الخادم خطوات/مهام فرعية لهذه المهمة.";
    target.appendChild(empty);
  } else {
    const current = Number.isInteger(mission.current_step) ? mission.current_step : -1;
    plan.forEach((step, index) => {
      const card = document.createElement("article");
      card.className = "subtask-card";
      const title = document.createElement("h3");
      title.textContent = `${step.step_id || `خطة-${index + 1}`} · ${step.action || "خطوة بلا أداة محددة"}`;
      const detail = document.createElement("p");
      detail.textContent = step.objective || "لا يوجد وصف محفوظ لهذه الخطوة.";
      const status = document.createElement("small");
      status.className = "subtask-status";
      status.textContent = index === current ? "موضع مؤشر المهمة الحالي" : index < current ? "قبل مؤشر الخطة الحالي؛ راجع الأحداث والأدلة" : "لاحق في الخطة؛ لم يصل إليه المؤشر الحالي";
      const checks = document.createElement("p");
      checks.textContent = `المتطلبات السابقة: ${(step.prerequisites || []).join(", ") || "لا توجد"} · التحقق المخطط: ${(step.verification || []).join("، ") || "غير محدد"}`;
      card.append(title, detail, status, checks);
      target.appendChild(card);
    });
  }
  const progress = mission.progress && typeof mission.progress === "object" ? mission.progress : {};
  const agentRuns = Array.isArray(progress.agent_runs) ? progress.agent_runs : (Array.isArray(progress.agents) ? progress.agents : []);
  const agentTitle = document.createElement("h2");
  agentTitle.textContent = "سجلات التنفيذ والوكلاء الفرعيين إن وُجدت";
  target.appendChild(agentTitle);
  if (agentRuns.length) {
    agentRuns.forEach((record) => target.appendChild(showJson(record)));
  } else {
    const note = document.createElement("p");
    note.className = "muted";
    note.textContent = "لا يسجل هذا المسار الحالي هويات مستقلة لوكلاء فرعيين لكل mission؛ تعرض الواجهة بدلًا من ذلك plan steps والطابور وسجل الأدوات الفعلي من الخادم، دون اختلاق agent runs.";
    target.appendChild(note);
  }
  const calls = Array.isArray(progress.model_loop?.tool_results) ? progress.model_loop.tool_results : [];
  const callsTitle = document.createElement("h2");
  callsTitle.textContent = `نتائج استدعاءات الأدوات المحفوظة (${calls.length})`;
  target.appendChild(callsTitle);
  calls.slice(-40).forEach((call) => target.appendChild(showJson(call)));
}

function renderReportFindings(target) {
  const report = state.missionViews.report;
  if (!report) return;
  const summary = report.mission_summary || {};
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const evidence = report.evidence || {};
  const card = document.createElement("div");
  card.className = "result";
  card.textContent = `نتيجة التقرير: ${summary.outcome || "UNKNOWN"}\nحالة المهمة: ${summary.mission_status || "غير متاحة"}\nسلسلة Evidence: ${evidence.execution_chain_integrity || "غير معروفة"}\nFinding rows: ${findings.length}\n\nهذه النتائج مأخوذة من report builder الخادمي. الادعاءات غير الحاملة لـprovenance حتمي تظهر كـUNVERIFIED ولا تمنح نتيجة VERIFIED.`;
  target.appendChild(card);
  findings.forEach((finding) => {
    const item = document.createElement("article");
    item.className = "subtask-card";
    const title = document.createElement("h3");
    title.textContent = `${finding.criterion_id || "معيار غير محدد"} · ${finding.status || "UNKNOWN"}`;
    const detail = document.createElement("p");
    detail.textContent = `المصدر: ${finding.source || "غير معروف"} · نتيجة الادعاء: ${finding.claimed_result || "لا يوجد"} · الثقة: ${finding.confidence ?? "غير مسجلة"} · hash: ${finding.evidence_hash || "غير متاح"}`;
    item.append(title, detail);
    target.appendChild(item);
  });
}

function renderMissionReport(target) {
  const report = state.missionViews.report;
  if (!report) {
    const note = document.createElement("p");
    note.className = "muted";
    note.textContent = state.missionViews.reportError ? `تعذر تحميل التقرير: ${state.missionViews.reportError}` : "لا يوجد تقرير محفوظ لهذه المهمة.";
    target.appendChild(note);
    return;
  }
  const summary = report.mission_summary || {};
  const verification = summary.verification || {};
  const evidence = report.evidence || {};
  const card = document.createElement("div");
  card.className = "result";
  card.textContent = `Outcome: ${summary.outcome || "UNKNOWN"}\nMission: ${summary.mission_id || "غير متاح"}\nRequest: ${summary.request_id || "غير متاح"}\nStatus: ${summary.mission_status || "UNKNOWN"}\nVerified: ${verification.verified === true ? "نعم — وفق شروط التقرير" : verification.verified === false ? "لا" : "غير محدد"}\nEvidence chain: ${evidence.execution_chain_integrity || "غير معروفة"}\nEvidence digest SHA-256: ${evidence.digest_sha256 || "غير متاح"}\nTrusted evidence: ${verification.trusted_evidence_count ?? 0} · غير موثق: ${verification.unverified_evidence_count ?? 0}\nمعايير التحقق الناقصة: ${(verification.missing_criteria || []).join(", ") || "لا توجد/غير محددة"}\n\nالمالك: ${(report.owner_approval_status || {}).status || "غير معروف"} · الثقة الكلية لا تُستنتج: ${(report.confidence || {}).aggregate ?? "لا يوجد"}`;
  target.appendChild(card);
  ["limitations", "unknown_states", "tool_failures", "provenance"].forEach((key) => {
    const section = document.createElement("article");
    section.className = "result record-card";
    const title = document.createElement("h3");
    title.textContent = key;
    section.append(title, showJson(report[key] ?? []));
    target.appendChild(section);
  });
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
  const panel = document.createElement("div");
  panel.className = "settings-layout";
  const summary = document.createElement("div");
  summary.className = "result";
  try {
    const health = await api("/api/public/health");
    const runtime = state.modelManager?.manager?.runtime || {};
    summary.textContent = `CyberSentinel Desktop\nBackend: ${health.ok === true ? "جاهز" : "غير جاهز"} · ${health.version || "version n/a"}\nLocal runtime: ${runtime.status || "لم يُفعّل نموذج"}${runtime.model_id ? ` · ${runtime.model_id}` : ""}\nInference backend: llama.cpp CPU · بعد تنزيل النموذج يدعم العمل دون إنترنت.`;
  } catch (error) {
    summary.textContent = `تعذر قراءة حالة الخدمة: ${errorText(error)}`;
  }
  const managerTitle = document.createElement("h2");
  managerTitle.textContent = "إدارة النماذج المحلية";
  const helper = document.createElement("p");
  helper.className = "muted";
  helper.textContent = "اختر عائلة/حجم/quantization من الكتالوج المثبت. يفحص التطبيق RAM والمساحة قبل التنزيل، ويتحقق من SHA-256 قبل التثبيت. لا يتم التبديل أثناء وجود mission فعالة.";
  const notice = document.createElement("div");
  notice.id = "modelManagerNotice";
  notice.className = "notice";
  notice.setAttribute("role", "status");
  const list = document.createElement("div");
  list.id = "settingsModelList";
  list.className = "model-list";
  const providerNote = document.createElement("p");
  providerNote.className = "muted";
  let providersText = "";
  if (state.ownerAuthenticated) {
    try {
      const result = await api("/api/public/providers");
      providersText = (result.providers || []).map((provider) => {
        const caps = Object.entries(provider.capabilities || {}).filter(([, enabled]) => enabled).map(([name]) => name);
        return `${provider.name}: ${provider.configured ? "مهيأ" : "غير مهيأ"} · قدرات: ${caps.join(", ") || "غير معلنة"}`;
      }).join("\n") || "لا يوجد مزود خارجي مهيأ.";
    } catch (error) { providersText = errorText(error); }
  } else providersText = "سجّل الدخول لعرض حالة المزودين.";
  providerNote.textContent = `مزودو النموذج المهيّؤون (قراءة فقط؛ لا تُعرض مفاتيح أو عناوين):\n${providersText}`;
  const note = document.createElement("p");
  note.className = "muted";
  note.textContent = "كتالوج هذه النسخة يدعم Qwen3 4B/8B وDeepSeek R1 Distill Qwen 7B بملفات GGUF Q4_K_M. حزم المحرك والنماذج تُجلب من المصادر المثبتة وتُحفظ تحت بيانات المستخدم.";
  panel.append(summary, managerTitle, helper, notice, list, providerNote, note);
  showInfoPanel(panel);
  try {
    state.modelManager = await api("/api/public/desktop/models");
    renderModelCards(list);
    const operation = state.modelManager.manager?.operation || {};
    if (["downloading", "verifying", "activating"].includes(operation.status)) scheduleModelPoll();
  } catch (error) {
    list.textContent = errorText(error);
  }
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
  if (!state.activeProjectId) { setNotice("أنشئ مشروعًا أو اختر مشروعًا نشطًا أولاً.", "warn"); return; }
  const button = $("#createMission");
  button.disabled = true;
  setNotice("جارٍ إنشاء المهمة وتسجيلها في طابور التنفيذ...", "warn");
  try {
    const data = await api("/api/public/missions", {
      method: "POST",
      body: JSON.stringify({ objective: $("#missionObjective").value.trim(), project_id: state.activeProjectId }),
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
