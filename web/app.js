let conversationId = localStorage.getItem("cs_conversation_id") || "";
let csrfToken = "";
let sessionPromise = null;
let ownerAuthenticated = false;

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

  let response = await fetch(path, {
    ...options,
    credentials: "include",
    headers: await makeHeaders(),
  });
  if (isPublicApi && path !== "/api/public/session" && response.status === 401) {
    csrfToken = "";
    sessionPromise = null;
    response = await fetch(path, {
      ...options,
      credentials: "include",
      headers: await makeHeaders(),
    });
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

function updateAuthUI(data) {
  ownerAuthenticated = data.authenticated === true;
  $("#authState").textContent = ownerAuthenticated
    ? `مسجل الدخول: ${data.username || "المالك"}`
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
  };
  return messages[error.message] || "تعذر إكمال الطلب. تحقق من الاتصال ثم حاول مرة أخرى.";
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
  (items || []).forEach((item) => bubble(
    "bot",
    `أداة: ${item.name || item.type}\nالحالة: ${item.status || "completed"}${item.request_id ? `\nRequest: ${item.request_id}` : ""}`,
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
  const loading = bubble("bot", "أبدأ فهم الطلب وجمع الأدلة...", "loading");
  try {
    const data = await api("/api/public/chat", {
      method: "POST",
      body: JSON.stringify({ text, conversation_id: conversationId || undefined }),
    });
    loading.remove();
    conversationId = data.conversation_id;
    localStorage.setItem("cs_conversation_id", conversationId);
    activity(data.activity);
    bubble("bot", data.answer || "اكتمل التحليل.");
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
    $("#conn").textContent = `● ${health.version || "متصل"}`;
    $("#statusOut").innerHTML = `<div class="kv"><div class="card">الحالة<b>ONLINE</b></div><div class="card">الإصدار<b>${esc(health.version || "")}</b></div><div class="card">المصادقة<b>${auth.authenticated ? "Owner" : "مطلوب تسجيل الدخول"}</b></div></div><div class="result">${auth.authenticated ? "الجلسة موثقة بحساب المالك." : "الجلسة العامة لا تمنح صلاحيات المالك؛ سجّل الدخول قبل استخدام الأدوات."}</div>`;
  } catch {
    $("#conn").textContent = "○ غير متصل";
    $("#authState").textContent = "تعذر التحقق من الجلسة";
  }
}

function esc(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;",
  }[character]));
}

async function direct(command, output) {
  if (!ownerAuthenticated) {
    $(output).textContent = "سجّل الدخول بحساب المالك أولاً.";
    return;
  }
  try {
    const data = await api("/api/public/chat", {
      method: "POST",
      body: JSON.stringify({ text: command, conversation_id: conversationId || undefined }),
    });
    conversationId = data.conversation_id;
    localStorage.setItem("cs_conversation_id", conversationId);
    $(output).innerHTML = `<div class="result">${esc(data.answer || "")}</div><div class="result">${esc(JSON.stringify(data.activity, null, 2))}</div>`;
    status();
  } catch (error) {
    $(output).textContent = errorText(error);
    if (error.message === "owner_authorization_required") updateAuthUI({ authenticated: false });
  }
}

$("#form").onsubmit = (event) => {
  event.preventDefault();
  send($("#input").value);
};
$("#input").onkeydown = (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    send(event.target.value);
  }
};
$$('[data-p]').forEach((button) => button.addEventListener("click", () => send(button.dataset.p)));
$("#intelBtn").onclick = () => direct("حدّث استخبارات التهديدات ثم اعرض الملخص", "#intelOut");
$("#localBtn").onclick = () => direct("افحص الجهاز محليًا", "#localOut");
$("#reload").onclick = status;
$("#menu").onclick = () => $("#side").classList.toggle("open");
$$(".nav").forEach((navigation) => navigation.addEventListener("click", () => {
  $$(".nav").forEach((item) => item.classList.remove("active"));
  navigation.classList.add("active");
  $$(".page").forEach((page) => page.classList.add("hidden"));
  const action = navigation.dataset.action;
  $(`#${action}`).classList.remove("hidden");
  $("#side").classList.remove("open");
  if (action === "status") status();
}));

$("#loginForm").onsubmit = async (event) => {
  event.preventDefault();
  const button = $("#loginButton");
  button.disabled = true;
  $("#authMessage").textContent = "جارٍ التحقق...";
  try {
    const data = await api("/api/public/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username: $("#loginUsername").value.trim(),
        password: $("#loginPassword").value,
      }),
    });
    $("#loginPassword").value = "";
    updateAuthUI(data);
    await status();
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

status();
setInterval(status, 15000);
