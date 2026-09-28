let conversationId=localStorage.getItem("cs_conversation_id")||"";
let csrfToken="";
let sessionPromise=null;
const $=s=>document.querySelector(s), $$=s=>document.querySelectorAll(s);

async function ensureSession(){
  if(csrfToken)return csrfToken;
  if(!sessionPromise){
    sessionPromise=fetch("/api/public/session",{method:"POST",credentials:"include",headers:{"Accept":"application/json"}})
      .then(async r=>{const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.error||`HTTP ${r.status}`);csrfToken=d.session?.csrf_token||"";if(!csrfToken)throw Error("public session was not issued");return csrfToken;})
      .catch(e=>{sessionPromise=null;throw e;});
  }
  return sessionPromise;
}

async function api(path,opt={}){
  const h={"Accept":"application/json",...(opt.headers||{})};
  if(opt.body)h["Content-Type"]="application/json";
  if(path.startsWith("/api/public/")&&path!=="/api/public/session")h["X-CSRF-Token"]=await ensureSession();
  const r=await fetch(path,{...opt,credentials:"include",headers:h});
  const d=await r.json().catch(()=>({}));
  if(!r.ok)throw Error(d.error||`HTTP ${r.status}`);
  return d;
}

function bubble(who,text,kind=""){
  const e=document.createElement("div");e.className="msg "+who+(kind?" "+kind:"");e.innerHTML=`<div><div class="who">${who==="user"?"أنت":"CyberSentinel X"}</div><div class="bubble"></div></div>`;e.querySelector(".bubble").textContent=text;$("#messages").appendChild(e);$("#messages").scrollTop=1e9;return e;
}
function activity(items){(items||[]).forEach(x=>bubble("bot",`أداة: ${x.name||x.type}\nالحالة: ${x.status||"completed"}${x.request_id?`\nRequest: ${x.request_id}`:""}`,"activity"))}
async function send(text){text=text.trim();if(!text)return;$(".welcome")?.remove();bubble("user",text);$("#input").value="";const loading=bubble("bot","أبدأ فهم الطلب وجمع الأدلة...","loading");try{const d=await api("/api/public/chat",{method:"POST",body:JSON.stringify({text,conversation_id:conversationId||undefined})});loading.remove();conversationId=d.conversation_id;localStorage.setItem("cs_conversation_id",conversationId);activity(d.activity);bubble("bot",d.answer||"اكتمل التحليل.");}catch(e){loading.remove();bubble("bot","خطأ: "+e.message)}status()}
async function status(){try{const d=await api("/api/public/health");$("#conn").textContent="● "+(d.version||"متصل");$("#statusOut").innerHTML=`<div class="kv"><div class="card">الحالة<b>ONLINE</b></div><div class="card">الإصدار<b>${esc(d.version||"")}</b></div></div><div class="result">الجلسة العامة لا تمنح صلاحيات المالك.</div>`;}catch{$("#conn").textContent="○ غير متصل"}}
function esc(s){return String(s).replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#039;"}[m]))}
async function direct(command,out){try{const d=await api("/api/public/chat",{method:"POST",body:JSON.stringify({text:command,conversation_id:conversationId||undefined})});conversationId=d.conversation_id;localStorage.setItem("cs_conversation_id",conversationId);$(out).innerHTML=`<div class="result">${esc(d.answer)}</div><div class="result">${esc(JSON.stringify(d.activity,null,2))}</div>`;status()}catch(e){$(out).innerHTML=`<div class="result">خطأ: ${esc(e.message)}</div>`}}
$("#form").onsubmit=e=>{e.preventDefault();send($("#input").value)};$("#input").onkeydown=e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();send(e.target.value)}};$$('[data-p]').forEach(b=>b.onclick=()=>send(b.dataset.p));$("#intelBtn").onclick=()=>direct("حدّث استخبارات التهديدات ثم اعرض الملخص","#intelOut");$("#localBtn").onclick=()=>direct("افحص الجهاز محليًا","#localOut");$("#reload").onclick=status;$("#menu").onclick=()=>$("#side").classList.toggle("open");$$('.nav').forEach(n=>n.onclick=()=>{$$('.nav').forEach(x=>x.classList.remove('active'));n.classList.add('active');$$('.page').forEach(x=>x.classList.add('hidden'));const a=n.dataset.action;$("#"+a).classList.remove('hidden');$("#side").classList.remove('open');if(a==='status')status()});ensureSession().then(status).catch(()=>status());setInterval(status,15000);
