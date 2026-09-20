let token=localStorage.getItem("cs_token")||"";
const $=s=>document.querySelector(s), $$=s=>document.querySelectorAll(s);
function headers(){return token?{"X-CyberSentinel-Token":token}:{}}
async function api(path,opt={}){
  const h={...headers(),...(opt.headers||{})};
  if(opt.body)h["Content-Type"]="application/json";
  let r=await fetch(path,{...opt,headers:h}),d={};
  try{d=await r.json()}catch{}
  if(r.status===401){
    const t=prompt("أدخل BRIDGE_TOKEN المحلي");
    if(!t)throw Error("لم يتم إدخال التوكن");
    token=t;localStorage.setItem("cs_token",token);
    return api(path,opt);
  }
  if(!r.ok)throw Error(d.error||`HTTP ${r.status}`);
  return d;
}
function bubble(who,text){
  const e=document.createElement("div");e.className="msg "+who;
  e.innerHTML=`<div><div class="who">${who==="user"?"أنت":"CyberSentinel X"}</div><div class="bubble"></div></div>`;
  e.querySelector(".bubble").textContent=text;$("#messages").appendChild(e);$("#messages").scrollTop=1e9;
}
async function send(text){
  text=text.trim();if(!text)return;
  $(".welcome")?.remove();bubble("user",text);$("#input").value="";
  try{
    const d=await api("/api/command",{method:"POST",body:JSON.stringify({text})});
    bubble("bot",d.answer||"تم التنفيذ.");
    if(d.plan?.length)bubble("bot","الخطة:\n"+d.plan.map(x=>Array.isArray(x)?x[0]+" → "+x[1]:x).join("\n"));
  }catch(e){bubble("bot","خطأ: "+e.message)}
  status();
}
async function status(){
  try{
    const d=await api("/api/status");
    $("#conn").textContent="● متصل";
    const c=d.event_counts||{};
    $("#statusOut").innerHTML=`<div class="kv">
      <div class="card">الحالة<b>ONLINE</b></div>
      <div class="card">الأحداث<b>${Object.values(c).reduce((a,b)=>a+b,0)}</b></div>
      <div class="card">المراقبة<b>${d.watch_count}</b></div>
      <div class="card">LLM<b>${d.llm.configured?"مفعّل":"محلي"}</b></div>
      </div><div class="result">${esc(JSON.stringify(d.recent_events,null,2))}</div>`;
  }catch{$("#conn").textContent="○ غير متصل"}
}
function esc(s){return String(s).replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]))}
async function direct(command,out){
  try{let d=await api("/api/command",{method:"POST",body:JSON.stringify({text:command})});$(out).innerHTML=`<div class="result">${esc(d.answer)}</div><div class="result">${esc(JSON.stringify(d.results,null,2))}</div>`;status()}
  catch(e){$(out).innerHTML=`<div class="result">خطأ: ${esc(e.message)}</div>`}
}
$("#form").onsubmit=e=>{e.preventDefault();send($("#input").value)};
$("#input").onkeydown=e=>{if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();send(e.target.value)}};
$$("[data-p]").forEach(b=>b.onclick=()=>send(b.dataset.p));
$("#intelBtn").onclick=()=>direct("حدّث استخبارات التهديدات","#intelOut");
$("#localBtn").onclick=()=>direct("افحص الجهاز محليًا","#localOut");
$("#reload").onclick=status;
$("#menu").onclick=()=>$("#side").classList.toggle("open");
$$(".nav").forEach(n=>n.onclick=()=>{
  $$(".nav").forEach(x=>x.classList.remove("active"));n.classList.add("active");
  $$(".page").forEach(x=>x.classList.add("hidden"));
  const a=n.dataset.action;$("#"+a).classList.remove("hidden");$("#side").classList.remove("open");
  if(a==="status")status();
});
status();setInterval(status,15000);