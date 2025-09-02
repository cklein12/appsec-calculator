/* AppSec Investigation Calculator (clean, stable) */

// ----- Data -----
function getDefaultTasks() {
  return [
    { group: "Triage", name: "Check if it’s a duplicate of an existing issue", defaultMinutes: 6, includedByDefault: true },
    { group: "Triage", name: "Validate scanner rule quality and detection in code context", defaultMinutes: 8, includedByDefault: true },
    { group: "Triage", name: "Confirm affected asset is still in use", defaultMinutes: 6, includedByDefault: true },
    { group: "Triage", name: "Review historical vulnerabilities on the same asset/component", defaultMinutes: 7, includedByDefault: true },
    { group: "Triage", name: "Identify which environment it affects (prod/staging/dev)", defaultMinutes: 3, includedByDefault: true },

    { group: "Confirm exploitability & impact", name: "Determine data sensitivity of the asset", defaultMinutes: 7, includedByDefault: true },
    { group: "Confirm exploitability & impact", name: "Estimate potential business impact", defaultMinutes: 10, includedByDefault: true },
    { group: "Confirm exploitability & impact", name: "Scope blast radius", defaultMinutes: 9, includedByDefault: true },
    { group: "Confirm exploitability & impact", name: "Check threat intelligence / exploit DBs", defaultMinutes: 6, includedByDefault: true },
    { group: "Confirm exploitability & impact", name: "Assess exposure surface (internet-facing vs internal)", defaultMinutes: 5, includedByDefault: true },
    { group: "Confirm exploitability & impact", name: "Investigate potential attack paths via toxic combinations", defaultMinutes: 10, includedByDefault: true },

    { group: "Reproduction", name: "Set up or access a test environment", defaultMinutes: 15, includedByDefault: true },
    { group: "Reproduction", name: "Configure the vulnerable version", defaultMinutes: 12, includedByDefault: true },
    { group: "Reproduction", name: "Execute PoC payloads / scanner replay", defaultMinutes: 12, includedByDefault: true },
    { group: "Reproduction", name: "Adjust and repeat for environmental differences", defaultMinutes: 10, includedByDefault: true },

    { group: "Investigation / RCA", name: "Collect logs, stack traces, telemetry", defaultMinutes: 12, includedByDefault: true },
    { group: "Investigation / RCA", name: "Trace the vulnerable code path or misconfig", defaultMinutes: 15, includedByDefault: true },
    { group: "Investigation / RCA", name: "Identify affected versions/branches/deployments", defaultMinutes: 9, includedByDefault: true },
    { group: "Investigation / RCA", name: "Evaluate exploit preconditions (auth/roles)", defaultMinutes: 7, includedByDefault: true },
    { group: "Investigation / RCA", name: "Consult SMEs/developers", defaultMinutes: 12, includedByDefault: true },
    { group: "Investigation / RCA", name: "Gather evidence (attack paths, code refs, CVEs)", defaultMinutes: 10, includedByDefault: true },
    { group: "Investigation / RCA", name: "Review outstanding vulns to weigh priority", defaultMinutes: 8, includedByDefault: true },

    { group: "Remediation", name: "Identify asset owner (repo/service/team)", defaultMinutes: 8, includedByDefault: true },
    { group: "Remediation", name: "Gather deployment details", defaultMinutes: 8, includedByDefault: true },
    { group: "Remediation", name: "Create a ticket and follow up", defaultMinutes: 6, includedByDefault: true },
    { group: "Remediation", name: "Developer reviews evidence and investigates further", defaultMinutes: 20, includedByDefault: true },
    { group: "Remediation", name: "Developer creates PR and commits the fix", defaultMinutes: 45, includedByDefault: true }
  ];
}

function buildInitialState() {
  return getDefaultTasks().map((task, index) => ({
    id: String(index + 1),
    group: task.group,
    name: task.name,
    minutes: task.defaultMinutes,
    included: Boolean(task.includedByDefault),
    defaultMinutes: task.defaultMinutes,
    lockedByJit: false
  }));
}

// ----- Helpers -----
function groupTasks(tasks) {
  const map = new Map();
  for (const t of tasks) {
    if (!map.has(t.group)) map.set(t.group, []);
    map.get(t.group).push(t);
  }
  return map;
}
function computeTotals(tasks) { const perGroupTotals = new Map(); let totalMinutes = 0; for (const t of tasks) { const val = t.included ? Math.max(0, Number(t.minutes) || 0) : 0; if (!perGroupTotals.has(t.group)) perGroupTotals.set(t.group, 0); perGroupTotals.set(t.group, perGroupTotals.get(t.group) + val); totalMinutes += val; } return { totalMinutes, perGroupTotals }; }

function applyJitMode(tasks, enabled) {
  const zeroSet = new Set([
    "Triage|Check if it’s a duplicate of an existing issue",
    "Triage|Validate scanner rule quality and detection in code context",
    "Triage|Confirm affected asset is still in use",
    "Triage|Review historical vulnerabilities on the same asset/component",
    "Triage|Identify which environment it affects (prod/staging/dev)",
    "Confirm exploitability & impact|Determine data sensitivity of the asset",
    "Confirm exploitability & impact|Estimate potential business impact",
    "Confirm exploitability & impact|Scope blast radius",
    "Confirm exploitability & impact|Check threat intelligence / exploit DBs",
    "Confirm exploitability & impact|Assess exposure surface (internet-facing vs internal)",
    "Confirm exploitability & impact|Investigate potential attack paths via toxic combinations",
    "Investigation / RCA|Collect logs, stack traces, telemetry",
    "Investigation / RCA|Trace the vulnerable code path or misconfig",
    "Investigation / RCA|Identify affected versions/branches/deployments",
    "Investigation / RCA|Evaluate exploit preconditions (auth/roles)",
    "Investigation / RCA|Gather evidence (attack paths, code refs, CVEs)",
    "Remediation|Identify asset owner (repo/service/team)",
    "Remediation|Gather deployment details",
    "Remediation|Create a ticket and follow up"
  ]);
  for (const t of tasks) {
    const key = `${t.group}|${t.name}`;
    if (enabled && zeroSet.has(key)) { t.minutes = 0; t.lockedByJit = true; }
    else if (!enabled && t.lockedByJit) { t.minutes = t.defaultMinutes; t.lockedByJit = false; }
    else { t.lockedByJit = false; }
  }
}

// ----- False positive modeling -----
function getFpInputs() { const tri=document.getElementById("fpTriage"), imp=document.getElementById("fpImpact"), rep=document.getElementById("fpRepro"), rca=document.getElementById("fpRca"); return { tri: Math.max(0, Number(tri?.value)||0), imp: Math.max(0, Number(imp?.value)||0), rep: Math.max(0, Number(rep?.value)||0), rca: Math.max(0, Number(rca?.value)||0) }; }

function computeExpectedMinutes(tasks) {
  const { totalMinutes, perGroupTotals } = computeTotals(tasks);
  const order = ["Triage","Confirm exploitability & impact","Reproduction","Investigation / RCA","Remediation"];
  let cum = 0; const cumMap = new Map(); for (const g of order) { const add = perGroupTotals.get(g)||0; cum += add; cumMap.set(g,cum); }
  const fp = getFpInputs(); const sumFp = Math.min(100, fp.tri+fp.imp+fp.rep+fp.rca); const remainder = Math.max(0, 100-sumFp);
  const expected = (fp.tri/100)*(cumMap.get("Triage")||0) + (fp.imp/100)*(cumMap.get("Confirm exploitability & impact")||0) + (fp.rep/100)*(cumMap.get("Reproduction")||0) + (fp.rca/100)*(cumMap.get("Investigation / RCA")||0) + (remainder/100)*totalMinutes;
  const note=document.getElementById("fpNote"); if(note){ note.textContent = `Allocated ${sumFp}% to stop-stages; ${remainder}% go full path.`; }
  return { expectedMinutes: Math.round(expected), totalMinutes, perGroupTotals };
}

function renderFpSplit(tasks) {
  const { totalMinutes, perGroupTotals } = computeExpectedMinutes(tasks);
  const order=["Triage","Confirm exploitability & impact","Reproduction","Investigation / RCA","Remediation"]; let cum=0; const cumMap=new Map(); order.forEach(g=>{ cum += (perGroupTotals.get(g)||0); cumMap.set(g,cum); });
  const fp=getFpInputs(); const fpMinutes=(fp.tri/100)*(cumMap.get("Triage")||0)+(fp.imp/100)*(cumMap.get("Confirm exploitability & impact")||0)+(fp.rep/100)*(cumMap.get("Reproduction")||0)+(fp.rca/100)*(cumMap.get("Investigation / RCA")||0); const remainder=Math.max(0,100-(fp.tri+fp.imp+fp.rep+fp.rca)); const realMinutes=(remainder/100)*totalMinutes; const totalExpected = fpMinutes+realMinutes; const fpPct=totalExpected?Math.round((fpMinutes/totalExpected)*100):0; const realPct=100-fpPct;
  const fpFill=document.getElementById("fpFillFp"), realFill=document.getElementById("fpFillReal"), fpLbl=document.getElementById("fpMinutesLabel"), realLbl=document.getElementById("realMinutesLabel"); if(fpFill) fpFill.style.width=fpPct+"%"; if(realFill) realFill.style.width=realPct+"%"; if(fpLbl) fpLbl.textContent=`${Math.round(fpMinutes)} min`; if(realLbl) realLbl.textContent=`${Math.round(realMinutes)} min`;
}

// Summary / ROI / Spend
function updateExpectedSummary(tasks) { const { expectedMinutes } = computeExpectedMinutes(tasks); const m=document.getElementById("totalMinutes"); if(m) m.textContent=String(expectedMinutes); }
function computeAndRenderRoi(tasks) {
  const hr=document.getElementById('hourlyRate'), vol=document.getElementById('issuesPerMonth'), val=document.getElementById('roiValue'), bar=document.getElementById('roiFill'); if(!hr||!vol||!val||!bar) return;
  const rate=Math.max(0, Number(hr.value)||0), issues=Math.max(0, Number(vol.value)||0);
  const jitToggle=document.getElementById('jitToggle');
  if (!jitToggle || !jitToggle.checked) { val.textContent='$0'; bar.style.width='0%'; return; }
  const without=computeExpectedMinutes(buildInitialState()).expectedMinutes;
  const cloned=tasks.map(t=>({...t}));
  applyJitMode(cloned, true);
  const withJit=computeExpectedMinutes(cloned).expectedMinutes;
  const saved=(without-withJit);
  const hours=saved*issues/60;
  const dollars=hours*rate;
  val.textContent=`$${Math.round(dollars).toLocaleString()}`;
  const cap=50000;
  bar.style.width=Math.max(0, Math.min(100, Math.round((dollars/cap)*100)))+"%";
}
function computeAndRenderSpend(tasks) {
  const hr=document.getElementById('hourlyRate'), vol=document.getElementById('issuesPerMonth'), val=document.getElementById('spendValue'); if(!hr||!vol||!val) return;
  const rate=Math.max(0, Number(hr.value)||0), issues=Math.max(0, Number(vol.value)||0);
  const { expectedMinutes } = computeExpectedMinutes(tasks);
  const dollars = (expectedMinutes/60) * issues * rate;
  val.textContent = `$${Math.round(dollars).toLocaleString()}`;
}

// Donut + legend
function renderStageDonut(tasks) {
  const canvas=document.getElementById('donutCanvas'); if(!canvas) return; const ctx=canvas.getContext('2d'); const { perGroupTotals }=computeTotals(tasks); const order=['Triage','Confirm exploitability & impact','Reproduction','Investigation / RCA','Remediation']; const values=order.map(g=>perGroupTotals.get(g)||0); const total=values.reduce((a,b)=>a+b,0)||1; const colors=['#ff9abf','#9ad8ff','#ffd57a','#a7f3d0','#c7c6ff']; const cx=canvas.width/2, cy=canvas.height/2, r=Math.min(cx,cy)-10, ir=r*0.6; ctx.clearRect(0,0,canvas.width,canvas.height); let start=-Math.PI/2; values.forEach((v,i)=>{ const angle=(v/total)*Math.PI*2; ctx.beginPath(); ctx.moveTo(cx,cy); ctx.arc(cx,cy,r,start,start+angle); ctx.closePath(); ctx.fillStyle=colors[i%colors.length]; ctx.fill(); start+=angle; }); ctx.globalCompositeOperation='destination-out'; ctx.beginPath(); ctx.arc(cx,cy,ir,0,Math.PI*2); ctx.fill(); ctx.globalCompositeOperation='source-over';
  const legend=document.getElementById('stageLegend'); if(legend){ legend.innerHTML=''; order.forEach((g,i)=>{ const row=document.createElement('div'); row.className='legend-row'; const dot=document.createElement('span'); dot.className='dot'; dot.style.backgroundColor=colors[i%colors.length]; const label=document.createElement('span'); label.textContent=g; const val=document.createElement('span'); val.className='legend-val'; val.textContent=(perGroupTotals.get(g)||0)+' min'; row.appendChild(dot); row.appendChild(label); row.appendChild(val); legend.appendChild(row); }); }
}

// Rendering
function renderApp(tasks) {
  const container=document.getElementById("groupsContainer"); container.innerHTML=""; const groups=groupTasks(tasks); updateExpectedSummary(tasks); renderFpSplit(tasks); renderStageDonut(tasks); computeAndRenderSpend(tasks);
  for (const [groupName, list] of groups.entries()) {
    const groupEl=document.createElement("section"); groupEl.className="group";
    const header=document.createElement("div"); header.className="group-header"; const title=document.createElement("div"); title.className="group-title"; title.textContent=groupName; const subtotal=document.createElement("div"); subtotal.className="group-subtotal"; subtotal.textContent=`${computeTotals(list).totalMinutes} min`; header.appendChild(title); header.appendChild(subtotal);
    const tasksEl=document.createElement("div"); tasksEl.className="tasks";
    for (const t of list) {
      const row=document.createElement("div"); row.className=`task${t.included?"":" disabled"}`; const label=document.createElement("label"); const cb=document.createElement("input"); cb.type="checkbox"; cb.checked=t.included; cb.setAttribute("aria-label",`Include ${t.name}`); cb.addEventListener("change",()=>{ t.included=cb.checked; renderEverything(tasks); }); label.appendChild(cb); const name=document.createElement("div"); name.className="task-name"; name.textContent=t.name; const controls=document.createElement("div"); controls.className="task-controls"; const input=document.createElement("input"); input.type="number"; input.min="0"; input.step="1"; input.inputMode="numeric"; input.value=String(t.minutes); input.disabled=!t.included || t.lockedByJit===true; input.addEventListener("input",()=>{ const v=Math.max(0, Math.floor(Number(input.value)||0)); input.value=String(v); t.minutes=v; subtotal.textContent=`${computeTotals(list).totalMinutes} min`; updateExpectedSummary(tasks); renderFpSplit(tasks); renderStageDonut(tasks); computeAndRenderRoi(tasks); computeAndRenderSpend(tasks); }); const unit=document.createElement("span"); unit.className="minutes-label"; unit.textContent="min"; controls.appendChild(input); controls.appendChild(unit); row.appendChild(label); row.appendChild(name); row.appendChild(controls); tasksEl.appendChild(row);
    }
    // per-stage custom task input aligned with rows
    const addRow=document.createElement('div'); addRow.className='task custom-task-controls';
    const spacer=document.createElement('div'); spacer.style.width='16px';
    const addName=document.createElement('input'); addName.type='text'; addName.placeholder='New task name';
    const controls=document.createElement('div'); controls.className='task-controls';
    const addMin=document.createElement('input'); addMin.type='number'; addMin.min='0'; addMin.step='1'; addMin.placeholder='Minutes';
    const addBtn=document.createElement('button'); addBtn.className='button button-add'; addBtn.type='button'; addBtn.textContent='Add task';
    addBtn.addEventListener('click', ()=>{ const name=(addName.value||'').trim(); const minutes=Math.max(0, Math.floor(Number(addMin.value)||0)); if(!name) return; tasks.push({ id:String(Date.now()), group: groupName, name, minutes, included:true, defaultMinutes: minutes, lockedByJit:false }); addName.value=''; addMin.value=''; renderEverything(tasks); });
    controls.appendChild(addMin); controls.appendChild(addBtn);
    addRow.appendChild(spacer); addRow.appendChild(addName); addRow.appendChild(controls);

    groupEl.appendChild(header); groupEl.appendChild(tasksEl); groupEl.appendChild(addRow); container.appendChild(groupEl);
  }
}

function renderEverything(tasks) { const jitToggle=document.getElementById("jitToggle"); const jitEnabled=Boolean(jitToggle && jitToggle.checked); applyJitMode(tasks, jitEnabled); renderApp(tasks); computeAndRenderRoi(tasks); }

// Init
document.addEventListener("DOMContentLoaded",()=>{ const tasks=buildInitialState(); const jitToggle=document.getElementById("jitToggle"); if(jitToggle){ jitToggle.checked=false; jitToggle.addEventListener("change",()=>renderEverything(tasks)); } ["fpTriage","fpImpact","fpRepro","fpRca"].forEach(id=>{ const el=document.getElementById(id); if(el) el.addEventListener("input",()=>renderEverything(tasks)); }); const hr=document.getElementById('hourlyRate'), vol=document.getElementById('issuesPerMonth'); if(hr) hr.addEventListener("input",()=>{ computeAndRenderRoi(tasks); computeAndRenderSpend(tasks); }); if(vol) vol.addEventListener("input",()=>{ computeAndRenderRoi(tasks); computeAndRenderSpend(tasks); }); renderEverything(tasks); });
