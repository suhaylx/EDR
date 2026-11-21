'use strict';
// The SOC console is deliberately a lab-only UI. Values come from the Go API;
// no synthetic detections, endpoint status or scan result is fabricated here.
const state={token:'',view:'overview',days:7,agentFilter:'',graph:null,data:{}};
const $=id=>document.getElementById(id);
const esc=value=>String(value??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const count=n=>Number(n||0).toLocaleString('en-US');
const labelTime=t=>t?new Date(t).toLocaleString(undefined,{dateStyle:'medium',timeStyle:'short'}):'Never reported';
const rows=(arr,keys)=>arr.length?`<div class="table-wrap"><table><thead><tr>${keys.map(k=>`<th>${esc(k[0])}</th>`).join('')}</tr></thead><tbody>${arr.map(x=>`<tr>${keys.map(k=>`<td>${esc(typeof k[1]==='function'?k[1](x):x[k[1]])}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`:'<div class="empty">No records for this selection. This does not establish the fleet is safe.</div>';
const notice=(msg,failed=false)=>{const n=$('notice');n.textContent=msg;n.className=failed?'danger':'';};
async function api(path,opt={}){if(!state.token)throw Error('Enter a development API token first.');const r=await fetch('/api'+path,{...opt,headers:{Authorization:'Bearer '+state.token,...(opt.body?{'Content-Type':'application/json'}:{}),...(opt.headers||{})}});if(!r.ok)throw Error((await r.text()).slice(0,200));return r.json();}
async function refresh(){try{const paths=['/overview?days='+state.days,'/agents','/events','/detections','/policies','/assignments','/scan-jobs'];const [overview,agents,events,alerts,policies,assignments,scans]=await Promise.all(paths.map(p=>api(p)));state.data={overview,agents,events,alerts,policies,assignments,scans};notice('Connected to the development Go API. Metrics cover retained in-memory telemetry, not verified production endpoint protection.');draw();}catch(e){notice('Connection failed: '+e.message,true);}}
function navigate(view,filter=''){const target=document.querySelector(`.nav[data-view="${view}"]`);if(!target)return;document.querySelectorAll('.nav').forEach(b=>{b.classList.toggle('active',b===target);b.setAttribute('aria-current',b===target?'page':'false');});state.view=view;state.agentFilter=filter;draw();}
const formatInactive=e=>e.status==='unknown'?'Unknown (no trustworthy heartbeat)':e.status==='online'?'Active now':e.inactive_days<1?`${Math.max(0,Math.round(e.inactive_seconds/60))} minutes`:`${e.inactive_days.toFixed(2)} days`;
const renderPill=e=>e==='online'?'Online':e==='offline'?'Offline':'Unknown';
function statCard(title,value,description,nav,filter=''){
  return `<button type="button" class="card stat-card" data-go="${esc(nav)}" data-filter="${esc(filter)}" aria-label="Open ${esc(title)} details"><span>${esc(title)}</span><strong>${esc(count(value))}</strong><small>${esc(description)}</small><span class="card-link">View details &rarr;</span></button>`;
}
function barList(items, label, value, modifier=''){
  if(!items.length)return '<div class="empty">No observed activity in this period.</div>';
  const max=Math.max(1,...items.map(x=>Number(value(x)||0)));
  return `<div class="bar-list">${items.map(x=>{const n=Number(value(x)||0);return `<div class="bar-row"><div class="bar-title"><span title="${esc(label(x))}">${esc(label(x))}</span><strong>${esc(count(n))}</strong></div><div class="bar-track"><div class="bar-fill ${esc(modifier)}" style="width:${Math.max(0,Math.min(100,n/max*100))}%"></div></div></div>`;}).join('')}</div>`;
}
const chartDays=arr=>{
  if(!arr.length)return '<div class="empty">No daily summary.</div>';
  const max=Math.max(1,...arr.map(x=>x.count));
  return `<div class="daily-chart" role="img" aria-label="Daily alerts (UTC): ${esc(arr.map(x=>x.day+': '+x.count).join(', '))}">${arr.map(x=>`<div class="daily-col" title="${esc(x.day+': '+x.count+' alerts')}"><span>${esc(x.count)}</span><div class="daily-bar" style="height:${Math.max(x.count?4:0,x.count/max*100)}%"></div><small>${esc(x.day.slice(5))}</small></div>`).join('')}</div>`;
};
function overviewHTML(d){
  const o=d.overview, offline=(o.inactive_machines||[]), rankings=(o.most_active||[]), sev=o.severity||[];
  const coverage=o.agents?Math.round(100*o.online/o.agents):0;
  const unsupported=(o.unavailable||[]).map(x=>x.replaceAll('_',' '));
  return `<section class="toolbar panel toolbar-panel"><div><h2>Fleet security overview</h2><p>Endpoint activity is based on server-received heartbeats within ${esc(o.heartbeat_ttl_seconds/60)} minutes. Counts reflect retained in-memory lab telemetry, not a complete security history.</p></div><div class="field compact-field"><label for="windowDays">Time window (UTC calendar days)</label><select id="windowDays"><option value="1" ${state.days===1?'selected':''}>Today</option><option value="7" ${state.days===7?'selected':''}>Last 7 days</option><option value="30" ${state.days===30?'selected':''}>Last 30 days</option></select></div></section>
  <div class="cards overview-cards">${statCard('Managed agents',o.agents,'Enrolled lab records','agents')}${statCard('Online agents',o.online,'Heartbeat within 5 minutes','agents','online')}${statCard('Offline agents',o.offline,'Last heartbeat more than 5 minutes ago','agents','offline')}${statCard('Unknown status',o.unknown,'No valid recent server heartbeat','agents','unknown')}${statCard('Alerts',o.alerts,'Heuristic detections in selected window','alerts')}${statCard('Critical + high',o.high_risk_alerts,'High-severity observed detections','alerts')}${statCard('Retained events',o.events,'Events received in selected window','events')}${statCard('Failed scan jobs',o.scans.failed,'Reported failed or expired jobs','scans')}</div>
  <div class="overview-grid"><section class="panel"><div class="section-heading"><h2>Daily alerts</h2><span class="section-meta">UTC · ${esc(state.days)} day${state.days===1?'':'s'}</span></div>${chartDays(o.alert_trend||[])}<p class="section-note">Generated from the existing prototype detection rule. Alert totals do not equal confirmed infections or incidents.</p></section>
  <section class="panel"><div class="section-heading"><h2>Alerts by severity</h2><button class="text-link" type="button" data-go="alerts">Inspect alerts</button></div>${barList(sev,x=>x.severity,x=>x.count,'severity-bar')}<p class="section-note">Explicit zeroes mean no matching retained alerts, not proof that threats are absent.</p></section></div>
  <div class="overview-grid"><section class="panel"><div class="section-heading"><h2>Most active machines</h2><span class="section-meta">Ranked by recorded event volume</span></div>${rows(rankings,[['Endpoint','id'],['OS','platform'],['Events','events'],['Alerts','alerts'],['Status',x=>renderPill(x.status)]])}<p class="section-note">Activity means telemetry count, not CPU utilization, maliciousness or network bandwidth.</p></section>
  <section class="panel"><div class="section-heading"><h2>Inactive machines</h2><button class="text-link" type="button" data-go="agents" data-filter="offline">Open endpoint list</button></div>${rows(offline,[['Endpoint','id'],['OS','platform'],['Last heartbeat',x=>labelTime(x.last_seen)],['Inactive for',formatInactive],['Events','events']])}<p class="section-note">Duration is calculated from last server-received heartbeat. Missing heartbeat time is shown as unknown, not an invented number of days.</p></section></div>
  <div class="overview-grid"><section class="panel"><div class="section-heading"><h2>Most-triggered detection rules</h2><button class="text-link" type="button" data-go="alerts">Explore rule hits</button></div>${barList(o.top_rules||[],x=>x.rule_id,x=>x.count)}<p class="section-note">This counts alert-generating rule matches. It does not count installed rules, Sysmon logging events or signature database entries.</p></section>
  <section class="panel"><div class="section-heading"><h2>Applied policy coverage</h2><button class="text-link" type="button" data-go="policies">Open policies</button></div>${rows(o.policy_coverage||[],[['Policy','policy_name'],['Endpoints','endpoints'],['Policy ID','policy_id']])}<div class="status-summary"><div><strong>${esc(coverage)}%</strong><small>agents online now</small></div><div><strong>${esc(count(o.policy_errors))}</strong><small>reported policy errors</small></div></div><p class="section-note">Applied policy acknowledgments are not equivalent to verified Sysmon rule execution.</p></section></div>
  <div class="overview-grid"><section class="panel"><h2>Scan job health</h2><div class="scan-health">${[['Queued',o.scans.queued],['Leased',o.scans.leased],['Completed',o.scans.completed],['Failed / expired',o.scans.failed]].map(x=>`<div><span>${esc(x[0])}</span><strong>${esc(count(x[1]))}</strong></div>`).join('')}</div><p class="section-note">These are lab job states. A completed job is an agent-reported result, not independent ClamAV proof.</p></section>
  <section class="panel"><h2>Security visibility gaps · Agent 1</h2><p>Unavailable metrics are clearly labeled until authenticated endpoint telemetry, real AV execution and persistence exist.</p><div class="gap-list">${unsupported.map(x=>`<span class="gap-item">Not instrumented: ${esc(x)}</span>`).join('')}</div></section></div>
  <section class="panel"><div class="section-heading"><h2>Recent endpoint events</h2><button class="text-link" type="button" data-go="events">Open telemetry</button></div>${rows(d.events.slice(-10).reverse(),[['Time',x=>labelTime(x.time)],['Agent','device_id'],['Type','type'],['Image / file',x=>x.image||x.file_path||'—']])}</section>
  <div class="data-stamp">Overview generated ${esc(labelTime(o.generated_at))}. No tenant isolation, durable history or live agent protection is available in this laboratory prototype.</div>`;
}
function incidentGraphHTML(g){
  const nodes=g.nodes||[], edges=g.edges||[];
  const byID=new Map(nodes.map(n=>[n.id,n]));
  const processes=nodes.filter(n=>n.kind==='process');
  const procEdges=edges.filter(e=>e.relation==='parent_process');
  const parent=new Map(procEdges.map(e=>[e.to,e]));
  const children=new Map();
  for(const edge of procEdges){if(!children.has(edge.from))children.set(edge.from,[]);children.get(edge.from).push(edge.to);}
  const visited=new Set();
  function processTree(id){
    if(visited.has(id))return '';
    visited.add(id);
    const p=byID.get(id);if(!p)return '';
    const edge=parent.get(id), relation=edge?edge.provenance:'root/unknown';
    const extra=nodes.filter(n=>n.kind==='event'&&n.process_guid===p.process_guid).length;
    return `<li><div class="process-node"><strong>${esc(p.image||p.label)}</strong><span class="graph-tag">${esc(p.status)}</span><small>Process GUID: ${esc(p.process_guid)} · ${extra} retained event(s) · parent link: ${esc(relation)}</small></div>${children.get(id)?.length?`<ul>${children.get(id).map(processTree).join('')}</ul>`:''}</li>`;
  }
  const roots=processes.filter(n=>!parent.has(n.id)).map(n=>n.id);
  const forest=roots.concat(processes.map(n=>n.id));
  const tree=forest.map(processTree).join('');
  const activity=nodes.filter(n=>n.kind==='event'||n.kind==='detection').sort((a,b)=>(a.time||'').localeCompare(b.time||'')||a.id.localeCompare(b.id));
  const title=g.seed_detection_id?'Detection evidence graph':'Process evidence graph';
  return `<section class="panel"><div class="section-heading"><h2>${esc(title)}</h2><span class="graph-tag">Retained lab evidence only</span></div><p>Host: <strong>${esc(g.device_id)}</strong> · Seed Process GUID: <code>${esc(g.seed_process_guid)}</code> · ${nodes.length} node(s) · ${edges.length} edge(s)</p><p>This view shows observed/reported relationships, not a verified full infection chain or confirmed malicious execution.</p>${g.truncated?'<p class="graph-warning">Graph truncated by configured node limit. Some evidence may be missing.</p>':''}</section>
  <div class="overview-grid"><section class="panel"><h2>Process lineage</h2>${tree?`<ul class="process-tree">${tree}</ul>`:'<div class="empty">No process lineage within the retained events.</div>'}<p class="section-note">Parent links are labeled OBSERVED only when supported by a retained process-create event. Other links are reported, not confirmed.</p></section>
  <section class="panel"><h2>Evidence timeline</h2>${activity.length?`<ol class="evidence-timeline">${activity.map(n=>`<li><time>${esc(labelTime(n.time))}</time><strong>${esc(n.kind==='detection'?'Detection · '+n.label:n.event_type)}</strong><span>${esc(n.file_path||n.detail||n.label)}</span><small>Process: ${esc(n.process_guid||'not reported')} · ${esc(n.event_id||n.id)}${n.kind==='detection'?' · '+esc(n.severity+' / '+n.confidence):''}</small></li>`).join('')}</ol>`:'<div class="empty">No retained events support this selected process.</div>'}</section></div>
  <section class="panel"><h2>Investigation coverage and uncertainties</h2><ul class="coverage-gaps">${(g.gaps||[]).map(x=>`<li>${esc(x)}</li>`).join('')}</ul><p class="section-note">Supported evidence types can include process, file, loaded DLL, DNS, network, registry and detection observations. Only signals actually received and retained can appear. Not all links imply cause and effect.</p></section>`;
}
function investigationViewHTML(d){
  const detections=d.alerts||[];
  const options=detections.map(x=>`<option value="${esc(x.id)}">${esc(x.device_id+' · '+x.rule_id+' · '+x.process_image)}</option>`).join('');
  return `<section class="panel"><h2>Trace the complete observed process story</h2><p>Start from a real detection record or enter an observed process GUID. Follow parent/child processes and the available file, module, DNS and network activity. A graph cannot reconstruct events that were never collected.</p><form id="graphForm" class="graph-search stack"><div class="field"><label for="graphDetection">Detection seed (optional)</label><select id="graphDetection"><option value="">Select a detection or enter a Process GUID</option>${options}</select></div><div class="field"><label for="graphDevice">Endpoint ID</label><input id="graphDevice" required maxlength="96" placeholder="win-lab-01" value="${esc(state.graph?.device_id||detections[0]?.device_id||'')}"></div><div class="field"><label for="graphProcess">Process GUID (used when no detection selected)</label><input id="graphProcess" maxlength="160" placeholder="{process-guid}" value="${esc(state.graph?.seed_process_guid||'')}"></div><button type="submit">Build evidence graph</button></form><p class="section-note">Lab-only query. All graph nodes are restricted to one endpoint. Production tenant scoping, durable collection, and event provenance are not implemented.</p></section>${state.graph?incidentGraphHTML(state.graph):'<section class="panel empty">No investigation loaded. Select a detection above or enter an endpoint and process GUID.</section>'}`;
}
function bindInvestigationForm(){
  const form=$('graphForm');if(!form)return;
  $('graphDetection').addEventListener('change',e=>{
    const d=(state.data.alerts||[]).find(x=>x.id===e.target.value);
    if(d){$('graphDevice').value=d.device_id;$('graphProcess').value=d.process_guid||'';}
  });
  form.addEventListener('submit',async e=>{
    e.preventDefault();
    const dev=$('graphDevice').value.trim(), det=$('graphDetection').value, proc=$('graphProcess').value.trim();
    if(!dev||(!det&&!proc)){notice('Choose a detection or enter an endpoint and Process GUID.',true);return;}
    const params=new URLSearchParams({device_id:dev,depth:'4',max_nodes:'250'});
    if(det)params.set('detection_id',det);else params.set('process_guid',proc);
    try{state.graph=await api('/investigations?'+params);notice('Graph loaded from retained events. It is not proof of a full infection or complete telemetry coverage.');draw();}
    catch(err){state.graph=null;notice('Graph unavailable: '+err.message,true);draw();}
  });
}
function draw(){
  const v=state.view;const labels={overview:['Security overview','Fleet heartbeat status, detections, rule hits and operational visibility'],agents:['Agent management','Enrolled Windows and Linux agents'],alerts:['Security alerts','Heuristic detection evidence; no confirmed malware classification'],scans:['AV scan jobs','Queue an agent scan request; actual ClamAV scanning is not connected'],events:['Telemetry & triage','Raw endpoint events (not yet correlated incidents)'],policies:['Sysmon policy library','Create and inspect policy drafts. Applying to endpoints is not implemented.'],assignments:['Policy assignments','Assign a desired policy to an agent or group'],investigations:['Process & incident graph','Observed process lineage, related evidence and missing telemetry']};$('viewTitle').textContent=labels[v][0];$('viewHint').textContent=labels[v][1];const d=state.data;const c=$('content');if(!d.overview){c.innerHTML='';return;}
  if(v==='overview'){
    c.innerHTML=overviewHTML(d);
    $('windowDays').addEventListener('change',e=>{state.days=Number(e.target.value);refresh();});
  }else if(v==='agents'){
    const all=d.overview.endpoints||[];
    const filtered=state.agentFilter?all.filter(x=>x.status===state.agentFilter):all;
    c.innerHTML=`<section class="panel"><div class="section-heading"><h2>Agent inventory</h2><div class="field compact-field"><label for="agentStatus">Heartbeat status</label><select id="agentStatus"><option value="" ${state.agentFilter===''?'selected':''}>All agents</option>${['online','offline','unknown'].map(s=>`<option value="${s}" ${state.agentFilter===s?'selected':''}>${s}</option>`).join('')}</select></div></div>${rows(filtered,[['ID','id'],['OS','platform'],['Group','group'],['Status','status'],['Last seen',x=>labelTime(x.last_seen)],['Inactive for',formatInactive],['Events','events'],['Alerts','alerts'],['Reported health','reported_health'],['Policy error',x=>x.last_policy_error||'—']])}<p class="section-note">Status is derived from last server-received heartbeat, not the agent-reported health label. Event/alert counts use the selected overview time window.</p></section>`;
    $('agentStatus').addEventListener('change',e=>{state.agentFilter=e.target.value;draw();});
  }else if(v==='alerts'){
    const now=new Date();
    const start=Date.UTC(now.getUTCFullYear(),now.getUTCMonth(),now.getUTCDate()-(state.days-1));
    const alerts=d.alerts.filter(x=>{const timestamp=new Date(x.observed_at).getTime();return timestamp>=start&&timestamp<=now.getTime();});
    c.innerHTML=`<section class="panel"><h2>Detection signals · ${esc(state.days)}-day window</h2><p>Generated by the prototype DLL-load correlation rule. A detection is an investigation signal, not a confirmed compromise or an automated block.</p>${rows(alerts,[['Observed',x=>labelTime(x.observed_at)],['Severity','severity'],['Confidence','confidence'],['Endpoint','device_id'],['Rule','rule_id'],['Process','process_image'],['Loaded module','module_path'],['Signals',x=>(x.signals||[]).join(', ')],['Evidence','load_event_id']])}</section><section class="panel"><h2>Trace observed attack context</h2><p>Build a process and evidence graph from one of these detected signals; every displayed relationship has an evidence identifier.</p><div class="graph-actions">${alerts.slice(0,20).map(x=>`<button type="button" data-trace="${esc(x.id)}" data-device="${esc(x.device_id)}">Investigate ${esc(x.rule_id)} · ${esc(x.device_id)}</button>`).join('')||'<p class="empty">No detection available to investigate.</p>'}</div></section>`;
    c.querySelectorAll('[data-trace]').forEach(btn=>btn.addEventListener('click',async()=>{
      try{state.graph=await api('/investigations?'+new URLSearchParams({device_id:btn.dataset.device,detection_id:btn.dataset.trace,depth:'4',max_nodes:'250'}));navigate('investigations');}catch(err){notice('Unable to build investigation: '+err.message,true);}
    }));
  }else if(v==='investigations'){
    c.innerHTML=investigationViewHTML(d);
    bindInvestigationForm();
  }else if(v==='scans'){
    const options=d.agents.map(x=>`<option value="${esc(x.id)}">${esc(x.id+' ('+x.platform+')')}</option>`).join('');c.innerHTML=`<section class="panel"><h2>Scan history</h2><p>Development lab only: these are queued commands and agent-claimed results, not verified ClamAV detections.</p>${rows([...d.scans].reverse(),[['Requested','created_at'],['Agent','agent_id'],['Mode','scan_type'],['Status','status'],['Verdict',x=>x.verdict||'Not scanned'],['Engine',x=>x.engine||'—'],['Details','detail']])}</section><section class="panel"><h2>Request a scan (does not execute locally)</h2><form id="newScan" class="stack"><div class="field"><label for="scanAgent">Endpoint</label><select id="scanAgent" required>${options}</select></div><div class="field"><label for="scanMode">Scan type</label><select id="scanMode"><option value="quick">Quick</option><option value="full">Full</option><option value="path">Custom path</option></select></div><div class="field"><label for="scanPath">Absolute device-local path (custom scan only)</label><input id="scanPath" autocomplete="off" placeholder="C:\\Windows\\System32 or /home/user"></div><button type="submit" ${options?'':'disabled'}>Queue scan</button></form><p>Requires a real authenticated Rust agent and ClamAV worker to execute. Never interpret a queued scan as protection.</p></section>`;
    $('newScan').addEventListener('submit',async e=>{e.preventDefault();try{const scan_type=$('scanMode').value;const payload={agent_id:$('scanAgent').value,request_id:'ui-'+globalThis.crypto.randomUUID(),scan_type};if(scan_type==='path')payload.path=$('scanPath').value.trim();await api('/scan-jobs',{method:'POST',body:JSON.stringify(payload)});await refresh();notice('Scan request queued. No scan has executed yet.');}catch(err){notice('Scan not queued: '+err.message,true);}});
  }else if(v==='events'){
    c.innerHTML=`<section class="panel"><h2>Raw event stream</h2>${rows([...d.events].reverse(),[['Timestamp','time'],['Source','source'],['Host','device_id'],['Type','type'],['Process','image'],['File','file_path'],['SHA-256','sha256']])}</section>`;
  }else if(v==='policies'){
    c.innerHTML=`<section class="panel"><h2>Existing policies</h2>${rows(d.policies,[['Name','name'],['OS','platform'],['Revision','revision'],['SHA-256','sha256'],['ID','id']])}</section><section class="panel"><h2>Create XML policy (lab only)</h2><form class="stack" id="newPolicy"><div class="field"><label for="pname">Policy name</label><input id="pname" required maxlength="96" placeholder="Windows workstation"></div><div class="field"><label for="platform">Operating system</label><select id="platform"><option value="windows">Windows</option><option value="linux">Linux</option></select></div><div class="field"><label for="xml">Sysmon XML (syntax check only; no runtime schema validation)</label><textarea id="xml" spellcheck="false" required placeholder="&lt;Sysmon schemaversion=...&gt;...&lt;/Sysmon&gt;"></textarea></div><button type="submit">Save policy revision</button></form></section>`;
    $('newPolicy').addEventListener('submit',async e=>{e.preventDefault();try{await api('/policies',{method:'POST',body:JSON.stringify({name:$('pname').value,platform:$('platform').value,xml:$('xml').value})});await refresh();notice('Saved lab policy record. Not deployed to endpoints.');}catch(err){notice(err.message,true);}});
  }else if(v==='assignments'){
    const options=d.policies.map(x=>`<option value="${esc(x.id)}">${esc(x.name+' ('+x.platform+', v'+x.revision+')')}</option>`).join('');c.innerHTML=`<section class="panel"><h2>Policy assignments</h2>${rows(d.assignments,[['Scope','target_type'],['Target','target_id'],['Platform','platform'],['Policy ID','policy_id']])}</section><section class="panel"><h2>Assign desired policy (lab only)</h2><form id="newAssign" class="stack"><div class="field"><label for="ttype">Target scope</label><select id="ttype"><option value="agent">Single agent</option><option value="group">Group</option><option value="default">Platform default</option></select></div><div class="field"><label for="target">Agent ID or group name</label><input id="target" placeholder="win-lab-01" required></div><div class="field"><label for="aplat">Platform</label><select id="aplat"><option>windows</option><option>linux</option></select></div><div class="field"><label for="policy">Desired policy</label><select id="policy">${options}</select></div><button ${options?'':'disabled'} type="submit">Save assignment</button></form><p>Saving an assignment does not reconfigure Sysmon. Agent-side safe apply and rollback are future work.</p></section>`;
    $('newAssign').addEventListener('submit',async e=>{e.preventDefault();try{await api('/assignments',{method:'POST',body:JSON.stringify({target_type:$('ttype').value,target_id:$('target').value,platform:$('aplat').value,policy_id:$('policy').value})});await refresh();notice('Desired assignment saved in lab store. No endpoint change made.');}catch(err){notice(err.message,true);}});
  }
  c.querySelectorAll('[data-go]').forEach(b=>b.addEventListener('click',()=>navigate(b.dataset.go,b.dataset.filter||'')));
}
document.querySelectorAll('.nav').forEach(b=>b.addEventListener('click',()=>navigate(b.dataset.view)));
$('connect').addEventListener('click',()=>{state.token=$('token').value;$('token').value='';refresh();});
$('refresh').addEventListener('click',refresh);
