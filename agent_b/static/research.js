'use strict';
const $ = s => document.querySelector(s);
let selected = null, notes = [], connection = null, busy = false, previewKey = '', deleteArmed = false;
function el(tag, text, parent) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if(parent) parent.append(node); return node; }
function status(text) { $('#activity').textContent = text; }
async function api(url, body) { const r = await fetch(url, body ? {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)} : {}); const result = await r.json(); if(!r.ok) throw new Error(result.error || 'Research request failed'); return result; }
function link(parent, text, url) { try { const u = new URL(url); if(u.protocol !== 'https:' || u.username || u.password) return; const a=el('a',text,parent); a.href=u.href; a.target='_blank'; a.rel='noopener noreferrer'; a.className='reference'; } catch {} }
function consentReset(form) { form.querySelectorAll('input[type=checkbox]').forEach(x=>{x.checked=false;}); }
function destination() { $('#model-destination').textContent = connection ? `Destination: ${connection.provider} · ${connection.model || 'no model selected'} · ${connection.destination || 'not configured'}` : 'Configure a model connection in Settings first.'; }
function buttons() { document.querySelectorAll('form button').forEach(b=>{b.disabled=busy;}); $('#check-dependencies').disabled=busy || previewKey !== manifestKey(); $('#cancel').hidden=!busy; $('#delete-note').disabled=busy; }
function manifestKey() { return JSON.stringify([$('#manifest-format').value,$('#manifest-text').value]); }
function resetPreview() { previewKey=''; $('#dependency-preview').hidden=true; $('#dependency-consent').checked=false; buttons(); }
async function refresh() {
  const data=await api('/api/research'); notes=data.notes;
  if(connection?.fingerprint !== data.connection.fingerprint) $('#model-consent').checked=false;
  connection=data.connection; destination(); busy=notes.some(n=>n.status==='running'); buttons();
  $('#notes').replaceChildren();
  if(!notes.length) el('p','No research yet. Start with an advisory or selected files above.',$('#notes'));
  notes.forEach(n=>{const b=el('button',n.title,$('#notes')); b.type='button'; b.className='note-button'; b.setAttribute('aria-pressed',String(selected?.id===n.id)); el('small',`${n.status} · ${n.created}`,b); b.onclick=()=>openNote(n.id).catch(e=>status(e.message));});
  if(selected?.status==='running') await openNote(selected.id);
}
async function openNote(id) {
  const n=await api('/api/research/'+encodeURIComponent(id));
  if(selected?.id!==id || selected?.status!==n.status) { $('#model-consent').checked=false; deleteArmed=false; }
  selected=n; $('#note-title').textContent=n.title; $('#note-meta').textContent=`${n.created} · ${n.status} · ${n.disclaimer}`;
  $('#note-content').replaceChildren(); $('#note-actions').hidden=n.status==='running'; $('#download-note').href='/api/research/'+n.id+'/download';
  $('#delete-note').textContent='Delete local note'; $('#review-form').hidden=n.status!=='complete'||n.kind==='review';
  document.querySelectorAll('.note-button').forEach((b,i)=>b.setAttribute('aria-pressed',String(notes[i]?.id===id)));
  if(n.status==='running') { el('p','Working on your selected material. Network requests have bounded timeouts; cancel stops subsequent work.',$('#note-content')); return; }
  if(n.error) { el('p',n.error,$('#note-content')); status(n.error); return; }
  const r=n.result||{};
  el('p',r.note||'',$('#note-content'));
  if(r.source_url) link($('#note-content'),'Advisory data source',r.source_url);
  if(r.summary) el('p',r.summary,$('#note-content'));
  if(r.withdrawn) el('p','WITHDRAWN advisory: '+r.withdrawn,$('#note-content'));
  if(r.published||r.modified) el('p',`Published: ${r.published||'not supplied'} · Modified: ${r.modified||'not supplied'}`,$('#note-content'));
  if(r.commit) el('p',`Pinned commit: ${r.commit}`,$('#note-content'));
  (r.files||[]).forEach(f=>{const details=el('details',undefined,$('#note-content')); el('summary',`${f.path} · ${f.lines} lines${f.redacted?' · redaction applied':''}`,details); el('p','Original SHA-256: '+f.sha256,details); if(f.source_url) link(details,'Pinned source',f.source_url); el('pre',f.text.split('\n').map((line,i)=>`${i+1}: ${line}`).join('\n'),details);});
  (r.matches||[]).forEach(m=>{const d=el('details',undefined,$('#note-content')); el('summary',`${m.package.name} ${m.version} (${m.package.ecosystem}) · ${m.advisories.length} advisory matches`,d); el('p',m.status+(m.truncated?' · Results truncated: look up individual advisories; this is not a complete result.':''),d); m.advisories.forEach(id=>link(d,id,'https://osv.dev/vulnerability/'+encodeURIComponent(id)));});
  if(r.skipped?.length) el('pre','Not checked:\n'+r.skipped.join('\n'),$('#note-content'));
  if(r.affected) el('pre','Published affected ranges (review FIX events and vendor backports):\n'+JSON.stringify(r.affected,null,2),$('#note-content'));
  (r.references||[]).forEach(ref=>link($('#note-content'),ref.type+' · '+ref.url,ref.url));
  if(r.review) { el('p',`Review of ${r.parent_title}; model output is unverified.`,$('#note-content')); el('pre',r.review,$('#note-content')); }
  status('Note ready. Inspect the evidence before deciding what to share or conclude.');
}
async function start(kind, body, form) {
  busy=true; buttons(); status('Starting read-only research…');
  try { const n=await api('/api/research/start',{kind,...body}); consentReset(form); await openNote(n.id); await refresh(); }
  catch(e) { status(e.message); busy=false; buttons(); }
}
$('#advisory-form').onsubmit=e=>{e.preventDefault(); start('advisory',{identifier:$('#identifier').value,allow_network:$('#advisory-consent').checked},e.target);};
$('#preview-dependencies').onclick=async()=>{try {const key=manifestKey(); const result=await api('/api/research/preview-dependencies',{format:$('#manifest-format').value,text:$('#manifest-text').value}); if(key!==manifestKey()) return; previewKey=key; $('#dependency-preview').textContent=JSON.stringify(result,null,2); $('#dependency-preview').hidden=false; buttons(); status('Preview is local. Only the listed package names and versions will be sent to OSV if you approve.');} catch(e){resetPreview();status(e.message);}};
$('#manifest-text').oninput=resetPreview; $('#manifest-format').onchange=resetPreview;
$('#manifest-file').onchange=async e=>{try {const f=e.target.files[0]; if(!f) return; if(f.size>120000) throw new Error('Manifest exceeds 120 KB'); $('#manifest-text').value=await f.text(); resetPreview();} catch(error){status(error.message);}};
$('#dependencies-form').onsubmit=e=>{e.preventDefault(); if(!previewKey||previewKey!==manifestKey()) {status('Preview the current manifest first.');return;} start('dependencies',{format:$('#manifest-format').value,text:$('#manifest-text').value,allow_network:$('#dependency-consent').checked},e.target);};
$('#github-form').onsubmit=e=>{e.preventDefault(); start('github',{repository:$('#repository').value,ref:$('#revision').value,paths:$('#source-paths').value.split('\n').map(s=>s.trim()).filter(Boolean),allow_network:$('#github-consent').checked},e.target);};
$('#upload-form').onsubmit=async e=>{e.preventDefault(); const form=e.target; try {const files=[...$('#source-files').files]; if(!files.length||files.length>6) throw new Error('Choose 1–6 source files.'); const payload=[]; for(const f of files){if(f.size>120000) throw new Error('Each source file must be at most 120 KB.'); const data=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(String(reader.result).split(',')[1]);reader.onerror=()=>reject(new Error('Could not read file'));reader.readAsDataURL(f);}); payload.push({name:f.name,data});} await start('upload',{files:payload},form);}catch(error){status(error.message);}};
$('#review-form').onsubmit=e=>{e.preventDefault(); if(!selected||!connection) return; start('review',{note_id:selected.id,allow_model:$('#model-consent').checked,connection_fingerprint:connection.fingerprint},e.target);};
$('#cancel').onclick=async()=>{try {await api('/api/research/cancel',{});status('Cancellation requested. Already-sent data cannot be recalled.');}catch(e){status(e.message);}};
$('#delete-note').onclick=async()=>{if(!selected)return;if(!deleteArmed){deleteArmed=true;$('#delete-note').textContent='Confirm permanent local deletion';status('Export the note first if you need it. Click again to permanently delete this local note.');return;}try{await api('/api/research/delete',{id:selected.id});selected=null;$('#note-title').textContent='Note deleted';$('#note-content').replaceChildren();$('#note-actions').hidden=true;$('#review-form').hidden=true;await refresh();status('The selected local research note was deleted.');}catch(e){status(e.message);}};
for(const id of ['advisory-form','github-form']) $('#'+id).addEventListener('input',e=>{if(e.target.type!=='checkbox')consentReset(e.currentTarget);});
async function poll(){try{await refresh();if(!selected)status(busy?'Research is running. Select its note to follow progress.':notes.length?'Notebook ready. Select a saved note or start new research.':'Ready. No data is sent until you choose an action.');}catch(e){status('Notebook unavailable: '+e.message);}finally{setTimeout(poll,busy?1200:5000);}}
poll();
