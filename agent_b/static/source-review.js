'use strict';
// Passive UI offers only. Neither detecting a version nor opening the panel
// authorises network access, model sharing, or assessment work.
const AgentBReview = (() => {
  const dismissed = new Set();
  function offerFor(message) {
    const meta = message.metadata || {};
    if (message.role !== 'assistant' || meta.thinking || meta.intermediate || meta.progress || meta.harness_status || meta.connection || dismissed.has(String(message.id))) return false;
    const text = String(message.content || '');
    return /\bCVE-\d{4}-\d{4,10}\b/i.test(text) || (/\bv?\d+\.\d+(?:\.\d+)?\b/.test(text) && /\b(vulnerab\w*|advisory|outdated|affected|unpatched|backport\w*)\b/i.test(text));
  }
  if (typeof document === 'undefined') return {offerFor};
  const q = s => document.querySelector(s);
  let selected = null, connection = null, busy = false, timer = null, preview = '', deleting = false;
  const panel = q('#source-review-panel');
  function say(text) { q('#review-status').textContent = text; }
  function node(tag, text, parent) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; parent.append(e); return e; }
  async function api(path, body) {
    const r = await fetch(path, body === undefined ? {} : {method:'POST', headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const result = await r.json(); if (!r.ok) throw new Error(result.error || 'Check failed'); return result;
  }
  function buttons() {
    q('#review-start').disabled = busy;
    q('#review-preview').disabled = busy;
    q('#review-ask').disabled = busy || !connection?.model;
    q('#review-delete').disabled = busy;
    q('#review-cancel').hidden = !busy;
  }
  function manifestKey() { return JSON.stringify([q('#review-format').value,q('#review-manifest').value]); }
  function resetConsent() { q('#review-network').checked = false; q('#review-model-consent').checked = false; }
  function chooseKind() {
    const kind = q('#review-kind').value;
    panel.querySelectorAll('[data-review-kind]').forEach(e => { e.hidden = e.dataset.reviewKind !== kind; });
    q('#review-network-label').hidden = kind === 'upload';
    q('#review-network').required = kind !== 'upload';
    q('#review-network-text').textContent = kind === 'github' ? 'Retrieve these public files from GitHub.' : kind === 'advisory' ? 'Send this advisory ID to OSV.' : kind === 'dependencies' ? 'Send the previewed package names and versions to OSV.' : 'Send this package name and version to OSV.';
    q('#review-start').textContent = {version:'Check version',advisory:'Check advisory',github:'Retrieve selected files',upload:'Import locally',dependencies:'Check dependencies'}[kind];
    resetConsent();
  }
  function link(parent, title, url) {
    try { const u = new URL(url); if (u.protocol !== 'https:' || u.username || u.password) return; const a=node('a',title,parent); a.href=u.href;a.target='_blank';a.rel='noopener noreferrer';a.className='download-link'; } catch {}
  }
  async function show(id) {
    const note = await api('/api/research/'+encodeURIComponent(id));
    const finished = selected?.id === id && selected?.status === 'running' && note.status !== 'running';
    if (selected?.id !== id || selected?.status !== note.status) { resetConsent(); deleting=false; }
    selected=note; deleting=false; q('#review-result').hidden=false; q('#review-title').textContent=note.title;
    q('#review-delete').textContent='Delete note'; q('#review-notes').value=id;
    const body=q('#review-evidence'); body.replaceChildren();
    q('#review-download').href='/api/research/'+encodeURIComponent(id)+'/download';
    q('#review-model-form').hidden=note.status!=='complete'||note.kind==='review';
    if (note.status==='running') { say('Checking…'); return; }
    if (note.error) { node('p',note.error,body); say(note.error); return; }
    const r=note.result||{};
    if (r.review) { node('p','AI review · verify the advice and citations.',body); node('pre',r.review,body); }
    if (r.summary) node('p',r.summary,body);
    if (r.withdrawn) node('p','Withdrawn: '+r.withdrawn,body);
    if (r.source_url) link(body,'Advisory source',r.source_url);
    if (r.commit) node('p','Pinned commit: '+r.commit,body);
    (r.files||[]).forEach(f=>{const d=node('details',undefined,body);node('summary',f.path+(f.redacted?' · redacted':''),d);node('p','Original SHA-256: '+f.sha256,d);if(f.source_url)link(d,'Pinned source',f.source_url);node('pre',f.text.split('\n').map((l,i)=>`${i+1}: ${l}`).join('\n'),d);});
    (r.matches||[]).forEach(m=>{const d=node('details',undefined,body);node('summary',`${m.package.name} ${m.version} · ${m.advisories.length} advisory matches`,d);node('p',m.status+(m.truncated?' · Incomplete result: pagination was not followed.':''),d);m.advisories.forEach(id=>link(d,id,'https://osv.dev/vulnerability/'+encodeURIComponent(id)));});
    if(r.affected){const d=node('details',undefined,body);node('summary','Affected ranges',d);node('pre',JSON.stringify(r.affected,null,2),d);}
    (r.references||[]).forEach(ref=>link(body,ref.type+' · '+ref.url,ref.url));
    if(r.skipped?.length)node('pre','Not checked:\n'+r.skipped.join('\n'),body);
    if(r.note) { const d=node('details',undefined,body);node('summary','Scope & limitations',d);node('p',r.note,d); }
    say('Ready to review. No testing was performed.');
    if(finished)q('#review-result').scrollIntoView({block:'nearest'});
  }
  async function refresh() {
    const data=await api('/api/research');
    if(connection?.fingerprint!==data.connection.fingerprint) q('#review-model-consent').checked=false;
    connection=data.connection;
    q('#review-destination').textContent=connection.model?`Share with ${connection.model} · ${connection.destination}`:'Choose a model in Settings to request a review.';
    busy=data.notes.some(n=>n.status==='running');buttons();
    const list=q('#review-notes');list.replaceChildren();node('option','Choose a note…',list).value='';
    data.notes.forEach(n=>{node('option',`${n.title} · ${n.status}`,list).value=n.id;});
    list.value=selected?.id||'';
    if(selected?.status==='running')await show(selected.id);
  }
  async function poll() {
    clearTimeout(timer);
    if(panel.classList.contains('hidden'))return;
    try{await refresh();}catch(e){say(e.message);}finally{if(!panel.classList.contains('hidden'))timer=setTimeout(poll,busy?1200:5000);}
  }
  function open(content='') {
    const advisory=content.match(/\bCVE-\d{4}-\d{4,10}\b/i), version=content.match(/\bv?(\d+\.\d+(?:\.\d+)?)\b/);
    if(advisory){q('#review-kind').value='advisory';q('#review-advisory').value=advisory[0].toUpperCase();}
    else if(version){q('#review-kind').value='version';q('#review-version').value=version[1];q('#review-package').value='';}
    chooseKind();panel.classList.remove('hidden');resetConsent();poll();q('#review-kind').focus();
  }
  function close() { panel.classList.add('hidden');clearTimeout(timer);resetConsent();q('#open-source-review').focus(); }
  async function start(kind,body) {
    busy=true;buttons();say('Checking…');
    try {const job=await api('/api/research/start',{kind,...body});resetConsent();await refresh();await show(job.id);}
    catch(e){say(e.message);await refresh().catch(()=>{});}
  }
  function bindOffers(root,messages=[]) {
    root.querySelectorAll('[data-review-offer]').forEach(card=>{
      card.querySelector('[data-open-review]').onclick=()=>open(String(messages.find(m=>String(m.id)===card.dataset.reviewOffer)?.content||''));
      card.querySelector('[data-dismiss-review]').onclick=()=>{dismissed.add(card.dataset.reviewOffer);card.remove();};
    });
  }
  q('#open-source-review').onclick=()=>open();q('#close-source-review').onclick=close;
  q('#review-kind').onchange=chooseKind;
  q('#review-input-form').addEventListener('input',e=>{if(e.target.type!=='checkbox'){q('#review-network').checked=false;preview='';q('#review-preview-result').hidden=true;}});
  q('#review-preview').onclick=async()=>{try{const key=manifestKey();const data=await api('/api/research/preview-dependencies',{format:q('#review-format').value,text:q('#review-manifest').value});if(key!==manifestKey())return;preview=key;q('#review-preview-result').textContent=JSON.stringify(data,null,2);q('#review-preview-result').hidden=false;say('Only these package names and versions will be sent.');}catch(e){say(e.message);}};
  q('#review-input-form').onsubmit=async e=>{
    e.preventDefault();if(busy)return;
    const kind=q('#review-kind').value, consent=q('#review-network').checked;
    try {
      if(kind==='version'){
        const name=q('#review-package').value.trim(),version=q('#review-version').value.trim();
        if(!name||!version)throw new Error('Enter a package and exact version.');
        const purl=`pkg:${q('#review-ecosystem').value}/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
        await start('dependencies',{format:'cyclonedx',text:JSON.stringify({bomFormat:'CycloneDX',components:[{purl}]}),allow_network:consent});
      }else if(kind==='advisory')await start(kind,{identifier:q('#review-advisory').value,allow_network:consent});
      else if(kind==='github')await start(kind,{repository:q('#review-repository').value,ref:q('#review-revision').value,paths:q('#review-paths').value.split('\n').map(p=>p.trim()).filter(Boolean),allow_network:consent});
      else if(kind==='dependencies'){
        if(preview!==manifestKey())throw new Error('Preview the current manifest first.');
        await start(kind,{format:q('#review-format').value,text:q('#review-manifest').value,allow_network:consent});
      }else{
        const files=[...q('#review-files').files];if(!files.length||files.length>6)throw new Error('Choose 1–6 source files.');
        const payload=[];
        for(const f of files){if(f.size>120000)throw new Error('Each file must be at most 120 KB.');const data=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(String(reader.result).split(',')[1]);reader.onerror=()=>reject(new Error('Could not read file'));reader.readAsDataURL(f);});payload.push({name:f.name,data});}
        await start(kind,{files:payload});
      }
    }catch(error){say(error.message);}
  };
  q('#review-notes').onchange=async e=>{if(e.target.value)try{await show(e.target.value);}catch(error){say(error.message);}};
  q('#review-model-form').onsubmit=e=>{e.preventDefault();if(!selected||!connection||busy)return;start('review',{note_id:selected.id,allow_model:q('#review-model-consent').checked,connection_fingerprint:connection.fingerprint});};
  q('#review-cancel').onclick=async()=>{try{await api('/api/research/cancel',{});say('Cancel requested. Sent data cannot be recalled.');}catch(e){say(e.message);}};
  q('#review-delete').onclick=async()=>{if(!selected||busy)return;if(!deleting){deleting=true;q('#review-delete').textContent='Confirm deletion';say('Download first if needed. Deletion is permanent.');return;}try{await api('/api/research/delete',{id:selected.id});selected=null;deleting=false;resetConsent();q('#review-result').hidden=true;q('#review-model-form').hidden=true;await refresh();say('Note deleted.');}catch(e){say(e.message);}};
  chooseKind();
  return {offerFor,bindOffers};
})();
if (typeof module !== 'undefined') module.exports = AgentBReview;
