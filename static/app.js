'use strict';

// All email-derived strings are escaped or assigned with textContent. Email HTML
// is never inserted into the page. No cookies, browser storage, or third-party code.
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const escapeHTML = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const icon = (name, extra = '') => `<svg class="icon ${extra}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
const VERDICTS = {
  malicious: {label: 'Malicious', icon: 'alert', color: '#cc0000'},
  uncertain: {label: 'Needs review', icon: 'clock', color: '#d9b16b'},
  benign: {label: 'Benign', icon: 'check', color: '#95aa82'},
  simulation: {label: 'Simulation', icon: 'spark', color: '#b5a8ce'},
};
const state = {
  token: '', limits: {files: 25, file_bytes: 10485760, batch_bytes: 20971520},
  source: 'loading', records: [], campaigns: [], errors: [], analyzedAt: null,
  duplicates: 0, view: 'overview', filter: 'all', search: '', sort: 'recent',
  campaign: null, unreviewed: false, selected: null, detailTab: 'evidence',
  files: [], busy: false, controller: null, confirmAction: null,
};
let toastTimer;

function badge(value) {
  const key = Object.hasOwn(VERDICTS, value) ? value : 'uncertain';
  const def = VERDICTS[key];
  return `<span class="badge ${key}">${icon(def.icon)}${def.label}</span>`;
}
function effective(record) { return record.effective_verdict || record.verdict; }
function totals() {
  const counts = {all: state.records.length, malicious: 0, uncertain: 0, benign: 0, simulation: 0};
  state.records.forEach((r) => { counts[effective(r)] += 1; });
  return counts;
}
function initials(name) {
  const parts = String(name).replace(/[<>@._-]/g, ' ').trim().split(/\s+/);
  return (parts.slice(0, 2).map((p) => p[0] || '').join('') || '?').toUpperCase();
}
function sizeLabel(bytes) {
  return bytes >= 1048576 ? `${(bytes / 1048576).toFixed(1)} MiB` : `${Math.max(1, Math.ceil(bytes / 1024))} KiB`;
}
function fullDate(value) {
  if (!value) return 'Date unavailable';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? 'Date unavailable' : d.toLocaleString(undefined, {dateStyle: 'medium', timeStyle: 'short'});
}
function relativeDate(value) {
  if (!value) return 'Unknown';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'Unknown';
  const mins = Math.floor((Date.now() - d.getTime()) / 60000);
  if (mins < -1) return d.toLocaleDateString(undefined, {month: 'short', day: 'numeric'});
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return d.toLocaleDateString(undefined, {month: 'short', day: 'numeric'});
}
function defang(value) {
  return String(value).replace(/^https:/i, 'hxxps:').replace(/^http:/i, 'hxxp:').replace(/\./g, '[.]');
}
function notify(message, error = false) {
  const toast = $('#toast');
  clearTimeout(toastTimer);
  toast.classList.toggle('error', error);
  toast.innerHTML = `${icon(error ? 'alert' : 'check')}<span>${escapeHTML(message)}</span>`;
  toast.hidden = false;
  toastTimer = setTimeout(() => { toast.hidden = true; }, error ? 7000 : 4200);
}
async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options, credentials: 'same-origin', cache: 'no-store',
    headers: {'X-Workspace-Token': state.token, ...options.headers},
  });
  let body;
  try { body = await response.json(); }
  catch { throw new Error('The local server could not be reached. Keep its terminal open and try again.'); }
  if (!response.ok) throw new Error(body.error || 'The request could not be completed.');
  return body;
}
function applyBatch(batch) {
  state.source = batch.source;
  state.records = batch.results;
  state.campaigns = batch.campaigns;
  state.errors = batch.errors || [];
  state.duplicates = batch.duplicates_skipped || 0;
  state.analyzedAt = batch.analyzed_at;
  state.filter = 'all'; state.search = ''; state.campaign = null; state.unreviewed = false;
  $('#search').value = ''; $('#unreviewed').checked = false;
  state.view = 'overview';
  render();
}
async function loadDemo() {
  if (state.busy) return;
  state.busy = true;
  setLoading(true);
  try {
    const batch = await api('/api/demo');
    applyBatch(batch);
  } catch (error) {
    if (state.source === 'loading') state.source = 'error';
    render(); notify(error.message, true);
  } finally { state.busy = false; setLoading(false); }
}
function setLoading(loading) {
  $$('[data-upload], #load-demo, #clear-workspace, #banner-action').forEach((button) => { button.disabled = loading; });
  $('#export-results').disabled = loading || !state.records.length;
  $('#export-mobile').disabled = loading || !state.records.length;
}
function clearWorkspace() {
  state.records = []; state.campaigns = []; state.errors = []; state.duplicates = 0;
  state.source = 'empty'; state.filter = 'all'; state.search = ''; state.campaign = null;
  state.selected = null; state.analyzedAt = null; state.unreviewed = false; state.files = [];
  $('#search').value = ''; $('#unreviewed').checked = false;
  state.view = 'overview'; render(); notify('Workspace cleared. Nothing was saved.');
}
function confirmChange(kind) {
  if (state.busy) return;
  if (state.source !== 'upload' || !state.records.length) {
    if (kind === 'demo') loadDemo(); else clearWorkspace();
    return;
  }
  state.confirmAction = kind;
  $('#confirm-title').textContent = kind === 'demo' ? 'Switch to the sample workspace?' : 'Clear this workspace?';
  $('#confirm-description').textContent = 'This replaces the current batch and review status. Export first to keep a copy.';
  $('#confirm-action').textContent = kind === 'demo' ? 'Load sample emails' : 'Clear workspace';
  openDialog('confirm-dialog');
}
function navigate(view) {
  state.view = view;
  if (view !== 'inbox') state.campaign = null;
  $('#sidebar').classList.remove('mobile-open');
  $('#mobile-menu').setAttribute('aria-expanded', 'false');
  render();
}
function render() {
  const titles = {overview: ['Stay on target.', 'Your reported emails. One clear picture.'], inbox: ['Your inbox, in focus.', 'Every report. The context behind every verdict.'], campaigns: ['Connect the dots.', 'Related emails. A bigger picture of the same threat.']};
  $('#page-title').textContent = titles[state.view][0];
  $('#page-subtitle').textContent = titles[state.view][1];
  $('#breadcrumb-view').textContent = {overview: 'Overview', inbox: 'Email inbox', campaigns: 'Campaigns'}[state.view];
  $$('[data-nav]').forEach((button) => {
    const active = button.dataset.nav === state.view;
    button.classList.toggle('active', active);
    if (active) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
  });
  $('#inbox-layout').hidden = state.view === 'campaigns';
  $('#campaign-section').hidden = state.view !== 'campaigns';
  $('#inbox-layout').classList.toggle('inbox-full', state.view === 'inbox');
  $('#right-column').hidden = state.view !== 'overview';
  $('#inbox-heading').firstChild.textContent = state.view === 'inbox' ? 'Email inbox ' : 'Recent emails ';
  $('#inbox-count').textContent = state.records.length;
  $('#campaign-count').textContent = state.campaigns.length;
  $('#export-results').disabled = state.busy || !state.records.length;
  $('#export-mobile').disabled = state.busy || !state.records.length;
  renderBanner(); renderMetrics(); renderTable(); renderBreakdown(); renderCampaigns(); renderErrors();
}
function renderBanner() {
  const banner = $('#workspace-banner');
  banner.classList.remove('live', 'error');
  const action = $('#banner-action'); action.hidden = false;
  action.innerHTML = `Start fresh${icon('arrow')}`;
  if (state.source === 'demo') {
    $('#banner-text').innerHTML = '<strong>Sample workspace.</strong> Eight fictional emails. Not connected to your mailbox.';
  } else if (state.source === 'upload') {
    banner.classList.add('live');
    const reviewed = state.records.filter((r) => r.reviewed).length;
    $('#banner-text').innerHTML = `<strong>Your local batch.</strong> ${state.records.length} email${state.records.length === 1 ? '' : 's'} analyzed &middot; ${reviewed} reviewed &middot; Results reset on refresh.`;
    action.innerHTML = `Workspace details${icon('arrow')}`;
  } else if (state.source === 'loading') {
    $('#banner-text').textContent = 'Connecting to your local workspace...'; action.hidden = true;
  } else if (state.source === 'error') {
    banner.classList.add('error');
    $('#banner-text').textContent = 'The workspace could not load. Check that the server is running, then refresh this page.';
    action.innerHTML = `Try again${icon('refresh')}`;
  } else {
    $('#banner-text').innerHTML = '<strong>A fresh workspace.</strong> Add your emails to begin. Everything stays local.';
    action.innerHTML = `Try the demo${icon('arrow')}`;
  }
}
function renderMetrics() {
  const c = totals();
  $('#metric-total').textContent = c.all;
  $('#metric-malicious').textContent = c.malicious;
  $('#metric-uncertain').textContent = c.uncertain;
  $('#metric-low').textContent = c.benign + c.simulation;
  $('#metric-low-note').textContent = `${c.benign} benign \u00b7 ${c.simulation} ${c.simulation === 1 ? 'simulation' : 'simulations'}`;
  $$('[data-metric]').forEach((b) => {
    const key = b.dataset.metric;
    b.setAttribute('aria-label', `Show ${key === 'all' ? 'all emails' : key === 'low' ? 'benign and simulation emails' : VERDICTS[key].label.toLowerCase()}`);
  });
}
function filteredRecords() {
  const query = state.search.toLocaleLowerCase().trim();
  return state.records.filter((r) => {
    const status = effective(r);
    if (state.filter === 'low' ? !['benign', 'simulation'].includes(status) : state.filter !== 'all' && status !== state.filter) return false;
    if (state.campaign && r.campaign_id !== state.campaign) return false;
    if (state.unreviewed && r.reviewed) return false;
    return !query || [r.subject, r.sender, r.sender_name, r.filename].some((x) => String(x).toLocaleLowerCase().includes(query));
  }).sort((a, b) => {
    if (state.sort === 'score') return b.score - a.score || a.subject.localeCompare(b.subject);
    if (state.sort === 'subject') return a.subject.localeCompare(b.subject);
    return (Date.parse(b.received_at) || 0) - (Date.parse(a.received_at) || 0);
  });
}
function renderTable() {
  const c = totals();
  const labels = [['all', 'All emails'], ['malicious', 'Malicious'], ['uncertain', 'Needs review'], ['benign', 'Benign'], ['simulation', 'Training']];
  if (state.filter === 'low') labels.push(['low', 'Benign + training']);
  $('#filter-tabs').innerHTML = labels.map(([key, label]) => `<button class="filter-tab${state.filter === key ? ' active' : ''}" data-filter="${key}" aria-pressed="${state.filter === key}">${label}<span class="tab-count">${key === 'low' ? c.benign + c.simulation : c[key]}</span></button>`).join('');
  const filtered = filteredRecords();
  const visible = state.view === 'overview' ? filtered.slice(0, 6) : filtered;
  $('#table-count').textContent = filtered.length;
  $('#campaign-filter').hidden = !state.campaign;
  $('#email-rows').innerHTML = visible.map((r) => `<tr data-record="${r.id}">
    <td><div class="email-entry"><span class="email-avatar ${effective(r)}" aria-hidden="true">${escapeHTML(initials(r.sender_name))}</span><div class="email-copy"><button class="email-subject" data-record="${r.id}" title="${escapeHTML(r.subject)}">${r.reviewed ? `<span class="reviewed-marker" aria-label="Reviewed">${icon('check')}</span>` : ''}${escapeHTML(r.subject)}</button><span class="email-sender" title="${escapeHTML(r.sender)}">${escapeHTML(r.sender)}</span></div></div></td>
    <td>${badge(effective(r))}</td><td><span class="score ${effective(r)}" title="${r.score} local-rule points, not a probability"><span class="score-dot"></span>${r.score}</span></td>
    <td><time class="time" title="${escapeHTML(fullDate(r.received_at))}">${escapeHTML(relativeDate(r.received_at))}</time></td><td>${icon('chevron', 'row-arrow')}</td>
  </tr>`).join('');
  const empty = visible.length === 0;
  $('#empty-state').hidden = !empty;
  $('.table-scroll').hidden = empty;
  if (empty) {
    const noData = !state.records.length;
    $('#empty-title').textContent = state.source === 'loading' ? 'Opening your workspace...' : noData ? 'A fresh start.' : 'Nothing matches just yet.';
    $('#empty-description').textContent = noData ? 'Drop in an email. We will help you take a closer look.' : 'Try a different search, or clear your filters to see all emails.';
    $('#empty-action').innerHTML = `${noData ? 'Analyze an email' : 'Clear filters'}${icon('arrow')}`;
    $('#empty-action').disabled = state.busy || state.source === 'loading';
  }
  const reviewed = state.records.filter((r) => r.reviewed).length;
  $('#table-footer-text').textContent = state.records.length ? `Showing ${visible.length} of ${filtered.length} emails${reviewed ? ` \u00b7 ${reviewed} reviewed` : ''}` : 'Your next investigation starts here';
  $('#view-all').hidden = state.view !== 'overview' || !state.records.length;
  $('#table-subtitle').textContent = state.campaign ? 'Related emails. Individual evidence, shared context.' : 'A little context for every decision.';
}
function renderBreakdown() {
  const c = totals();
  $('#donut-total').textContent = c.all;
  const steps = []; let offset = 0;
  for (const [key, def] of Object.entries(VERDICTS)) {
    const end = offset + (c.all ? c[key] / c.all * 100 : 0);
    if (c[key]) steps.push(`${def.color} ${offset}% ${Math.max(offset, end - 0.8)}%`, `#fff ${Math.max(offset, end - 0.8)}% ${end}%`);
    offset = end;
  }
  $('#donut').style.background = c.all ? `conic-gradient(${steps.join(',')})` : '#eeeee8';
  $('#donut').setAttribute('aria-label', `${c.all} emails: ${c.malicious} malicious, ${c.uncertain} need review, ${c.benign} benign, ${c.simulation} simulations.`);
  $('#legend').innerHTML = Object.entries(VERDICTS).map(([key, def]) => `<button class="legend-row" data-filter="${key}" data-goto-inbox="true"><span class="legend-dot" style="background:${def.color}"></span><span>${def.label}</span><strong>${c[key]}</strong><span class="legend-percent">${c.all ? Number((c[key] / c.all * 100).toFixed(1)) : 0}%</span></button>`).join('');
}
function renderCampaigns() {
  const reasonNames = {url: 'Shared URL', subject: 'Similar subject', body: 'Similar content', infra: 'Shared infrastructure'};
  const query = state.search.trim().toLocaleLowerCase();
  const campaigns = state.campaigns.filter((c) => !query || state.records.some((r) => c.members.includes(r.id) && [r.subject, r.sender, r.sender_name].some((x) => x.toLocaleLowerCase().includes(query))));
  $('#campaign-cards').innerHTML = campaigns.map((c, i) => `<article class="campaign-card"><div class="campaign-card-top">${icon('layers')}${badge(c.verdict)}</div><h3>${escapeHTML(c.subject)}</h3><p class="campaign-count">${c.members.length} related emails &middot; Suggested campaign ${i + 1}</p><div class="reason-tags">${c.reasons.map((r) => `<span class="reason-tag">${reasonNames[r] || escapeHTML(r)}</span>`).join('')}</div><div class="campaign-card-footer"><span>Analyst confirmation needed</span><button class="text-button" data-campaign="${c.id}">Review emails${icon('arrow')}</button></div></article>`).join('');
  $('#campaign-empty').hidden = campaigns.length > 0;
  $('#campaign-empty h3').textContent = query ? 'No campaigns match your search.' : 'No related campaigns yet.';
}
function renderErrors() {
  const target = $('#batch-errors');
  target.hidden = !state.errors.length && !state.duplicates;
  target.innerHTML = `${state.errors.length ? `<details><summary>${state.errors.length} email${state.errors.length === 1 ? '' : 's'} could not be analyzed</summary>${state.errors.map((e) => `<p><strong>${escapeHTML(e.filename)}</strong>: ${escapeHTML(e.message)}</p>`).join('')}</details>` : ''}${state.duplicates ? `<p>${state.duplicates} exact duplicate${state.duplicates === 1 ? ' was' : 's were'} skipped.</p>` : ''}`;
}

function openDialog(id) {
  const dialog = document.getElementById(id);
  if (!dialog.open) dialog.showModal();
}
function closeDialog(id) {
  if (id === 'upload-dialog' && state.controller) state.controller.abort();
  document.getElementById(id).close();
}
function openUpload() {
  if (state.busy || !state.token) {
    if (!state.token) notify('Refresh the page to reconnect to the local server.', true);
    return;
  }
  state.files = []; $('#file-input').value = ''; $('#upload-error').hidden = true;
  renderFiles(); openDialog('upload-dialog');
}
function uploadError(message) {
  $('#upload-error').textContent = message; $('#upload-error').hidden = false;
}
function addFiles(files) {
  if (state.busy) return;
  const errors = [];
  for (const file of files) {
    if (!file.name.toLowerCase().endsWith('.eml')) { errors.push(`${file.name}: choose an .eml file.`); continue; }
    if (!file.size || file.size > state.limits.file_bytes) { errors.push(`${file.name}: use a nonempty file no larger than 10 MiB.`); continue; }
    if (file.name.length > 180) { errors.push(`${file.name.slice(0, 35)}: shorten the filename to 180 characters.`); continue; }
    if (state.files.some((f) => f.name === file.name && f.size === file.size && f.lastModified === file.lastModified)) continue;
    if (state.files.length >= state.limits.files) { errors.push('A batch can contain up to 25 emails.'); break; }
    if (state.files.reduce((total, f) => total + f.size, file.size) > state.limits.batch_bytes) { errors.push('The batch must be 20 MiB or smaller.'); continue; }
    state.files.push(file);
  }
  $('#upload-error').hidden = !errors.length;
  if (errors.length) uploadError(errors.slice(0, 3).join(' '));
  renderFiles();
}
function renderFiles() {
  $('#file-list').innerHTML = state.files.map((f, i) => `<div class="file-item">${icon('file')}<span class="file-name" title="${escapeHTML(f.name)}">${escapeHTML(f.name)}</span><span class="file-size">${sizeLabel(f.size)}</span><button class="icon-button" data-remove-file="${i}" aria-label="Remove ${escapeHTML(f.name)}"${state.busy ? ' disabled' : ''}>${icon('close')}</button></div>`).join('');
  $('#analyze-button').disabled = !state.files.length || state.busy;
  $('#analyze-button').innerHTML = state.busy ? '<span class="spinner" aria-hidden="true"></span><span>Analyzing...</span>' : `${icon('spark')}<span>Analyze ${state.files.length ? state.files.length + ' ' : ''}email${state.files.length === 1 ? '' : 's'}</span>`;
  $('#dropzone').setAttribute('aria-disabled', String(state.busy));
}
function encodeFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error(`Could not read ${file.name}.`));
    reader.onload = () => resolve({name: file.name, data: String(reader.result).split(',')[1]});
    reader.readAsDataURL(file);
  });
}
async function analyzeUploads() {
  if (state.busy || !state.files.length) return;
  state.busy = true; state.controller = new AbortController();
  const controller = state.controller;
  const timeout = setTimeout(() => controller.abort('timeout'), 90000);
  setLoading(true); renderFiles(); $('#upload-error').hidden = true;
  try {
    const files = [];
    for (const file of state.files) {
      if (controller.signal.aborted) throw new DOMException('Canceled', 'AbortError');
      files.push(await encodeFile(file));
    }
    const batch = await api('/api/analyze', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({files}), signal: controller.signal});
    if (!batch.results.length) {
      throw new Error(batch.errors?.map((e) => `${e.filename}: ${e.message}`).join(' ') || 'No email could be analyzed. Please export the original message as an .eml file.');
    }
    applyBatch(batch);
    state.files = []; $('#file-input').value = ''; $('#file-list').replaceChildren();
    $('#upload-dialog').close();
    notify(`${batch.results.length} email${batch.results.length === 1 ? '' : 's'} analyzed. ${batch.errors.length ? 'Check the skipped-file notice.' : 'Ready for a closer look.'}`);
  } catch (error) {
    if (controller.signal.aborted) {
      if (controller.signal.reason === 'timeout') uploadError('Analysis timed out. Try fewer or smaller emails.');
    } else uploadError(error.message || 'Analysis failed. Please try again.');
  } finally {
    clearTimeout(timeout); state.controller = null; state.busy = false;
    if (!$('#upload-dialog').open) { state.files = []; $('#file-input').value = ''; }
    setLoading(false); renderFiles();
  }
}

function openRecord(id) {
  const record = state.records.find((r) => r.id === id);
  if (!record) return;
  state.selected = id; state.detailTab = 'evidence';
  renderDetail(record); openDialog('detail-dialog'); $('.detail-scroll').scrollTop = 0;
}
function renderDetail(r) {
  $('#detail-context').innerHTML = `${icon(state.source === 'demo' ? 'spark' : 'lock')}${state.source === 'demo' ? 'Fictional sample email' : 'Local analysis'}${r.related_count ? ` &middot; ${r.related_count} related email${r.related_count > 1 ? 's' : ''}` : ''}`;
  $('#detail-subject').textContent = r.subject;
  $('#detail-avatar').textContent = initials(r.sender_name);
  $('#detail-sender-name').textContent = r.sender_name;
  $('#detail-sender').textContent = r.sender;
  const metadata = [['To', r.recipients.join(', ') || 'Not provided'], ['Received', fullDate(r.received_at)], ['File', r.filename]];
  if (r.reply_to) metadata.push(['Reply-To', r.reply_to]);
  $('#detail-metadata').innerHTML = metadata.map(([label, value]) => `<dt>${label}</dt><dd>${escapeHTML(value)}</dd>`).join('');
  const changed = effective(r) !== r.verdict;
  $('#detail-verdict').innerHTML = `${badge(effective(r))}<div class="verdict-score"><strong>${r.score}</strong><span>rule points</span></div><p class="verdict-explanation">${changed ? `Campaign escalation: individual verdict is ${VERDICTS[r.verdict].label.toLowerCase()}. A related email is higher risk. ` : ''}Local-rule assessment, not a probability. ${effective(r) === 'malicious' ? 'Verify the evidence before taking action.' : effective(r) === 'uncertain' ? 'An analyst should review this message.' : 'Demo-only trusted origin; not proof of real-world safety.'}</p>`;
  const signals = r.signals.length ? r.signals.map((s) => `<div class="signal-item"><span class="signal-points ${s.points === 0 ? 'neutral' : s.points < 0 ? 'negative' : ''}">${s.points > 0 ? '+' : ''}${s.points}</span><p>${escapeHTML(s.evidence)}</p></div>`).join('') : '<p class="empty-details">No local risk signals matched. This is not a live reputation check.</p>';
  $('#detail-evidence').innerHTML = `<div class="signal-list">${signals}</div><h3 class="section-label">AUTHENTICATION CLAIMS</h3><div class="auth-grid">${['spf', 'dkim', 'dmarc'].map((key) => `<div class="auth-item"><strong>${key.toUpperCase()}</strong><span>${escapeHTML(r.authentication[key] || 'Not present')}</span></div>`).join('')}</div><p class="auth-note">${r.authentication.trusted ? 'Synthetic trust is enabled for this built-in demo message only.' : 'These are unverified header claims. Uploaded email cannot establish its own authentication trust.'}</p>${r.techniques.length ? `<h3 class="section-label">BEHAVIOR LABELS (ATT&amp;CK)</h3><div class="techniques">${r.techniques.map((t) => `<span>${escapeHTML(t)}</span>`).join('')}</div>` : ''}`;
  $('#detail-email').innerHTML = `<p class="preview-note">${icon('shield')}Plain text only. Links are not clickable. HTML and attachments are never executed.</p><pre class="plain-preview"></pre>${r.body_truncated ? '<p class="auth-note">Preview shortened to 24,000 characters. Inspect the original for the complete message.</p>' : ''}`;
  $('#detail-email .plain-preview').textContent = r.body || '(No readable text body.)';
  $('#detail-indicators').innerHTML = `<div class="indicator-block"><div class="indicator-title"><h3>Links <span class="count-label">${r.link_count}</span></h3>${r.links.length ? `<button class="text-button" id="copy-links">${icon('copy')}Copy defanged</button>` : ''}</div>${r.links.length ? r.links.map((l) => `<code class="indicator-value">${escapeHTML(defang(l))}</code>`).join('') : '<p class="empty-details">No links extracted.</p>'}${r.link_count > r.links.length ? '<p class="auth-note">Only the first 100 distinct links are displayed.</p>' : ''}</div><div class="indicator-block"><div class="indicator-title"><h3>Attachments <span class="count-label">${r.attachment_count}</span></h3></div>${r.attachments.length ? r.attachments.map((a) => `<div class="attachment-card"><strong>${escapeHTML(a.filename)}</strong><p>${escapeHTML(a.content_type)} &middot; ${sizeLabel(a.size)}</p><code>SHA-256: ${escapeHTML(a.sha256)}</code></div>`).join('') : '<p class="empty-details">No attachments extracted.</p>'}${r.attachment_count > r.attachments.length ? '<p class="auth-note">Only the first 100 attachments are displayed.</p>' : ''}</div>${r.phones.length ? `<div class="indicator-block"><div class="indicator-title"><h3>Phone numbers</h3></div>${r.phones.map((p) => `<code class="indicator-value">${escapeHTML(p)}</code>`).join('')}</div>` : ''}<p class="auth-note">Indicators have not been looked up in a live reputation service. Extraction is not a safety verdict.</p>`;
  renderReviewState(r); switchDetailTab(state.detailTab);
}
function renderReviewState(r) {
  $('#review-state').textContent = r.reviewed ? 'Reviewed in this session' : 'Not reviewed yet';
  $('#mark-reviewed').classList.toggle('reviewed', r.reviewed);
  $('#mark-reviewed').innerHTML = `${icon(r.reviewed ? 'circle-check' : 'check')}${r.reviewed ? 'Reviewed \u00b7 undo' : 'Mark reviewed'}`;
  $('#mark-reviewed').setAttribute('aria-pressed', String(r.reviewed));
}
function switchDetailTab(name) {
  state.detailTab = name;
  $$('[data-tab]').forEach((button) => {
    const active = button.dataset.tab === name;
    button.setAttribute('aria-selected', String(active)); button.tabIndex = active ? 0 : -1;
    $(`#detail-${button.dataset.tab}`).hidden = !active;
  });
}
async function copyLinks() {
  const record = state.records.find((r) => r.id === state.selected);
  if (!record) return;
  try { await navigator.clipboard.writeText(record.links.map(defang).join('\n')); notify('Defanged links copied.'); }
  catch { notify('Clipboard access is unavailable. Select the link text to copy it manually.', true); }
}
function exportResults() {
  if (!state.records.length) return;
  const output = {
    application: 'Phish Triage', version: '0.3.0', source: state.source,
    mode: 'local_rules_only', exported_at: new Date().toISOString(), analyzed_at: state.analyzedAt,
    notice: 'Rule-based assessment, not proof of safety. No live reputation checks. Includes email previews; treat this file as sensitive.',
    results: state.records, campaigns: state.campaigns, errors: state.errors,
    duplicates_skipped: state.duplicates,
  };
  const blob = new Blob([JSON.stringify(output, null, 2)], {type: 'application/json'});
  const url = URL.createObjectURL(blob); const anchor = document.createElement('a');
  anchor.href = url; anchor.download = `phish-triage-${state.source}-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.append(anchor); anchor.click(); anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
  notify('Results exported. Keep the JSON private; it includes email previews.');
}

// Delegated actions keep dynamic rows and filters keyboard accessible.
document.addEventListener('click', (event) => {
  const target = event.target.closest('button, [data-record], a.brand');
  if (!target || target.disabled) return;
  if (target.matches('a.brand')) { event.preventDefault(); navigate('overview'); }
  else if (target.dataset.nav) navigate(target.dataset.nav);
  else if (target.hasAttribute('data-upload')) openUpload();
  else if (target.hasAttribute('data-settings')) openDialog('settings-dialog');
  else if (target.dataset.close) closeDialog(target.dataset.close);
  else if (target.dataset.filter) {
    state.filter = target.dataset.filter;
    if (target.dataset.gotoInbox) navigate('inbox'); else renderTable();
  }
  else if (target.dataset.metric) { state.filter = target.dataset.metric; state.campaign = null; navigate('inbox'); }
  else if (target.dataset.record) openRecord(target.dataset.record);
  else if (target.dataset.campaign) { state.campaign = target.dataset.campaign; state.filter = 'all'; state.view = 'inbox'; render(); }
  else if (target.dataset.tab) switchDetailTab(target.dataset.tab);
  else if (target.hasAttribute('data-remove-file')) { state.files.splice(Number(target.dataset.removeFile), 1); renderFiles(); }
  else if (target.id === 'copy-links') copyLinks();
});
$('#search').addEventListener('input', (event) => { state.search = event.target.value; renderTable(); renderCampaigns(); });
$('#sort').addEventListener('change', (event) => { state.sort = event.target.value; renderTable(); });
$('#unreviewed').addEventListener('change', (event) => { state.unreviewed = event.target.checked; renderTable(); });
$('#view-all').addEventListener('click', () => navigate('inbox'));
$('#clear-campaign').addEventListener('click', () => { state.campaign = null; renderTable(); });
$('#load-demo').addEventListener('click', () => confirmChange('demo'));
$('#clear-workspace').addEventListener('click', () => confirmChange('clear'));
$('#confirm-action').addEventListener('click', () => {
  $('#confirm-dialog').close();
  if (state.confirmAction === 'demo') loadDemo(); else clearWorkspace();
});
$('#banner-action').addEventListener('click', () => {
  if (state.source === 'demo') clearWorkspace();
  else if (state.source === 'upload') openDialog('settings-dialog');
  else if (state.source === 'error') location.reload();
  else loadDemo();
});
$('#empty-action').addEventListener('click', () => {
  if (!state.records.length) openUpload();
  else {
    state.filter = 'all'; state.search = ''; state.campaign = null; state.unreviewed = false;
    $('#search').value = ''; $('#unreviewed').checked = false; renderTable();
  }
});
$('#export-results').addEventListener('click', exportResults);
$('#export-mobile').addEventListener('click', exportResults);
$('#mobile-menu').addEventListener('click', () => {
  const open = $('#sidebar').classList.toggle('mobile-open');
  $('#mobile-menu').setAttribute('aria-expanded', String(open));
});
$('#mark-reviewed').addEventListener('click', () => {
  const r = state.records.find((item) => item.id === state.selected);
  if (!r) return;
  r.reviewed = !r.reviewed; renderReviewState(r); render();
});
$('.detail-tabs').addEventListener('keydown', (event) => {
  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
  event.preventDefault();
  const tabs = $$('[data-tab]'); let index = tabs.findIndex((t) => t.dataset.tab === state.detailTab);
  if (event.key === 'ArrowLeft') index = (index + tabs.length - 1) % tabs.length;
  if (event.key === 'ArrowRight') index = (index + 1) % tabs.length;
  if (event.key === 'Home') index = 0;
  if (event.key === 'End') index = tabs.length - 1;
  switchDetailTab(tabs[index].dataset.tab); tabs[index].focus();
});
const dropzone = $('#dropzone');
dropzone.addEventListener('click', () => { if (!state.busy) $('#file-input').click(); });
dropzone.addEventListener('keydown', (event) => {
  if (['Enter', ' '].includes(event.key)) { event.preventDefault(); if (!state.busy) $('#file-input').click(); }
});
$('#file-input').addEventListener('change', (event) => { addFiles(event.target.files); event.target.value = ''; });
for (const eventName of ['dragenter', 'dragover']) {
  dropzone.addEventListener(eventName, (event) => { event.preventDefault(); dropzone.classList.add('dragover'); });
}
for (const eventName of ['dragleave', 'drop']) {
  dropzone.addEventListener(eventName, (event) => { event.preventDefault(); dropzone.classList.remove('dragover'); });
}
dropzone.addEventListener('drop', (event) => addFiles(event.dataTransfer.files));
// Prevent the browser from navigating to an email accidentally dropped outside the zone.
window.addEventListener('dragover', (event) => { if ([...event.dataTransfer.types].includes('Files')) event.preventDefault(); });
window.addEventListener('drop', (event) => {
  if ([...event.dataTransfer.types].includes('Files')) {
    event.preventDefault();
    if (!$('#upload-dialog').open && !document.querySelector('dialog[open]')) { openUpload(); addFiles(event.dataTransfer.files); }
  }
});
$('#analyze-button').addEventListener('click', analyzeUploads);
$$('dialog').forEach((dialog) => {
  dialog.addEventListener('click', (event) => {
    if (event.target !== dialog) return;
    const rect = dialog.getBoundingClientRect();
    if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) closeDialog(dialog.id);
  });
  dialog.addEventListener('cancel', () => { if (dialog.id === 'upload-dialog' && state.controller) state.controller.abort(); });
});
$('#upload-dialog').addEventListener('close', () => {
  if (!state.busy) { state.files = []; $('#file-input').value = ''; $('#file-list').replaceChildren(); }
});
document.addEventListener('keydown', (event) => {
  const editing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName);
  if (event.key === '/' && !editing && !document.querySelector('dialog[open]')) { event.preventDefault(); $('#search').focus(); }
  if (event.key === 'Escape' && $('#sidebar').classList.contains('mobile-open')) {
    $('#sidebar').classList.remove('mobile-open'); $('#mobile-menu').setAttribute('aria-expanded', 'false');
  }
});

async function boot() {
  render(); setLoading(true);
  try {
    const session = await api('/api/session');
    state.token = session.token; state.limits = session.limits;
    await loadDemo();
  } catch (error) {
    state.source = 'error'; render(); setLoading(false); notify(error.message || 'Unable to start the workspace.', true);
  }
}
boot();
