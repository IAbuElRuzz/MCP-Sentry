'use strict';
const $ = id => document.getElementById(id);
const fragment = new URLSearchParams(location.hash.slice(1));
if (fragment.has('token')) { sessionStorage.setItem('sentry-token', fragment.get('token')); history.replaceState(null, '', location.pathname); }
let snapshot = null, busy = false;
const cell = (tag, text) => { const el = document.createElement(tag); el.textContent = String(text ?? ''); return el; };
function renderEvents() {
  const query = $('search').value.toLowerCase();
  const events = (snapshot?.events || []).filter(e => [e.tool, e.event, e.reason, e.decision].join(' ').toLowerCase().includes(query));
  $('events').replaceChildren();
  for (const event of events) {
    const row = document.createElement('tr');
    row.append(cell('td', new Date(event.timestamp * 1000).toLocaleTimeString()));
    const decision = document.createElement('td'), badge = cell('span', event.decision);
    badge.className = 'decision';
    if (['block', 'error', 'allow', 'alert', 'would_block'].includes(event.decision)) badge.classList.add(event.decision);
    decision.append(badge); row.append(decision);
    const tool = cell('td', event.tool || 'Gateway'); tool.append(cell('small', event.event)); row.append(tool, cell('td', event.reason));
    $('events').append(row);
  }
  $('empty').hidden = events.length !== 0; $('count').textContent = `${events.length} events`;
}
async function refresh() {
  if (busy) return; busy = true;
  try {
    const query = new URLSearchParams({session: $('session').value, decision: $('decision').value});
    const response = await fetch('/api/activity?' + query, {headers: {Authorization: 'Bearer ' + (sessionStorage.getItem('sentry-token') || '')}, cache: 'no-store'});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Unable to load activity');
    snapshot = data;
    const selected = $('session').value;
    $('session').replaceChildren(new Option('All sessions', ''));
    for (const session of data.sessions) $('session').add(new Option(session.session.slice(0, 12) + ' · ' + new Date(session.last_seen * 1000).toLocaleString(), session.session));
    if (selected && !data.sessions.some(s => s.session === selected)) $('session').add(new Option(selected.slice(0, 12), selected));
    $('session').value = selected;
    const totals = data.report?.totals || {};
    for (const [id, key] of Object.entries({forwarded:'forwarded',blocked:'blocked_before_dispatch',redacted:'redacted_calls',withheld:'responses_blocked'})) $(id).textContent = totals[key] || 0;
    $('findings').replaceChildren();
    for (const finding of data.report?.findings || []) { const li = document.createElement('li'); li.append(cell('span', finding.reason), cell('b', finding.count)); $('findings').append(li); }
    if (!$('findings').children.length) $('findings').append(cell('li', 'No findings in this selection.'));
    $('notice').textContent = data.notice; renderEvents();
    $('status').textContent = data.empty ? data.notice : 'Updated ' + new Date().toLocaleTimeString() + ' · Read-only audit connection';
  } catch (error) { $('status').textContent = error.message + '. Open the private URL printed by the dashboard command.'; }
  finally { busy = false; }
}
$('session').addEventListener('change', refresh); $('decision').addEventListener('change', refresh); $('refresh').addEventListener('click', refresh); $('search').addEventListener('input', renderEvents);
$('export').addEventListener('click', () => { if (!snapshot) return; const url = URL.createObjectURL(new Blob([JSON.stringify(snapshot, null, 2)], {type:'application/json'})); const link = document.createElement('a'); link.href = url; link.download = 'mcpsentry-activity.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); });
setInterval(() => { if ($('live').checked && !document.hidden) refresh(); }, 5000); refresh();
