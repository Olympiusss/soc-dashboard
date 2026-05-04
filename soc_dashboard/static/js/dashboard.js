/**
 * Sentrium SOC — Per-Client Dashboard JS  v6
 * Executive-grade: Overview | Alerts (AV) | EDR (S1) | Settings
 */
'use strict';

let ws = null, reconnectAttempts = 0, lastUpdateTime = null, _updateTimer = null;

// ── DOM refs ─────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ═══════════════════════════════════════════════════════════════════════════
//  Tab Switching
// ═══════════════════════════════════════════════════════════════════════════
function switchTab(id) {
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    const pane = $(id), btn = document.querySelector(`.tab-btn[data-target="${id}"]`);
    if (pane) pane.classList.add('active');
    if (btn)  btn.classList.add('active');
}
document.querySelectorAll('.tab-btn[data-target]').forEach(b =>
    b.addEventListener('click', () => switchTab(b.dataset.target))
);

// ═══════════════════════════════════════════════════════════════════════════
//  REST Pre-load
// ═══════════════════════════════════════════════════════════════════════════
async function preload() {
    try {
        const r = await fetch(`/api/client/${encodeURIComponent(CLIENT_NAME)}/data`);
        if (r.ok) renderClient(await r.json());
    } catch(e) { console.warn('[REST] pre-load failed:', e); }
}

// ═══════════════════════════════════════════════════════════════════════════
//  WebSocket
// ═══════════════════════════════════════════════════════════════════════════
function connectWS() {
    ws = new WebSocket(WS_URL);
    ws.onopen = () => {
        reconnectAttempts = 0;
        const o = $('reconnect-overlay'); if (o) o.classList.remove('visible');
        const li = $('live-indicator');   if (li) li.classList.remove('disconnected');
    };
    ws.onmessage = e => {
        try {
            const d = JSON.parse(e.data);
            const client = (d.clients||[]).find(c => c.name.toLowerCase() === CLIENT_NAME.toLowerCase());
            if (client) { renderClient(client); lastUpdateTime = new Date(); startTimer(); }
            updateStatus(d.system_status);
        } catch(err) { console.error('[WS]', err); }
    };
    ws.onclose = () => {
        const li = $('live-indicator'); if (li) li.classList.add('disconnected');
        reconnectAttempts++;
        if (reconnectAttempts > 2) { const o = $('reconnect-overlay'); if (o) o.classList.add('visible'); }
        setTimeout(connectWS, Math.min(reconnectAttempts * 2000, 15000));
    };
    ws.onerror = () => ws.close();
}

// ═══════════════════════════════════════════════════════════════════════════
//  Main render
// ═══════════════════════════════════════════════════════════════════════════
function renderClient(c) {
    if (!c) return;
    lastUpdateTime = lastUpdateTime || new Date();

    // Platform banner
    const platforms = c.platforms || [];
    const ppEl = $('platform-pills');
    if (ppEl) ppEl.innerHTML = platforms.map(p =>
        p === 'SentinelOne'
            ? '<span class="plat-pill plat-pill-s1"><span class="plat-dot"></span>SentinelOne</span>'
            : '<span class="plat-pill plat-pill-av"><span class="plat-dot"></span>AlienVault</span>'
    ).join('') || '—';

    const psEl = $('platform-stats');
    if (psEl) {
        const avN = c.av_total_alarms || 0;
        const s1N = (c.recent_alerts||[]).filter(a => a.platform === 'SentinelOne').length;
        psEl.innerHTML =
            (platforms.includes('SentinelOne') ? `<span class="plat-stat">S1 threats: <strong>${fmt(s1N)}</strong></span>` : '') +
            (platforms.includes('AlienVault')  ? `<span class="plat-stat">AV alarms: <strong>${fmt(avN)}</strong></span>`  : '');
    }

    // KPIs
    const avTotal = c.av_total_alarms || c.total_alerts || 0;
    animKPI('kv-alarms',    avTotal);
    animKPI('kv-threats',   c.total_threats || 0);
    animKPI('kv-endpoints', c.total_endpoints || 0);
    animKPI('kv-blocked',   c.blocked_attempts || 0);
    animKPI('kv-dfir',      c.dfir_cases || 0);

    // KPI bars (as % of reasonable max)
    setBar('kb-alarms',    avTotal, 100);
    setBar('kb-threats',   c.total_threats, 50);
    setBar('kb-endpoints', c.total_endpoints, 500);
    setBar('kb-blocked',   c.blocked_attempts, 20);
    setBar('kb-dfir',      c.dfir_cases, 10);

    // Charts
    updateEventChart(c.event_timeline || []);
    updateEDRChart(c.threat_classifications || []);

    // Overview quick panels
    renderDashPrio(c.av_priority_breakdown || []);
    renderDashMethods(c.av_method_summary || []);

    // Alerts tab badge
    const badge = $('tab-av-badge');
    if (badge && avTotal > 0) { badge.textContent = fmt(avTotal); badge.style.display = 'inline'; }

    // Alerts tab
    const avLbl = $('av-total-lbl');
    if (avLbl) avLbl.textContent = `${fmt(avTotal)} alarms · 24hr window`;
    const listTotal = $('av-list-total');
    if (listTotal) listTotal.textContent = fmt(avTotal);

    renderPrioTable(c.av_priority_breakdown || []);
    renderMethTable(c.av_method_summary || []);
    renderAssetTable('src-tbody', c.av_top_sources || []);
    renderAssetTable('dst-tbody', c.av_top_destinations || []);
    renderAlarmList(c.recent_alerts || []);

    // EDR tab
    const s1Alerts = (c.recent_alerts||[]).filter(a => a.platform === 'SentinelOne');
    const s1Lbl = $('s1-threat-lbl');
    if (s1Lbl) s1Lbl.textContent = `${fmt(s1Alerts.length)} threats · 24hr window`;
    renderS1Table(s1Alerts);

    startTimer();
}

// ═══════════════════════════════════════════════════════════════════════════
//  Overview panels
// ═══════════════════════════════════════════════════════════════════════════
function renderDashPrio(rows) {
    const el = $('dash-prio');
    if (!el) return;
    if (!rows.length) { el.innerHTML = '<p style="color:#9CA3AF;font-size:.82rem;padding:8px 0;">No AV data available</p>'; return; }
    el.innerHTML = rows.map(r => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid #F3F4F6;">
            <span class="p-badge p-${r.priority.toLowerCase()}">${esc(r.priority)}</span>
            <span style="font-weight:800;font-size:.9rem;">${fmt(r.total)}</span>
            <span style="font-size:.72rem;color:#9CA3AF;">${r.statuses.open} open · ${r.statuses.closed} closed${r.statuses.in_review ? ' · '+r.statuses.in_review+' review' : ''}</span>
        </div>`).join('');
}

function renderDashMethods(rows) {
    const el = $('dash-methods');
    if (!el) return;
    if (!rows.length) { el.innerHTML = '<p style="color:#9CA3AF;font-size:.82rem;padding:8px 0;">No AV data available</p>'; return; }
    const max = rows[0]?.count || 1;
    el.innerHTML = rows.slice(0,6).map(r => `
        <div style="padding:6px 0;border-bottom:1px solid #F3F4F6;">
            <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
                <span style="font-size:.8rem;font-weight:600;color:#111827;">${esc(r.method)}</span>
                <span style="font-size:.78rem;font-weight:700;color:#C2410C;">${fmt(r.count)}</span>
            </div>
            <div style="height:4px;border-radius:2px;background:#F3F4F6;">
                <div style="height:100%;border-radius:2px;background:#C2410C;width:${Math.round((r.count/max)*100)}%;"></div>
            </div>
        </div>`).join('');
}

// ═══════════════════════════════════════════════════════════════════════════
//  Alerts Tab renderers
// ═══════════════════════════════════════════════════════════════════════════
function renderPrioTable(rows) {
    const el = $('prio-tbody');
    if (!el) return;
    if (!rows.length) { el.innerHTML = '<tr><td colspan="3" class="empty-msg">No alarm data for this period</td></tr>'; return; }
    el.innerHTML = rows.map(r => {
        const st = r.statuses || {};
        const chips = [
            st.open      ? `<span class="chip chip-open">${st.open} Open</span>` : '',
            st.closed    ? `<span class="chip chip-closed">${st.closed} Closed</span>` : '',
            st.in_review ? `<span class="chip chip-review">${st.in_review} In Review</span>` : '',
        ].filter(Boolean).join('');
        return `<tr>
            <td><span class="p-badge p-${r.priority.toLowerCase()}">${esc(r.priority)}</span></td>
            <td style="font-weight:800;">${fmt(r.total)}</td>
            <td><div class="chips">${chips || '<span style="color:#9CA3AF;font-size:.72rem;">—</span>'}</div></td>
        </tr>`;
    }).join('');
}

function renderMethTable(rows) {
    const el = $('meth-tbody');
    if (!el) return;
    if (!rows.length) { el.innerHTML = '<tr><td colspan="3" class="empty-msg">No data</td></tr>'; return; }
    const max = rows[0]?.count || 1;
    el.innerHTML = rows.slice(0,15).map(r => `
        <tr>
            <td><div style="font-weight:600;">${esc(r.method)}</div>${r.strategy ? `<div class="intent-sub">Strategy: ${esc(r.strategy)}</div>` : ''}</td>
            <td><span class="intent-sub">${esc(r.intent || '—')}</span></td>
            <td style="text-align:right;">
                <div class="bar-wrap" style="justify-content:flex-end;">
                    <div class="bar-bg" style="width:60px;"><div class="bar-fill" style="width:${Math.round((r.count/max)*100)}%;"></div></div>
                    <span class="count-n">${fmt(r.count)}</span>
                </div>
            </td>
        </tr>`).join('');
}

function renderAssetTable(tbodyId, rows) {
    const el = $(tbodyId);
    if (!el) return;
    if (!rows.length) { el.innerHTML = '<tr><td colspan="3" class="empty-msg">No data</td></tr>'; return; }
    el.innerHTML = rows.map((r, i) => `
        <tr>
            <td><div class="asset-n">${i+1}. ${esc(r.asset)}</div></td>
            <td><span class="cnt-lbl">${fmt(r.count)}</span></td>
            <td><div class="asset-tags">${(r.alarm_types||[]).slice(0,2).map(t => esc(t)).join(', ') || '—'}</div></td>
        </tr>`).join('');
}

function renderAlarmList(all) {
    const el = $('alarm-tbody');
    if (!el) return;
    const avAlerts = all.filter(a => a.platform === 'AlienVault');
    if (!avAlerts.length) { el.innerHTML = '<tr><td colspan="6" class="empty-msg">No AlienVault alarms in the current 24hr window</td></tr>'; return; }
    el.innerHTML = avAlerts.map(a => {
        const p = (a.confidence || a.severity || 'low').toLowerCase();
        const st = a.status || 'Closed';
        const stCls = st === 'Open' ? 'st-open' : st === 'In Review' ? 'st-review' : 'st-closed';
        return `<tr>
            <td><div class="alarm-n">${esc(a.alert_type || '—')}</div><div class="alarm-sub">${esc(a.intent || '')}${a.intent&&a.strategy?' · ':''}${esc(a.strategy||'')}</div></td>
            <td><span class="p-badge p-${p}">${esc(a.confidence || p)}</span></td>
            <td><span class="st-badge ${stCls}">${esc(st)}</span></td>
            <td style="font-size:.8rem;">${esc(a.source||'—')}</td>
            <td style="font-size:.8rem;color:#9CA3AF;">${esc(a.destination||'—')}</td>
            <td style="font-size:.75rem;color:#9CA3AF;white-space:nowrap;">${esc(a.reported_at||a.time||'—')}</td>
        </tr>`;
    }).join('');
}

// ═══════════════════════════════════════════════════════════════════════════
//  EDR Tab
// ═══════════════════════════════════════════════════════════════════════════
function renderS1Table(alerts) {
    const el = $('s1-tbody');
    if (!el) return;
    if (!alerts.length) { el.innerHTML = '<tr><td colspan="6" class="empty-msg">No SentinelOne threats in the current 24hr window</td></tr>'; return; }
    el.innerHTML = alerts.map(a => {
        const conf = (a.confidence||'').toLowerCase();
        const cCls = conf==='malicious'?'t-mal':conf==='suspicious'?'t-sus':'t-unk';
        const vCls = a.analyst_verdict==='True Positive'?'v-tp':a.analyst_verdict==='False Positive'?'v-fp':'v-sus';
        const iCls = a.status==='Resolved'?'i-res':a.status==='In Progress'?'i-prog':'i-open';
        return `<tr>
            <td><div class="alarm-n">${esc(a.alert_type||'—')}</div><div class="alarm-sub">${esc(a.id||'')}</div></td>
            <td><span class="t-badge ${cCls}">${esc(a.confidence||'Unknown')}</span></td>
            <td><span class="v-badge ${vCls}">${esc(a.analyst_verdict||'Pending')}</span></td>
            <td><span class="i-badge ${iCls}">${esc(a.status||'Unknown')}</span></td>
            <td style="font-size:.8rem;">${esc(a.source||'—')}</td>
            <td style="font-size:.75rem;color:#9CA3AF;white-space:nowrap;">${esc(a.reported_at||a.time||'—')}</td>
        </tr>`;
    }).join('');
}

// ═══════════════════════════════════════════════════════════════════════════
//  System status
// ═══════════════════════════════════════════════════════════════════════════
function updateStatus(st) {
    const el = $('system-status'); if (!el) return;
    el.classList.remove('degraded','error');
    const txt = el.querySelector('.status-text');
    if (st==='degraded') { el.classList.add('degraded'); txt.textContent='Partial Connectivity'; }
    else if (st==='error'||st==='unconfigured') { el.classList.add('error'); txt.textContent='Configuration Required'; }
    else if (txt) { txt.textContent='All Systems Operational'; }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════
const _kpiAnims = {};
function animKPI(id, target) {
    const el = $(id); if (!el) return;
    const start = Number(el.dataset.val)||0;
    el.dataset.val = target;
    if (_kpiAnims[id]) cancelAnimationFrame(_kpiAnims[id]);
    const t0 = performance.now();
    function step(now) {
        const p = Math.min((now-t0)/700, 1);
        const e = 1 - Math.pow(1-p, 3);
        el.textContent = fmt(Math.round(start + (target-start)*e));
        if (p < 1) _kpiAnims[id] = requestAnimationFrame(step);
    }
    _kpiAnims[id] = requestAnimationFrame(step);
}

function setBar(id, val, max) {
    const el = $(id); if (!el) return;
    el.style.width = Math.min(Math.round((val/Math.max(max,1))*100), 100) + '%';
}

function fmt(n) {
    n = Number(n)||0;
    if (n>=1e6) return (n/1e6).toFixed(1)+'M';
    if (n>=1e3) return (n/1e3).toFixed(1)+'k';
    return String(n);
}

function esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
}

function startTimer() {
    if (_updateTimer) clearInterval(_updateTimer);
    _updateTimer = setInterval(() => {
        if (!lastUpdateTime) return;
        const s = Math.floor((Date.now()-lastUpdateTime.getTime())/1000);
        const el = $('last-updated');
        if (el) el.textContent = s<5?'just now':s<60?`${s}s ago`:`${Math.floor(s/60)}m ago`;
    }, 1000);
}

// ═══════════════════════════════════════════════════════════════════════════
//  Bootstrap
// ═══════════════════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', async () => {
    const nn = $('nav-client-name');
    if (nn && CLIENT_NAME.length > 14) { nn.textContent = CLIENT_NAME.substring(0,14)+'…'; nn.title = CLIENT_NAME; }
    if (typeof initEventChart === 'function') initEventChart();
    if (typeof initEDRChart   === 'function') initEDRChart();
    await preload();
    connectWS();
});
