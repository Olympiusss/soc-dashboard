'use strict';
// Sentrium SOC — Per-Client Dashboard JS v7
// Sidebar nav, conditional EDR, premium renderers

let ws = null, reconnectAttempts = 0, lastUpdateTime = null, _timer = null;
const $ = id => document.getElementById(id);

// ── Section switching via sidebar nav ────────────────────────────────────────
function switchSection(sectionId) {
    document.querySelectorAll('.client-section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.client-nav-item').forEach(b => b.classList.remove('active'));
    const sec = $(sectionId);
    if (sec) sec.classList.add('active');
    const btn = document.querySelector(`.client-nav-item[data-section="${sectionId}"]`);
    if (btn) btn.classList.add('active');
}

document.querySelectorAll('.client-nav-item[data-section]').forEach(btn =>
    btn.addEventListener('click', () => switchSection(btn.dataset.section))
);

// ── Platform nav visibility ───────────────────────────────────────────────────
function applyPlatformNav(platforms) {
    const hasS1 = platforms.includes('SentinelOne');
    const hasAV = platforms.includes('AlienVault');

    const navAlerts = $('nav-alerts');
    const navEdr    = $('nav-edr');

    if (navAlerts) navAlerts.style.display = hasAV ? '' : 'none';
    if (navEdr)    navEdr.style.display    = hasS1 ? '' : 'none';

    // If current section is EDR but client has no S1, switch to overview
    const activeSection = document.querySelector('.client-section.active');
    if (activeSection?.id === 'section-edr' && !hasS1) switchSection('section-overview');
    if (activeSection?.id === 'section-alerts' && !hasAV) switchSection('section-overview');
}

// ── REST pre-load ─────────────────────────────────────────────────────────────
async function preload() {
    try {
        const r = await fetch(`/api/client/${encodeURIComponent(CLIENT_NAME)}/data`);
        if (r.ok) renderClient(await r.json());
    } catch (e) { console.warn('[REST]', e); }
}

// ── WebSocket ─────────────────────────────────────────────────────────────────
function connectWS() {
    ws = new WebSocket(WS_URL);
    ws.onopen = () => {
        reconnectAttempts = 0;
        const o = $('reconnect-overlay'); if (o) o.classList.remove('visible');
    };
    ws.onmessage = e => {
        try {
            const d = JSON.parse(e.data);
            const client = (d.clients || []).find(
                c => c.name.toLowerCase() === CLIENT_NAME.toLowerCase()
            );
            if (client) { renderClient(client); lastUpdateTime = new Date(); tick(); }
            updateSysStatus(d.system_status);
        } catch (err) { console.error('[WS]', err); }
    };
    ws.onclose = () => {
        reconnectAttempts++;
        if (reconnectAttempts > 2) {
            const o = $('reconnect-overlay'); if (o) o.classList.add('visible');
        }
        setTimeout(connectWS, Math.min(reconnectAttempts * 2000, 15000));
    };
    ws.onerror = () => ws.close();
}

// ── Main render ───────────────────────────────────────────────────────────────
function renderClient(c) {
    if (!c) return;

    const platforms = c.platforms || [];
    applyPlatformNav(platforms);

    // Sidebar client identity
    const nameEl = $('sidebar-client-name');
    if (nameEl) nameEl.textContent = c.name || CLIENT_NAME;

    const tagsEl = $('sidebar-plat-tags');
    if (tagsEl) tagsEl.innerHTML = platforms.map(p =>
        p === 'SentinelOne'
            ? '<span class="cpill cpill-s1">S1</span>'
            : '<span class="cpill cpill-av">AV</span>'
    ).join('') || '—';

    // Platform strip
    const ppEl = $('plat-pills-strip');
    if (ppEl) ppEl.innerHTML = platforms.map(p =>
        p === 'SentinelOne'
            ? '<span class="cpill cpill-s1">SentinelOne</span>'
            : '<span class="cpill cpill-av">AlienVault</span>'
    ).join('') || '—';

    const psEl = $('plat-stats-strip');
    if (psEl) {
        const parts = [];
        if (platforms.includes('AlienVault'))  parts.push(`AV alarms: <strong>${fmt(c.av_total_alarms || 0)}</strong>`);
        if (platforms.includes('SentinelOne')) parts.push(`S1 threats: <strong>${fmt(c.total_threats || 0)}</strong>`);
        psEl.innerHTML = parts.join(' &nbsp;·&nbsp; ');
    }

    // KPIs
    const avTotal = c.av_total_alarms || 0;
    animNum('kv-alarms',    avTotal);
    animNum('kv-threats',   c.total_threats   || 0);
    animNum('kv-endpoints', c.total_endpoints || 0);
    animNum('kv-blocked',   c.blocked_attempts|| 0);
    animNum('kv-dfir',      c.dfir_cases      || 0);

    // Hide KPI tiles not applicable to this client's platforms
    const kvAlarms    = $('kv-alarms')?.closest('.kpi-tile');
    const kvThreats   = $('kv-threats')?.closest('.kpi-tile');
    const kvEndpoints = $('kv-endpoints')?.closest('.kpi-tile');
    if (kvAlarms)    kvAlarms.style.display    = platforms.includes('AlienVault')  ? '' : 'none';
    if (kvThreats)   kvThreats.style.display   = platforms.includes('SentinelOne') ? '' : 'none';
    if (kvEndpoints) kvEndpoints.style.display = platforms.includes('SentinelOne') ? '' : 'none';

    // Charts
    if (typeof updateEventChart === 'function') updateEventChart(c.event_timeline || []);

    // Overview panels
    renderDashPrio(c.av_priority_breakdown || []);
    renderDashMethods(c.av_method_summary  || []);

    // Alerts nav badge
    const nb = $('nav-alerts-badge');
    if (nb && avTotal > 0) { nb.textContent = fmt(avTotal); nb.style.display = 'inline'; }

    // Alerts section
    const avLbl = $('av-total-lbl');
    if (avLbl) avLbl.textContent = `${fmt(avTotal)} alarms · 24hr window`;
    const listTot = $('av-list-total'); if (listTot) listTot.textContent = fmt(avTotal);

    renderPrioTable(c.av_priority_breakdown  || []);
    renderMethTable(c.av_method_summary      || []);
    renderAssetTable('src-tbody', c.av_top_sources      || []);
    renderAssetTable('dst-tbody', c.av_top_destinations || []);
    renderAlarmLog(c.recent_alerts || []);

    // EDR section
    const s1Alerts = (c.recent_alerts || []).filter(a => a.platform === 'SentinelOne');
    const s1Lbl = $('s1-threat-lbl');
    if (s1Lbl) s1Lbl.textContent = `${fmt(s1Alerts.length)} threats · 24hr window`;
    const edrBadge = $('nav-edr-badge');
    if (edrBadge && s1Alerts.length) { edrBadge.textContent = fmt(s1Alerts.length); edrBadge.style.display = 'inline'; }
    renderS1Table(s1Alerts);
}

// ── Overview panels ───────────────────────────────────────────────────────────
function renderDashPrio(rows) {
    const el = $('dash-prio'); if (!el) return;
    if (!rows.length) { el.innerHTML = '<p style="color:#3A4A6A;font-size:.8rem;padding:6px 0;">No AV alarm data for this period.</p>'; return; }
    el.innerHTML = rows.map(r => {
        const p = r.priority.toLowerCase();
        const st = r.statuses || {};
        return `<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.04);">
            <span class="pb pb-${p}" style="min-width:62px;">${esc(r.priority)}</span>
            <span style="font-weight:800;font-size:.95rem;min-width:32px;">${fmt(r.total)}</span>
            <span style="font-size:.7rem;color:#4A5A7A;flex:1;">${st.open||0} open &nbsp;·&nbsp; ${st.closed||0} closed${st.in_review?` &nbsp;·&nbsp; ${st.in_review} review`:''}</span>
        </div>`;
    }).join('');
}

function renderDashMethods(rows) {
    const el = $('dash-methods'); if (!el) return;
    if (!rows.length) { el.innerHTML = '<p style="color:#3A4A6A;font-size:.8rem;padding:6px 0;">No AV alarm data for this period.</p>'; return; }
    const max = rows[0]?.count || 1;
    el.innerHTML = rows.slice(0, 6).map(r => `
        <div style="padding:7px 0;border-bottom:1px solid rgba(255,255,255,.04);">
            <div style="display:flex;justify-content:space-between;margin-bottom:5px;">
                <span style="font-size:.8rem;font-weight:600;color:#C8D4F0;">${esc(r.method)}</span>
                <span style="font-size:.76rem;font-weight:800;color:#F97316;">${fmt(r.count)}</span>
            </div>
            <div class="bar-row"><div class="bar-bg"><div class="bar-fill" style="width:${Math.round((r.count/max)*100)}%;"></div></div></div>
        </div>`).join('');
}

// ── Alerts section renderers ──────────────────────────────────────────────────
function renderPrioTable(rows) {
    const el = $('prio-tbody'); if (!el) return;
    if (!rows.length) { el.innerHTML = '<tr><td colspan="5" class="empty-msg">No alarm data for this period.</td></tr>'; return; }
    el.innerHTML = rows.map(r => {
        const st = r.statuses || {};
        return `<tr>
            <td><span class="pb pb-${r.priority.toLowerCase()}">${esc(r.priority)}</span></td>
            <td style="font-weight:800;">${fmt(r.total)}</td>
            <td>${st.open ? `<span class="sc sc-open">${st.open}</span>` : '—'}</td>
            <td>${st.closed ? `<span class="sc sc-closed">${st.closed}</span>` : '—'}</td>
            <td>${st.in_review ? `<span class="sc sc-review">${st.in_review}</span>` : '—'}</td>
        </tr>`;
    }).join('');
}

function renderMethTable(rows) {
    const el = $('meth-tbody'); if (!el) return;
    if (!rows.length) { el.innerHTML = '<tr><td colspan="4" class="empty-msg">No data.</td></tr>'; return; }
    const max = rows[0]?.count || 1;
    el.innerHTML = rows.slice(0, 15).map(r => `
        <tr>
            <td style="font-weight:600;color:#C8D4F0;">${esc(r.method)}</td>
            <td style="color:#5A6A8A;font-size:.76rem;">${esc(r.strategy || '—')}</td>
            <td style="color:#5A6A8A;font-size:.76rem;">${esc(r.intent || '—')}</td>
            <td style="text-align:right;">
                <div class="bar-row" style="justify-content:flex-end;">
                    <div class="bar-bg" style="width:50px;"><div class="bar-fill" style="width:${Math.round((r.count/max)*100)}%;"></div></div>
                    <span class="bar-cnt">${fmt(r.count)}</span>
                </div>
            </td>
        </tr>`).join('');
}

function renderAssetTable(tbodyId, rows) {
    const el = $(tbodyId); if (!el) return;
    if (!rows.length) { el.innerHTML = '<tr><td colspan="4" class="empty-msg">No data.</td></tr>'; return; }
    el.innerHTML = rows.map((r, i) => `
        <tr>
            <td style="color:#5A6A8A;font-size:.76rem;">${i + 1}</td>
            <td style="font-weight:600;color:#C8D4F0;">${esc(r.asset)}</td>
            <td><span class="asset-cnt">${fmt(r.count)}</span></td>
            <td style="color:#5A6A8A;font-size:.72rem;">${(r.alarm_types || []).slice(0, 2).map(esc).join(', ') || '—'}</td>
        </tr>`).join('');
}

function renderAlarmLog(all) {
    const el = $('alarm-tbody'); if (!el) return;
    const av = all.filter(a => a.platform === 'AlienVault');
    if (!av.length) { el.innerHTML = '<tr><td colspan="6" class="empty-msg">No AlienVault alarms in the 24hr window.</td></tr>'; return; }
    el.innerHTML = av.map(a => {
        const p  = (a.confidence || a.severity || 'low').toLowerCase();
        const st = a.status || 'Closed';
        const stCls = st === 'Open' ? 'sc-open' : st === 'In Review' ? 'sc-review' : 'sc-closed';
        return `<tr>
            <td><div class="alarm-name">${esc(a.alert_type || '—')}</div><div class="alarm-sub">${esc((a.intent && a.strategy) ? `${a.intent} · ${a.strategy}` : (a.intent || a.strategy || ''))}</div></td>
            <td><span class="pb pb-${p}">${esc(p.charAt(0).toUpperCase()+p.slice(1))}</span></td>
            <td><span class="sc ${stCls}">${esc(st)}</span></td>
            <td style="font-size:.78rem;color:#9BAAC8;">${esc(a.source || '—')}</td>
            <td style="font-size:.76rem;color:#4A5A7A;">${esc(a.destination || '—')}</td>
            <td class="alarm-time">${esc(a.reported_at || a.time || '—')}</td>
        </tr>`;
    }).join('');
}

// ── EDR (S1) ──────────────────────────────────────────────────────────────────
function renderS1Table(alerts) {
    const el = $('s1-tbody'); if (!el) return;
    if (!alerts.length) { el.innerHTML = '<tr><td colspan="6" class="empty-msg">No SentinelOne threats in the 24hr window.</td></tr>'; return; }
    el.innerHTML = alerts.map(a => {
        const conf = (a.confidence || '').toLowerCase();
        const cCls = conf === 'malicious' ? 'conf-mal' : conf === 'suspicious' ? 'conf-sus' : 'conf-unk';
        const vCls = a.analyst_verdict === 'True Positive' ? 'vb-tp' : a.analyst_verdict === 'False Positive' ? 'vb-fp' : a.analyst_verdict ? 'vb-sus' : 'vb-pen';
        const stCls = a.status === 'Resolved' ? 'sc-closed' : a.status === 'In Progress' ? 'sc-review' : 'sc-open';
        return `<tr>
            <td><div class="alarm-name">${esc(a.alert_type || '—')}</div><div class="alarm-sub">${esc(a.id || '')}</div></td>
            <td><span class="pb ${cCls}">${esc(a.confidence || 'Unknown')}</span></td>
            <td><span class="vb ${vCls}">${esc(a.analyst_verdict || 'Pending')}</span></td>
            <td><span class="sc ${stCls}">${esc(a.status || 'Open')}</span></td>
            <td style="font-size:.78rem;color:#9BAAC8;">${esc(a.source || '—')}</td>
            <td class="alarm-time">${esc(a.reported_at || a.time || '—')}</td>
        </tr>`;
    }).join('');
}

// ── System status ─────────────────────────────────────────────────────────────
function updateSysStatus(st) {
    const el = $('system-status'); if (!el) return;
    el.className = 'system-status' + (st === 'degraded' ? ' degraded' : st === 'error' || st === 'unconfigured' ? ' error' : '');
    const txt = el.querySelector('.status-text');
    if (txt) txt.textContent = st === 'degraded' ? 'Partial Connectivity' : st === 'error' || st === 'unconfigured' ? 'Configuration Required' : 'All Systems Operational';
}

// ── Helpers ───────────────────────────────────────────────────────────────────
const _anims = {};
function animNum(id, target) {
    const el = $(id); if (!el) return;
    const start = Number(el.dataset.val) || 0;
    el.dataset.val = target;
    if (_anims[id]) cancelAnimationFrame(_anims[id]);
    const t0 = performance.now();
    (function step(now) {
        const p = Math.min((now - t0) / 700, 1);
        const e = 1 - Math.pow(1 - p, 3);
        el.textContent = fmt(Math.round(start + (target - start) * e));
        if (p < 1) _anims[id] = requestAnimationFrame(step);
    })(t0);
}

function fmt(n) {
    n = Number(n) || 0;
    if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1) + 'k';
    return String(n);
}

function esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
}

function tick() {
    if (_timer) clearInterval(_timer);
    _timer = setInterval(() => {
        if (!lastUpdateTime) return;
        const s = Math.floor((Date.now() - lastUpdateTime.getTime()) / 1000);
        const el = $('last-updated');
        if (el) el.textContent = s < 5 ? 'just now' : s < 60 ? `${s}s ago` : `${Math.floor(s / 60)}m ago`;
    }, 1000);
}

// ── Boot ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
    if (typeof initEventChart === 'function') initEventChart();
    await preload();
    connectWS();
});
