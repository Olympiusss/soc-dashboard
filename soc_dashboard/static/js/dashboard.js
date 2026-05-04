/**
 * Sentrium SOC — Per-Client Dashboard JS
 * Tabs: Dashboard | Alerts (AV) | EDR (S1) | Settings
 */
'use strict';

let ws = null, reconnectAttempts = 0, lastUpdateTime = null, updateTimerID = null;

// ── DOM refs ──────────────────────────────────────────────
const alertsTbody      = document.getElementById('alerts-tbody');
const alarmListTbody   = document.getElementById('alarm-list-tbody');
const prioTbody        = document.getElementById('prio-tbody');
const methodTbody      = document.getElementById('method-tbody');
const srcTbody         = document.getElementById('src-tbody');
const dstTbody         = document.getElementById('dst-tbody');
const lastUpdatedEl    = document.getElementById('last-updated');
const systemStatusEl   = document.getElementById('system-status');
const notifCountEl     = document.getElementById('notif-count');
const liveIndicator    = document.getElementById('live-indicator');
const reconnectOverlay = document.getElementById('reconnect-overlay');
const platformPillsEl  = document.getElementById('platform-pills');
const platformStatsEl  = document.getElementById('platform-stats');


// ═══════════════════════════════════════════════════════════
//  Tab Switching
// ═══════════════════════════════════════════════════════════
function switchTab(targetId) {
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    const pane = document.getElementById(targetId);
    const btn  = document.querySelector(`.tab-btn[data-target="${targetId}"]`);
    if (pane) pane.classList.add('active');
    if (btn)  btn.classList.add('active');
}

document.querySelectorAll('.tab-btn[data-target]').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.target));
});

// Sidebar nav → tabs
document.querySelectorAll('.nav-item[data-tab]').forEach(item => {
    item.addEventListener('click', e => {
        e.preventDefault();
        const tabMap = { alerts: 'tab-alerts', edr: 'tab-edr', settings: 'tab-settings' };
        const target = tabMap[item.dataset.tab];
        if (target) switchTab(target);
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        item.classList.add('active');
    });
});


// ═══════════════════════════════════════════════════════════
//  REST Pre-load
// ═══════════════════════════════════════════════════════════
async function preloadClientData() {
    try {
        const r = await fetch(`/api/client/${encodeURIComponent(CLIENT_NAME)}/data`);
        if (r.ok) displayClientData(await r.json());
    } catch(e) { console.warn('[REST] pre-load failed:', e); }
}


// ═══════════════════════════════════════════════════════════
//  WebSocket
// ═══════════════════════════════════════════════════════════
function connectWebSocket() {
    if (ws && ws.readyState === WebSocket.OPEN) return;
    ws = new WebSocket(WS_URL);
    ws.onopen = () => {
        reconnectAttempts = 0;
        if (reconnectOverlay) reconnectOverlay.classList.remove('visible');
        liveIndicator.classList.remove('disconnected');
    };
    ws.onmessage = e => {
        try {
            const d = JSON.parse(e.data);
            if (d.type === 'client_detail') displayClientData(d.client);
            else handleDashboardUpdate(d);
        } catch(err) { console.error('[WS] parse error', err); }
    };
    ws.onclose = () => {
        liveIndicator.classList.add('disconnected');
        reconnectAttempts++;
        if (reconnectAttempts > 2 && reconnectOverlay) reconnectOverlay.classList.add('visible');
        setTimeout(connectWebSocket, Math.min(reconnectAttempts * 2000, 15000));
    };
    ws.onerror = () => ws.close();
}


// ═══════════════════════════════════════════════════════════
//  Main Data Handler
// ═══════════════════════════════════════════════════════════
function handleDashboardUpdate(state) {
    lastUpdateTime = new Date();
    updateSystemStatus(state.system_status);
    const client = (state.clients||[]).find(c => c.name.toLowerCase() === CLIENT_NAME.toLowerCase());
    if (client) displayClientData(client);
    startUpdateTimer();
}

function displayClientData(client) {
    lastUpdateTime = lastUpdateTime || new Date();

    // Platform banner
    renderPlatformBanner(client);

    // KPIs (Dashboard tab)
    const avAlarms  = client.av_total_alarms || client.total_alerts || 0;
    const s1Alerts  = (client.recent_alerts||[]).filter(a => a.platform === 'SentinelOne');
    animateKPI('kpi-blocked',   client.blocked_attempts || 0);
    animateKPI('kpi-alerts',    avAlarms);
    animateKPI('kpi-threats',   client.total_threats || 0);
    animateKPI('kpi-endpoints', client.total_endpoints || 0);
    animateKPI('kpi-dfir',      client.dfir_cases || 0);

    // Charts
    updateEventChart(client.event_timeline || []);
    updateEDRChart(client.threat_classifications || []);

    // Dashboard quick summary
    renderDashPrioSummary(client.av_priority_breakdown || []);
    renderDashMethodSummary(client.av_method_summary || []);

    // Alerts tab badge
    const badge = document.getElementById('tab-alerts-badge');
    if (badge && avAlarms > 0) { badge.textContent = formatNumber(avAlarms); badge.style.display = 'inline'; }

    // ── Alerts tab ──
    renderAVTotal(client.av_total_alarms || 0);
    renderPriorityTable(client.av_priority_breakdown || []);
    renderMethodTable(client.av_method_summary || []);
    renderAssetTable('src-tbody', client.av_top_sources || []);
    renderAssetTable('dst-tbody', client.av_top_destinations || []);
    renderAlarmList(client.recent_alerts || []);

    // ── EDR tab ──
    renderS1ThreatCount(s1Alerts.length);
    renderAlertsTable(s1Alerts);
    if (notifCountEl) notifCountEl.textContent = s1Alerts.filter(a => a.status === 'Unresolved' || a.status === 'In Progress').length;

    startUpdateTimer();
}


// ═══════════════════════════════════════════════════════════
//  Platform Banner
// ═══════════════════════════════════════════════════════════
function renderPlatformBanner(client) {
    if (!platformPillsEl) return;
    const platforms = client.platforms || [];
    platformPillsEl.innerHTML = platforms.map(p =>
        p === 'SentinelOne'
            ? `<span class="plat-pill plat-pill-s1"><span class="plat-dot"></span>SentinelOne</span>`
            : `<span class="plat-pill plat-pill-av"><span class="plat-dot"></span>AlienVault</span>`
    ).join(' ') || '—';
    if (platformStatsEl) {
        const av = client.av_total_alarms || 0;
        const s1 = (client.recent_alerts||[]).filter(a => a.platform==='SentinelOne').length;
        platformStatsEl.innerHTML =
            (platforms.includes('SentinelOne') ? `<span class="platform-stat">S1 threats: <strong>${formatNumber(s1)}</strong></span>` : '') +
            (platforms.includes('AlienVault')  ? `<span class="platform-stat">AV alarms: <strong>${formatNumber(av)}</strong></span>` : '');
    }
}


// ═══════════════════════════════════════════════════════════
//  Dashboard quick summaries
// ═══════════════════════════════════════════════════════════
function renderDashPrioSummary(rows) {
    const el = document.getElementById('dash-prio-summary');
    if (!el) return;
    if (!rows.length) { el.innerHTML = '<p style="color:var(--text-muted);font-size:.82rem;">No AV data available</p>'; return; }
    el.innerHTML = rows.map(r =>
        `<div style="display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid rgba(0,0,0,.04);">
            <span class="prio-badge prio-${r.priority.toLowerCase()}">${escHtml(r.priority)}</span>
            <span style="font-size:.82rem;font-weight:700;">${formatNumber(r.total)}</span>
            <span style="font-size:.72rem;color:var(--text-muted);">${r.statuses.open} open · ${r.statuses.closed} closed</span>
         </div>`
    ).join('');
}

function renderDashMethodSummary(rows) {
    const el = document.getElementById('dash-method-summary');
    if (!el) return;
    if (!rows.length) { el.innerHTML = '<p style="color:var(--text-muted);font-size:.82rem;">No AV data available</p>'; return; }
    const max = rows[0]?.count || 1;
    el.innerHTML = rows.slice(0,5).map(r =>
        `<div style="padding:5px 0;border-bottom:1px solid rgba(0,0,0,.04);">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <span style="font-size:.8rem;font-weight:600;color:var(--text-primary);">${escHtml(r.method)}</span>
                <span style="font-size:.75rem;font-weight:700;color:#F97316;">${formatNumber(r.count)}</span>
            </div>
            <div style="height:4px;border-radius:2px;background:rgba(249,115,22,.15);margin-top:4px;">
                <div style="height:100%;border-radius:2px;background:#F97316;width:${Math.round((r.count/max)*100)}%;"></div>
            </div>
         </div>`
    ).join('');
}


// ═══════════════════════════════════════════════════════════
//  Alerts Tab Renderers
// ═══════════════════════════════════════════════════════════
function renderAVTotal(total) {
    const el = document.getElementById('av-total-count');
    if (el) el.textContent = `${formatNumber(total)} alarms · 24hr window`;
    const lt = document.getElementById('av-list-total');
    if (lt) lt.textContent = formatNumber(total);
}

function renderPriorityTable(rows) {
    if (!prioTbody) return;
    if (!rows.length) {
        prioTbody.innerHTML = '<tr><td colspan="3" style="color:var(--text-muted);padding:16px 8px;">No alarm data</td></tr>';
        return;
    }
    prioTbody.innerHTML = rows.map(r => {
        const st = r.statuses || {};
        const chips = [
            st.open     ? `<span class="status-chip chip-open">${st.open} Open</span>`     : '',
            st.closed   ? `<span class="status-chip chip-closed">${st.closed} Closed</span>` : '',
            st.in_review? `<span class="status-chip chip-review">${st.in_review} In Review</span>` : '',
            st.other && st.other > 0 ? `<span class="status-chip chip-closed">${st.other} Other</span>` : '',
        ].filter(Boolean).join('');
        return `<tr>
            <td><span class="prio-badge prio-${r.priority.toLowerCase()}">${escHtml(r.priority)}</span></td>
            <td style="font-weight:700;">${formatNumber(r.total)}</td>
            <td><div class="status-sub">${chips}</div></td>
        </tr>`;
    }).join('');
}

function renderMethodTable(rows) {
    if (!methodTbody) return;
    if (!rows.length) {
        methodTbody.innerHTML = '<tr><td colspan="3" style="color:var(--text-muted);padding:16px 8px;">No data</td></tr>';
        return;
    }
    const max = rows[0]?.count || 1;
    methodTbody.innerHTML = rows.slice(0, 15).map(r => `
        <tr>
            <td><div style="font-weight:600;font-size:.8rem;">${escHtml(r.method)}</div>${r.strategy ? `<div class="intent-tag">Strategy: ${escHtml(r.strategy)}</div>` : ''}</td>
            <td><span style="font-size:.75rem;color:var(--text-muted);">${escHtml(r.intent || '—')}</span></td>
            <td style="text-align:right;">
                <div class="count-bar-wrap" style="justify-content:flex-end;">
                    <div class="count-bar" style="width:${Math.round((r.count/max)*60)}px;"></div>
                    <strong style="font-size:.8rem;">${formatNumber(r.count)}</strong>
                </div>
            </td>
        </tr>`
    ).join('');
}

function renderAssetTable(tbodyId, rows) {
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return;
    if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="3" style="color:var(--text-muted);padding:16px 8px;">No data</td></tr>';
        return;
    }
    tbody.innerHTML = rows.map((r, i) => `
        <tr>
            <td><div class="asset-name">${i+1}. ${escHtml(r.asset)}</div></td>
            <td><span class="count-pill">${formatNumber(r.count)}</span></td>
            <td><div class="asset-tags">${(r.alarm_types||[]).map(t => escHtml(t)).join(', ') || '—'}</div></td>
        </tr>`
    ).join('');
}

function renderAlarmList(allAlerts) {
    if (!alarmListTbody) return;
    const avAlerts = allAlerts.filter(a => a.platform === 'AlienVault');
    if (!avAlerts.length) {
        alarmListTbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:32px;color:var(--text-muted);">No AlienVault alarms in the current window</td></tr>';
        return;
    }
    alarmListTbody.innerHTML = avAlerts.map(a => {
        const prio = (a.confidence || a.severity || 'low').toLowerCase();
        const prioBadge = `<span class="prio-badge prio-${prio}">${escHtml(a.confidence || prio)}</span>`;
        const st = a.status || 'Open';
        const stClass = st === 'Open' ? 'av-st-open' : st === 'In Review' ? 'av-st-review' : 'av-st-closed';
        const stBadge = `<span class="av-st-badge ${stClass}">${escHtml(st)}</span>`;
        return `<tr>
            <td>
                <div class="alarm-name">${escHtml(a.alert_type || '—')}</div>
                <div class="alarm-meta">${escHtml(a.intent || '')}${a.intent && a.strategy ? ' · ' : ''}${escHtml(a.strategy || '')}</div>
                <div class="alarm-meta" style="margin-top:2px;">${escHtml(a.time || '')}</div>
            </td>
            <td>${prioBadge}</td>
            <td>${stBadge}</td>
            <td style="font-size:.8rem;">${escHtml(a.source || '—')}</td>
            <td style="font-size:.8rem;color:var(--text-muted);">${escHtml(a.destination || '—')}</td>
            <td style="font-size:.75rem;color:var(--text-muted);white-space:nowrap;">${escHtml(a.reported_at || a.time || '—')}</td>
        </tr>`;
    }).join('');
}


// ═══════════════════════════════════════════════════════════
//  EDR (S1) Tab
// ═══════════════════════════════════════════════════════════
function renderS1ThreatCount(n) {
    const el = document.getElementById('s1-threat-count');
    if (el) el.textContent = `${formatNumber(n)} threats · 24hr window`;
}

function renderAlertsTable(alerts) {
    if (!alertsTbody) return;
    if (!alerts.length) {
        alertsTbody.innerHTML = '<tr class="empty-row"><td colspan="7" style="text-align:center;padding:32px;">No SentinelOne threats in the current window</td></tr>';
        return;
    }
    alertsTbody.innerHTML = alerts.map(a => {
        const conf = (a.confidence||'').toLowerCase();
        const confClass = conf==='malicious'?'conf-malicious':conf==='suspicious'?'conf-suspicious':'conf-unknown';
        const verdictClass = a.analyst_verdict==='True Positive'?'verdict-tp':a.analyst_verdict==='False Positive'?'verdict-fp':a.analyst_verdict==='Suspicious'?'verdict-sus':'verdict-other';
        const stClass = a.status==='Resolved'?'inc-resolved':a.status==='In Progress'?'inc-progress':a.status==='Unresolved'?'inc-unresolved':'inc-other';
        return `<tr>
            <td><strong class="threat-id">${escHtml(a.id)}</strong></td>
            <td class="threat-details-cell">${escHtml(a.alert_type)} <span class="platform-chip platform-s1">S1</span></td>
            <td><span class="conf-badge ${confClass}">${escHtml(a.confidence||'Unknown')}</span></td>
            <td><span class="verdict-badge ${verdictClass}">${escHtml(a.analyst_verdict||'Pending')}</span></td>
            <td><span class="inc-badge ${stClass}">${escHtml(a.status||'Unknown')}</span></td>
            <td class="endpoint-name">${escHtml(a.source||'—')}</td>
            <td class="reported-time">${escHtml(a.reported_at||a.time||'')}</td>
        </tr>`;
    }).join('');
}


// ═══════════════════════════════════════════════════════════
//  System Status
// ═══════════════════════════════════════════════════════════
function updateSystemStatus(status) {
    if (!systemStatusEl) return;
    systemStatusEl.classList.remove('degraded','error');
    const txt = systemStatusEl.querySelector('.status-text');
    if (status==='degraded') { systemStatusEl.classList.add('degraded'); txt.textContent='Partial Connectivity'; }
    else if (status==='error'||status==='unconfigured') { systemStatusEl.classList.add('error'); txt.textContent='Configuration Required'; }
    else { txt.textContent='All System Operational'; }
}


// ═══════════════════════════════════════════════════════════
//  KPI Animation
// ═══════════════════════════════════════════════════════════
const kpiAnimations = {};
function animateKPI(id, target) {
    const card = document.getElementById(id);
    if (!card) return;
    const el = card.querySelector('.kpi-value');
    if (!el) return;
    const current = parseInt(el.dataset.target)||0;
    el.dataset.target = target;
    if (kpiAnimations[id]) cancelAnimationFrame(kpiAnimations[id]);
    const start = performance.now();
    function step(now) {
        const p = Math.min((now-start)/800,1);
        const e = 1-Math.pow(1-p,3);
        el.textContent = formatNumber(Math.round(current+(target-current)*e));
        if (p<1) kpiAnimations[id] = requestAnimationFrame(step);
    }
    kpiAnimations[id] = requestAnimationFrame(step);
}


// ═══════════════════════════════════════════════════════════
//  Update timer
// ═══════════════════════════════════════════════════════════
function startUpdateTimer() {
    if (updateTimerID) clearInterval(updateTimerID);
    updateTimerID = setInterval(() => {
        if (!lastUpdateTime||!lastUpdatedEl) return;
        const s = Math.floor((Date.now()-lastUpdateTime.getTime())/1000);
        lastUpdatedEl.textContent = s<5?'just now':s<60?`${s}s ago`:`${Math.floor(s/60)}m ago`;
    }, 1000);
}


// ═══════════════════════════════════════════════════════════
//  Utilities
// ═══════════════════════════════════════════════════════════
function escHtml(str) {
    if (!str) return '';
    const d = document.createElement('div');
    d.textContent = String(str);
    return d.innerHTML;
}

function formatNumber(n) {
    n = Number(n)||0;
    if (n>=1000000) return (n/1000000).toFixed(1)+'M';
    if (n>=1000) return (n/1000).toFixed(1)+'k';
    return String(n);
}


// ═══════════════════════════════════════════════════════════
//  Bootstrap
// ═══════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', async () => {
    const navName = document.getElementById('nav-client-name');
    if (navName && CLIENT_NAME.length > 14) { navName.textContent = CLIENT_NAME.substring(0,14)+'…'; navName.title = CLIENT_NAME; }
    initEventChart();
    initEDRChart();
    await preloadClientData();
    connectWebSocket();
});
