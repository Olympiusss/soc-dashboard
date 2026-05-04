/**
 * Sentrium Integrated SOC Dashboard — Per-Client Dashboard Logic
 * Handles REST pre-load, WebSocket live updates, S1 threats table,
 * and AlienVault alarms table — split by platform.
 */

'use strict';

// ═══════════════════════════════════════════════════════════
//  State
// ═══════════════════════════════════════════════════════════

let ws = null;
let reconnectAttempts = 0;
let lastUpdateTime = null;
let updateTimerID = null;

// DOM references
const alertsTbody      = document.getElementById('alerts-tbody');
const avAlarmsTbody    = document.getElementById('av-alarms-tbody');
const lastUpdatedEl    = document.getElementById('last-updated');
const systemStatusEl   = document.getElementById('system-status');
const notifCountEl     = document.getElementById('notif-count');
const activeCountEl    = document.getElementById('active-count');
const avAlarmCountEl   = document.getElementById('av-alarm-count');
const liveIndicator    = document.getElementById('live-indicator');
const reconnectOverlay = document.getElementById('reconnect-overlay');
const avSection        = document.getElementById('av-section');
const platformPillsEl  = document.getElementById('platform-pills');
const platformStatsEl  = document.getElementById('platform-stats');


// ═══════════════════════════════════════════════════════════
//  REST Pre-load (fast initial render before WS connects)
// ═══════════════════════════════════════════════════════════

async function preloadClientData() {
    try {
        const resp = await fetch(`/api/client/${encodeURIComponent(CLIENT_NAME)}/data`);
        if (resp.ok) {
            const client = await resp.json();
            displayClientData(client);
            console.log('[REST] Pre-loaded client data:', CLIENT_NAME);
        }
    } catch (e) {
        console.warn('[REST] Pre-load failed (will rely on WS):', e);
    }
}


// ═══════════════════════════════════════════════════════════
//  WebSocket Connection
// ═══════════════════════════════════════════════════════════

function connectWebSocket() {
    if (ws && ws.readyState === WebSocket.OPEN) return;

    ws = new WebSocket(WS_URL);

    ws.onopen = () => {
        console.log('[WS] Connected');
        reconnectAttempts = 0;
        if (reconnectOverlay) reconnectOverlay.classList.remove('visible');
        liveIndicator.classList.remove('disconnected');
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.type === 'client_detail') {
                displayClientData(data.client);
            } else {
                handleDashboardUpdate(data);
            }
        } catch (e) {
            console.error('[WS] Parse error:', e);
        }
    };

    ws.onclose = () => {
        console.log('[WS] Disconnected');
        liveIndicator.classList.add('disconnected');
        reconnectAttempts++;
        const delay = Math.min(reconnectAttempts * 2000, 15000);
        if (reconnectAttempts > 2 && reconnectOverlay) {
            reconnectOverlay.classList.add('visible');
        }
        setTimeout(connectWebSocket, delay);
    };

    ws.onerror = () => ws.close();
}


// ═══════════════════════════════════════════════════════════
//  Data Handlers
// ═══════════════════════════════════════════════════════════

function handleDashboardUpdate(state) {
    lastUpdateTime = new Date();
    updateSystemStatus(state.system_status);

    const clients = state.clients || [];
    const client = clients.find(
        c => c.name.toLowerCase() === CLIENT_NAME.toLowerCase()
    );

    if (client) {
        displayClientData(client);
    } else {
        console.warn(`Client "${CLIENT_NAME}" not found in ${clients.length} clients`);
    }

    startUpdateTimer();
}

function displayClientData(client) {
    // ── KPI Cards ──
    animateKPI('kpi-blocked',  client.blocked_attempts || 0);
    animateKPI('kpi-alerts',   client.total_alerts || 0);
    animateKPI('kpi-events',   client.events_processed || 0);
    animateKPI('kpi-dfir',     client.dfir_cases || 0);
    animateKPI('kpi-sectors',  (client.platforms || []).length);

    // ── Charts ──
    updateEventChart(client.event_timeline || []);
    updateEDRChart(client.threat_classifications || []);

    // ── Platform Banner ──
    renderPlatformBanner(client);

    // ── Split alerts by platform ──
    const allAlerts = client.recent_alerts || [];
    const s1Alerts  = allAlerts.filter(a => a.platform === 'SentinelOne');
    const avAlerts  = allAlerts.filter(a => a.platform === 'AlienVault');

    // ── S1 Threats Table ──
    renderAlertsTable(s1Alerts);
    const activeAlerts = s1Alerts.filter(
        a => a.status === 'Unresolved' || a.status === 'In Progress'
    ).length;
    if (notifCountEl) {
        notifCountEl.textContent = activeAlerts;
        notifCountEl.dataset.count = activeAlerts;
    }
    if (activeCountEl) activeCountEl.textContent = `${activeAlerts} Active`;

    // ── AV Alarms Table ──
    const hasAV = (client.platforms || []).includes('AlienVault');
    if (hasAV || avAlerts.length > 0) {
        if (avSection) avSection.classList.add('visible');
        renderAVAlarmsTable(avAlerts, client.total_alerts || 0, s1Alerts.length);
    } else {
        if (avSection) avSection.classList.remove('visible');
    }

    lastUpdateTime = lastUpdateTime || new Date();
    startUpdateTimer();
}


// ═══════════════════════════════════════════════════════════
//  Platform Banner
// ═══════════════════════════════════════════════════════════

function renderPlatformBanner(client) {
    const platforms = client.platforms || [];
    if (!platformPillsEl) return;

    const pills = platforms.map(p => {
        if (p === 'SentinelOne') {
            return `<span class="plat-pill plat-pill-s1"><span class="plat-pill-dot"></span>SentinelOne</span>`;
        }
        if (p === 'AlienVault') {
            return `<span class="plat-pill plat-pill-av"><span class="plat-pill-dot"></span>AlienVault</span>`;
        }
        return `<span class="plat-pill">${escapeHtml(p)}</span>`;
    }).join(' ');

    platformPillsEl.innerHTML = pills || '—';

    if (platformStatsEl) {
        const allAlerts = client.recent_alerts || [];
        const s1Count   = allAlerts.filter(a => a.platform === 'SentinelOne').length;
        const avCount   = allAlerts.filter(a => a.platform === 'AlienVault').length;
        let stats = '';
        if (s1Count > 0 || platforms.includes('SentinelOne')) {
            stats += `<span class="platform-stat">S1 threats: <strong>${formatNumber(s1Count)}</strong></span>`;
        }
        if (avCount > 0 || platforms.includes('AlienVault')) {
            stats += `<span class="platform-stat">AV alarms: <strong>${formatNumber(client.total_alerts - s1Count || avCount)}</strong></span>`;
        }
        platformStatsEl.innerHTML = stats;
    }
}


// ═══════════════════════════════════════════════════════════
//  UI Renderers
// ═══════════════════════════════════════════════════════════

function updateSystemStatus(status) {
    const el = systemStatusEl;
    if (!el) return;
    el.classList.remove('degraded', 'error');

    if (status === 'degraded') {
        el.classList.add('degraded');
        el.querySelector('.status-text').textContent = 'Partial Connectivity';
    } else if (status === 'error' || status === 'unconfigured') {
        el.classList.add('error');
        el.querySelector('.status-text').textContent = 'Configuration Required';
    } else {
        el.querySelector('.status-text').textContent = 'All System Operational';
    }
}

function renderAlertsTable(alerts) {
    if (!alertsTbody) return;

    if (!alerts.length) {
        alertsTbody.innerHTML = '<tr class="empty-row"><td colspan="7" style="text-align:center;padding:40px;color:var(--text-muted);">No SentinelOne threats in the monitored window</td></tr>';
        return;
    }

    const rows = alerts.map(a => {
        const platformChip = `<span class="platform-chip platform-s1">S1</span>`;

        const conf = (a.confidence || '').toLowerCase();
        const confClass = conf === 'malicious' ? 'conf-malicious' : conf === 'suspicious' ? 'conf-suspicious' : 'conf-unknown';
        const confBadge = `<span class="conf-badge ${confClass}">${escapeHtml(a.confidence || 'Unknown')}</span>`;

        const verdict = a.analyst_verdict || '';
        const verdictClass = verdict === 'True Positive' ? 'verdict-tp'
            : verdict === 'False Positive' ? 'verdict-fp'
            : verdict === 'Suspicious' ? 'verdict-sus'
            : 'verdict-other';
        const verdictHtml = verdict
            ? `<span class="verdict-badge ${verdictClass}">${escapeHtml(verdict)}</span>`
            : `<span class="verdict-badge verdict-other">Pending</span>`;

        const status = a.status || '';
        const statusClass = status === 'Resolved' ? 'inc-resolved'
            : status === 'In Progress' ? 'inc-progress'
            : status === 'Unresolved' ? 'inc-unresolved'
            : 'inc-other';
        const statusHtml = `<span class="inc-badge ${statusClass}">${escapeHtml(status || 'Unknown')}</span>`;

        const endpoint = a.source
            ? `<span class="endpoint-name">${escapeHtml(a.source)}</span>`
            : `<span style="color:var(--text-muted)">—</span>`;

        return `
            <tr>
                <td><strong class="threat-id">${escapeHtml(a.id)}</strong></td>
                <td class="threat-details-cell">${escapeHtml(a.alert_type)} ${platformChip}</td>
                <td>${confBadge}</td>
                <td>${verdictHtml}</td>
                <td>${statusHtml}</td>
                <td>${endpoint}</td>
                <td class="reported-time">${escapeHtml(a.reported_at || a.time || '')}</td>
            </tr>
        `;
    }).join('');

    alertsTbody.innerHTML = rows;
}

function renderAVAlarmsTable(alarms, totalAVAlerts, s1Count) {
    if (!avAlarmsTbody) return;

    // Update count badge
    const avTotal = totalAVAlerts - s1Count;
    if (avAlarmCountEl) {
        avAlarmCountEl.textContent = `${formatNumber(Math.max(avTotal, alarms.length))} alarms`;
    }

    if (!alarms.length) {
        avAlarmsTbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:30px;color:var(--text-muted);">No AlienVault alarms in the monitored window</td></tr>';
        return;
    }

    const rows = alarms.map(a => {
        // Priority badge
        const prio = (a.confidence || a.severity || 'medium').toLowerCase();
        const prioClass = prio === 'critical' ? 'prio-critical'
            : prio === 'high' ? 'prio-high'
            : prio === 'low'  ? 'prio-low'
            : 'prio-medium';
        const prioBadge = `<span class="prio-badge ${prioClass}">${escapeHtml((a.confidence || prio).charAt(0).toUpperCase() + (a.confidence || prio).slice(1))}</span>`;

        // Status badge
        const status = (a.status || 'Open');
        const statusClass = status === 'Open' ? 'av-status-open' : 'av-status-closed';
        const statusBadge = `<span class="av-status-badge ${statusClass}">${escapeHtml(status)}</span>`;

        // Source
        const src = a.source
            ? `<span class="endpoint-name">${escapeHtml(a.source)}</span>`
            : `<span style="color:var(--text-muted)">—</span>`;

        return `
            <tr>
                <td><strong class="threat-id" style="color:#F97316;">${escapeHtml(a.id)}</strong></td>
                <td style="max-width:280px;">${escapeHtml(a.alert_type || '—')}</td>
                <td>${prioBadge}</td>
                <td>${statusBadge}</td>
                <td>${src}</td>
                <td class="reported-time">${escapeHtml(a.reported_at || a.time || '—')}</td>
            </tr>
        `;
    }).join('');

    avAlarmsTbody.innerHTML = rows;
}


// ═══════════════════════════════════════════════════════════
//  KPI Animation (Count-up effect)
// ═══════════════════════════════════════════════════════════

const kpiAnimations = {};

function animateKPI(cardId, target) {
    const card = document.getElementById(cardId);
    if (!card) return;

    const el = card.querySelector('.kpi-value');
    if (!el) return;

    const current = parseInt(el.dataset.target) || 0;
    el.dataset.target = target;

    if (kpiAnimations[cardId]) cancelAnimationFrame(kpiAnimations[cardId]);

    const duration = 800;
    const start = performance.now();

    function step(now) {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const val = Math.round(current + (target - current) * eased);
        el.textContent = formatNumber(val);
        if (progress < 1) kpiAnimations[cardId] = requestAnimationFrame(step);
    }

    kpiAnimations[cardId] = requestAnimationFrame(step);
}


// ═══════════════════════════════════════════════════════════
//  Update Timer
// ═══════════════════════════════════════════════════════════

function startUpdateTimer() {
    if (updateTimerID) clearInterval(updateTimerID);
    updateTimerID = setInterval(() => {
        if (!lastUpdateTime) return;
        const secs = Math.floor((Date.now() - lastUpdateTime.getTime()) / 1000);
        if (lastUpdatedEl) {
            lastUpdatedEl.textContent = secs < 5 ? 'just now' : secs < 60 ? `${secs}s ago` : `${Math.floor(secs / 60)}m ago`;
        }
    }, 1000);
}


// ═══════════════════════════════════════════════════════════
//  Utilities
// ═══════════════════════════════════════════════════════════

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function formatNumber(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
    return String(n);
}


// ═══════════════════════════════════════════════════════════
//  Sidebar Navigation
// ═══════════════════════════════════════════════════════════

document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
        if (item.getAttribute('href') === '/') return;
        e.preventDefault();
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        item.classList.add('active');
    });
});


// ═══════════════════════════════════════════════════════════
//  Bootstrap
// ═══════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', async () => {
    // Truncate long client name in sidebar nav
    const navName = document.getElementById('nav-client-name');
    if (navName && CLIENT_NAME.length > 14) {
        navName.textContent = CLIENT_NAME.substring(0, 14) + '…';
        navName.title = CLIENT_NAME;
    }

    initEventChart();
    initEDRChart();

    // Pre-load via REST so the page renders immediately
    await preloadClientData();

    // Then connect WebSocket for live updates
    connectWebSocket();
});
