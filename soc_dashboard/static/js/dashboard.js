/**
 * Sentrium Integrated SOC Dashboard — Per-Client Dashboard Logic
 * Handles WebSocket connection, filters data for CLIENT_NAME,
 * updates KPIs, charts, and alerts table in real time.
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
const lastUpdatedEl    = document.getElementById('last-updated');
const systemStatusEl   = document.getElementById('system-status');
const notifCountEl     = document.getElementById('notif-count');
const activeCountEl    = document.getElementById('active-count');
const liveIndicator    = document.getElementById('live-indicator');
const reconnectOverlay = document.getElementById('reconnect-overlay');


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

    // Update system status
    updateSystemStatus(state.system_status);

    // Find this client in the state
    const clients = state.clients || [];
    const client = clients.find(
        c => c.name.toLowerCase() === CLIENT_NAME.toLowerCase()
    );

    if (client) {
        displayClientData(client);
    } else {
        // Client not found — show zeros
        console.warn(`Client "${CLIENT_NAME}" not found in ${clients.length} clients`);
    }

    startUpdateTimer();
}

function displayClientData(client) {
    // KPI Cards
    animateKPI('kpi-blocked',  client.blocked_attempts || 0);
    animateKPI('kpi-alerts',   client.total_alerts || 0);
    animateKPI('kpi-events',   client.events_processed || 0);
    animateKPI('kpi-dfir',     client.dfir_cases || 0);
    animateKPI('kpi-sectors',  (client.platforms || []).length);

    // Charts
    updateEventChart(client.event_timeline || []);
    updateEDRChart(client.threat_classifications || []);

    // Alerts table
    renderAlertsTable(client.recent_alerts || []);

    // Notification count — Unresolved = active
    const activeAlerts = (client.recent_alerts || []).filter(
        a => a.status === 'Unresolved' || a.status === 'In Progress'
    ).length;
    if (notifCountEl) {
        notifCountEl.textContent = activeAlerts;
        notifCountEl.dataset.count = activeAlerts;
    }
    if (activeCountEl) {
        activeCountEl.textContent = `${activeAlerts} Active`;
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
        alertsTbody.innerHTML = '<tr class="empty-row"><td colspan="7" style="text-align:center;padding:40px;">No incidents in the last 24 hours</td></tr>';
        return;
    }

    const rows = alerts.map(a => {
        const platformChip = a.platform === 'SentinelOne'
            ? `<span class="platform-chip platform-s1">S1</span>`
            : `<span class="platform-chip platform-av">AV</span>`;

        // AI Confidence badge
        const conf = (a.confidence || '').toLowerCase();
        const confClass = conf === 'malicious' ? 'conf-malicious' : conf === 'suspicious' ? 'conf-suspicious' : 'conf-unknown';
        const confBadge = `<span class="conf-badge ${confClass}">${escapeHtml(a.confidence || 'Unknown')}</span>`;

        // Analyst Verdict
        const verdict = a.analyst_verdict || '';
        const verdictClass = verdict === 'True Positive' ? 'verdict-tp'
            : verdict === 'False Positive' ? 'verdict-fp'
            : verdict === 'Suspicious' ? 'verdict-sus'
            : 'verdict-other';
        const verdictHtml = verdict
            ? `<span class="verdict-badge ${verdictClass}">${escapeHtml(verdict)}</span>`
            : `<span class="verdict-badge verdict-other">Pending</span>`;

        // Incident Status badge
        const status = a.status || '';
        const statusClass = status === 'Resolved' ? 'inc-resolved'
            : status === 'In Progress' ? 'inc-progress'
            : status === 'Unresolved' ? 'inc-unresolved'
            : 'inc-other';
        const statusHtml = `<span class="inc-badge ${statusClass}">${escapeHtml(status || 'Unknown')}</span>`;

        // Endpoint
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
//  Sidebar Navigation
// ═══════════════════════════════════════════════════════════

document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
        if (item.getAttribute('href') === '/') return; // Allow back navigation
        e.preventDefault();
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        item.classList.add('active');
    });
});


// ═══════════════════════════════════════════════════════════
//  Utilities
// ═══════════════════════════════════════════════════════════

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}


// ═══════════════════════════════════════════════════════════
//  Bootstrap
// ═══════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    initEventChart();
    initEDRChart();
    connectWebSocket();
});
