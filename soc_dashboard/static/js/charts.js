/**
 * Sentrium Integrated SOC Dashboard — Chart Configurations
 * ApexCharts instances for Event Activity and EDR Telemetry.
 */

'use strict';

// ═══════════════════════════════════════════════════════════
//  Event Activity — Area Chart (24hr timeline)
// ═══════════════════════════════════════════════════════════

let eventChart = null;

function initEventChart() {
    const el = document.getElementById('event-chart');
    if (!el) return;

    const options = {
        chart: {
            type: 'area',
            height: 260,
            fontFamily: "'Inter', sans-serif",
            toolbar: { show: false },
            zoom: { enabled: false },
            animations: {
                enabled: true,
                easing: 'easeinout',
                speed: 600,
                dynamicAnimation: { enabled: true, speed: 400 },
            },
            dropShadow: {
                enabled: true,
                top: 3,
                left: 0,
                blur: 6,
                opacity: 0.12,
                color: '#F97316',
            },
        },
        series: [
            { name: 'Total Events', data: [] },
            { name: 'Blocked', data: [] },
        ],
        colors: ['#3B82F6', '#F97316'],
        fill: {
            type: 'gradient',
            gradient: {
                shadeIntensity: 1,
                opacityFrom: 0.35,
                opacityTo: 0.05,
                stops: [0, 90, 100],
            },
        },
        stroke: {
            curve: 'smooth',
            width: [2.5, 2.5],
        },
        xaxis: {
            categories: [],
            labels: {
                style: { fontSize: '11px', fontWeight: 600, colors: '#9CA3AF' },
            },
            axisBorder: { show: false },
            axisTicks: { show: false },
        },
        yaxis: {
            labels: {
                style: { fontSize: '11px', fontWeight: 600, colors: '#9CA3AF' },
                formatter: (val) => formatNumber(val),
            },
        },
        grid: {
            borderColor: 'rgba(0,0,0,0.04)',
            strokeDashArray: 6,
            xaxis: { lines: { show: true } },
            yaxis: { lines: { show: true } },
            padding: { top: -10, bottom: -5 },
        },
        dataLabels: { enabled: false },
        legend: { show: false },
        tooltip: {
            theme: 'light',
            style: { fontSize: '12px', fontFamily: "'Inter', sans-serif" },
            y: { formatter: (val) => formatNumber(val) },
        },
    };

    eventChart = new ApexCharts(el, options);
    eventChart.render();
}

function updateEventChart(timeline) {
    if (!eventChart || !timeline || !timeline.length) return;

    const categories = timeline.map(t => t.timestamp);
    const totalData = timeline.map(t => t.value);
    const blockedData = timeline.map(t => t.blocked);

    eventChart.updateOptions({
        xaxis: { categories },
    }, false, false);

    eventChart.updateSeries([
        { name: 'Total Events', data: totalData },
        { name: 'Blocked', data: blockedData },
    ], true);
}


// ═══════════════════════════════════════════════════════════
//  EDR Telemetry Detection — Donut Chart
// ═══════════════════════════════════════════════════════════

let edrChart = null;

function initEDRChart() {
    const el = document.getElementById('edr-chart');
    if (!el) return;

    const options = {
        chart: {
            type: 'donut',
            height: 280,
            fontFamily: "'Inter', sans-serif",
            animations: {
                enabled: true,
                easing: 'easeinout',
                speed: 800,
            },
        },
        series: [],
        labels: [],
        colors: ['#3B82F6', '#F97316', '#22C55E', '#8B5CF6', '#EF4444', '#06B6D4'],
        plotOptions: {
            pie: {
                donut: {
                    size: '58%',
                    labels: {
                        show: true,
                        total: {
                            show: true,
                            label: 'Total',
                            fontSize: '13px',
                            fontWeight: 800,
                            color: '#111827',
                            formatter: (w) => {
                                return formatNumber(w.globals.seriesTotals.reduce((a, b) => a + b, 0));
                            },
                        },
                        value: {
                            fontSize: '20px',
                            fontWeight: 900,
                            color: '#111827',
                            formatter: (val) => formatNumber(parseInt(val)),
                        },
                    },
                },
            },
        },
        stroke: { width: 2, colors: ['#FFFFFF'] },
        legend: {
            position: 'bottom',
            fontSize: '11px',
            fontWeight: 600,
            labels: { colors: '#6B7280' },
            markers: { width: 10, height: 10, radius: 3 },
            itemMargin: { horizontal: 8, vertical: 4 },
        },
        dataLabels: { enabled: false },
        tooltip: {
            style: { fontSize: '12px', fontFamily: "'Inter', sans-serif" },
            y: { formatter: (val) => formatNumber(val) },
        },
        responsive: [{
            breakpoint: 480,
            options: { chart: { height: 240 }, legend: { position: 'bottom' } },
        }],
    };

    edrChart = new ApexCharts(el, options);
    edrChart.render();
}

function updateEDRChart(classifications) {
    if (!edrChart || !classifications || !classifications.length) return;

    const labels = classifications.map(c => c.name);
    const series = classifications.map(c => c.count);
    const colors = classifications.map(c => c.color || '#6B7280');

    edrChart.updateOptions({
        labels,
        colors,
    }, false, false);

    edrChart.updateSeries(series, true);
}


// ═══════════════════════════════════════════════════════════
//  Utility
// ═══════════════════════════════════════════════════════════

function formatNumber(num) {
    if (num == null || isNaN(num)) return '0';
    num = Number(num);
    if (num >= 1_000_000_000) return (num / 1_000_000_000).toFixed(1).replace(/\.0$/, '') + 'B';
    if (num >= 1_000_000) return (num / 1_000_000).toFixed(1).replace(/\.0$/, '') + 'M';
    if (num >= 1_000) return (num / 1_000).toFixed(1).replace(/\.0$/, '') + 'k';
    return num.toLocaleString();
}
