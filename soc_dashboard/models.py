"""
Sentrium Integrated SOC Dashboard — Data Models
Pydantic models for type safety, validation, and JSON serialization.
"""

from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class AlertItem(BaseModel):
    """Single alert entry for the Recent Alerts table."""
    id: str = ""
    alert_type: str = ""          # Threat file name / alarm method
    source: str = ""              # Endpoint / computer name / source IP
    severity: str = "low"         # malicious, suspicious, low
    confidence: str = ""          # Malicious, Suspicious (AI confidence) / AV priority
    analyst_verdict: str = ""     # True Positive, False Positive, Suspicious
    status: str = "open"          # unresolved, in_progress, resolved / Open, Closed
    time: str = ""                # Relative time (e.g. 2h ago)
    reported_at: str = ""         # Exact reported timestamp
    platform: str = ""            # SentinelOne, AlienVault
    # AV-specific extras
    intent: str = ""              # AV rule_intent category
    strategy: str = ""            # AV rule_strategy
    destination: str = ""         # AV destination asset


class TimePoint(BaseModel):
    """Single data point for time-series charts."""
    timestamp: str = ""
    value: int = 0
    blocked: int = 0


class ThreatClassification(BaseModel):
    """Threat classification breakdown for donut chart."""
    name: str
    count: int
    color: str = "#3B82F6"


class PlatformStatus(BaseModel):
    """Per-platform data for a client."""
    platform: str  # "SentinelOne" or "AlienVault"
    is_active: bool = True
    total_endpoints: int = 0
    total_threats: int = 0
    total_alerts: int = 0
    events_processed: int = 0
    blocked_attempts: int = 0


# ── AV Alarm Breakdown Models ────────────────────────────────────────────────

class AVStatusCount(BaseModel):
    """Status counts within a priority group."""
    open: int = 0
    closed: int = 0
    in_review: int = 0
    other: int = 0


class AVPriorityRow(BaseModel):
    """Alarm count broken down by priority and status."""
    priority: str           # High, Medium, Low, Critical
    total: int = 0
    statuses: AVStatusCount = Field(default_factory=AVStatusCount)
    color: str = "#6B7280"  # display color


class AVMethodRow(BaseModel):
    """Alarm count by rule method/strategy (intent category)."""
    method: str             # e.g. "C&C Communication Detected"
    intent: str = ""        # e.g. "Delivery & Attack"
    strategy: str = ""
    count: int = 0


class AVAssetRow(BaseModel):
    """Asset with highest alarm activity (source or destination)."""
    asset: str
    count: int = 0
    alarm_types: list[str] = Field(default_factory=list)  # top method names


# ── Main Models ──────────────────────────────────────────────────────────────

class ClientSummary(BaseModel):
    """Aggregated security data for a single client across all platforms."""
    name: str
    platforms: list[str] = Field(default_factory=list)
    s1_site_id: Optional[str] = None

    # KPI Metrics (aggregated across platforms)
    total_endpoints: int = 0
    total_threats: int = 0
    total_alerts: int = 0
    events_processed: int = 0
    blocked_attempts: int = 0
    dfir_cases: int = 0

    # Breakdowns
    threat_classifications: list[ThreatClassification] = Field(default_factory=list)
    recent_alerts: list[AlertItem] = Field(default_factory=list)
    event_timeline: list[TimePoint] = Field(default_factory=list)

    # Per-platform detail
    platform_data: list[PlatformStatus] = Field(default_factory=list)

    # ── AV Alarm Breakdowns (populated from full alarm list) ──
    av_total_alarms: int = 0
    av_priority_breakdown: list[AVPriorityRow] = Field(default_factory=list)
    av_method_summary: list[AVMethodRow] = Field(default_factory=list)
    av_top_sources: list[AVAssetRow] = Field(default_factory=list)
    av_top_destinations: list[AVAssetRow] = Field(default_factory=list)


class DashboardState(BaseModel):
    """Complete dashboard state pushed via WebSocket."""
    last_updated: str = ""
    refresh_interval: int = 30
    total_clients: int = 0
    system_status: str = "operational"  # operational, degraded, error

    # Global KPIs (across ALL clients)
    global_endpoints: int = 0
    global_threats: int = 0
    global_alerts: int = 0
    global_events: int = 0
    global_blocked: int = 0
    global_dfir_cases: int = 0
    sectors_affected: int = 0

    # Client list
    clients: list[ClientSummary] = Field(default_factory=list)

    # Selected client detail (sent when client is selected)
    selected_client: Optional[ClientSummary] = None

    # Global breakdowns
    global_classifications: list[ThreatClassification] = Field(default_factory=list)
    global_alerts_list: list[AlertItem] = Field(default_factory=list)
    global_timeline: list[TimePoint] = Field(default_factory=list)
