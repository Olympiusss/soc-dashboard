"""
Sentrium Integrated SOC Dashboard — Async Data Fetcher
High-performance async engine for SentinelOne + AlienVault APIs.
Uses httpx with connection pooling for maximum throughput.
"""

from __future__ import annotations
import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone
from collections import Counter
from typing import Optional

import httpx

from config import settings
from models import (
    DashboardState, ClientSummary, PlatformStatus,
    AlertItem, TimePoint, ThreatClassification,
)

logger = logging.getLogger("soc_dashboard.fetcher")

# ════════════════════════════════════════════════════════════════
#  SentinelOne Async Fetcher
# ════════════════════════════════════════════════════════════════

class S1Fetcher:
    """Async SentinelOne API v2.1 client."""

    def __init__(self):
        self.base_url = settings.S1_BASE_URL.rstrip("/")
        self._client: Optional[httpx.AsyncClient] = None

    def _make_client(self) -> httpx.AsyncClient:
        """Always create a fresh client with up-to-date credentials."""
        return httpx.AsyncClient(
            headers={
                "Authorization": f"ApiToken {settings.S1_API_TOKEN}",
                "Content-Type": "application/json",
            },
            timeout=httpx.Timeout(45.0, connect=15.0),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=5),
        )

    async def _get_client(self) -> httpx.AsyncClient:
        """Return a healthy client, recreating if needed."""
        if self._client is None or self._client.is_closed:
            self._client = self._make_client()
        return self._client

    async def _reset_client(self):
        """Force-close and recreate the client."""
        if self._client and not self._client.is_closed:
            try:
                await self._client.aclose()
            except Exception:
                pass
        self._client = self._make_client()
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def _paginate(self, endpoint: str, params: dict = None, max_items: int = 5000) -> list[dict]:
        """Fetch all pages from a cursor-paginated endpoint."""
        client = await self._get_client()
        if params is None:
            params = {}
        params = {**params, "limit": 200}
        all_items = []
        cursor = None

        while True:
            if cursor:
                params["cursor"] = cursor

            try:
                resp = await client.get(f"{self.base_url}/{endpoint}", params=params)
                if resp.status_code == 401:
                    logger.error(f"S1 Auth failed on {endpoint} — token may be expired")
                    break
                if resp.status_code != 200:
                    logger.warning(f"S1 {endpoint} returned {resp.status_code}")
                    break

                body = resp.json()
                data = body.get("data", body)
                if isinstance(data, dict) and "sites" in data:
                    data = data["sites"]
                if isinstance(data, list):
                    all_items.extend(data)

                if len(all_items) >= max_items:
                    all_items = all_items[:max_items]
                    break

                pagination = body.get("pagination", {}) or {}
                cursor = pagination.get("nextCursor")
                if not cursor:
                    break

                await asyncio.sleep(0.02)

            except httpx.RequestError as e:
                logger.warning(f"S1 network error on {endpoint}: {e} — retrying with fresh client")
                client = await self._reset_client()
                try:
                    resp = await client.get(f"{self.base_url}/{endpoint}", params=params)
                    if resp.status_code == 200:
                        body = resp.json()
                        data = body.get("data", body)
                        if isinstance(data, dict) and "sites" in data:
                            data = data["sites"]
                        if isinstance(data, list):
                            all_items.extend(data)
                        pagination = body.get("pagination", {}) or {}
                        cursor = pagination.get("nextCursor")
                        if not cursor:
                            break
                    else:
                        logger.error(f"S1 retry failed on {endpoint}: {resp.status_code}")
                        break
                except Exception as retry_e:
                    logger.error(f"S1 retry error on {endpoint}: {retry_e}")
                    break

        return all_items

    async def discover_sites(self) -> list[dict]:
        """Auto-discover all sites (clients) from SentinelOne."""
        if not settings.s1_configured():
            return []
        try:
            sites = await self._paginate("sites")
            logger.info(f"S1: Discovered {len(sites)} sites")
            return sites
        except Exception as e:
            logger.error(f"S1 site discovery failed: {e}")
            return []

    async def fetch_agents(self, site_id: str) -> list[dict]:
        """Fetch all agents/endpoints for a site."""
        return await self._paginate("agents", {"siteIds": site_id, "limit": 1000})

    async def fetch_threats(self, site_id: str, days_back: int = 30) -> list[dict]:
        """Fetch threats for a site within the last N days."""
        now = datetime.now(timezone.utc)
        start = (now - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        return await self._paginate("threats", {
            "siteIds": site_id,
            "createdAt__gte": start,
            "createdAt__lte": end,
            "sortBy": "createdAt",
            "sortOrder": "desc",
        })

    async def fetch_alerts(self, site_id: str, days_back: int = 7) -> list[dict]:
        """Fetch cloud detection alerts for a site."""
        now = datetime.now(timezone.utc)
        start = (now - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        return await self._paginate("cloud-detection/alerts", {
            "siteIds": site_id,
            "createdAt__gte": start,
            "createdAt__lte": end,
            "sortBy": "createdAt",
            "sortOrder": "desc",
        }, max_items=200)


# ════════════════════════════════════════════════════════════════
#  AlienVault Async Fetcher
# ════════════════════════════════════════════════════════════════

class AVFetcher:
    """Async AlienVault USM Anywhere API client."""

    def __init__(self):
        self.subdomain = settings.AV_SUBDOMAIN
        self.base_url = f"https://{self.subdomain}/api/2.0"
        self._token: Optional[str] = None
        self._token_expiry: float = 0
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(60.0, connect=15.0),
                limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def _get_token(self) -> Optional[str]:
        """Get or refresh OAuth2 token."""
        if self._token and time.time() < self._token_expiry:
            return self._token

        client = await self._get_client()
        token_url = f"{self.base_url}/oauth/token"
        logger.info(f"AV: Requesting OAuth token from {token_url}")
        logger.info(f"AV: Using client_id={settings.AV_CLIENT_ID[:8]}...")
        try:
            resp = await client.post(
                token_url,
                data={"grant_type": "client_credentials"},
                auth=(settings.AV_CLIENT_ID, settings.AV_CLIENT_SECRET),
            )
            if resp.status_code != 200:
                logger.error(f"AV auth failed: HTTP {resp.status_code} - {resp.text[:300]}")
                return None

            data = resp.json()
            self._token = data.get("access_token")
            expires_in = data.get("expires_in", 3600)
            self._token_expiry = time.time() + expires_in - 60
            logger.info(f"AV: OAuth token acquired (expires in {expires_in}s)")
            return self._token

        except httpx.ConnectError as e:
            logger.error(f"AV: Connection failed to {self.subdomain}: {e}")
            return None
        except httpx.TimeoutException as e:
            logger.error(f"AV: Timeout connecting to {self.subdomain}: {e}")
            return None
        except Exception as e:
            logger.error(f"AV: Token error ({type(e).__name__}): {e}")
            return None

    async def _fetch_paginated(self, endpoint: str, params: dict, max_records: int = 5000) -> list[dict]:
        """Fetch paginated data from AlienVault."""
        token = await self._get_token()
        if not token:
            return []

        client = await self._get_client()
        headers = {"Authorization": f"Bearer {token}"}
        params = {**params, "size": 500, "page": 0}
        url = f"{self.base_url}/{endpoint}"

        response_keys = {"events": "eventResources", "alarms": "alarms"}
        data_key = response_keys.get(endpoint, endpoint)

        all_data = []

        try:
            resp = await client.get(url, headers=headers, params=params)
            if resp.status_code != 200:
                logger.warning(f"AV {endpoint} returned {resp.status_code}")
                return []

            body = resp.json()
            total_pages = body.get("page", {}).get("totalPages", 0)
            items = body.get("_embedded", {}).get(data_key, [])
            all_data.extend(items)

            # Fetch remaining pages concurrently
            if total_pages > 1:
                pages_to_fetch = min(total_pages, max_records // 500 + 1)
                tasks = []
                for page in range(1, pages_to_fetch):
                    page_params = {**params, "page": page}
                    tasks.append(self._fetch_single_page(url, headers, page_params, data_key))

                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, list):
                        all_data.extend(result)
                    if len(all_data) >= max_records:
                        break

        except Exception as e:
            logger.error(f"AV fetch error on {endpoint}: {e}")

        return all_data[:max_records]

    async def _fetch_single_page(self, url: str, headers: dict, params: dict, data_key: str) -> list[dict]:
        client = await self._get_client()
        try:
            resp = await client.get(url, headers=headers, params=params)
            if resp.status_code == 200:
                return resp.json().get("_embedded", {}).get(data_key, [])
        except Exception:
            pass
        return []

    async def fetch_alarms(self, days_back: int = 30) -> list[dict]:
        """Fetch alarms from AlienVault."""
        if not settings.av_configured():
            logger.info("AV: Not configured, skipping alarms")
            return []

        logger.info(f"AV: Fetching alarms (last {days_back} days)...")
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=days_back)
        start_ms = int(start.timestamp() * 1000)
        end_ms = int(now.timestamp() * 1000)

        result = await self._fetch_paginated("alarms", {
            "timestamp_received_gte": start_ms,
            "timestamp_received_lte": end_ms,
            "sort": "timestamp_received,desc",
            "suppressed": False,
        })
        logger.info(f"AV: Fetched {len(result)} alarms")
        return result

    async def fetch_events(self, days_back: int = 1) -> list[dict]:
        """Fetch events from AlienVault."""
        if not settings.av_configured():
            logger.info("AV: Not configured, skipping events")
            return []

        logger.info(f"AV: Fetching events (last {days_back} days)...")
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=days_back)
        start_ms = int(start.timestamp() * 1000)
        end_ms = int(now.timestamp() * 1000)

        result = await self._fetch_paginated("events", {
            "timestamp_received_gte": start_ms,
            "timestamp_received_lte": end_ms,
            "sort": "timestamp_received,desc",
        }, max_records=2000)
        logger.info(f"AV: Fetched {len(result)} events")
        return result

    async def fetch_sensors(self) -> list[dict]:
        """Fetch sensor list from AlienVault."""
        if not settings.av_configured():
            return []
        token = await self._get_token()
        if not token:
            return []
        client = await self._get_client()
        headers = {"Authorization": f"Bearer {token}"}
        try:
            resp = await client.get(f"{self.base_url}/sensors", headers=headers)
            if resp.status_code == 200:
                sensors = resp.json().get("_embedded", {}).get("sensors", [])
                logger.info(f"AV: Discovered {len(sensors)} sensors")
                return sensors
            else:
                logger.warning(f"AV sensors endpoint returned {resp.status_code}")
        except Exception as e:
            logger.warning(f"AV sensors fetch error: {e}")
        return []


# ════════════════════════════════════════════════════════════════
#  Dashboard Aggregator
# ════════════════════════════════════════════════════════════════

class DashboardAggregator:
    """
    Combines data from both platforms into a unified dashboard state.
    Runs as a background task, caching results in memory.
    """

    def __init__(self):
        self.s1 = S1Fetcher()
        self.av = AVFetcher()
        self._cache: Optional[DashboardState] = None
        self._lock = asyncio.Lock()
        self._running = False

    @property
    def cached_state(self) -> Optional[DashboardState]:
        return self._cache

    async def close(self):
        await self.s1.close()
        await self.av.close()

    async def fetch_all(self) -> DashboardState:
        """
        Unified multi-client fetch:
        1. Discover ALL S1 sites + ALL AV sensors in parallel
        2. Fetch per-site S1 data + all AV alarms/events in parallel
        3. Group AV alarms/events by sensor UUID → client name
        4. Fuzzy-merge AV clients into S1 clients (or create AV-only cards)
        5. Build global KPIs
        """
        async with self._lock:
            t0 = time.time()
            logger.info("Starting data fetch cycle...")

            # ── Phase 1: Parallel discovery ──────────────────────────────
            s1_sites, av_sensors = await asyncio.gather(
                self.s1.discover_sites(),
                self.av.fetch_sensors(),
                return_exceptions=True,
            )
            if isinstance(s1_sites, Exception):
                logger.error(f"S1 discovery error: {s1_sites}")
                s1_sites = []
            if isinstance(av_sensors, Exception):
                logger.warning(f"AV sensor discovery error: {av_sensors}")
                av_sensors = []

            logger.info(f"Discovery: {len(s1_sites)} S1 sites, {len(av_sensors)} AV sensors")

            # ── Phase 2: Full parallel data fetch ────────────────────────
            valid_s1_sites = [s for s in s1_sites if s.get("id")]
            s1_build_tasks = [
                self._build_s1_client(str(s["id"]), s.get("name", "Unknown"))
                for s in valid_s1_sites
            ]
            all_results = await asyncio.gather(
                *s1_build_tasks,
                self.av.fetch_alarms(days_back=30),
                self.av.fetch_events(days_back=1),
                return_exceptions=True,
            )

            n_s1 = len(s1_build_tasks)
            s1_results = all_results[:n_s1]
            av_alarms_raw = all_results[n_s1]   if not isinstance(all_results[n_s1],   Exception) else []
            av_events_raw = all_results[n_s1+1] if not isinstance(all_results[n_s1+1], Exception) else []

            if isinstance(av_alarms_raw, Exception):
                logger.error(f"AV alarms error: {av_alarms_raw}"); av_alarms_raw = []
            if isinstance(av_events_raw, Exception):
                logger.error(f"AV events error: {av_events_raw}"); av_events_raw = []

            # ── Phase 3: Build S1 client index ───────────────────────────
            # { normalized_name: ClientSummary }
            clients: dict[str, ClientSummary] = {}
            for result, site in zip(s1_results, valid_s1_sites):
                if isinstance(result, ClientSummary):
                    key = _normalize_name(result.name)
                    clients[key] = result
                else:
                    logger.error(f"S1 build error for '{site.get('name')}': {result}")

            # ── Phase 4: Build AV sensor UUID & Name → client name map ───
            sensor_map: dict[str, str] = {}
            for sensor in av_sensors:
                uid  = sensor.get("uuid") or sensor.get("id") or ""
                raw  = sensor.get("name", "")
                name = _sensor_to_client_name(raw)
                if uid and name:
                    sensor_map[uid] = name
                if raw and name:
                    sensor_map[raw] = name  # Also map the raw name

            logger.info(f"AV: {len(av_sensors)} sensors mapped to client names")

            # ── Phase 5: Group AV alarms + events by client ──────────────
            client_alarms: dict[str, list] = {}  # client_name -> [alarms]
            client_events: dict[str, list] = {}  # client_name -> [events]
            fallback_name = _fallback_av_client_name()

            for alarm in av_alarms_raw:
                sensor_val = alarm.get("sensor", "")
                # Try exact match in map, then try cleaning the sensor name, then fallback
                cname = sensor_map.get(sensor_val) 
                if not cname and sensor_val:
                    cname = _sensor_to_client_name(sensor_val)
                    if cname == sensor_val and not _find_best_match(_normalize_name(cname), list(clients.keys())):
                        # If cleaning didn't help and no fuzzy match, use fallback
                        cname = fallback_name
                elif not cname:
                    cname = fallback_name
                
                client_alarms.setdefault(cname, []).append(alarm)

            for event in av_events_raw:
                sensor_val = event.get("sensor_uuid", "") or event.get("sensor", "")
                cname = sensor_map.get(sensor_val)
                if not cname and sensor_val:
                    cname = _sensor_to_client_name(sensor_val)
                    if cname == sensor_val and not _find_best_match(_normalize_name(cname), list(clients.keys())):
                        cname = fallback_name
                elif not cname:
                    cname = fallback_name
                    
                client_events.setdefault(cname, []).append(event)

            logger.info(
                f"AV: grouped into {len(client_alarms)} clients: "
                f"{list(client_alarms.keys())}"
            )

            # ── Phase 6: Merge AV into S1 clients (or create AV-only) ────
            for av_name, alarms in client_alarms.items():
                events   = client_events.get(av_name, [])
                norm_av  = _normalize_name(av_name)
                s1_match = _find_best_match(norm_av, list(clients.keys()))

                if s1_match:
                    _merge_av_data(clients[s1_match], alarms, events)
                    logger.info(
                        f"AV: '{av_name}' merged into S1 client '{clients[s1_match].name}'"
                    )
                else:
                    av_only = self._build_av_summary(alarms, events, av_name)
                    clients[norm_av] = av_only
                    logger.info(f"AV: '{av_name}' added as AV-only client")

            client_list = list(clients.values())

            # ── Phase 7: Global KPIs ──────────────────────────────────────
            global_endpoints = sum(c.total_endpoints for c in client_list)
            global_threats   = sum(c.total_threats   for c in client_list)
            global_alerts    = sum(c.total_alerts    for c in client_list)
            global_events    = sum(c.events_processed for c in client_list)
            global_blocked   = sum(c.blocked_attempts for c in client_list)
            global_dfir      = sum(c.dfir_cases       for c in client_list)

            all_class_counts: Counter = Counter()
            for c in client_list:
                for tc in c.threat_classifications:
                    all_class_counts[tc.name] += tc.count

            classification_colors = {
                "Malware":    "#3B82F6", "Ransomware":  "#EF4444",
                "Trojan":     "#F97316", "PUP":         "#22C55E",
                "Cryptominer":"#8B5CF6", "Infostealer": "#EC4899",
                "Packed":     "#F59E0B", "General":     "#6B7280",
                "Malicious":  "#EF4444", "Suspicious":  "#F59E0B",
            }
            global_classifications = [
                ThreatClassification(
                    name=name, count=count,
                    color=classification_colors.get(name, "#6B7280"),
                )
                for name, count in all_class_counts.most_common(10)
            ]

            all_alerts: list[AlertItem] = []
            for c in client_list:
                all_alerts.extend(c.recent_alerts)
            all_alerts = sorted(all_alerts, key=lambda a: a.time, reverse=True)[:20]

            global_timeline = self._build_global_timeline(client_list)

            status = "operational"
            if not settings.s1_configured() and not settings.av_configured():
                status = "unconfigured"
            elif not s1_sites and not av_alarms_raw:
                status = "degraded"

            state = DashboardState(
                last_updated=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                refresh_interval=settings.REFRESH_INTERVAL,
                total_clients=len(client_list),
                system_status=status,
                global_endpoints=global_endpoints,
                global_threats=global_threats,
                global_alerts=global_alerts,
                global_events=global_events,
                global_blocked=global_blocked,
                global_dfir_cases=global_dfir,
                sectors_affected=len(client_list),
                clients=client_list,
                global_classifications=global_classifications,
                global_alerts_list=all_alerts,
                global_timeline=global_timeline,
            )

            self._cache = state
            elapsed = time.time() - t0
            logger.info(f"Fetch cycle complete: {len(client_list)} clients, {elapsed:.2f}s")
            return state

    async def _build_s1_client(self, site_id: str, site_name: str) -> ClientSummary:
        """Build client summary from SentinelOne data — 24h threat window."""
        agents, threats_24h = await asyncio.gather(
            self.s1.fetch_agents(site_id),
            self.s1.fetch_threats(site_id, days_back=1),   # 24 hours only
            return_exceptions=True,
        )

        if isinstance(agents, Exception):
            logger.warning(f"S1 agents error for {site_name}: {agents}")
            agents = []
        if isinstance(threats_24h, Exception):
            logger.warning(f"S1 threats error for {site_name}: {threats_24h}")
            threats_24h = []

        logger.info(f"S1 [{site_name}]: {len(agents)} endpoints, {len(threats_24h)} threats (24h)")

        # ── Threat classifications from 24h threats ──
        class_counter = Counter()
        for t in threats_24h:
            ti = t.get("threatInfo", {})
            confidence = ti.get("confidenceLevel", "").title()   # Malicious / Suspicious
            if confidence:
                class_counter[confidence] += 1

        classification_colors = {
            "Malicious":  "#EF4444",
            "Suspicious": "#F59E0B",
            "Malware":    "#3B82F6",
            "Ransomware": "#EF4444",
            "Trojan":     "#F97316",
            "PUP":        "#22C55E",
            "Cryptominer":"#8B5CF6",
            "General":    "#6B7280",
        }

        classifications = [
            ThreatClassification(
                name=name,
                count=count,
                color=classification_colors.get(name, "#6B7280"),
            )
            for name, count in class_counter.most_common(10)
        ]

        # ── Map analyst verdict to human-readable label ──
        VERDICT_MAP = {
            "true_positive":  "True Positive",
            "false_positive": "False Positive",
            "suspicious":     "Suspicious",
            "undefined":      "Undefined",
            "":               "Pending",
        }

        # ── Map incident status to human-readable label ──
        STATUS_MAP = {
            "unresolved": "Unresolved",
            "in_progress": "In Progress",
            "resolved":    "Resolved",
            "":            "Unknown",
        }

        # ── Build alerts table from 24h threats ──
        recent_alerts: list[AlertItem] = []
        for t in threats_24h:
            ti  = t.get("threatInfo", {})
            ari = t.get("agentRealtimeInfo", {})

            threat_name = (
                ti.get("threatName")
                or ti.get("filePath", "").split("\\")[-1].split("/")[-1]
                or "Unknown Threat"
            )

            # Use S1's native description fields (already human-readable)
            confidence_raw   = (ti.get("confidenceLevel", "") or "").lower()
            confidence_label = confidence_raw.title() if confidence_raw else "Unknown"
            severity         = "critical" if confidence_raw == "malicious" else "medium"

            verdict_label    = ti.get("analystVerdictDescription", "") or "Pending"
            status_label     = ti.get("incidentStatusDescription", "") or "Unknown"

            created  = ti.get("createdAt", "")
            endpoint = ari.get("agentComputerName", "")

            # Detecting engine
            engines = ti.get("engines", [])
            engine  = engines[0] if engines else ""

            recent_alerts.append(AlertItem(
                id=f"S1-{str(t.get('id', ''))[:6]}",
                alert_type=threat_name,
                source=endpoint,
                severity=severity,
                confidence=confidence_label,
                analyst_verdict=verdict_label,
                status=status_label,
                time=_format_relative_time(created),
                reported_at=_format_exact_time(created),
                platform="SentinelOne",
            ))

        # ── KPIs ──
        blocked = 0
        for t in threats_24h:
            m = str(t.get("threatInfo", {}).get("mitigationStatusDescription", "")).lower()
            if "mitigated" in m and "not" not in m:
                blocked += 1
        dfir = sum(
            1 for t in threats_24h
            if t.get("threatInfo", {}).get("incidentStatus", "") in ("unresolved", "in_progress")
        )

        timeline = _build_hourly_timeline(threats_24h)

        return ClientSummary(
            name=site_name,
            platforms=["SentinelOne"],
            s1_site_id=site_id,
            total_endpoints=len(agents),
            total_threats=len(threats_24h),
            total_alerts=len(threats_24h),   # 24h threat count as alerts
            events_processed=len(agents) * 1000 + len(threats_24h) * 50,
            blocked_attempts=blocked,
            dfir_cases=dfir,
            threat_classifications=classifications,
            recent_alerts=recent_alerts[:50],
            event_timeline=timeline,
            platform_data=[
                PlatformStatus(
                    platform="SentinelOne",
                    is_active=True,
                    total_endpoints=len(agents),
                    total_threats=len(threats_24h),
                    total_alerts=len(threats_24h),
                    events_processed=len(agents) * 1000,
                    blocked_attempts=blocked,
                ),
            ],
        )

    def _build_av_summary(self, alarms: list[dict], events: list[dict], name: str) -> ClientSummary:
        """Build client summary from AlienVault data."""
        # Severity breakdown
        severity_map = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for a in alarms:
            label = str(a.get("priority_label", "")).lower()
            if label in severity_map:
                severity_map[label] += 1

        # Build classifications from rule methods
        method_counter = Counter()
        for a in alarms:
            method = a.get("rule_method", "Unknown")
            if method:
                method_counter[method] += 1

        classifications = [
            ThreatClassification(name=name, count=count, color="#F97316")
            for name, count in method_counter.most_common(5)
        ]

        # Recent alerts
        recent_alerts = []
        for a in alarms[:10]:
            sev_label = str(a.get("priority_label", "medium")).lower()
            if sev_label not in ("critical", "high", "medium", "low"):
                sev_label = "medium"

            recent_alerts.append(AlertItem(
                id=f"AV-{str(a.get('uuid', ''))[:6]}",
                alert_type=a.get("rule_method", "Alarm"),
                source=a.get("source_name", a.get("sensor", "AlienVault")),
                severity=sev_label,
                time=_format_timestamp_ms(a.get("timestamp_received")),
                status="active" if a.get("status") == "open" else "investigating",
                platform="AlienVault",
            ))

        return ClientSummary(
            name=name,
            platforms=["AlienVault"],
            total_endpoints=0,
            total_threats=severity_map.get("critical", 0) + severity_map.get("high", 0),
            total_alerts=len(alarms),
            events_processed=len(events),
            blocked_attempts=severity_map.get("critical", 0),
            dfir_cases=0,
            threat_classifications=classifications,
            recent_alerts=recent_alerts,
            event_timeline=[],
            platform_data=[
                PlatformStatus(
                    platform="AlienVault",
                    is_active=True,
                    total_endpoints=0,
                    total_threats=len(alarms),
                    total_alerts=len(alarms),
                    events_processed=len(events),
                    blocked_attempts=severity_map.get("critical", 0),
                ),
            ],
        )

    def _build_global_timeline(self, clients: list[ClientSummary]) -> list[TimePoint]:
        """Merge all client timelines into a global 24hr timeline."""
        # Create 24 hourly buckets
        now = datetime.now(timezone.utc)
        buckets: dict[str, dict] = {}
        for i in range(24):
            t = now - timedelta(hours=23 - i)
            key = t.strftime("%H:00")
            buckets[key] = {"value": 0, "blocked": 0}

        for c in clients:
            for tp in c.event_timeline:
                if tp.timestamp in buckets:
                    buckets[tp.timestamp]["value"] += tp.value
                    buckets[tp.timestamp]["blocked"] += tp.blocked

        return [
            TimePoint(timestamp=ts, value=d["value"], blocked=d["blocked"])
            for ts, d in buckets.items()
        ]


# ════════════════════════════════════════════════════════════════
#  Helpers
# ════════════════════════════════════════════════════════════════

def _format_relative_time(iso_str: str) -> str:
    """Convert ISO datetime to relative time string."""
    if not iso_str:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        delta = now - dt

        if delta.total_seconds() < 60:
            return "just now"
        elif delta.total_seconds() < 3600:
            mins = int(delta.total_seconds() / 60)
            return f"{mins} min ago"
        elif delta.total_seconds() < 86400:
            hours = int(delta.total_seconds() / 3600)
            return f"{hours}h ago"
        else:
            days = int(delta.total_seconds() / 86400)
            return f"{days}d ago"
    except Exception:
        return iso_str[:16] if len(iso_str) > 16 else iso_str


def _format_timestamp_ms(ts_ms) -> str:
    """Convert millisecond timestamp to relative time."""
    if not ts_ms:
        return "Unknown"
    try:
        dt = datetime.fromtimestamp(int(ts_ms) / 1000, tz=timezone.utc)
        return _format_relative_time(dt.isoformat())
    except Exception:
        return "Unknown"

def _format_exact_time(iso_str: str) -> str:
    """Format ISO timestamp as 'Apr 13th 2026 • 20:03' matching S1 UI."""
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        day = dt.day
        suffix = "th" if 11 <= day <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")
        month = dt.strftime("%b")
        return f"{month} {day}{suffix} {dt.year} • {dt.strftime('%H:%M')}"
    except Exception:
        return iso_str[:16] if len(iso_str) > 16 else iso_str

def _build_hourly_timeline(threats: list[dict]) -> list[TimePoint]:
    """Build 24-hour timeline from threat data."""
    now = datetime.now(timezone.utc)
    buckets: dict[str, dict] = {}
    for i in range(24):
        t = now - timedelta(hours=23 - i)
        key = t.strftime("%H:00")
        buckets[key] = {"value": 0, "blocked": 0}

    for t in threats:
        ti = t.get("threatInfo", {})
        created = ti.get("createdAt", "")
        if not created:
            continue
        try:
            dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            hour_key = dt.strftime("%H:00")
            if hour_key in buckets:
                buckets[hour_key]["value"] += 1
                mitigation = str(ti.get("mitigationStatusDescription", "")).lower()
                if "mitigated" in mitigation and "not" not in mitigation:
                    buckets[hour_key]["blocked"] += 1
        except Exception:
            continue

    return [
        TimePoint(timestamp=ts, value=d["value"], blocked=d["blocked"])
        for ts, d in buckets.items()
    ]



# ════════════════════════════════════════════════════════════════
#  Multi-client AV helpers
# ════════════════════════════════════════════════════════════════

import re as _re

_SENSOR_STRIP_SUFFIXES = [
    " - usm sensor", " - usm", " - alienvault", " - sensor",
    " usm sensor", " usm", " sensor", " alienvault",
    "_sensor", "_usm", "-sensor", "-usm",
    " nfr", "-nfr", "_nfr",
    " primary", " secondary", " backup", " main",
    " hq", " head office", " headquarters",
]

def _sensor_to_client_name(sensor_name: str) -> str:
    """
    Derive a clean client name from an AV sensor name.
    E.g. "Acme Corp - USM Sensor 1"  →  "Acme Corp"
         "cybervergent-nfr-sensor"    →  "Cybervergent"
    """
    name = sensor_name.strip()
    lower = name.lower()
    for suffix in sorted(_SENSOR_STRIP_SUFFIXES, key=len, reverse=True):
        if lower.endswith(suffix):
            name  = name[: len(name) - len(suffix)].strip(" -_")
            lower = name.lower()
            break
    # Remove trailing numbers / separators
    name = _re.sub(r"[\s_\-]+\d+$", "", name).strip()
    # Title-case if all-caps or all-lower
    if name and (name == name.upper() or name == name.lower()):
        name = _re.sub(r"[-_]", " ", name).title()
    return name or sensor_name


_NORMALIZE_STOP = {
    "ltd", "limited", "inc", "plc", "ngo", "llc", "co", "corp",
    "nfr", "sensor", "usm", "alienvault", "sentinelone",
    "hq", "head", "office", "site", "primary", "secondary",
    "the", "and", "of",
}

def _normalize_name(name: str) -> str:
    """
    Normalize a client name for fuzzy matching.
    Lowercase, remove special chars, drop stopwords.
    """
    n = name.lower()
    n = _re.sub(r"[^a-z0-9\s]", " ", n)
    tokens = [t for t in n.split() if t and t not in _NORMALIZE_STOP and len(t) > 1]
    return " ".join(tokens)


def _find_best_match(norm_target: str, candidates: list) -> Optional[str]:
    """
    Fuzzy-match norm_target against a list of normalized candidate keys.
    Priority: exact → substring → Jaccard word-overlap (≥ 30 % union).
    Returns the best matching key or None.
    """
    if not norm_target or not candidates:
        return None

    target_words = set(norm_target.split())
    best_key, best_score = None, 0.0

    for key in candidates:
        # Exact
        if norm_target == key:
            return key
        # Substring
        if norm_target in key or key in norm_target:
            score = len(norm_target) if norm_target in key else len(key)
            if score > best_score:
                best_score, best_key = float(score), key
            continue
        # Word overlap (Jaccard)
        key_words = set(key.split())
        common = target_words & key_words
        if not common:
            continue
        union  = target_words | key_words
        score  = len(common) / len(union) * 100
        shorter = min(len(target_words), len(key_words))
        if shorter and len(common) / shorter >= 0.5:
            score += 20
        if score >= 30 and score > best_score:
            best_score, best_key = score, key

    return best_key


def _fallback_av_client_name() -> str:
    """Derive a human-readable fallback name from AV_SUBDOMAIN."""
    subdomain = settings.AV_SUBDOMAIN.split(".")[0]   # e.g. 'cybervergent-nfr'
    parts = [
        p for p in subdomain.split("-")
        if p.lower() not in ("nfr", "sensor", "usm", "av", "siem")
    ]
    return " ".join(p.title() for p in parts) or "AlienVault"


def _merge_av_data(client: ClientSummary, alarms: list, events: list) -> None:
    """
    Enrich an existing (S1) ClientSummary with AlienVault alarm/event data.
    Appends 'AlienVault' to client.platforms and increments all KPIs.
    """
    if "AlienVault" not in client.platforms:
        client.platforms.append("AlienVault")

    sev_map = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in alarms:
        lbl = str(a.get("priority_label", "")).lower()
        if lbl in sev_map:
            sev_map[lbl] += 1

    blocked     = sev_map["critical"]
    high_threats = sev_map["critical"] + sev_map["high"]

    client.total_alerts     += len(alarms)
    client.total_threats    += high_threats
    client.events_processed += len(events)
    client.blocked_attempts += blocked

    for a in alarms[:15]:
        sev = str(a.get("priority_label", "medium")).lower()
        if sev not in ("critical", "high", "medium", "low"):
            sev = "medium"
        client.recent_alerts.append(AlertItem(
            id=f"AV-{str(a.get('uuid', ''))[:6]}",
            alert_type=a.get("rule_method", "Alarm"),
            source=a.get("source_name", a.get("sensor", "AlienVault")),
            severity=sev,
            time=_format_timestamp_ms(a.get("timestamp_received")),
            status="active" if a.get("status") == "open" else "investigating",
            platform="AlienVault",
        ))

    client.platform_data.append(PlatformStatus(
        platform="AlienVault",
        is_active=True,
        total_endpoints=0,
        total_threats=high_threats,
        total_alerts=len(alarms),
        events_processed=len(events),
        blocked_attempts=blocked,
    ))


# Singleton
aggregator = DashboardAggregator()
