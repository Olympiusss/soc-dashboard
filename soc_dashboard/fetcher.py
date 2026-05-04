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
    AVPriorityRow, AVStatusCount, AVMethodRow, AVAssetRow,
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
    """Async AlienVault USM Anywhere API client (deployments-based)."""

    def __init__(self):
        self.subdomain = settings.AV_SUBDOMAIN
        self.base_url = f"https://{self.subdomain}"
        self._token: Optional[str] = None
        self._token_expiry: float = 0
        self._dep_tokens: dict = {}      # dep_url -> {token, expiry}
        self._deployments: list = []     # cached deployment list
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                verify=False,
                timeout=httpx.Timeout(60.0, connect=15.0),
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=5),
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def _get_token_with_path(self) -> tuple[Optional[str], str]:
        """Get OAuth2 token + base API path (e.g. '/api/1.1') from the working endpoint."""
        if self._token and time.time() < self._token_expiry:
            return self._token, getattr(self, "_base_api_path", "/api/1.1")

        client = await self._get_client()
        base = self.base_url.rstrip("/")
        for ep in ("/api/1.1/oauth/token", "/api/1.0/oauth/token", "/api/2.0/oauth/token",
                   "/oauth/token", "/oauth2/token"):
            try:
                resp = await client.post(
                    base + ep,
                    data={"grant_type": "client_credentials"},
                    auth=(settings.AV_CLIENT_ID, settings.AV_CLIENT_SECRET),
                )
                if resp.status_code == 200:
                    data = resp.json()
                    self._token = data.get("access_token")
                    self._token_expiry = time.time() + int(data.get("expires_in", 3600)) - 60
                    # Derive base path from the working endpoint
                    if "1.1" in ep:
                        self._base_api_path = "/api/1.1"
                    elif "2.0" in ep:
                        self._base_api_path = "/api/2.0"
                    else:
                        self._base_api_path = "/api/1.1"
                    logger.info(f"AV: Token acquired via {ep} (base_path={self._base_api_path})")
                    return self._token, self._base_api_path
                logger.warning(f"AV auth {ep} → HTTP {resp.status_code}")
            except Exception as e:
                logger.warning(f"AV auth {ep} → {e}")
        logger.error("AV: All auth endpoints failed")
        return None, "/api/1.1"

    async def _get_token(self) -> Optional[str]:
        """Compatibility wrapper — returns just the token."""
        token, _ = await self._get_token_with_path()
        return token

    def _resolve_deployment_url(self, dep: dict) -> Optional[str]:
        """Extract a usable base URL from a deployment object."""
        # Try explicit URL fields first
        for key in ("url", "fqdn", "hostname", "base_url"):
            val = dep.get(key, "")
            if val:
                return (f"https://{val}" if not val.startswith("http") else val).rstrip("/")
        # Try self-link href
        self_link = dep.get("_links", {}).get("self", {}).get("href", "")
        if self_link and "alienvault.cloud" in self_link:
            from urllib.parse import urlparse as _up
            p = _up(self_link)
            if p.scheme and p.netloc:
                return f"{p.scheme}://{p.netloc}"
        # Try id field (sometimes contains full URL)
        dep_id = dep.get("id", "")
        if dep_id and "://" in dep_id:
            return f"https://{dep_id.split('://')[1].split('/')[0]}"
        # Try name field — with or without .alienvault.cloud suffix
        name = dep.get("name", "")
        if name:
            if "alienvault.cloud" in name:
                return (f"https://{name}" if not name.startswith("http") else name).rstrip("/")
            # Construct from bare name (e.g. 'capitalsage' → 'https://capitalsage.alienvault.cloud')
            if name and not name.startswith("http") and " " not in name:
                return f"https://{name}.alienvault.cloud"
        return None

    async def _get_deployment_token(self, dep_url: str) -> Optional[str]:
        """Authenticate against a specific deployment and cache the token."""
        cached = self._dep_tokens.get(dep_url)
        if cached and time.time() < cached["expiry"]:
            return cached["token"]
        client = await self._get_client()
        for ep in ("/api/2.0/oauth/token", "/api/1.1/oauth/token"):
            try:
                resp = await client.post(
                    dep_url.rstrip("/") + ep,
                    data={"grant_type": "client_credentials"},
                    auth=(settings.AV_CLIENT_ID, settings.AV_CLIENT_SECRET),
                )
                if resp.status_code == 200:
                    data = resp.json()
                    token = data.get("access_token")
                    self._dep_tokens[dep_url] = {
                        "token": token,
                        "expiry": time.time() + int(data.get("expires_in", 3600)) - 300,
                    }
                    return token
            except Exception:
                continue
        return None

    async def fetch_deployments(self) -> list[dict]:
        """Fetch all deployments — exact async port of working extractor."""
        if not settings.av_configured():
            return []
        if self._deployments:
            return self._deployments
        token, base_api_path = await self._get_token_with_path()
        if not token:
            return []
        client = await self._get_client()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        base = self.base_url.rstrip("/")
        # Mirror working extractor: base_api_path first, then fallbacks, deduplicated
        paths_raw = [
            f"{base_api_path.rstrip('/')}/deployments",
            "/api/2.0/deployments",
            "/api/1.1/deployments",
            "/deployments",
        ]
        seen: set = set()
        paths = [p for p in paths_raw if not (p in seen or seen.add(p))]  # type: ignore
        for path in paths:
            try:
                resp = await client.get(base + path, headers=headers, timeout=30)
                logger.info(f"AV deployments {path} → HTTP {resp.status_code}")
                if resp.status_code == 200:
                    data = resp.json()
                    import json as _json
                    logger.info(f"AV deployments raw: {_json.dumps(data)[:600]}")
                    # Exact if/elif pattern from working extractor (avoids 'or' chaining bug)
                    if "_embedded" in data:
                        embedded = data["_embedded"]
                        # Try all possible key names
                        deps = (embedded.get("deployments")
                                or embedded.get("tenantList")
                                or embedded.get("tenants")
                                or next(iter(embedded.values()), []))
                    elif isinstance(data, list):
                        deps = data
                    else:
                        deps = data.get("deployments", [])
                    logger.info(f"AV: {len(deps)} deployment objects from {path}")
                    if deps:
                        logger.info(f"AV: keys={list(deps[0].keys())} | first={deps[0]}")
                        for d in deps:
                            d["_resolved_url"] = self._resolve_deployment_url(d)
                        valid = [d for d in deps if d.get("_resolved_url")]
                        logger.info(f"AV: {len(valid)}/{len(deps)} with resolved URLs")
                        # Return all (even without URLs) — alarm fetch skips unresolvable ones
                        self._deployments = deps
                        return deps
                    else:
                        logger.warning(f"AV: {path} returned 200 but 0 deployments")
            except Exception as e:
                logger.warning(f"AV deployments {path} → {e}")
        logger.warning("AV: No deployments — using central URL as fallback")
        return []


    async def _fetch_alarms_one(self, dep_url: str, dep_name: str, central_token: str, days_back: int) -> list[dict]:
        """Fetch alarms from one deployment with strict client-side time filtering."""
        if not dep_url:
            logger.warning(f"AV: {dep_name} has no URL — skipping")
            return []
        client = await self._get_client()
        token = (await self._get_deployment_token(dep_url)) or central_token
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        now      = datetime.now(timezone.utc)
        start_ms = int((now - timedelta(days=days_back)).timestamp() * 1000)
        end_ms   = int(now.timestamp() * 1000)
        url = dep_url.rstrip("/") + "/api/2.0/alarms"

        # Send both possible field names — AV accepts whichever it knows
        params = {
            "timestamp_occured_gte":  start_ms,
            "timestamp_occured_lte":  end_ms,
            "timestamp_received_gte": start_ms,
            "timestamp_received_lte": end_ms,
            "sort": "timestamp_occured,desc",
            "size": 200,
            "page": 0,
        }
        all_alarms: list[dict] = []
        try:
            resp = await client.get(url, headers=headers, params=params, timeout=30)
            if resp.status_code != 200:
                logger.warning(f"AV alarms {dep_name} → HTTP {resp.status_code}")
                return []
            body = resp.json()
            total_pages = body.get("page", {}).get("totalPages", 1)
            batch = body.get("_embedded", {}).get("alarms", [])
            for a in batch:
                a["_deployment_name"] = dep_name
            all_alarms.extend(batch)

            # For 24hr window limit to 2 pages (400 alarms max); longer windows up to 5
            max_pages = min(total_pages, 2 if days_back <= 1 else 5)
            if max_pages > 1:
                async def _page(pg: int) -> list[dict]:
                    try:
                        r = await client.get(url, headers=headers,
                                             params={**params, "page": pg}, timeout=30)
                        if r.status_code == 200:
                            items = r.json().get("_embedded", {}).get("alarms", [])
                            for a in items:
                                a["_deployment_name"] = dep_name
                            return items
                    except Exception:
                        pass
                    return []
                pages = await asyncio.gather(
                    *[_page(p) for p in range(1, max_pages)],
                    return_exceptions=True,
                )
                for r in pages:
                    if isinstance(r, list):
                        all_alarms.extend(r)
        except Exception as e:
            logger.error(f"AV alarm fetch {dep_name}: {e}")

        # ── Strict client-side time-window filter ────────────────────────────
        # The AV API server-side filter is unreliable; enforce the window locally.
        def _in_window(a: dict) -> bool:
            ts = a.get("timestamp_occured") or a.get("timestamp_received") or 0
            return start_ms <= int(ts) <= end_ms

        filtered = [a for a in all_alarms if _in_window(a)]
        logger.info(
            f"AV: {dep_name} → {len(all_alarms)} raw, {len(filtered)} in {days_back}d window"
        )
        return filtered

    async def fetch_alarms_per_deployment(self, days_back: int = 7) -> dict[str, list]:
        """
        Fetch alarms from ALL deployments with concurrency control to prevent OOM.
        Uses a semaphore to limit to 4 concurrent deployment fetches.
        """
        logger.info(f"AV: fetch_alarms_per_deployment | base_url={self.base_url} | client_id={settings.AV_CLIENT_ID[:6]}...")
        if not settings.av_configured():
            logger.warning("AV: Not configured — AV_CLIENT_ID or AV_CLIENT_SECRET is empty")
            return {}
        central_token = await self._get_token()
        if not central_token:
            return {}
        deployments = await self.fetch_deployments()
        if not deployments:
            logger.info("AV: No deployments — fetching from central URL as single client")
            name = _fallback_av_client_name()
            alarms = await self._fetch_alarms_one(self.base_url, name, central_token, days_back)
            return {name: alarms} if alarms else {}

        # Use semaphore to cap concurrent fetches at 4 (prevents OOM)
        sem = asyncio.Semaphore(4)

        async def _fetch_with_sem(dep: dict) -> tuple[str, list]:
            dep_url  = dep.get("_resolved_url", "")
            dep_name = dep.get("name", "Unknown")
            async with sem:
                alarms = await self._fetch_alarms_one(dep_url, dep_name, central_token, days_back)
            return dep_name, alarms

        results = await asyncio.gather(
            *[_fetch_with_sem(d) for d in deployments],
            return_exceptions=True,
        )
        out: dict[str, list] = {}
        for res in results:
            if isinstance(res, tuple):
                name, alarms = res
                out[name] = alarms  # Always include — even empty list keeps the card alive
            elif isinstance(res, Exception):
                logger.error(f"AV deployment fetch error: {res}")
        # Ensure ALL known cached deployments appear even if their fetch failed this cycle
        for dep in self._deployments:
            dep_name = dep.get("name", "Unknown")
            if dep_name not in out:
                out[dep_name] = []  # 0 alarms this cycle but still show the card
                logger.info(f"AV: {dep_name} — 0 alarms this cycle (cached deployment kept)")
        logger.info(f"AV: {len(out)} deployments total (including 0-alarm): {list(out.keys())}")
        return out

    async def fetch_alarms(self, days_back: int = 30) -> list[dict]:
        """Flat alarm list (used by debug endpoint)."""
        all_alarms: list[dict] = []
        for alarms in (await self.fetch_alarms_per_deployment(days_back)).values():
            all_alarms.extend(alarms)
        return all_alarms

    async def fetch_events(self, days_back: int = 1) -> list[dict]:
        """Fetch events from central URL (summary use only)."""
        if not settings.av_configured():
            return []
        token = await self._get_token()
        if not token:
            return []
        client = await self._get_client()
        now = datetime.now(timezone.utc)
        start_ms = int((now - timedelta(days=days_back)).timestamp() * 1000)
        end_ms   = int(now.timestamp() * 1000)
        try:
            resp = await client.get(
                self.base_url.rstrip("/") + "/api/2.0/events",
                headers={"Authorization": f"Bearer {token}"},
                params={"timestamp_received_gte": start_ms, "timestamp_received_lte": end_ms,
                        "sort": "timestamp_received,desc", "size": 500, "page": 0},
            )
            if resp.status_code == 200:
                return resp.json().get("_embedded", {}).get("eventResources", [])
        except Exception as e:
            logger.warning(f"AV events: {e}")
        return []

    async def fetch_sensors(self) -> list[dict]:
        """Legacy — returns deployments as sensor objects for compatibility."""
        return await self.fetch_deployments()



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

            # ── Phase 2: Parallel data fetch ───────────────────────────────
            valid_s1_sites = [s for s in s1_sites if s.get("id")]
            s1_build_tasks = [
                self._build_s1_client(str(s["id"]), s.get("name", "Unknown"))
                for s in valid_s1_sites
            ]
            all_results = await asyncio.gather(
                *s1_build_tasks,
                self.av.fetch_alarms_per_deployment(days_back=1),  # 24hr window
                self.av.fetch_events(days_back=1),
                return_exceptions=True,
            )

            n_s1 = len(s1_build_tasks)
            s1_results       = all_results[:n_s1]
            av_per_dep_raw   = all_results[n_s1]   if not isinstance(all_results[n_s1],   Exception) else {}
            av_events_raw    = all_results[n_s1+1] if not isinstance(all_results[n_s1+1], Exception) else []

            if isinstance(av_per_dep_raw, Exception):
                logger.error(f"AV per-deployment fetch error: {av_per_dep_raw}"); av_per_dep_raw = {}
            if isinstance(av_events_raw, Exception):
                logger.error(f"AV events error: {av_events_raw}"); av_events_raw = []

            # ── Phase 3: Build S1 client index ───────────────────────────
            clients: dict[str, ClientSummary] = {}
            for result, site in zip(s1_results, valid_s1_sites):
                if isinstance(result, ClientSummary):
                    key = _normalize_name(result.name)
                    clients[key] = result
                else:
                    logger.error(f"S1 build error for '{site.get('name')}': {result}")

            # ── Phase 4: Merge AV deployments into S1 clients (or create AV-only) ──
            # Seed with ALL cached deployments first — so cards appear even on 0-alarm cycles
            cached_deps = self.av._deployments or []
            for dep in cached_deps:
                dep_name = dep.get("name", "Unknown")
                if dep_name not in av_per_dep_raw:
                    av_per_dep_raw[dep_name] = []

            total_av_alarms = sum(len(v) for v in av_per_dep_raw.values())
            logger.info(f"AV: {len(av_per_dep_raw)} deployments, {total_av_alarms} total alarms")
            logger.info(f"AV: deployment names: {list(av_per_dep_raw.keys())}")

            for dep_name, alarms in av_per_dep_raw.items():
                norm_dep = _normalize_name(dep_name)
                s1_match = _find_best_match(norm_dep, list(clients.keys()), raw_av_name=dep_name)

                if s1_match:
                    _merge_av_data(clients[s1_match], alarms, [])
                    logger.info(f"AV: '{dep_name}' merged → S1 '{clients[s1_match].name}'")
                else:
                    clean_name = dep_name.replace("-", " ").title()
                    av_only = self._build_av_summary(alarms, [], clean_name)
                    clients[norm_dep] = av_only
                    logger.info(f"AV: '{dep_name}' → standalone AV-only card ({len(alarms)} alarms)")


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
            elif not s1_sites and not av_per_dep_raw:
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
        """Build ClientSummary from AlienVault data — computes full breakdowns from ALL alarms."""

        # ── Priority × Status breakdown ──────────────────────────────────
        PRIORITY_COLORS = {
            "critical": "#DC2626", "high": "#EF4444",
            "medium": "#F59E0B",   "low": "#22C55E",
        }
        prio_map: dict[str, dict] = {}   # priority → {open, closed, in_review, other}
        for a in alarms:
            prio = str(a.get("priority_label", "low")).lower()
            if prio not in ("critical", "high", "medium", "low"):
                prio = "low"
            st = str(a.get("status", "")).lower()
            if prio not in prio_map:
                prio_map[prio] = {"open": 0, "closed": 0, "in_review": 0, "other": 0}
            if st == "open":
                prio_map[prio]["open"] += 1
            elif st in ("closed", "resolved"):
                prio_map[prio]["closed"] += 1
            elif st in ("in_review", "investigating"):
                prio_map[prio]["in_review"] += 1
            else:
                prio_map[prio]["other"] += 1

        av_priority_breakdown = []
        for prio in ("critical", "high", "medium", "low"):
            if prio in prio_map:
                counts = prio_map[prio]
                total = sum(counts.values())
                av_priority_breakdown.append(AVPriorityRow(
                    priority=prio.capitalize(),
                    total=total,
                    statuses=AVStatusCount(
                        open=counts["open"],
                        closed=counts["closed"],
                        in_review=counts["in_review"],
                        other=counts["other"],
                    ),
                    color=PRIORITY_COLORS.get(prio, "#6B7280"),
                ))

        # ── Method / Intent / Strategy breakdown ─────────────────────────
        method_counter: dict[str, dict] = {}   # method → {count, intent, strategy}
        for a in alarms:
            method   = a.get("rule_method", "") or a.get("method", "") or "Unknown"
            intent   = a.get("rule_intent", "") or a.get("intent", "") or ""
            strategy = a.get("rule_strategy", "") or a.get("strategy", "") or ""
            key = method
            if key not in method_counter:
                method_counter[key] = {"count": 0, "intent": intent, "strategy": strategy}
            method_counter[key]["count"] += 1

        av_method_summary = [
            AVMethodRow(
                method=m,
                intent=d["intent"],
                strategy=d["strategy"],
                count=d["count"],
            )
            for m, d in sorted(method_counter.items(), key=lambda x: -x[1]["count"])
        ][:20]

        # ── Top 5 Sources ─────────────────────────────────────────────────
        source_counter: dict[str, Counter] = {}
        for a in alarms:
            src = a.get("source_name", "") or a.get("src_ip", "") or ""
            if not src:
                continue
            method = a.get("rule_method", "Unknown")
            if src not in source_counter:
                source_counter[src] = Counter()
            source_counter[src][method] += 1

        av_top_sources = [
            AVAssetRow(
                asset=src,
                count=sum(c.values()),
                alarm_types=list(dict(c.most_common(3)).keys()),
            )
            for src, c in sorted(source_counter.items(), key=lambda x: -sum(x[1].values()))
        ][:5]

        # ── Top 5 Destinations ────────────────────────────────────────────
        dest_counter: dict[str, Counter] = {}
        for a in alarms:
            dst = a.get("destination_name", "") or a.get("dst_ip", "") or ""
            if not dst:
                continue
            method = a.get("rule_method", "Unknown")
            if dst not in dest_counter:
                dest_counter[dst] = Counter()
            dest_counter[dst][method] += 1

        av_top_destinations = [
            AVAssetRow(
                asset=dst,
                count=sum(c.values()),
                alarm_types=list(dict(c.most_common(3)).keys()),
            )
            for dst, c in sorted(dest_counter.items(), key=lambda x: -sum(x[1].values()))
        ][:5]

        # ── Severity KPIs ─────────────────────────────────────────────────
        severity_map = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in av_priority_breakdown:
            severity_map[r.priority.lower()] = r.total

        # ── Classifications (for pie chart) ──────────────────────────────
        intent_counter: Counter = Counter()
        for a in alarms:
            intent = a.get("rule_intent", "") or a.get("intent", "Other")
            if intent:
                intent_counter[intent] += 1

        INTENT_COLORS = {
            "System Compromise":         "#DC2626",
            "Exploitation & Installation":"#EF4444",
            "Delivery & Attack":          "#F97316",
            "Reconnaissance & Probing":   "#F59E0B",
            "Environmental Awareness":    "#3B82F6",
        }
        classifications = [
            ThreatClassification(
                name=intent,
                count=count,
                color=INTENT_COLORS.get(intent, "#6B7280"),
            )
            for intent, count in intent_counter.most_common(5)
        ]

        # ── Recent alerts (50 most recent for the table) ──────────────────
        recent_alerts = []
        for a in alarms[:50]:
            prio_label = str(a.get("priority_label", "low")).lower()
            if prio_label not in ("critical", "high", "medium", "low"):
                prio_label = "low"
            ts_ms = a.get("timestamp_occured") or a.get("timestamp_received")
            recent_alerts.append(AlertItem(
                id=f"AV-{str(a.get('uuid', ''))[:6]}",
                alert_type=a.get("rule_method", a.get("rule_intent", "Alarm")),
                source=a.get("source_name", a.get("sensor", "")),
                destination=a.get("destination_name", ""),
                severity=prio_label,
                confidence=prio_label.capitalize(),
                status="Open" if a.get("status") == "open" else
                       "In Review" if a.get("status") in ("in_review", "investigating") else "Closed",
                time=_format_timestamp_ms(ts_ms),
                reported_at=_format_exact_time_ms(ts_ms),
                intent=a.get("rule_intent", ""),
                strategy=a.get("rule_strategy", ""),
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
            av_total_alarms=len(alarms),
            av_priority_breakdown=av_priority_breakdown,
            av_method_summary=av_method_summary,
            av_top_sources=av_top_sources,
            av_top_destinations=av_top_destinations,
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

def _format_exact_time_ms(ts_ms) -> str:
    """Format millisecond epoch timestamp as 'Apr 13th 2026 • 20:03'."""
    if not ts_ms:
        return ""
    try:
        dt = datetime.fromtimestamp(int(ts_ms) / 1000, tz=timezone.utc)
        return _format_exact_time(dt.isoformat())
    except Exception:
        return ""


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


# Explicit mapping for AlienVault names -> SentinelOne names
# Use lowercase for both sides of the mapping
_AV_TO_S1_MAP = {
    "appzonegroup (qore)": "qore inc technologies",
    "appzonegroup": "qore inc technologies",
    "appzone": "qore inc technologies",
    "qore": "qore inc technologies",
    "zonenetwork": "zone payment network limited",
    "etranzact2": "etranzact",
    "etranzact": "etranzact",
    "cybervergent": "cybervergent",
    "esentry-nfr": "cybervergent",
}

def _find_best_match(norm_target: str, candidates: list, raw_av_name: str = "") -> Optional[str]:
    """
    Fuzzy-match norm_target against a list of normalized candidate keys.
    Priority: Explicit Map -> exact → substring → Jaccard word-overlap (≥ 30 % union).
    Returns the best matching key or None.
    """
    if not candidates:
        return None

    # 1. Check explicit mapping first
    raw_lower = raw_av_name.lower().strip()
    if raw_lower in _AV_TO_S1_MAP:
        mapped_s1 = _AV_TO_S1_MAP[raw_lower]
        # Find the normalized candidate that matches our mapped S1 name
        for key in candidates:
            if mapped_s1 in key or key in mapped_s1:
                return key

    if not norm_target:
        return None

    target_words = set(norm_target.split())
    best_key, best_score = None, 0.0

    for key in candidates:
        # 2. Exact
        if norm_target == key:
            return key
        # 3. Substring
        if norm_target in key or key in norm_target:
            score = len(norm_target) if norm_target in key else len(key)
            if score > best_score:
                best_score, best_key = float(score), key
            continue
        # 4. Word overlap (Jaccard)
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
    Computes full AV breakdowns: priority x status, methods, sources, destinations.
    """
    if "AlienVault" not in client.platforms:
        client.platforms.append("AlienVault")

    # ── Priority x Status breakdown ──────────────────────────────
    PRIORITY_COLORS = {
        "critical": "#DC2626", "high": "#EF4444",
        "medium": "#F59E0B",   "low": "#22C55E",
    }
    prio_map: dict[str, dict] = {}
    for a in alarms:
        prio = str(a.get("priority_label", "low")).lower()
        if prio not in ("critical", "high", "medium", "low"):
            prio = "low"
        st = str(a.get("status", "")).lower()
        if prio not in prio_map:
            prio_map[prio] = {"open": 0, "closed": 0, "in_review": 0, "other": 0}
        if st == "open":
            prio_map[prio]["open"] += 1
        elif st in ("closed", "resolved"):
            prio_map[prio]["closed"] += 1
        elif st in ("in_review", "investigating"):
            prio_map[prio]["in_review"] += 1
        else:
            prio_map[prio]["other"] += 1

    av_priority_breakdown = []
    sev_map = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for prio in ("critical", "high", "medium", "low"):
        if prio in prio_map:
            counts = prio_map[prio]
            total = sum(counts.values())
            sev_map[prio] = total
            av_priority_breakdown.append(AVPriorityRow(
                priority=prio.capitalize(),
                total=total,
                statuses=AVStatusCount(
                    open=counts["open"],
                    closed=counts["closed"],
                    in_review=counts["in_review"],
                    other=counts["other"],
                ),
                color=PRIORITY_COLORS.get(prio, "#6B7280"),
            ))

    # ── Method / Intent / Strategy breakdown ─────────────────────
    method_counter: dict[str, dict] = {}
    for a in alarms:
        method   = a.get("rule_method", "") or a.get("method", "") or "Unknown"
        intent   = a.get("rule_intent", "") or a.get("intent", "") or ""
        strategy = a.get("rule_strategy", "") or a.get("strategy", "") or ""
        if method not in method_counter:
            method_counter[method] = {"count": 0, "intent": intent, "strategy": strategy}
        method_counter[method]["count"] += 1

    av_method_summary = [
        AVMethodRow(method=m, intent=d["intent"], strategy=d["strategy"], count=d["count"])
        for m, d in sorted(method_counter.items(), key=lambda x: -x[1]["count"])
    ][:20]

    # ── Top 5 Sources ─────────────────────────────────────────────
    source_counter: dict[str, Counter] = {}
    for a in alarms:
        src = a.get("source_name", "") or a.get("src_ip", "") or ""
        if not src:
            continue
        m = a.get("rule_method", "Unknown")
        if src not in source_counter:
            source_counter[src] = Counter()
        source_counter[src][m] += 1
    av_top_sources = [
        AVAssetRow(asset=s, count=sum(c.values()), alarm_types=list(dict(c.most_common(3)).keys()))
        for s, c in sorted(source_counter.items(), key=lambda x: -sum(x[1].values()))
    ][:5]

    # ── Top 5 Destinations ────────────────────────────────────────
    dest_counter: dict[str, Counter] = {}
    for a in alarms:
        dst = a.get("destination_name", "") or a.get("dst_ip", "") or ""
        if not dst:
            continue
        m = a.get("rule_method", "Unknown")
        if dst not in dest_counter:
            dest_counter[dst] = Counter()
        dest_counter[dst][m] += 1
    av_top_destinations = [
        AVAssetRow(asset=d, count=sum(c.values()), alarm_types=list(dict(c.most_common(3)).keys()))
        for d, c in sorted(dest_counter.items(), key=lambda x: -sum(x[1].values()))
    ][:5]

    # ── Set breakdown fields on client ────────────────────────────
    client.av_total_alarms       = len(alarms)
    client.av_priority_breakdown = av_priority_breakdown
    client.av_method_summary     = av_method_summary
    client.av_top_sources        = av_top_sources
    client.av_top_destinations   = av_top_destinations
    client.total_alerts         += len(alarms)
    client.total_threats        += sev_map["critical"] + sev_map["high"]
    client.events_processed     += len(events)
    client.blocked_attempts     += sev_map["critical"]

    # ── AV AlertItems (up to 50) ──────────────────────────────────
    for a in alarms[:50]:
        prio_label = str(a.get("priority_label", "low")).lower()
        if prio_label not in ("critical", "high", "medium", "low"):
            prio_label = "low"
        ts_ms = a.get("timestamp_occured") or a.get("timestamp_received")
        st = str(a.get("status", "")).lower()
        client.recent_alerts.append(AlertItem(
            id=f"AV-{str(a.get('uuid', ''))[:6]}",
            alert_type=a.get("rule_method", a.get("rule_intent", "Alarm")),
            source=a.get("source_name", a.get("sensor", "")),
            destination=a.get("destination_name", ""),
            severity=prio_label,
            confidence=prio_label.capitalize(),
            status="Open" if st == "open" else
                   "In Review" if st in ("in_review", "investigating") else "Closed",
            time=_format_timestamp_ms(ts_ms),
            reported_at=_format_exact_time_ms(ts_ms),
            intent=a.get("rule_intent", ""),
            strategy=a.get("rule_strategy", ""),
            platform="AlienVault",
        ))

    client.platform_data.append(PlatformStatus(
        platform="AlienVault",
        is_active=True,
        total_endpoints=0,
        total_threats=sev_map["critical"] + sev_map["high"],
        total_alerts=len(alarms),
        events_processed=len(events),
        blocked_attempts=sev_map["critical"],
    ))


# Singleton
aggregator = DashboardAggregator()
