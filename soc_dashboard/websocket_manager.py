"""
Sentrium Integrated SOC Dashboard — WebSocket Manager
Manages connected browser clients and broadcasts data updates.
"""

from __future__ import annotations
import json
import logging
from typing import Set
from fastapi import WebSocket

logger = logging.getLogger("soc_dashboard.ws")


class WebSocketManager:
    """Manages WebSocket connections and broadcasts dashboard state."""

    def __init__(self):
        self._connections: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        """Accept and register a new WebSocket connection."""
        await ws.accept()
        self._connections.add(ws)
        logger.info(f"WebSocket connected. Total: {len(self._connections)}")

    def disconnect(self, ws: WebSocket):
        """Remove a disconnected WebSocket."""
        self._connections.discard(ws)
        logger.info(f"WebSocket disconnected. Total: {len(self._connections)}")

    @property
    def active_count(self) -> int:
        return len(self._connections)

    async def broadcast(self, data: dict):
        """
        Broadcast data to ALL connected clients simultaneously.
        Removes any dead connections silently.
        """
        if not self._connections:
            return

        payload = json.dumps(data, default=str)
        dead: list[WebSocket] = []

        for ws in self._connections.copy():
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self._connections.discard(ws)

    async def send_to(self, ws: WebSocket, data: dict):
        """Send data to a specific WebSocket."""
        try:
            payload = json.dumps(data, default=str)
            await ws.send_text(payload)
        except Exception:
            self._connections.discard(ws)


# Singleton instance
ws_manager = WebSocketManager()
