"""
Sentrium Integrated SOC Dashboard — FastAPI Application
Main entry point. Serves dashboard, handles auth, runs background fetcher.
"""
from __future__ import annotations
import asyncio
import logging
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from config import settings
from auth import verify_totp, create_session, validate_session, destroy_session
from fetcher import aggregator
from websocket_manager import ws_manager
# ── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-28s │ %(levelname)-5s │ %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("soc_dashboard.app")
# ── Paths ────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
# ── Background task control ──────────────────────────────────
_bg_task: asyncio.Task | None = None
async def _background_fetcher():
    """Background loop: fetch data every REFRESH_INTERVAL seconds, broadcast via WS."""
    logger.info(f"Background fetcher started (interval: {settings.REFRESH_INTERVAL}s)")
    while True:
        try:
            state = await aggregator.fetch_all()
            await ws_manager.broadcast(state.model_dump())
            logger.info(
                f"Broadcast: {state.total_clients} clients, "
                f"{ws_manager.active_count} WS connections"
            )
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Background fetch error: {e}")
        await asyncio.sleep(settings.REFRESH_INTERVAL)
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    global _bg_task
    # Start background fetcher
    _bg_task = asyncio.create_task(_background_fetcher())
    logger.info("═══ Sentrium SOC Dashboard started ═══")
    yield
    # Shutdown
    if _bg_task:
        _bg_task.cancel()
        try:
            await _bg_task
        except asyncio.CancelledError:
            pass
    await aggregator.close()
    logger.info("═══ Sentrium SOC Dashboard stopped ═══")
# ── FastAPI App ──────────────────────────────────────────────
app = FastAPI(
    title="Sentrium Integrated SOC Dashboard",
    version="1.0.0",
    lifespan=lifespan,
)
# Mount static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
# Templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
# ════════════════════════════════════════════════════════════════
#  Auth helpers
# ════════════════════════════════════════════════════════════════
SESSION_COOKIE = "sentrium_session"
def _get_session_token(request: Request) -> str | None:
    return request.cookies.get(SESSION_COOKIE)
def _is_authenticated(request: Request) -> bool:
    return validate_session(_get_session_token(request))
# ════════════════════════════════════════════════════════════════
#  Routes
# ════════════════════════════════════════════════════════════════
@app.get("/", response_class=HTMLResponse)
async def client_grid(request: Request):
    """Client Grid overview — shows all clients as clickable cards."""
    if not _is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse(
        request=request,
        name="clients.html",
        context={
            "ws_url": f"ws://{request.headers.get('host', 'localhost:8080')}/ws",
        }
    )
@app.get("/client/{client_name}", response_class=HTMLResponse)
async def client_dashboard(request: Request, client_name: str):
    """Per-client SOC dashboard — detailed view for a specific client."""
    if not _is_authenticated(request):
        return RedirectResponse(url="/login", status_code=302)
    from urllib.parse import unquote
    decoded_name = unquote(client_name)
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "refresh_interval": settings.REFRESH_INTERVAL,
            "ws_url": f"ws://{request.headers.get('host', 'localhost:8080')}/ws",
            "client_name": decoded_name,
        }
    )
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page with TOTP."""
    if _is_authenticated(request):
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": None,
            "totp_configured": settings.totp_configured(),
        }
    )
@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, totp_code: str = Form(...)):
    """Handle TOTP login form submission."""
    if verify_totp(totp_code.strip()):
        token = create_session()
        response = RedirectResponse(url="/", status_code=302)
        response.set_cookie(
            key=SESSION_COOKIE,
            value=token,
            httponly=True,
            samesite="lax",
            max_age=settings.SESSION_TIMEOUT_MINUTES * 60,
        )
        logger.info("User authenticated via TOTP")
        return response
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": "Invalid verification code. Please try again.",
            "totp_configured": settings.totp_configured(),
        }
    )
@app.get("/logout")
async def logout(request: Request):
    """Logout and destroy session."""
    destroy_session(_get_session_token(request))
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(SESSION_COOKIE)
    return response
# ════════════════════════════════════════════════════════════════
#  REST API (fallback for non-WS clients)
# ════════════════════════════════════════════════════════════════
@app.get("/api/state")
async def api_state(request: Request):
    """Get current dashboard state as JSON."""
    if not _is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    state = aggregator.cached_state
    if state:
        return JSONResponse(state.model_dump())
    return JSONResponse({"error": "No data yet. Waiting for first fetch cycle."}, status_code=503)
@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "s1_configured": settings.s1_configured(),
        "av_configured": settings.av_configured(),
        "ws_connections": ws_manager.active_count,
    }
# ════════════════════════════════════════════════════════════════
#  WebSocket
# ════════════════════════════════════════════════════════════════
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """WebSocket endpoint for real-time dashboard updates."""
    await ws_manager.connect(ws)
    # Send cached state immediately on connect
    if aggregator.cached_state:
        await ws_manager.send_to(ws, aggregator.cached_state.model_dump())
    try:
        while True:
            # Keep connection alive by receiving messages (ping/pong)
            data = await ws.receive_text()
            # Handle client messages (e.g., select_client)
            if data.startswith("select:"):
                client_name = data[7:].strip()
                await _send_client_detail(ws, client_name)
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception:
        ws_manager.disconnect(ws)
async def _send_client_detail(ws: WebSocket, client_name: str):
    """Send detailed data for a specific client."""
    state = aggregator.cached_state
    if not state:
        return
    for client in state.clients:
        if client.name.lower() == client_name.lower():
            await ws_manager.send_to(ws, {
                "type": "client_detail",
                "client": client.model_dump(),
            })
            return
    await ws_manager.send_to(ws, {
        "type": "error",
        "message": f"Client '{client_name}' not found",
    })
# ════════════════════════════════════════════════════════════════
#  Entry point
# ════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True,
        log_level="info",
    )
