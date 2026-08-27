"""Application entrypoint.

Serves the API and, in single-service deployments, the dashboard itself. That
keeps the cookie same-origin, which is the simplest secure configuration.

    uvicorn backend.app.main:app --reload
"""

import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .baseline import baseline_loop, stop_baseline
from .config import settings
from .db import SessionLocal, init_db
from .engine import engine_loop, manager, retention_loop, stop_engine
from .ml.infer import get_detector
from .models import User
from .routers import api as api_router
from .routers import auth as auth_router
from .routers import team as team_router
from .security import decode_token, token_is_revoked

FRONTEND_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

_background_tasks = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()

    detector = get_detector()
    if detector.ready:
        m = detector.metrics or {}
        print(f"[sentry] model loaded — {m.get('architecture', 'MLP')} "
              f"classes={detector.class_names} "
              f"heldout_acc={m.get('accuracy')}% dataset={m.get('dataset')}")
    else:
        print(f"[sentry] WARNING: model NOT loaded — {detector.error}")
        print("[sentry] detection endpoints will report unavailable until you run:")
        print("[sentry]     python -m backend.app.ml.train")

    # Baselining and retention both run whether or not the simulator does — a
    # production deployment has the simulator off and still needs its traffic
    # baselined and its append-only tables trimmed.
    _background_tasks.extend([
        asyncio.create_task(engine_loop()),
        asyncio.create_task(baseline_loop()),
        asyncio.create_task(retention_loop()),
    ])
    try:
        yield
    finally:
        stop_engine()
        stop_baseline()
        for task in _background_tasks:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: B014
                pass
        _background_tasks.clear()


app = FastAPI(
    title="SENTRY",
    description="Neural-network network threat detection.",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,  # required for the session cookie
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"

    # Defence in depth behind the esc() discipline in the frontend. If one
    # unescaped interpolation ever slips through, this is what stops the
    # injected script from running at all, and stops any payload that does run
    # from exfiltrating to an attacker's host.
    #
    # 'unsafe-inline' for styles only: several pages set element.style directly
    # (the password hint colour, chart sizing). Scripts get no such exemption,
    # which is the half that actually matters. cdn.jsdelivr.net is Chart.js.
    # connect-src includes ws:/wss: for the live flow socket.
    response.headers["Content-Security-Policy"] = "; ".join([
        "default-src 'self'",
        "script-src 'self' https://cdn.jsdelivr.net",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'self' ws: wss:",
        "font-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
    ])

    if settings.is_production:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # API responses are per-user and change constantly. Without an explicit
    # header a browser may heuristically cache a GET, which showed up as a
    # stale team roster surviving a reload — and worse, writes incident and
    # flow data for one account into a shared on-disk cache. Static assets
    # are left alone so they still cache normally.
    if request.url.path.startswith("/api"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"  # HTTP/1.0 proxies
        response.headers["Expires"] = "0"
    return response


app.include_router(auth_router.router)
app.include_router(team_router.router)
app.include_router(api_router.router)


# ── live stream ───────────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Authenticated live flow stream.

    The session cookie is validated before accept(); an unauthenticated socket is
    closed rather than silently receiving another tenant's traffic.

    Revocation is checked here too, not just signature validity. A signed token
    stays cryptographically valid until it expires, so without the token_version
    check a socket opened before signing out — or before a password change made
    precisely because the token leaked — would keep streaming live traffic for
    the rest of the TTL. Long-lived connections are exactly where that gap
    matters most: the HTTP routes re-authenticate on every request, a WebSocket
    authenticates once and then runs for hours.
    """
    token = websocket.cookies.get(settings.cookie_name)
    payload = decode_token(token) if token else None
    if not payload:
        await websocket.close(code=4401)
        return

    db = SessionLocal()
    try:
        user = db.get(User, int(payload.get("sub", 0)))
        if not user or not user.is_active or user.org_id != payload.get("org"):
            await websocket.close(code=4401)
            return
        if token_is_revoked(user, payload):
            await websocket.close(code=4401)
            return
        org_id = user.org_id
    finally:
        db.close()

    await manager.connect(org_id, websocket)
    try:
        while True:
            # Keeps the connection open; clients need not send anything.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001
        pass
    finally:
        await manager.disconnect(org_id, websocket)


@app.exception_handler(404)
async def not_found(request: Request, exc):
    if request.url.path.startswith("/api"):
        return JSONResponse({"detail": "Not found"}, status_code=404)
    index = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index):
        return FileResponse(index, status_code=404)
    return JSONResponse({"detail": "Not found"}, status_code=404)


# ── static dashboard ──────────────────────────────────────────────────────
# Mounted last so it never shadows an API route.
if os.path.isdir(os.path.join(FRONTEND_DIR, "assets")):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIR, "assets")), name="assets")


@app.get("/", include_in_schema=False)
async def root():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


@app.get("/{page}.html", include_in_schema=False)
async def page(page: str):
    # Basename only — prevents ../ traversal out of the frontend directory.
    safe = os.path.basename(f"{page}.html")
    path = os.path.join(FRONTEND_DIR, safe)
    if os.path.exists(path):
        return FileResponse(path)
    return JSONResponse({"detail": "Not found"}, status_code=404)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.app.main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=settings.debug,
    )
