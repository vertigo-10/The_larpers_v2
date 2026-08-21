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
from .config import settings
from .db import SessionLocal, init_db
from .engine import engine_loop, manager, stop_engine
from .ml.infer import get_detector
from .models import User
from .routers import api as api_router
from .routers import auth as auth_router
from .routers import team as team_router
from .security import decode_token

FRONTEND_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

_engine_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _engine_task
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

    _engine_task = asyncio.create_task(engine_loop())
    try:
        yield
    finally:
        stop_engine()
        if _engine_task:
            _engine_task.cancel()
            try:
                await _engine_task
            except (asyncio.CancelledError, Exception):  # noqa: B014
                pass


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
