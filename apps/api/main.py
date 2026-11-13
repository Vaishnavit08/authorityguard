from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from authorityguard import __version__
from authorityguard.agents.router import router as demo_router
from authorityguard.audit.router import router as audit_router
from authorityguard.capabilities.router import router as capabilities_router
from authorityguard.deps import trace_id_for
from authorityguard.errors import DomainError
from authorityguard.gateway.router import router as gateway_router
from authorityguard.identity.router import router as identity_router
from authorityguard.policy.engine import get_policy
from authorityguard.tasks.router import router as tasks_router

STATIC = Path(__file__).parent / "static"


def create_app() -> FastAPI:
    # The schema is owned by Alembic: run `alembic upgrade head` before starting the API.
    app = FastAPI(
        title="AuthorityGuard",
        version=__version__,
        description=(
            "Delegated authorization and runtime policy enforcement for multi-agent AI systems. "
            "Open **/dashboard** for the interactive demo."
        ),
    )

    @app.middleware("http")
    async def _trace(request: Request, call_next):
        request.state.trace_id = trace_id_for(request)
        response = await call_next(request)
        response.headers["X-Trace-Id"] = request.state.trace_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.exception_handler(DomainError)
    async def _domain_error(_request: Request, exc: DomainError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": {"code": exc.code, "message": exc.message}},
        )

    @app.get("/health", tags=["meta"])
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__, "policy_version": get_policy().version}

    @app.get("/policy", tags=["meta"])
    def policy() -> dict:
        return get_policy().model_dump()

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse("/dashboard")

    @app.get("/dashboard", include_in_schema=False)
    def dashboard() -> FileResponse:
        # no-cache: browsers revalidate, so a redeploy is visible immediately.
        return FileResponse(
            STATIC / "dashboard.html", media_type="text/html", headers={"Cache-Control": "no-cache"}
        )

    for r in (
        identity_router,
        tasks_router,
        capabilities_router,
        gateway_router,
        audit_router,
        demo_router,
    ):
        app.include_router(r)
    return app


app = create_app()
