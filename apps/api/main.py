from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from authorityguard import __version__
from authorityguard.errors import DomainError
from authorityguard.identity.router import router as identity_router
from authorityguard.tasks.router import router as tasks_router


def create_app() -> FastAPI:
    # The schema is owned by Alembic: run `alembic upgrade head` before starting the API.
    app = FastAPI(
        title="AuthorityGuard",
        version=__version__,
        description="Delegated authorization gateway for multi-agent systems (MVP).",
    )

    @app.exception_handler(DomainError)
    async def _domain_error(_request: Request, exc: DomainError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": {"code": exc.code, "message": exc.message}},
        )

    @app.get("/health", tags=["meta"])
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    app.include_router(identity_router)
    app.include_router(tasks_router)
    return app


app = create_app()
