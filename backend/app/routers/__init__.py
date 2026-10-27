"""API Routers package for AOD-IPS backend."""

from app.routers.db_init import router as db_init_router, init_db
from app.routers.scenarios import router as scenarios_router
from app.routers.sessions import router as sessions_router
from app.routers.responses import router as responses_router
from app.routers.students import router as students_router
from app.routers.chat import router as chat_router
from app.routers.simulation import router as simulation_router

__all__ = [
    "db_init_router",
    "scenarios_router",
    "sessions_router",
    "responses_router",
    "students_router",
    "chat_router",
    "simulation_router",
    "init_db",
]
