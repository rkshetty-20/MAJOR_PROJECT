from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers.db_init import init_db, router as db_init_router
from app.routers.scenarios import router as scenarios_router
from app.routers.sessions import router as sessions_router
from app.routers.responses import router as responses_router
from app.routers.students import router as students_router
from app.routers.chat import router as chat_router
from app.routers.simulation import router as simulation_router
from app.routers.detect import router as detect_router
from app.routers.system import router as system_router
from app.routers.scenario_studio import router as scenario_studio_router
from app.routers.ids import router as ids_router
from app.routers.adaptive_learning import router as adaptive_learning_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan events for FastAPI.
    Automatically creates database tables on startup.
    """
    init_db()
    yield


app = FastAPI(
    title="AOD-IPS Backend API",
    version="1.0.0",
    description="AOD-IPS: Adaptive Offensive-Defensive Intrusion and Phishing Simulation Framework — cybersecurity training and evaluation platform featuring synthetic scenario generation, multi-layered IDS rule engines, lexical phishing detection, Random Forest anomaly classification, explainable risk fusion, and adaptive learning.",
    lifespan=lifespan,
)

# Enable CORS for the frontend dev server
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register route modules
app.include_router(scenarios_router)
app.include_router(sessions_router)
app.include_router(responses_router)
app.include_router(students_router)
app.include_router(chat_router)
app.include_router(simulation_router)
app.include_router(detect_router)
app.include_router(db_init_router)
app.include_router(system_router)
app.include_router(scenario_studio_router)
app.include_router(ids_router)
app.include_router(adaptive_learning_router)


@app.get("/", summary="Root API index")
def root_index() -> dict[str, str]:
    return {
        "message": "AOD-IPS Backend API is running.",
        "docs_url": "/docs",
        "redoc_url": "/redoc",
        "health_url": "/health",
        "frontend_dashboard": "http://localhost:5173",
    }


@app.get("/health", summary="Health check endpoint")
def get_health() -> dict[str, str]:
    return {"status": "ok"}
