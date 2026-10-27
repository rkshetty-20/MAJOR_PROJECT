from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.config import settings

# SQLite requires check_same_thread=False for FastAPI concurrency.
# PostgreSQL or other engines do not accept this argument, so we apply it conditionally.
connect_args = (
    {"check_same_thread": False}
    if settings.DATABASE_URL.startswith("sqlite")
    else {}
)

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    Yields a database session per request.
    Use with FastAPI Depends(get_db).
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
