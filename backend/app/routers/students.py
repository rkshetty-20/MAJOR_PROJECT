from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.services.adaptive_engine import recommend_next_scenario

router = APIRouter(prefix="/students", tags=["Students"])


# ==========================================
# Pydantic Schemas
# ==========================================

class RecommendationResponse(BaseModel):
    scenario_id: Optional[int] = None
    category: str
    difficulty: str
    reason: str

    model_config = ConfigDict(from_attributes=True)


# ==========================================
# Endpoints
# ==========================================

@router.get(
    "/{student_id}/recommendation",
    response_model=RecommendationResponse,
    summary="Get adaptive scenario recommendation for a student",
)
def get_student_recommendation(
    student_id: str,
    db: DBSession = Depends(get_db),
) -> RecommendationResponse:
    """
    Analyzes historical performance for the student across all attack categories.
    Recommends their weakest scenario area with difficulty adapted according to recent score trends.
    """
    rec_dict = recommend_next_scenario(student_id=student_id, db=db)
    return RecommendationResponse(**rec_dict)
