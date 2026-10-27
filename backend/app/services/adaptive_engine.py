import json
import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.models import (
    PerformanceHistory,
    Scenario,
    Session as SessionModel,
    ScenarioCategory,
    DifficultyLevel,
)

logger = logging.getLogger(__name__)


def recommend_next_scenario(student_id: str, db: Session) -> Dict[str, Any]:
    """
    Recommends the optimal next attack scenario for a student based on their
    performance history across scenarios:
    1. If fewer than 2 records exist, recommends the baseline easy port_scan scenario.
    2. Identifies the student's weakest category (lowest average score_achieved,
       ties broken by lowest attempt count to ensure balanced topic coverage).
    3. Calculates performance trend across the last up to 3 scores in that category:
       - 'improving' (recent half avg > earlier half avg) -> steps difficulty up (easy->medium->hard)
       - 'declining' / 'flat' -> keeps difficulty or steps down if last 2 scores were below 40% of max.
    4. Generates a plain-language explanation referencing real calculated numbers.
    5. Returns the matched Scenario id, category, difficulty, and explanation.

    Args:
        student_id: The identifier for the student.
        db: SQLAlchemy database session.

    Returns:
        dict: {scenario_id, category, difficulty, reason}
    """
    records: List[PerformanceHistory] = (
        db.query(PerformanceHistory)
        .filter(PerformanceHistory.student_id == student_id)
        .order_by(PerformanceHistory.timestamp.asc())
        .all()
    )

    # 1. Cold start / baseline check (< 2 history records)
    if len(records) < 2:
        baseline = (
            db.query(Scenario)
            .filter(
                Scenario.category == ScenarioCategory.PORT_SCAN,
                Scenario.difficulty == DifficultyLevel.EASY,
            )
            .first()
        )
        if not baseline:
            baseline = (
                db.query(Scenario)
                .filter(Scenario.category == ScenarioCategory.PORT_SCAN)
                .first()
            )

        return {
            "scenario_id": baseline.id if baseline else None,
            "category": "port_scan",
            "difficulty": "easy",
            "reason": "Not enough history yet — starting with the baseline scenario.",
        }

    # 2. Group records by category and compute averages
    records_by_cat: Dict[ScenarioCategory, List[PerformanceHistory]] = defaultdict(list)
    for rec in records:
        records_by_cat[rec.category].append(rec)

    # Find the category with the lowest average score (tie-break: fewest attempts)
    category_stats = []
    for cat, recs in records_by_cat.items():
        scores = [r.score_achieved for r in recs]
        avg_score = sum(scores) / len(scores)
        category_stats.append({
            "category": cat,
            "avg_score": avg_score,
            "attempts": len(scores),
            "scores": scores,
            "last_session_id": recs[-1].session_id,
        })

    # Sort key: lowest average score first, then lowest attempts
    category_stats.sort(key=lambda x: (x["avg_score"], x["attempts"]))
    weakest = category_stats[0]
    weakest_cat: ScenarioCategory = weakest["category"]
    weakest_avg = int(round(weakest["avg_score"]))

    # Compute comparison average across all other categories
    other_scores = [
        r.score_achieved for r in records if r.category != weakest_cat
    ]
    other_avg = (
        int(round(sum(other_scores) / len(other_scores)))
        if other_scores
        else weakest_avg
    )

    # 3. Analyze trend using the last up to 3 scores for the weakest category
    cat_scores = weakest["scores"]
    last_scores = cat_scores[-3:]  # up to last 3 scores

    if len(last_scores) == 1:
        trend = "flat"
    elif len(last_scores) == 2:
        earlier_avg = float(last_scores[0])
        recent_avg = float(last_scores[1])
        if recent_avg > earlier_avg:
            trend = "improving"
        elif recent_avg < earlier_avg:
            trend = "declining"
        else:
            trend = "flat"
    else:
        # 3 scores: compare earlier half (first item) with recent half (last 2 items)
        earlier_avg = float(last_scores[0])
        recent_avg = (last_scores[1] + last_scores[2]) / 2.0
        if recent_avg > earlier_avg:
            trend = "improving"
        elif recent_avg < earlier_avg:
            trend = "declining"
        else:
            trend = "flat"

    # 4. Determine last difficulty played in this category
    last_session = (
        db.query(SessionModel)
        .filter(SessionModel.id == weakest["last_session_id"])
        .first()
    )

    if last_session and last_session.scenario:
        last_diff = last_session.scenario.difficulty
    else:
        last_diff = DifficultyLevel.EASY

    # Max points in baseline scoring is 70 (50 correct + 20 speed bonus)
    max_pts = 70.0
    threshold_40_pct = 0.40 * max_pts  # 28.0

    # 5. Adapt difficulty level
    if trend == "improving":
        if last_diff == DifficultyLevel.EASY:
            recommended_diff = DifficultyLevel.MEDIUM
            action_desc = "raising difficulty to medium"
        elif last_diff == DifficultyLevel.MEDIUM:
            recommended_diff = DifficultyLevel.HARD
            action_desc = "raising difficulty to hard"
        else:
            recommended_diff = DifficultyLevel.HARD
            action_desc = "maintaining maximum difficulty (hard)"
    else:
        # Declining or flat: step down if last two scores were both below 40% (28 points)
        two_below_40 = (
            len(last_scores) >= 2
            and last_scores[-1] < threshold_40_pct
            and last_scores[-2] < threshold_40_pct
        )

        if two_below_40 and last_diff == DifficultyLevel.HARD:
            recommended_diff = DifficultyLevel.MEDIUM
            action_desc = "stepping down difficulty to medium"
        elif two_below_40 and last_diff == DifficultyLevel.MEDIUM:
            recommended_diff = DifficultyLevel.EASY
            action_desc = "stepping down difficulty to easy"
        else:
            recommended_diff = last_diff
            action_desc = f"keeping difficulty at {last_diff.value}"

    # 6. Build the plain-language explanation referencing real numbers
    cat_name = (
        weakest_cat.value
        if hasattr(weakest_cat, "value")
        else str(weakest_cat)
    )
    scores_str = ", ".join(str(s) for s in last_scores)
    reason = (
        f"Weakest area: {cat_name} (avg {weakest_avg} vs {other_avg} elsewhere). "
        f"Last {len(last_scores)} scores: {scores_str} ({trend}) — {action_desc}."
    )

    # 7. Look up matching Scenario id in database
    scenario = (
        db.query(Scenario)
        .filter(
            Scenario.category == weakest_cat,
            Scenario.difficulty == recommended_diff,
        )
        .first()
    )

    if not scenario:
        # Fallback to any scenario in this category
        scenario = (
            db.query(Scenario)
            .filter(Scenario.category == weakest_cat)
            .first()
        )

    return {
        "scenario_id": scenario.id if scenario else None,
        "category": cat_name,
        "difficulty": (
            recommended_diff.value
            if hasattr(recommended_diff, "value")
            else str(recommended_diff)
        ),
        "reason": reason,
    }
