import json
import logging
import os
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import SuricataEvent

logger = logging.getLogger(__name__)


def _parse_timestamp(ts_val: str | datetime) -> datetime:
    """Safely parse ISO timestamp into timezone-aware datetime."""
    if isinstance(ts_val, datetime):
        dt = ts_val
    else:
        clean_str = ts_val.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_str)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def ingest_new_events(
    session_id: int,
    eve_json_path: str,
    since_timestamp: datetime,
    db: Optional[Session] = None,
) -> List[SuricataEvent]:
    """
    Reads Suricata eve.json line-by-line, filters for 'alert' events occurring after
    since_timestamp, and inserts them as SuricataEvent rows scoped to session_id.
    Captures dest_port alongside network metadata for behavioral detection rules.

    Args:
        session_id: The ID of the active learning session.
        eve_json_path: Path to Suricata's eve.json log file.
        since_timestamp: Only events after this timestamp are ingested.
        db: Optional SQLAlchemy Session. If not provided, a local session is managed.

    Returns:
        A list of newly created SuricataEvent instances.
    """
    if not os.path.exists(eve_json_path) or not os.path.isfile(eve_json_path):
        logger.warning("Suricata eve.json not found at %s", eve_json_path)
        return []

    since_dt = _parse_timestamp(since_timestamp)
    created_events: List[SuricataEvent] = []

    manage_session = db is None
    session = SessionLocal() if manage_session else db

    try:
        with open(eve_json_path, mode="r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue

                try:
                    event = json.loads(line_str)
                except json.JSONDecodeError:
                    continue

                # Filter strictly for alert events
                if event.get("event_type") != "alert":
                    continue

                raw_ts = event.get("timestamp")
                if not raw_ts:
                    continue

                try:
                    event_dt = _parse_timestamp(raw_ts)
                except (ValueError, TypeError):
                    continue

                # Ingest only events occurring after since_timestamp
                if event_dt <= since_dt:
                    continue

                alert_info = event.get("alert", {})
                raw_signature = alert_info.get("signature", "Unknown Signature")
                severity_val = alert_info.get("severity", 3)
                try:
                    severity = int(severity_val)
                except (ValueError, TypeError):
                    severity = 3

                # Extract dest_port
                raw_dest_port = event.get("dest_port")
                dest_port: Optional[int] = None
                if raw_dest_port is not None:
                    try:
                        dest_port = int(raw_dest_port)
                    except (ValueError, TypeError):
                        dest_port = None

                suricata_event = SuricataEvent(
                    session_id=session_id,
                    raw_signature=str(raw_signature),
                    src_ip=str(event.get("src_ip", "0.0.0.0")),
                    dest_ip=str(event.get("dest_ip", "0.0.0.0")),
                    dest_port=dest_port,
                    protocol=str(event.get("proto", "TCP")),
                    severity=severity,
                    timestamp=event_dt,
                )
                session.add(suricata_event)
                created_events.append(suricata_event)

        if created_events:
            session.commit()
            for ev in created_events:
                session.refresh(ev)

        return created_events

    except Exception as exc:
        session.rollback()
        logger.error("Failed during Suricata event ingestion: %s", exc)
        raise
    finally:
        if manage_session:
            session.close()
