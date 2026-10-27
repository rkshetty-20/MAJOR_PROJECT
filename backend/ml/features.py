from datetime import datetime, timezone
from typing import Any, Dict, List, Union

FEATURE_NAMES: List[str] = [
    "distinct_dest_ports",
    "events_per_second",
    "distinct_dest_ips",
    "avg_severity",
    "protocol_diversity",
]

AUTH_FEATURE_NAMES: List[str] = [
    "failed_attempts",
    "successful_attempts",
    "distinct_targets",
    "distinct_devices",
    "events_per_minute",
    "login_success_after_failure",
]

def _to_epoch_seconds(ts_val: Union[datetime, str, int, float, None]) -> float:
    """Safely converts an ISO timestamp string, datetime, or number to epoch seconds."""
    if ts_val is None:
        return 0.0

    if isinstance(ts_val, (int, float)):
        return float(ts_val)

    if isinstance(ts_val, datetime):
        dt = ts_val
    else:
        # String ISO 8601 parsing
        clean_str = str(ts_val).replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(clean_str)
        except Exception:
            return 0.0

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.timestamp()


def extract_features(events: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Extracts behavioral ML feature metrics from a list of SuricataEvent-shaped dicts
    for a single source IP within a session.

    Expected event dict keys:
        src_ip, dest_ip, dest_port, protocol, severity, timestamp

    Returns:
        dict:
            - distinct_dest_ports: count of unique dest_port values
            - events_per_second: count of events / (max_timestamp - min_timestamp in seconds, min 1)
            - distinct_dest_ips: count of unique dest_ip values
            - avg_severity: mean of severity values
            - protocol_diversity: count of unique protocol values
    """
    if not events:
        return {
            "distinct_dest_ports": 0.0,
            "events_per_second": 0.0,
            "distinct_dest_ips": 0.0,
            "avg_severity": 0.0,
            "protocol_diversity": 0.0,
        }

    # 1. Unique destination ports
    dest_ports = {
        int(e["dest_port"])
        for e in events
        if e.get("dest_port") is not None
    }
    distinct_dest_ports = float(len(dest_ports))

    # 2. Unique destination IPs
    dest_ips = {
        str(e["dest_ip"]).strip()
        for e in events
        if e.get("dest_ip") is not None and str(e["dest_ip"]).strip()
    }
    distinct_dest_ips = float(len(dest_ips))

    # 3. Average severity
    severities = [
        float(e["severity"])
        for e in events
        if e.get("severity") is not None
    ]
    avg_severity = (sum(severities) / len(severities)) if severities else 0.0

    # 4. Protocol diversity
    protocols = {
        str(e["protocol"]).strip().upper()
        for e in events
        if e.get("protocol") is not None and str(e["protocol"]).strip()
    }
    protocol_diversity = float(len(protocols))

    # 5. Events per second
    timestamps = [
        _to_epoch_seconds(e.get("timestamp"))
        for e in events
        if e.get("timestamp") is not None
    ]

    if len(timestamps) >= 2:
        duration_seconds = max(max(timestamps) - min(timestamps), 1.0)
    else:
        duration_seconds = 1.0

    events_per_second = float(len(events)) / duration_seconds

    return {
        "distinct_dest_ports": distinct_dest_ports,
        "events_per_second": events_per_second,
        "distinct_dest_ips": distinct_dest_ips,
        "avg_severity": avg_severity,
        "protocol_diversity": protocol_diversity,
    }


def features_to_vector(features: Dict[str, float]) -> List[float]:
    """
    Ensures deterministic ordering of features for Scikit-Learn model input.
    """
    return [float(features.get(col, 0.0)) for col in FEATURE_NAMES]


def extract_auth_features(events: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Extracts behavioral ML feature metrics from a list of SecurityEvent-shaped dicts
    for a single source IP within a session (authentication attacks).

    Expected event dict keys:
        event_type, target, device, timestamp, payload_json
    """
    if not events:
        return {k: 0.0 for k in AUTH_FEATURE_NAMES}

    failed_attempts = 0.0
    successful_attempts = 0.0
    targets = set()
    devices = set()
    login_success_after_failure = 0.0

    for e in events:
        evt = str(e.get("event_type", "")).lower()
        if "failed" in evt:
            failed_attempts += 1.0
        elif "success" in evt or "baseline" in evt or evt == "known_device_login":
            successful_attempts += 1.0
            if failed_attempts > 0:
                login_success_after_failure = 1.0
        
        target = e.get("target")
        if target:
            targets.add(str(target).strip())
            
        device = e.get("device")
        if device:
            devices.add(str(device).strip())

    distinct_targets = float(len(targets))
    distinct_devices = float(len(devices))

    timestamps = [
        _to_epoch_seconds(e.get("timestamp"))
        for e in events
        if e.get("timestamp") is not None
    ]

    if len(timestamps) >= 2:
        duration_minutes = max(max(timestamps) - min(timestamps), 1.0) / 60.0
    else:
        duration_minutes = 1.0 / 60.0

    events_per_minute = float(len(events)) / max(duration_minutes, 0.016)

    return {
        "failed_attempts": failed_attempts,
        "successful_attempts": successful_attempts,
        "distinct_targets": distinct_targets,
        "distinct_devices": distinct_devices,
        "events_per_minute": events_per_minute,
        "login_success_after_failure": login_success_after_failure,
    }


def auth_features_to_vector(features: Dict[str, float]) -> List[float]:
    """
    Ensures deterministic ordering of features for Scikit-Learn model input (auth).
    """
    return [float(features.get(col, 0.0)) for col in AUTH_FEATURE_NAMES]
