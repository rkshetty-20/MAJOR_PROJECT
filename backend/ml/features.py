from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

# ---------------------------------------------------------------------------
# Feature contract (paper section on the ML port-scan detector).
#
# ``FEATURE_NAMES`` is the authoritative ordered schema of the five behavioural
# features reported in the paper. Everything that trains, stores or serves a
# model must go through the validators below so a renamed, reordered, wrongly
# typed or unit-shifted feature can never silently enter the estimator.
# ---------------------------------------------------------------------------
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

# Bumped whenever the ordered feature list or any unit below changes. Stored
# with every learning example, model artifact and metric report so a model is
# never served features it was not trained on.
FEATURE_SCHEMA_VERSION = "1.0"
AUTH_FEATURE_SCHEMA_VERSION = "1.0_auth"

# Per-feature unit, admissible range and the telemetry field it is derived from.
FEATURE_SPECS: Dict[str, Dict[str, Any]] = {
    "distinct_dest_ports": {
        "unit": "count", "minimum": 0.0, "maximum": 65535.0, "integer": True,
        "derived_from": "SuricataEvent.dest_port",
    },
    "events_per_second": {
        "unit": "events/second", "minimum": 0.0, "maximum": 100000.0, "integer": False,
        "derived_from": "count(SuricataEvent) / max(observed window seconds, 1)",
    },
    "distinct_dest_ips": {
        "unit": "count", "minimum": 0.0, "maximum": 100000.0, "integer": True,
        "derived_from": "SuricataEvent.dest_ip",
    },
    "avg_severity": {
        "unit": "suricata severity (1=high .. 4=informational)",
        "minimum": 0.0, "maximum": 4.0, "integer": False,
        "derived_from": "mean(SuricataEvent.severity)",
    },
    "protocol_diversity": {
        "unit": "count", "minimum": 0.0, "maximum": 256.0, "integer": True,
        "derived_from": "distinct upper(SuricataEvent.protocol)",
    },
}

AUTH_FEATURE_SPECS: Dict[str, Dict[str, Any]] = {
    "failed_attempts": {
        "unit": "count", "minimum": 0.0, "maximum": 1000000.0, "integer": True,
        "derived_from": "count(SecurityEvent.event_type ~= 'failed')",
    },
    "successful_attempts": {
        "unit": "count", "minimum": 0.0, "maximum": 1000000.0, "integer": True,
        "derived_from": "count(SecurityEvent.event_type ~= 'success|baseline|known_device_login')",
    },
    "distinct_targets": {
        "unit": "count", "minimum": 0.0, "maximum": 1000000.0, "integer": True,
        "derived_from": "distinct SecurityEvent.target",
    },
    "distinct_devices": {
        "unit": "count", "minimum": 0.0, "maximum": 1000000.0, "integer": True,
        "derived_from": "distinct SecurityEvent.device",
    },
    "events_per_minute": {
        "unit": "events/minute", "minimum": 0.0, "maximum": 1000000.0, "integer": False,
        "derived_from": "count(SecurityEvent) / max(observed window minutes, 0.016)",
    },
    "login_success_after_failure": {
        "unit": "boolean flag", "minimum": 0.0, "maximum": 1.0, "integer": False,
        "derived_from": "any success observed after a failure",
    },
}

# The Random Forest baseline reported in the research paper. Declared once and
# reused by the offline trainer, the adaptive candidate trainer and every
# metadata record, so "100 trees / depth 6" cannot drift between code paths.
RANDOM_FOREST_BASELINE: Dict[str, Any] = {
    "class_name": "RandomForestClassifier",
    "n_estimators": 100,
    "max_depth": 6,
    "min_samples_split": 2,
    "random_state": 42,
}


class FeatureSchemaError(ValueError):
    """Raised when features violate the declared names/order/types/units/ranges."""


def feature_names_for(task_name: str) -> List[str]:
    """Ordered feature names for a detection task."""
    if task_name in ("brute_force", "credential_stuffing"):
        return list(AUTH_FEATURE_NAMES)
    if task_name == "port_scan":
        return list(FEATURE_NAMES)
    raise FeatureSchemaError(f"No declared feature schema for task {task_name!r}.")


def feature_specs_for(task_name: str) -> Dict[str, Dict[str, Any]]:
    if task_name in ("brute_force", "credential_stuffing"):
        return dict(AUTH_FEATURE_SPECS)
    if task_name == "port_scan":
        return dict(FEATURE_SPECS)
    raise FeatureSchemaError(f"No declared feature schema for task {task_name!r}.")


def feature_schema_version_for(task_name: str) -> str:
    if task_name in ("brute_force", "credential_stuffing"):
        return AUTH_FEATURE_SCHEMA_VERSION
    return FEATURE_SCHEMA_VERSION


def validate_features(features: Dict[str, Any], task_name: str) -> None:
    """Validate names, completeness, type and unit range of a feature mapping.

    Raises :class:`FeatureSchemaError` naming every offending feature so a
    training or inference run fails loudly instead of scoring garbage.
    """
    if not isinstance(features, dict):
        raise FeatureSchemaError(
            f"{task_name}: expected a feature mapping, got {type(features).__name__}."
        )

    expected = feature_names_for(task_name)
    specs = feature_specs_for(task_name)
    problems: List[str] = []

    missing = [name for name in expected if name not in features]
    extra = sorted(str(key) for key in features if key not in expected)
    if missing:
        problems.append(f"missing feature(s): {missing}")
    if extra:
        problems.append(f"undeclared feature(s): {extra}")

    for name in expected:
        if name not in features:
            continue
        value = features[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            problems.append(f"{name} must be numeric, got {type(value).__name__}")
            continue
        number = float(value)
        if number != number:  # NaN is not an admissible telemetry value.
            problems.append(f"{name} is NaN")
            continue
        spec = specs[name]
        if spec["integer"] and number != int(number):
            problems.append(f"{name} must be an integer count, got {number}")
        if number < spec["minimum"] or number > spec["maximum"]:
            problems.append(
                f"{name}={number} outside admissible range "
                f"[{spec['minimum']}, {spec['maximum']}] {spec['unit']}"
            )

    if problems:
        raise FeatureSchemaError(f"{task_name}: " + "; ".join(problems))


def vectorize(features: Dict[str, Any], task_name: str) -> List[float]:
    """Strict, order-checked conversion of a feature mapping to a model vector."""
    validate_features(features, task_name)
    return [float(features[name]) for name in feature_names_for(task_name)]


def build_classifier(overrides: Optional[Dict[str, Any]] = None):
    """Instantiate the paper's Random Forest baseline deterministically."""
    from sklearn.ensemble import RandomForestClassifier

    params = dict(RANDOM_FOREST_BASELINE)
    params.pop("class_name", None)
    params.update(overrides or {})
    return RandomForestClassifier(**params)


def describe_classifier(clf: Any) -> Dict[str, Any]:
    """Extract the persisted configuration of a trained estimator."""
    return {
        "class_name": type(clf).__name__,
        "n_estimators": getattr(clf, "n_estimators", None),
        "max_depth": getattr(clf, "max_depth", None),
        "min_samples_split": getattr(clf, "min_samples_split", None),
        "random_state": getattr(clf, "random_state", None),
    }


def feature_importances(clf: Any, task_name: str) -> Dict[str, float]:
    """Per-feature importances keyed by declared name (None-safe)."""
    importances = getattr(clf, "feature_importances_", None)
    if importances is None:
        return {}
    names = feature_names_for(task_name)
    if len(list(importances)) != len(names):
        raise FeatureSchemaError(
            f"{task_name}: model exposes {len(list(importances))} importances for a "
            f"{len(names)}-feature schema; artifact does not match the declared features."
        )
    return {name: round(float(value), 6) for name, value in zip(names, importances)}


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
    """Legacy alias of :func:`vectorize` for the port-scan schema.

    Kept so existing imports keep working, but it now validates through the same
    single code path as everything else: there is deliberately no unvalidated
    way to build a model input vector.
    """
    return vectorize(features, "port_scan")


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
    """Legacy alias of :func:`vectorize` for the authentication schema."""
    return vectorize(features, "brute_force")
