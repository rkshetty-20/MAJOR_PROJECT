import argparse
import csv
import json
import os
import random
import sys
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Tuple

import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

# Ensure backend directory is in path for imports
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from ml.features import (
    FEATURE_NAMES,
    RANDOM_FOREST_BASELINE,
    build_classifier,
    describe_classifier,
    extract_features,
    vectorize,
)
from ml import registry
from ml.registry import SYNTHETIC_LIMITATION, TRAINING_SEED


def generate_synthetic_dataset(
    num_normal: int = 250,
    num_scan: int = 250,
    random_seed: int = TRAINING_SEED,
) -> Tuple[List[List[float]], List[int]]:
    """
    Generates synthetic labeled windows for port_scan training.
    Produces at least 200 samples per class:
      - Normal traffic (label 0): 1-4 distinct destination ports, modest event rates,
        typical services (HTTP, HTTPS, DNS, SSH), normal severities.
      - Port scan traffic (label 1): 15-80 distinct destination ports in tight time windows
        (1-8 seconds), high event rates, primarily TCP SYN/probe signatures.
    """
    random.seed(random_seed)
    np.random.seed(random_seed)

    X_vectors: List[List[float]] = []
    y_labels: List[int] = []

    base_time = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Generate Normal Traffic Samples (Label 0)
    common_ports = [80, 443, 53, 22, 3306, 8080, 21, 25]
    protocols = ["TCP", "UDP"]

    for i in range(num_normal):
        src_ip = f"192.168.1.{random.randint(50, 199)}"
        dest_ip = f"10.0.0.{random.randint(1, 10)}"

        # Low number of distinct ports (1 to 4)
        num_ports = random.randint(1, 4)
        sample_ports = random.sample(common_ports, min(num_ports, len(common_ports)))
        num_events = random.randint(3, 25)

        # Spread over 15 to 90 seconds
        duration = random.uniform(15.0, 90.0)

        events: List[Dict] = []
        for j in range(num_events):
            t_offset = random.uniform(0.0, duration)
            event = {
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "dest_port": random.choice(sample_ports),
                "protocol": random.choice(protocols),
                "severity": random.choice([3, 4]),  # Low severity / informational
                "timestamp": base_time + timedelta(seconds=t_offset),
            }
            events.append(event)

        feature_dict = extract_features(events)
        X_vectors.append(vectorize(feature_dict, "port_scan"))
        y_labels.append(0)

    # 2. Generate Port Scan Traffic Samples (Label 1)
    for i in range(num_scan):
        src_ip = f"10.10.14.{random.randint(10, 99)}"
        target_ip = "192.168.56.20"

        # High number of distinct ports (16 to 90)
        num_ports = random.randint(16, 90)
        ports = random.sample(range(1, 1024), num_ports)
        num_events = len(ports)

        # Compressed in a tight window of 1.0 to 9.0 seconds
        duration = random.uniform(1.0, 9.0)

        events: List[Dict] = []
        for j, port in enumerate(ports):
            t_offset = (j / max(num_events, 1)) * duration
            event = {
                "src_ip": src_ip,
                "dest_ip": target_ip,
                "dest_port": port,
                "protocol": "TCP",
                "severity": random.choice([1, 2]),  # Alert severity
                "timestamp": base_time + timedelta(seconds=t_offset),
            }
            events.append(event)

        feature_dict = extract_features(events)
        X_vectors.append(vectorize(feature_dict, "port_scan"))
        y_labels.append(1)

    return X_vectors, y_labels


def load_dataset_from_csv(csv_path: str) -> Tuple[List[List[float]], List[int]]:
    """
    Loads raw Suricata events from CSV, groups by (session_id/window_id, src_ip),
    applies extract_features, and returns feature vectors and labels.
    """
    if not os.path.isfile(csv_path):
        raise FileNotFoundError(f"CSV file not found at: {csv_path}")

    grouped_events: Dict[str, List[Dict]] = {}
    grouped_labels: Dict[str, int] = {}

    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            group_key = row.get("session_id") or row.get("window_id") or row.get("src_ip", "default")
            src_ip = row.get("src_ip", "0.0.0.0")
            full_key = f"{group_key}::{src_ip}"

            if full_key not in grouped_events:
                grouped_events[full_key] = []
                grouped_labels[full_key] = int(row.get("label", 0))

            grouped_events[full_key].append({
                "src_ip": src_ip,
                "dest_ip": row.get("dest_ip", "0.0.0.0"),
                "dest_port": int(row["dest_port"]) if row.get("dest_port") else None,
                "protocol": row.get("protocol") or row.get("proto", "TCP"),
                "severity": int(row.get("severity", 3)),
                "timestamp": row.get("timestamp"),
            })

    X_vectors: List[List[float]] = []
    y_labels: List[int] = []

    for key, events in grouped_events.items():
        feat_dict = extract_features(events)
        X_vectors.append(vectorize(feat_dict, "port_scan"))
        y_labels.append(grouped_labels[key])

    return X_vectors, y_labels


def train_model(csv_path: str = None) -> None:
    """Trains the Random Forest classifier, evaluates on test split, and saves artifact."""
    print("=" * 70)
    print("AOD-IPS Machine Learning: Port Scan Random Forest Training")
    print("=" * 70)

    # 1. Load Data
    if csv_path and os.path.isfile(csv_path):
        data_source = f"Real CSV File ({csv_path})"
        X, y = load_dataset_from_csv(csv_path)
    else:
        data_source = "In-Code Synthetic Generator (250 normal + 250 port-scan)"
        X, y = generate_synthetic_dataset(num_normal=250, num_scan=250, random_seed=42)

    X_array = np.array(X)
    y_array = np.array(y)

    total_samples = len(y_array)
    normal_count = int(np.sum(y_array == 0))
    scan_count = int(np.sum(y_array == 1))

    print(f"Data Source:           {data_source}")
    print(f"Total Window Samples:  {total_samples} (Normal: {normal_count}, Port-Scan: {scan_count})")
    print(f"Feature Dimension:     {len(FEATURE_NAMES)} {FEATURE_NAMES}")
    print("-" * 70)

    # 2. Train / Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X_array,
        y_array,
        test_size=0.25,
        random_state=42,
        stratify=y_array,
    )
    print(f"Training Set Size:     {len(y_train)} samples")
    print(f"Test Set Size:         {len(y_test)} samples (held-out)")
    print("-" * 70)

    # 3. Model Training - the paper's reported baseline configuration, taken from
    #    one declared source so the trainer and the service cannot drift.
    clf = build_classifier()
    clf.fit(X_train, y_train)
    print(f"Model Config:          {describe_classifier(clf)}")

    # 4. Evaluation on Held-Out Test Set
    y_pred = clf.predict(X_test)

    print("\n--- TEST SET CLASSIFICATION REPORT (scikit-learn real output) ---")
    report_str = classification_report(
        y_test,
        y_pred,
        target_names=["Normal (0)", "Port Scan (1)"],
        digits=4,
    )
    print(report_str)

    report_dict = classification_report(
        y_test,
        y_pred,
        target_names=["Normal (0)", "Port Scan (1)"],
        output_dict=True,
    )

    print("--- CONFUSION MATRIX ---")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    print(f"  [True Normal: {cm[0][0]}, False Port Scan: {cm[0][1]}]")
    print(f"  [False Normal: {cm[1][0]}, True Port Scan: {cm[1][1]}]")
    print("-" * 70)

    # 5. Feature Importances
    print("--- FEATURE IMPORTANCES ---")
    for name, imp in zip(FEATURE_NAMES, clf.feature_importances_):
        print(f"  {name:25s}: {imp:.4f}")
    print("-" * 70)

    # 6. Save Model Artifact + mandatory provenance sidecar
    models_dir = os.path.join(CURRENT_DIR, "models")
    os.makedirs(models_dir, exist_ok=True)
    model_path = os.path.join(models_dir, "port_scan_rf.joblib")

    # 7. Evaluation metrics payload (computed from the real sklearn output above)
    weighted_avg = report_dict.get("weighted avg", {})
    source_label = "real" if (csv_path and os.path.isfile(csv_path)) else "synthetic"

    metrics_payload = {
        "accuracy": round(float(report_dict.get("accuracy", 0.0)), 4),
        "precision": round(float(weighted_avg.get("precision", 0.0)), 4),
        "recall": round(float(weighted_avg.get("recall", 0.0)), 4),
        "f1": round(float(weighted_avg.get("f1-score", 0.0)), 4),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "data_source": source_label,
        "n_samples": int(total_samples),
        "n_train": int(len(y_train)),
        "n_test": int(len(y_test)),
    }

    X_digest_source = json.dumps({"X": X, "y": y}, sort_keys=True)
    import hashlib
    data_version = "sha256:" + hashlib.sha256(X_digest_source.encode("utf-8")).hexdigest()[:16]

    metadata = registry.save_model(
        clf, model_path,
        task_name="port_scan",
        training_data_digest=data_version,
        config=describe_classifier(clf),
        evaluation=metrics_payload,
        seed=RANDOM_FOREST_BASELINE["random_state"],
        random_seed=random_seed_for_report(),
        samples={"total": int(total_samples), "train": int(len(y_train)), "test": int(len(y_test))},
        limitations=SYNTHETIC_LIMITATION,
    )
    metadata["model_version"] = "base_model"
    metadata["training_data_source"] = data_source
    metadata["classes"] = [int(c) for c in list(getattr(clf, "classes_", []))]
    registry.write_metadata(model_path, metadata)

    print(f"\n[SUCCESS] Model successfully saved to:\n  {model_path}")
    print(f"[SUCCESS] Provenance sidecar saved to:\n  {registry.metadata_path(model_path)}")

    metrics_path = os.path.join(models_dir, "port_scan_rf_metrics.json")
    with open(metrics_path, mode="w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2)

    print(f"[SUCCESS] Metrics successfully saved to:\n  {metrics_path}")
    print("-" * 70)
    print("LIMITATION (preserved from the research paper):")
    print(f"  {SYNTHETIC_LIMITATION}")
    print("=" * 70)


def random_seed_for_report() -> int:
    """Seed used by the dataset generator, reported for reproducibility."""
    return TRAINING_SEED


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train Random Forest Port Scan Detector")
    parser.add_argument("--csv", type=str, default=None, help="Optional path to labeled CSV dataset")
    args = parser.parse_args()

    csv_arg = args.csv if args.csv else (sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else None)
    train_model(csv_arg)
