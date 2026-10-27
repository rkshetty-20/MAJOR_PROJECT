"""Machine learning package for AOD-IPS.

Public surface of the paper's ML contribution:

* :mod:`ml.features`  - the declared five-feature contract, its units/ranges, the
  Random Forest baseline configuration and the schema validators.
* :mod:`ml.registry`  - artifact storage, provenance sidecars and verified loading.
* :mod:`ml.train_port_scan_model` - deterministic offline trainer for the bundled
  baseline artifact.
* :mod:`ml.attest_base_models` - retro-attests an existing artifact with provenance.
"""

from ml.features import (
    AUTH_FEATURE_NAMES,
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    RANDOM_FOREST_BASELINE,
    FeatureSchemaError,
    build_classifier,
    extract_auth_features,
    extract_features,
    feature_names_for,
    validate_features,
    vectorize,
)

__all__ = [
    "AUTH_FEATURE_NAMES",
    "FEATURE_NAMES",
    "FEATURE_SCHEMA_VERSION",
    "RANDOM_FOREST_BASELINE",
    "FeatureSchemaError",
    "build_classifier",
    "extract_auth_features",
    "extract_features",
    "feature_names_for",
    "validate_features",
    "vectorize",
]
