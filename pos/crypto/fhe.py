from __future__ import annotations

from pos.crypto.thfhe_backend import (
    OPENFHE_AVAILABLE,
    Ciphertext,
    CiphertextVector,
    FHEThresholdFacade,
    GeneratedThresholdKeyMaterial,
    ThresholdFHEBackendProtocol,
    ThresholdFHEContext,
    build_threshold_key_material,
    initialize_fhe_backend,
    prepare_fhe_backend_for_participants,
    reset_fhe_backend_cache,
)

__all__ = [
    "OPENFHE_AVAILABLE",
    "Ciphertext",
    "CiphertextVector",
    "FHEThresholdFacade",
    "GeneratedThresholdKeyMaterial",
    "ThresholdFHEBackendProtocol",
    "ThresholdFHEContext",
    "build_threshold_key_material",
    "initialize_fhe_backend",
    "prepare_fhe_backend_for_participants",
    "reset_fhe_backend_cache",
]

# ---------------------------------------------------------------------------
# Strict KMS threshold backend entrypoint override
# ---------------------------------------------------------------------------
#
# This block intentionally keeps the existing FHE backends untouched and only
# intercepts POS_FHE_BACKEND=kms-threshold. It does not emulate plaintext
# operations and does not enable encoded_value fallback.


import os as _kms_threshold_os
from collections.abc import Sequence as _KmsSequence

from pos.crypto.thfhe_backend.kms_fhe_backend import (
    KmsThresholdFHEBackend as _KmsThresholdFHEBackend,
)

_ORIGINAL_INITIALIZE_FHE_BACKEND_BEFORE_KMS_THRESHOLD = initialize_fhe_backend


def initialize_fhe_backend(*args, **kwargs):
    backend_name = (
        _kms_threshold_os.environ.get("POS_FHE_BACKEND", "")
        .strip()
        .lower()
        .replace("_", "-")
    )

    if backend_name in {"kms-threshold", "kmsthreshold"}:
        participant_ids = kwargs.pop("participant_ids", None)
        threshold = kwargs.pop("threshold", None)

        if args:
            if participant_ids is not None:
                raise TypeError(
                    "participant_ids was provided both positionally and by keyword"
                )
            if len(args) > 1:
                raise TypeError(
                    "kms-threshold initialize_fhe_backend accepts at most one "
                    "positional argument: participant_ids"
                )
            participant_ids = args[0]

        if participant_ids is not None and not isinstance(
            participant_ids, _KmsSequence
        ):
            raise TypeError("participant_ids must be a sequence of participant ids")

        if threshold is None:
            threshold = int(_kms_threshold_os.environ.get("POS_KMS_THRESHOLD", "1"))

        return _KmsThresholdFHEBackend.from_env(
            participant_ids=participant_ids,
            threshold=int(threshold),
        )

    return _ORIGINAL_INITIALIZE_FHE_BACKEND_BEFORE_KMS_THRESHOLD(*args, **kwargs)

# ---------------------------------------------------------------------------
# Strict patent-mode backend policy wrapper
# ---------------------------------------------------------------------------
#
# This wrapper prevents accidental fallback to compatibility/mock/plaintext
# FHE backends when POS_STRICT_PATENT_MODE=1.

from pos.crypto.backend_policy import (
    assert_backend_allowed_for_strict_patent_mode as _assert_backend_allowed_for_strict_patent_mode,
)

_INITIALIZE_FHE_BACKEND_BEFORE_STRICT_POLICY = initialize_fhe_backend


def initialize_fhe_backend(*args, **kwargs):
    backend_name = (
        _kms_threshold_os.environ.get("POS_FHE_BACKEND", "")
        .strip()
        .lower()
        .replace("_", "-")
    )

    _assert_backend_allowed_for_strict_patent_mode(backend_name)

    return _INITIALIZE_FHE_BACKEND_BEFORE_STRICT_POLICY(*args, **kwargs)