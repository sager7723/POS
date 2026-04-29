from __future__ import annotations

import os
from dataclasses import MISSING, fields, is_dataclass
from typing import Any, Dict, Sequence

from .api import FHEThresholdFacade, GeneratedThresholdKeyMaterial
from .kms_fhe_backend import KmsThresholdFHEBackend
from .native_tfhe import NativeThfheBackend
from .openfhe_replacement import OpenFHEReplacementBackend

_ALLOWED_BACKENDS = {"thfhe", "openfhe_replacement", "kms-threshold"}
_BACKEND_SINGLETONS: Dict[str, FHEThresholdFacade] = {}


def _normalize_backend_name(backend_name: str) -> str:
    name = backend_name.strip().lower()
    if name == "kms_threshold":
        return "kms-threshold"
    if name == "openfhe-replacement":
        return "openfhe_replacement"
    return name


def _selected_backend_name() -> str:
    backend_name = _normalize_backend_name(os.getenv("POS_FHE_BACKEND", "thfhe"))
    if backend_name not in _ALLOWED_BACKENDS:
        raise ValueError(
            f"Unsupported POS_FHE_BACKEND='{backend_name}'. "
            f"Allowed backends are: {sorted(_ALLOWED_BACKENDS)}"
        )
    return backend_name


def _construct_backend(backend_name: str):
    backend_name = _normalize_backend_name(backend_name)

    if backend_name == "thfhe":
        return NativeThfheBackend()
    if backend_name == "openfhe_replacement":
        return OpenFHEReplacementBackend()
    if backend_name == "kms-threshold":
        return KmsThresholdFHEBackend.from_env()

    raise ValueError(f"unsupported backend: {backend_name}")


def _construct_generated_key_material(data: dict[str, Any]) -> GeneratedThresholdKeyMaterial:
    """
    Build GeneratedThresholdKeyMaterial while tolerating small constructor
    differences across the project history.
    """
    if is_dataclass(GeneratedThresholdKeyMaterial):
        kwargs: dict[str, Any] = {}
        for field in fields(GeneratedThresholdKeyMaterial):
            if field.name in data:
                kwargs[field.name] = data[field.name]
            elif field.default is not MISSING:
                kwargs[field.name] = field.default
            elif field.default_factory is not MISSING:  # type: ignore[attr-defined]
                kwargs[field.name] = field.default_factory()  # type: ignore[misc]
            else:
                kwargs[field.name] = None
        return GeneratedThresholdKeyMaterial(**kwargs)

    return GeneratedThresholdKeyMaterial(**data)


def _build_kms_threshold_key_material(
    participant_ids: Sequence[str],
    threshold: int,
) -> GeneratedThresholdKeyMaterial:
    backend = KmsThresholdFHEBackend.from_env(
        participant_ids=participant_ids,
        threshold=threshold,
    )
    binding = backend.distributed_keygen()

    key_id = str(binding["key_id"])
    keyset_reference = f"kms-threshold-keyset://{key_id}"
    public_key_reference = str(binding["public_key_reference"])
    server_key_reference = str(binding["server_key_reference"])

    participant_private_share_handles = {
        participant_id: f"kms-threshold-private-share://{key_id}/{participant_id}"
        for participant_id in participant_ids
    }

    data = {
        "backend_name": "kms-threshold",
        "public_key": public_key_reference,
        "server_key": server_key_reference,
        "server_key_reference": server_key_reference,
        "keyset_reference": keyset_reference,
        "participant_ids": list(participant_ids),
        "threshold": threshold,
        "participant_private_share_handles": participant_private_share_handles,
        "private_share_handles": participant_private_share_handles,
        "metadata": {
            "key_id": key_id,
            "public_key_reference": public_key_reference,
            "server_key_reference": server_key_reference,
            "keyset_reference": keyset_reference,
        },
    }

    return _construct_generated_key_material(data)


def build_threshold_key_material(
    participant_ids: Sequence[str],
    threshold: int,
    backend_name: str | None = None,
) -> GeneratedThresholdKeyMaterial:
    selected_backend = _normalize_backend_name(backend_name or _selected_backend_name())

    if selected_backend == "kms-threshold":
        return _build_kms_threshold_key_material(participant_ids, threshold)

    if selected_backend == "thfhe":
        return NativeThfheBackend.build_threshold_key_material(participant_ids, threshold)

    if selected_backend == "openfhe_replacement":
        return OpenFHEReplacementBackend.build_threshold_key_material(participant_ids, threshold)

    raise ValueError(f"unsupported backend: {selected_backend}")


def reset_fhe_backend_cache() -> None:
    _BACKEND_SINGLETONS.clear()


def initialize_fhe_backend(
    candidate_messages: dict[str, object] | None = None,
    participant_ids: Sequence[str] | None = None,
    distributed_key_result=None,
) -> FHEThresholdFacade:
    backend_name = _selected_backend_name()

    if distributed_key_result is not None:
        backend_name = _normalize_backend_name(distributed_key_result.fhe_backend_name)
        if backend_name not in _ALLOWED_BACKENDS:
            raise ValueError(
                f"distributed_key_result backend '{backend_name}' is not allowed in the final build"
            )

    if backend_name not in _BACKEND_SINGLETONS:
        _BACKEND_SINGLETONS[backend_name] = FHEThresholdFacade(_construct_backend(backend_name))

    facade = _BACKEND_SINGLETONS[backend_name]

    if distributed_key_result is not None:
        facade.load_distributed_key_result(distributed_key_result)
        return facade

    inferred_ids: list[str] = []
    if participant_ids is not None:
        inferred_ids = list(participant_ids)
    elif candidate_messages is not None:
        inferred_ids = list(candidate_messages.keys())

    if inferred_ids:
        facade.configure_participants(inferred_ids)

    return facade


def prepare_fhe_backend_for_participants(participant_ids: Sequence[str]) -> FHEThresholdFacade:
    return initialize_fhe_backend(participant_ids=participant_ids)
