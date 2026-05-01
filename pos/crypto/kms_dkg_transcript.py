from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class KmsDkgParticipantMaterial:
    participant_id: str
    share_public_key: str
    key_material_reference: str | None
    polynomial_commitment_hash: str | None


@dataclass(frozen=True)
class KmsDkgPublicMaterialDigest:
    public_key_path: str
    server_key_path: str
    public_key_sha256: str
    server_key_sha256: str
    verf_key_hashes: dict[str, str]
    verf_address_hashes: dict[str, str]


@dataclass(frozen=True)
class KmsDkgTranscript:
    key_id: str
    participant_ids: tuple[str, ...]
    threshold: int
    kms_type: str
    num_majority: int | None
    num_reconstruct: int | None
    decryption_mode: str | None
    fhe_params: str | None
    public_material: KmsDkgPublicMaterialDigest
    participant_materials: tuple[KmsDkgParticipantMaterial, ...]
    share_public_keys: dict[str, str]
    polynomial_commitments: dict[str, Any]
    secret_commitment_public_key: str | None
    material_mode: str
    dkg_material_root: str | None
    core_client_config: str | None
    transcript_hash: str

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        data = asdict(self)
        if not include_hash:
            data.pop("transcript_hash", None)
        return data

    def to_json(self) -> str:
        return _canonical_json(self.to_dict(include_hash=True))


def build_kms_dkg_transcript(
    *,
    participants: Sequence[Any] | None = None,
    participant_ids: Sequence[str] | None = None,
    threshold: int | None = None,
    distributed_key_result: Any | None = None,
    pp: Any | None = None,
) -> KmsDkgTranscript:
    """
    Build the POS-side verifiable transcript for patent Step2.

    This does not replace KMS threshold DKG. It records and binds the external
    KMS threshold key material to the POS protocol's participant ids,
    threshold, Feldman/VSS share public keys, polynomial commitments, and KMS
    public/server/verifier material hashes.
    """
    ids = _resolve_participant_ids(
        participants=participants,
        participant_ids=participant_ids,
        distributed_key_result=distributed_key_result,
    )
    resolved_threshold = _resolve_threshold(
        threshold=threshold,
        distributed_key_result=distributed_key_result,
    )

    key_id = _env_required("POS_KMS_KEY_ID")
    material_mode = os.environ.get("POS_KMS_MATERIAL_MODE", "formal_dkg").strip() or "formal_dkg"
    material_root = os.environ.get("POS_KMS_DKG_MATERIAL_ROOT")
    core_client_config = os.environ.get("POS_KMS_CORE_CLIENT_CONFIG")

    config_values = _read_kms_client_config(core_client_config)
    public_key_path = _resolve_public_key_path(key_id=key_id, material_root=material_root)
    server_key_path = _resolve_server_key_path(key_id=key_id, material_root=material_root)

    public_material = KmsDkgPublicMaterialDigest(
        public_key_path=str(public_key_path),
        server_key_path=str(server_key_path),
        public_key_sha256=_sha256_file(public_key_path),
        server_key_sha256=_sha256_file(server_key_path),
        verf_key_hashes=_collect_pub_hashes(material_root, "VerfKey"),
        verf_address_hashes=_collect_pub_hashes(material_root, "VerfAddress"),
    )

    share_public_keys = _extract_share_public_keys(distributed_key_result)
    polynomial_commitments = _extract_polynomial_commitments(distributed_key_result)
    participant_materials = _build_participant_materials(
        participant_ids=ids,
        share_public_keys=share_public_keys,
        polynomial_commitments=polynomial_commitments,
        distributed_key_result=distributed_key_result,
    )

    secret_commitment_public_key = None
    if distributed_key_result is not None:
        secret_commitment_public_key = getattr(
            distributed_key_result,
            "secret_commitment_public_key",
            None,
        )

    draft = KmsDkgTranscript(
        key_id=key_id,
        participant_ids=tuple(ids),
        threshold=resolved_threshold,
        kms_type=str(config_values.get("kms_type") or "threshold"),
        num_majority=_maybe_int(config_values.get("num_majority")),
        num_reconstruct=_maybe_int(config_values.get("num_reconstruct")),
        decryption_mode=_maybe_str(config_values.get("decryption_mode")),
        fhe_params=_maybe_str(config_values.get("fhe_params")),
        public_material=public_material,
        participant_materials=tuple(participant_materials),
        share_public_keys=share_public_keys,
        polynomial_commitments=polynomial_commitments,
        secret_commitment_public_key=secret_commitment_public_key,
        material_mode=material_mode,
        dkg_material_root=str(Path(material_root).expanduser().resolve()) if material_root else None,
        core_client_config=str(Path(core_client_config).expanduser().resolve()) if core_client_config else None,
        transcript_hash="",
    )

    transcript_hash = _sha256_text(_canonical_json(draft.to_dict(include_hash=False)))
    transcript = replace(draft, transcript_hash=transcript_hash)
    validate_kms_dkg_transcript(transcript)
    return transcript


def attach_kms_dkg_transcript_to_result(
    *,
    pp: Any | None,
    participants: Sequence[Any],
    result: Any,
) -> Any:
    transcript = build_kms_dkg_transcript(
        pp=pp,
        participants=participants,
        threshold=getattr(result, "threshold", None),
        distributed_key_result=result,
    )

    if not hasattr(result, "dkg_transcript"):
        raise TypeError(
            "DistributedKeyGenerationResult has no dkg_transcript field. "
            "Patch pos/models/stage2.py before attaching KMS DKG transcript."
        )

    kwargs: dict[str, Any] = {"dkg_transcript": transcript}

    if hasattr(result, "tfhe_trlwe_parameters"):
        params = dict(getattr(result, "tfhe_trlwe_parameters") or {})
        params["dkg_transcript_hash"] = transcript.transcript_hash
        params["dkg_key_id"] = transcript.key_id
        params["dkg_public_key_sha256"] = transcript.public_material.public_key_sha256
        params["dkg_server_key_sha256"] = transcript.public_material.server_key_sha256
        kwargs["tfhe_trlwe_parameters"] = params

    return replace(result, **kwargs)


def validate_kms_dkg_transcript(transcript: KmsDkgTranscript) -> None:
    if not transcript.key_id:
        raise ValueError("KMS DKG transcript key_id is empty")

    if not transcript.participant_ids:
        raise ValueError("KMS DKG transcript participant_ids is empty")

    if transcript.threshold <= 0:
        raise ValueError("KMS DKG transcript threshold must be positive")

    if transcript.threshold > len(transcript.participant_ids):
        raise ValueError(
            "KMS DKG transcript threshold must not exceed POS participant count"
        )

    if not transcript.public_material.public_key_sha256:
        raise ValueError("KMS DKG transcript public_key_sha256 is empty")

    if not transcript.public_material.server_key_sha256:
        raise ValueError("KMS DKG transcript server_key_sha256 is empty")

    recomputed = _sha256_text(_canonical_json(transcript.to_dict(include_hash=False)))
    if recomputed != transcript.transcript_hash:
        raise ValueError(
            "KMS DKG transcript hash mismatch: "
            f"expected {transcript.transcript_hash}, recomputed {recomputed}"
        )

    if transcript.material_mode.startswith("local") and _strict_patent_mode_enabled():
        if not _truthy(os.environ.get("POS_KMS_ALLOW_LOCAL_DKG_MATERIALS")):
            raise ValueError(
                "local KMS DKG material is not allowed in strict patent mode unless "
                "POS_KMS_ALLOW_LOCAL_DKG_MATERIALS=1 is set explicitly"
            )


def assert_ciphertext_bound_to_dkg_transcript(
    ciphertext: Any,
    transcript: KmsDkgTranscript,
) -> None:
    key_id = getattr(ciphertext, "key_id", None)

    if key_id is None and isinstance(ciphertext, Mapping):
        key_id = ciphertext.get("key_id")

    if key_id != transcript.key_id:
        raise ValueError(
            f"ciphertext key_id {key_id!r} is not bound to DKG transcript key_id "
            f"{transcript.key_id!r}"
        )


def _resolve_participant_ids(
    *,
    participants: Sequence[Any] | None,
    participant_ids: Sequence[str] | None,
    distributed_key_result: Any | None,
) -> tuple[str, ...]:
    if participant_ids:
        return tuple(str(x) for x in participant_ids)

    if participants:
        return tuple(str(getattr(p, "participant_id")) for p in participants)

    if distributed_key_result is not None:
        shares = getattr(distributed_key_result, "threshold_fhe_private_key_shares", None)
        if shares:
            return tuple(str(x) for x in shares.keys())

    raise ValueError("cannot resolve participant ids for KMS DKG transcript")


def _resolve_threshold(*, threshold: int | None, distributed_key_result: Any | None) -> int:
    if threshold is not None:
        return int(threshold)

    if distributed_key_result is not None:
        value = getattr(distributed_key_result, "threshold", None)
        if value is not None:
            return int(value)

    raise ValueError("cannot resolve threshold for KMS DKG transcript")


def _resolve_public_key_path(*, key_id: str, material_root: str | None) -> Path:
    explicit = os.environ.get("POS_KMS_PUBLIC_KEY_PATH")
    if explicit:
        return _require_file(Path(explicit).expanduser().resolve(), "POS_KMS_PUBLIC_KEY_PATH")

    if material_root:
        root = Path(material_root).expanduser().resolve()
        for path in sorted(root.glob(f"node*/keys/PUB/PublicKey/{key_id}")):
            return _require_file(path, "KMS public key")

    raise FileNotFoundError(
        "Cannot resolve KMS public key path. Set POS_KMS_PUBLIC_KEY_PATH or "
        "POS_KMS_DKG_MATERIAL_ROOT."
    )


def _resolve_server_key_path(*, key_id: str, material_root: str | None) -> Path:
    explicit = os.environ.get("POS_KMS_SERVER_KEY_PATH")
    if explicit:
        return _require_file(Path(explicit).expanduser().resolve(), "POS_KMS_SERVER_KEY_PATH")

    if material_root:
        root = Path(material_root).expanduser().resolve()
        for path in sorted(root.glob(f"node*/keys/PUB/ServerKey/{key_id}")):
            return _require_file(path, "KMS server key")

    raise FileNotFoundError(
        "Cannot resolve KMS server key path. Set POS_KMS_SERVER_KEY_PATH or "
        "POS_KMS_DKG_MATERIAL_ROOT."
    )


def _collect_pub_hashes(material_root: str | None, pub_kind: str) -> dict[str, str]:
    if not material_root:
        return {}

    root = Path(material_root).expanduser().resolve()
    if not root.is_dir():
        return {}

    results: dict[str, str] = {}
    pattern = f"node*/keys/PUB/{pub_kind}/*"
    for path in sorted(root.glob(pattern)):
        if path.is_file():
            results[str(path.relative_to(root))] = _sha256_file(path)
    return results


def _extract_share_public_keys(distributed_key_result: Any | None) -> dict[str, str]:
    if distributed_key_result is None:
        return {}

    share_public_keys = getattr(distributed_key_result, "share_public_keys", {}) or {}
    results: dict[str, str] = {}

    for participant_id, value in share_public_keys.items():
        if hasattr(value, "share_public_key"):
            results[str(participant_id)] = str(value.share_public_key)
        else:
            results[str(participant_id)] = str(value)

    return results


def _extract_polynomial_commitments(distributed_key_result: Any | None) -> dict[str, Any]:
    if distributed_key_result is None:
        return {}

    commitments = getattr(distributed_key_result, "polynomial_commitments", {}) or {}
    results: dict[str, Any] = {}

    for participant_id, value in commitments.items():
        results[str(participant_id)] = _jsonable(value)

    return results


def _build_participant_materials(
    *,
    participant_ids: Sequence[str],
    share_public_keys: Mapping[str, str],
    polynomial_commitments: Mapping[str, Any],
    distributed_key_result: Any | None,
) -> list[KmsDkgParticipantMaterial]:
    key_refs: dict[str, str | None] = {}

    if distributed_key_result is not None:
        shares = getattr(distributed_key_result, "threshold_fhe_private_key_shares", {}) or {}
        for participant_id, share in shares.items():
            key_refs[str(participant_id)] = getattr(share, "key_material_reference", None)

    materials: list[KmsDkgParticipantMaterial] = []
    for participant_id in participant_ids:
        commitment = polynomial_commitments.get(participant_id)
        materials.append(
            KmsDkgParticipantMaterial(
                participant_id=participant_id,
                share_public_key=str(share_public_keys.get(participant_id, "")),
                key_material_reference=key_refs.get(participant_id),
                polynomial_commitment_hash=(
                    _sha256_text(_canonical_json(commitment))
                    if commitment is not None
                    else None
                ),
            )
        )
    return materials


def _read_kms_client_config(path_text: str | None) -> dict[str, Any]:
    if not path_text:
        return {}

    path = Path(path_text).expanduser().resolve()
    if not path.is_file():
        return {}

    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:
        return _read_simple_toml_scalars(path)

    with path.open("rb") as fh:
        data = tomllib.load(fh)

    return {
        "kms_type": data.get("kms_type"),
        "num_majority": data.get("num_majority"),
        "num_reconstruct": data.get("num_reconstruct"),
        "decryption_mode": data.get("decryption_mode"),
        "fhe_params": data.get("fhe_params"),
    }


def _read_simple_toml_scalars(path: Path) -> dict[str, Any]:
    values: dict[str, Any] = {}

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        if "=" not in line:
            continue

        key, value = [part.strip() for part in line.split("=", 1)]
        value = value.split("#", 1)[0].strip().strip('"')

        if value.isdigit():
            values[key] = int(value)
        else:
            values[key] = value

    return values


def _jsonable(value: Any) -> Any:
    if value is None:
        return None

    if isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}

    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]

    if hasattr(value, "__dataclass_fields__"):
        return _jsonable(asdict(value))

    if hasattr(value, "__dict__"):
        return _jsonable(vars(value))

    return str(value)


def _sha256_file(path: Path) -> str:
    path = _require_file(path, "hash input")
    hasher = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _jsonable(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _require_file(path: Path, label: str) -> Path:
    if not path.is_file():
        raise FileNotFoundError(f"{label} does not exist: {path}")
    return path


def _env_required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing required environment variable: {name}")
    return value


def _maybe_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return int(value)


def _maybe_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _strict_patent_mode_enabled() -> bool:
    return (
        _truthy(os.environ.get("POS_STRICT_PATENT_MODE"))
        and os.environ.get("POS_FHE_BACKEND", "").strip().lower() == "kms-threshold"
    )
