from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

from pos.crypto.patent_widths import (
    lottery_data_type,
    lottery_modulus,
    lottery_word_bits,
    strict_kms_patent_mode_enabled,
    ticket_chunk_bits,
    ticket_data_type,
)


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def _read_simple_toml_scalars(path: Path) -> dict[str, Any]:
    values: dict[str, Any] = {}
    core_party_ids: list[int] = []

    if not path.is_file():
        return values

    current_core = False
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line == "[[cores]]":
            current_core = True
            continue

        if "=" not in line:
            continue

        key, value = [part.strip() for part in line.split("=", 1)]
        value = value.strip().strip('"')

        if current_core and key == "party_id":
            try:
                core_party_ids.append(int(value))
            except ValueError:
                pass
            continue

        if key in {"kms_type", "decryption_mode", "fhe_params"}:
            values[key] = value
        elif key in {"num_majority", "num_reconstruct"}:
            try:
                values[key] = int(value)
            except ValueError:
                values[key] = value

    if core_party_ids:
        values["core_party_ids"] = core_party_ids
        values["core_count"] = len(core_party_ids)

    return values


def _infer_material_root(server_key_path: Path) -> Path | None:
    for parent in server_key_path.parents:
        if parent.name in {"local-threshold-materials", "threshold-materials"}:
            return parent
    return None


def _public_key_path_for(server_key_path: Path, key_id: str) -> Path:
    # Expected layout:
    #   <root>/node1/keys/PUB/ServerKey/<key_id>
    #   <root>/node1/keys/PUB/PublicKey/<key_id>
    pub_dir = server_key_path.parent.parent
    return pub_dir / "PublicKey" / key_id


def _material_mode(material_root: Path | None) -> str:
    explicit = os.environ.get("POS_KMS_MATERIAL_MODE", "").strip()
    if explicit:
        return explicit

    root_text = str(material_root or "")
    if "local-threshold-materials" in root_text:
        return "local_threshold_development_dkg"

    return "formal_dkg"


def build_tfhe_trlwe_parameters(
    *,
    pp: Any | None = None,
    participant_ids: Sequence[str] | None = None,
    threshold: int | None = None,
) -> dict[str, Any]:
    """
    Build the public TFHE/TRLWE/KMS parameter manifest used by the patent path.

    In strict KMS patent mode this manifest is mandatory and binds:
      - KMS key_id
      - KMS config
      - ServerKey/PublicKey files
      - material root
      - lottery/ticket widths
      - KMS threshold config
      - public-parameter security/noise summary
    """
    if not strict_kms_patent_mode_enabled():
        return {
            "enabled": False,
            "backend_name": os.environ.get("POS_FHE_BACKEND", "compatibility"),
            "scheme": "compatibility",
        }

    key_id = os.environ.get("POS_KMS_KEY_ID", "").strip()
    core_client_bin = os.environ.get("POS_KMS_CORE_CLIENT_BIN", "").strip()
    core_client_config = os.environ.get("POS_KMS_CORE_CLIENT_CONFIG", "").strip()
    server_key_env = os.environ.get("POS_KMS_SERVER_KEY_PATH", "").strip()

    missing = [
        name
        for name, value in [
            ("POS_KMS_KEY_ID", key_id),
            ("POS_KMS_CORE_CLIENT_BIN", core_client_bin),
            ("POS_KMS_CORE_CLIENT_CONFIG", core_client_config),
            ("POS_KMS_SERVER_KEY_PATH", server_key_env),
        ]
        if not value
    ]
    if missing:
        raise RuntimeError(
            "strict patent KMS TFHE/TRLWE parameters require: "
            + ", ".join(missing)
        )

    core_client_bin_path = Path(core_client_bin).expanduser().resolve()
    core_client_config_path = Path(core_client_config).expanduser().resolve()
    server_key_path = Path(server_key_env).expanduser().resolve()

    material_root_env = os.environ.get("POS_KMS_DKG_MATERIAL_ROOT", "").strip()
    material_root = (
        Path(material_root_env).expanduser().resolve()
        if material_root_env
        else _infer_material_root(server_key_path)
    )

    public_key_path = _public_key_path_for(server_key_path, key_id)
    config_scalars = _read_simple_toml_scalars(core_client_config_path)
    mode = _material_mode(material_root)

    require_formal = _truthy(os.environ.get("POS_KMS_REQUIRE_FORMAL_DKG"))
    allow_local = _truthy(os.environ.get("POS_KMS_ALLOW_LOCAL_DKG_MATERIALS"))

    if require_formal and mode != "formal_dkg":
        raise RuntimeError(
            "formal DKG mode is required, but the active KMS material mode is "
            f"{mode!r}. Set POS_KMS_DKG_MATERIAL_ROOT to a formal DKG output "
            "and do not use local-threshold-materials."
        )

    if mode == "local_threshold_development_dkg" and not allow_local:
        raise RuntimeError(
            "strict patent mode detected local-threshold-materials. This is only "
            "allowed for development verification when "
            "POS_KMS_ALLOW_LOCAL_DKG_MATERIALS=1. For production, provide "
            "POS_KMS_DKG_MATERIAL_ROOT pointing at a formal DKG output and set "
            "POS_KMS_MATERIAL_MODE=formal_dkg."
        )

    participant_count = len(participant_ids or [])
    threshold_value = int(threshold or os.environ.get("POS_KMS_THRESHOLD", "1"))

    params: dict[str, Any] = {
        "enabled": True,
        "backend_name": "kms-threshold",
        "scheme": "TFHE",
        "ciphertext_family": "TLWE/TRLWE via KMS TFHE",
        "threshold_backend": "KMS threshold",
        "key_id": key_id,
        "keyset_reference": f"kms-threshold-keyset://{key_id}",
        "public_key_reference": f"kms-threshold-public-key://{key_id}",
        "server_key_reference": f"kms-threshold-server-key://{key_id}",
        "core_client_bin": str(core_client_bin_path),
        "core_client_config": str(core_client_config_path),
        "server_key_path": str(server_key_path),
        "public_key_path": str(public_key_path),
        "dkg_material_root": str(material_root) if material_root is not None else "",
        "material_mode": mode,
        "local_materials_allowed": allow_local,
        "formal_dkg_required": require_formal,
        "kms_type": config_scalars.get("kms_type"),
        "decryption_mode": config_scalars.get("decryption_mode"),
        "fhe_params": config_scalars.get("fhe_params"),
        "num_majority": config_scalars.get("num_majority"),
        "num_reconstruct": config_scalars.get("num_reconstruct"),
        "core_party_ids": config_scalars.get("core_party_ids", []),
        "core_count": config_scalars.get("core_count", 0),
        "threshold": threshold_value,
        "participant_count": participant_count,
        "lottery_word_bits": lottery_word_bits(),
        "ticket_chunk_bits": ticket_chunk_bits(),
        "lottery_data_type": lottery_data_type(),
        "ticket_data_type": ticket_data_type(),
        "lottery_modulus": lottery_modulus(),
        "ticket_chunk_modulus": 1 << ticket_chunk_bits(),
    }

    if pp is not None:
        params.update(
            {
                "public_security_parameter": getattr(pp, "security_parameter", None),
                "public_sigma": getattr(pp, "sigma", None),
                "public_mu": getattr(pp, "mu", None),
                "public_N": getattr(pp, "N", None),
                "public_q": getattr(pp, "q", None),
            }
        )

    for label, path in [
        ("core_client_bin", core_client_bin_path),
        ("core_client_config", core_client_config_path),
        ("server_key", server_key_path),
        ("public_key", public_key_path),
    ]:
        params[f"{label}_exists"] = path.is_file()

    if server_key_path.is_file():
        params["server_key_sha256"] = _sha256_file(server_key_path)
    else:
        params["server_key_sha256"] = ""

    if public_key_path.is_file():
        params["public_key_sha256"] = _sha256_file(public_key_path)
    else:
        params["public_key_sha256"] = ""

    return params


def validate_tfhe_trlwe_parameters(params: Mapping[str, Any]) -> None:
    if not params.get("enabled"):
        return

    required_true = [
        "core_client_bin_exists",
        "core_client_config_exists",
        "server_key_exists",
        "public_key_exists",
    ]
    missing = [name for name in required_true if not bool(params.get(name))]
    if missing:
        raise RuntimeError(
            "TFHE/TRLWE KMS parameter manifest has missing files: "
            + ", ".join(missing)
        )

    if params.get("scheme") != "TFHE":
        raise RuntimeError(f"unsupported FHE scheme: {params.get('scheme')!r}")

    if params.get("backend_name") != "kms-threshold":
        raise RuntimeError(f"unsupported FHE backend: {params.get('backend_name')!r}")

    if params.get("lottery_data_type") != "euint32":
        raise RuntimeError(
            "Stage-10-G patent closure expects lottery arithmetic euint32, got "
            f"{params.get('lottery_data_type')!r}"
        )

    if params.get("ticket_data_type") != "euint16":
        raise RuntimeError(
            "Stage-10-G patent closure expects ticket chunks euint16, got "
            f"{params.get('ticket_data_type')!r}"
        )

    if not params.get("key_id"):
        raise RuntimeError("TFHE/TRLWE KMS parameter manifest missing key_id")

    if not params.get("server_key_sha256"):
        raise RuntimeError("TFHE/TRLWE KMS parameter manifest missing server_key_sha256")

    if not params.get("public_key_sha256"):
        raise RuntimeError("TFHE/TRLWE KMS parameter manifest missing public_key_sha256")


def attach_tfhe_trlwe_parameters_to_public_parameters(
    pp: Any,
    *,
    participant_ids: Sequence[str] | None = None,
    threshold: int | None = None,
) -> dict[str, Any]:
    params = build_tfhe_trlwe_parameters(
        pp=pp,
        participant_ids=participant_ids,
        threshold=threshold,
    )
    validate_tfhe_trlwe_parameters(params)
    setattr(pp, "tfhe_trlwe_parameters", params)
    return params
