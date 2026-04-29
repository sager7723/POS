from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable

os.environ["POS_FHE_BACKEND"] = "kms-threshold"
os.environ["POS_STRICT_PATENT_MODE"] = "1"
os.environ["POS_LOTTERY_WORD_BITS"] = "32"
os.environ["POS_TICKET_CHUNK_BITS"] = "16"

# Current repository material is local-threshold-materials. Stage-10-G records
# and guards it explicitly. Production should remove this and use
# POS_KMS_MATERIAL_MODE=formal_dkg + POS_KMS_DKG_MATERIAL_ROOT.
os.environ.setdefault("POS_KMS_ALLOW_LOCAL_DKG_MATERIALS", "1")

from pos.crypto.fhe import initialize_fhe_backend, reset_fhe_backend_cache
from pos.crypto.patent_tfhe_trlwe import validate_tfhe_trlwe_parameters
from pos.models.stage2 import Participant
from pos.protocol.candidacy import run_phase3_candidacy
from pos.protocol.election import run_phase4_election
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.patent_step20 import recover_and_verify_winning_ticket
from pos.protocol.preparation import run_phase2_preparation


def _payload(value: str) -> dict[str, Any]:
    data = json.loads(value)
    if not isinstance(data, dict):
        raise AssertionError("ciphertext payload must be JSON object")
    return data


def _iter_ciphertext_payloads(phase3: Any, phase4: Any) -> Iterable[dict[str, Any]]:
    for message in phase3.candidate_messages.values():
        yield _payload(message.encrypted_stake)
        yield _payload(message.encrypted_prf_share)
        for chunk in message.encrypted_ticket:
            yield _payload(chunk)

    yield _payload(phase4.scaled_random_ciphertext)
    for chunk in phase4.winning_ticket_ciphertext:
        yield _payload(chunk)


def main() -> None:
    reset_fhe_backend_cache()

    phase1 = run_phase1_initialization()
    pp = phase1["public_parameters"]

    participants = [
        Participant("P1", 10),
        Participant("P2", 20),
        Participant("P3", 30),
    ]

    phase2 = run_phase2_preparation(
        pp=pp,
        participants=participants,
        threshold=int(os.environ.get("POS_KMS_THRESHOLD", "1")),
    )

    pp_params = dict(pp.tfhe_trlwe_parameters)
    dkg_params = dict(phase2.distributed_key_result.tfhe_trlwe_parameters)

    validate_tfhe_trlwe_parameters(pp_params)
    validate_tfhe_trlwe_parameters(dkg_params)

    assert pp_params["key_id"] == dkg_params["key_id"]
    assert pp_params["server_key_sha256"] == dkg_params["server_key_sha256"]
    assert pp_params["public_key_sha256"] == dkg_params["public_key_sha256"]
    assert pp_params["lottery_data_type"] == "euint32"
    assert pp_params["ticket_data_type"] == "euint16"
    assert phase2.distributed_key_result.fhe_keyset_reference == pp_params["keyset_reference"]
    assert phase2.distributed_key_result.public_key == pp_params["public_key_reference"]
    assert phase2.distributed_key_result.fhe_backend_name == "kms-threshold"

    phase3 = run_phase3_candidacy(
        pp=pp,
        participants=participants,
        phase2_result=phase2,
        proof_share_count=3,
    )

    phase4 = run_phase4_election(
        phase2,
        phase3.candidate_messages,
    )

    fhe = initialize_fhe_backend(
        participant_ids=phase4.proof_valid_candidate_ids,
        threshold=int(os.environ.get("POS_KMS_THRESHOLD", "1")),
    )
    ctx = fhe.setup(
        {
            "stage": "stage10_g_tfhe_trlwe_parameter_closure",
            "strict_no_plaintext_fallback": True,
            "operation": "validate_tfhe_trlwe_manifest_and_run_full_patent_path",
        }
    )

    runtime_params = dict(ctx.params["tfhe_trlwe_parameters"])
    validate_tfhe_trlwe_parameters(runtime_params)

    assert runtime_params["key_id"] == pp_params["key_id"]
    assert runtime_params["server_key_sha256"] == pp_params["server_key_sha256"]
    assert runtime_params["public_key_sha256"] == pp_params["public_key_sha256"]

    for payload in _iter_ciphertext_payloads(phase3, phase4):
        assert payload["backend"] == "kms-threshold"
        assert payload["key_id"] == pp_params["key_id"]
        assert payload["data_type"] in {"euint32", "euint16", "ebool"}
        assert Path(payload["ciphertext_path"]).is_file()

    recovery = recover_and_verify_winning_ticket(
        pp=pp,
        fhe=fhe,
        phase4_result=phase4,
        participant_artifacts=phase3.participant_artifacts,
    )

    print("=== Stage-10-G TFHE/TRLWE parameter closure ===")
    print("key_id:", pp_params["key_id"])
    print("scheme:", pp_params["scheme"])
    print("ciphertext_family:", pp_params["ciphertext_family"])
    print("kms_type:", pp_params["kms_type"])
    print("decryption_mode:", pp_params["decryption_mode"])
    print("fhe_params:", pp_params["fhe_params"])
    print("material_mode:", pp_params["material_mode"])
    print("dkg_material_root:", pp_params["dkg_material_root"])
    print("server_key_path:", pp_params["server_key_path"])
    print("public_key_path:", pp_params["public_key_path"])
    print("server_key_sha256:", pp_params["server_key_sha256"])
    print("public_key_sha256:", pp_params["public_key_sha256"])
    print("lottery_data_type:", pp_params["lottery_data_type"])
    print("ticket_data_type:", pp_params["ticket_data_type"])
    print("threshold:", pp_params["threshold"])
    print("participant_count:", pp_params["participant_count"])
    print("core_party_ids:", pp_params["core_party_ids"])
    print("winner_participant_id:", recovery.winner_participant_id)
    print("hash_matches_preimage:", recovery.hash_matches_preimage)
    print("suffix_matches_candidate:", recovery.suffix_matches_candidate)
    print("hash_matches_candidate:", recovery.hash_matches_candidate)

    assert recovery.hash_matches_preimage is True
    assert recovery.suffix_matches_candidate is True
    assert recovery.hash_matches_candidate is True

    if pp_params["material_mode"] == "local_threshold_development_dkg":
        print(
            "NOTICE: local-threshold-materials are explicitly recorded and allowed "
            "only for development verification. For production, set "
            "POS_KMS_MATERIAL_MODE=formal_dkg and POS_KMS_DKG_MATERIAL_ROOT."
        )

    print("\\nStage-10-G TFHE/TRLWE parameter closure check passed.")


if __name__ == "__main__":
    main()
