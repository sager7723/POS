from __future__ import annotations

import json
import os
from pathlib import Path

os.environ["POS_FHE_BACKEND"] = "kms-threshold"
os.environ["POS_STRICT_PATENT_MODE"] = "1"
os.environ["POS_LOTTERY_WORD_BITS"] = "32"
os.environ["POS_TICKET_CHUNK_BITS"] = "16"

os.environ.setdefault("POS_KMS_ALLOW_LOCAL_DKG_MATERIALS", "1")
os.environ.setdefault("POS_KMS_MATERIAL_MODE", "local_threshold_development_dkg")

from pos.crypto.kms_dkg_transcript import (
    assert_ciphertext_bound_to_dkg_transcript,
    build_kms_dkg_transcript,
    validate_kms_dkg_transcript,
)
from pos.crypto.thfhe_backend.kms_fhe_backend import KmsThresholdCiphertextHandle
from pos.models.stage2 import Participant
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import run_phase2_preparation


def main() -> None:
    participants = [
        Participant(participant_id="P1", stake_value=10),
        Participant(participant_id="P2", stake_value=20),
        Participant(participant_id="P3", stake_value=30),
    ]

    threshold = int(os.environ.get("POS_KMS_THRESHOLD", "1"))

    phase1 = run_phase1_initialization(128)
    pp = phase1["public_parameters"]

    phase2 = run_phase2_preparation(
        pp=pp,
        participants=participants,
        threshold=threshold,
    )

    dkg_result = phase2.distributed_key_result
    transcript = dkg_result.dkg_transcript

    if transcript is None:
        raise AssertionError("DistributedKeyGenerationResult.dkg_transcript is None")

    validate_kms_dkg_transcript(transcript)

    rebuilt = build_kms_dkg_transcript(
        pp=pp,
        participants=participants,
        threshold=threshold,
        distributed_key_result=dkg_result,
    )

    if rebuilt.transcript_hash != transcript.transcript_hash:
        raise AssertionError(
            "transcript_hash is not stable: "
            f"{transcript.transcript_hash} != {rebuilt.transcript_hash}"
        )

    expected_participant_ids = tuple(p.participant_id for p in participants)
    if transcript.participant_ids != expected_participant_ids:
        raise AssertionError(
            f"participant_ids mismatch: {transcript.participant_ids} != {expected_participant_ids}"
        )

    if transcript.threshold != threshold:
        raise AssertionError(f"threshold mismatch: {transcript.threshold} != {threshold}")

    if set(transcript.share_public_keys.keys()) != set(expected_participant_ids):
        raise AssertionError(
            "share_public_keys do not match POS participants: "
            f"{sorted(transcript.share_public_keys.keys())}"
        )

    if not transcript.public_material.public_key_sha256:
        raise AssertionError("public_key_sha256 missing")

    if not transcript.public_material.server_key_sha256:
        raise AssertionError("server_key_sha256 missing")

    dummy_ciphertext = KmsThresholdCiphertextHandle(
        backend="kms-threshold",
        key_id=transcript.key_id,
        data_type="euint32",
        ciphertext_path="/tmp/stage_b_dummy_ciphertext.ct",
        ciphertext_id="stage_b_dummy",
    )
    assert_ciphertext_bound_to_dkg_transcript(dummy_ciphertext, transcript)

    out_dir = Path("results/stage_b_kms_dkg_transcript")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "dkg_transcript.json").write_text(
        json.dumps(transcript.to_dict(), ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    print("=== Stage B KMS DKG Transcript Check ===")
    print("key_id:", transcript.key_id)
    print("participant_ids:", list(transcript.participant_ids))
    print("threshold:", transcript.threshold)
    print("kms_type:", transcript.kms_type)
    print("num_majority:", transcript.num_majority)
    print("num_reconstruct:", transcript.num_reconstruct)
    print("decryption_mode:", transcript.decryption_mode)
    print("fhe_params:", transcript.fhe_params)
    print("material_mode:", transcript.material_mode)
    print("public_key_sha256:", transcript.public_material.public_key_sha256)
    print("server_key_sha256:", transcript.public_material.server_key_sha256)
    print("verf_key_count:", len(transcript.public_material.verf_key_hashes))
    print("verf_address_count:", len(transcript.public_material.verf_address_hashes))
    print("share_public_key_count:", len(transcript.share_public_keys))
    print("polynomial_commitment_count:", len(transcript.polynomial_commitments))
    print("secret_commitment_public_key:", transcript.secret_commitment_public_key)
    print("transcript_hash:", transcript.transcript_hash)
    print("output:", out_dir / "dkg_transcript.json")
    print("Stage B KMS DKG transcript check passed.")


if __name__ == "__main__":
    main()
