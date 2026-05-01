from __future__ import annotations

import json
import os
from pathlib import Path
from time import perf_counter
from typing import Any

from pos.crypto.setup import step0_setup
from pos.models.stage2 import Participant
from pos.protocol.preparation import run_phase2_preparation
from pos.protocol.candidacy import run_phase3_candidacy
from pos.protocol.election import run_phase4_election
from pos.protocol.reveal import run_phase5_reveal


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _require_real_kms_environment() -> None:
    if not _truthy(os.environ.get("POS_STRICT_PATENT_MODE")):
        raise RuntimeError("POS_STRICT_PATENT_MODE=1 is required")

    backend = os.environ.get("POS_FHE_BACKEND", "").strip().lower().replace("_", "-")
    if backend != "kms-threshold":
        raise RuntimeError("POS_FHE_BACKEND=kms-threshold is required")

    eval_bin = os.environ.get("POS_KMS_TFHE_EVAL_BIN", "").strip()
    if not eval_bin:
        raise RuntimeError("POS_KMS_TFHE_EVAL_BIN must be set")
    if not Path(eval_bin).is_file():
        raise RuntimeError(f"POS_KMS_TFHE_EVAL_BIN does not exist: {eval_bin}")
    if not os.access(eval_bin, os.X_OK):
        raise RuntimeError(f"POS_KMS_TFHE_EVAL_BIN is not executable: {eval_bin}")


def _assert_opaque_proofs(phase3_result: Any) -> None:
    required_public_fields = {
        "strict_opaque_kms_binding",
        "opaque_statement_type",
        "dkg_transcript_hash",
        "public_key_sha256",
        "ciphertext_bindings_json",
        "witness_commitment",
    }

    for participant_id, message in phase3_result.candidate_messages.items():
        bundles = {
            "prf": message.prf_proof_shares,
            "stake_ciphertext": message.stake_ciphertext_proof_shares,
            "stake_pedersen": message.commitment_consistency_proof_shares,
            "ticket": message.ticket_proof_shares,
        }

        for label, proof_shares in bundles.items():
            if not proof_shares:
                raise AssertionError(f"{participant_id}:{label} proof_shares empty")

            public_data = proof_shares[0].statement_public_data
            missing = required_public_fields - set(public_data)
            if missing:
                raise AssertionError(
                    f"{participant_id}:{label} missing opaque public fields: "
                    + ", ".join(sorted(missing))
                )

            if public_data["strict_opaque_kms_binding"] != "true":
                raise AssertionError(
                    f"{participant_id}:{label} strict_opaque_kms_binding is not true"
                )


def _assert_validation_ok(phase4_result: Any) -> None:
    validation = phase4_result.validation_result
    if validation is None:
        raise AssertionError("phase4_result.validation_result is missing")

    invalid = [
        participant_id
        for participant_id, ok in validation.valid_participants.items()
        if not ok
    ]
    if invalid:
        raise AssertionError("invalid participants after Step11: " + ", ".join(invalid))

    for participant_id, records in validation.verification_records.items():
        if not records:
            raise AssertionError(f"{participant_id} has no verification records")

        for record in records:
            failed_flags = []
            for flag in [
                "polynomial_ok",
                "share_commitment_ok",
                "share_public_key_ok",
                "declared_public_key_vector_ok",
                "relation_ok",
                "noise_ok",
                "recovery_ok",
                "ciphertext_equation_ok",
                "commitment_equation_ok",
                "discrete_log_key_ok",
                "secret_recover_ok",
                "public_binding_ok",
            ]:
                if not getattr(record, flag):
                    failed_flags.append(flag)

            if failed_flags:
                raise AssertionError(
                    f"{participant_id}:{record.statement_type} failed flags: "
                    + ", ".join(failed_flags)
                )


def _assert_phase4_no_winner_oracle(phase4_result: Any) -> None:
    forbidden_attrs = [
        "winner_index",
        "expected_winner_index",
        "winner_participant_id",
        "expected_winning_ticket_chunks",
    ]
    for attr in forbidden_attrs:
        if hasattr(phase4_result, attr):
            raise AssertionError(f"Phase4Result must not expose {attr}")

    if not phase4_result.winning_ticket_ciphertext:
        raise AssertionError("Phase4Result.winning_ticket_ciphertext is empty")


def _assert_phase5_ok(phase5_result: Any, phase4_result: Any) -> None:
    if not phase5_result.public_verification_passed:
        raise AssertionError("Step23 public verification failed")

    if phase5_result.winner_id is None:
        raise AssertionError("Step21/22 did not identify a winner by ticket suffix")

    if not phase5_result.recovered_ticket_suffix:
        raise AssertionError("Step20 recovered_ticket_suffix is empty")

    if not phase5_result.revealed_ticket_preimage:
        raise AssertionError("Step22 revealed_ticket_preimage is empty")

    if phase5_result.winning_ticket_ciphertext != phase4_result.winning_ticket_ciphertext:
        raise AssertionError("Phase5 must decrypt exactly Phase4 winning_ticket_ciphertext")

    if set(phase5_result.decryption_shares_by_chunk.keys()) != set(
        range(len(phase4_result.winning_ticket_ciphertext))
    ):
        raise AssertionError("Step19 shares do not correspond exactly to winning ticket chunks")


def main() -> None:
    print("=== Stage H-2 Real KMS Full POS Flow Correctness Check ===")

    _require_real_kms_environment()

    participant_count = int(os.environ.get("POS_E2E_PARTICIPANT_COUNT", "3"))
    threshold = int(os.environ.get("POS_KMS_THRESHOLD", "2"))
    proof_share_count = int(os.environ.get("POS_E2E_PROOF_SHARE_COUNT", "4"))
    security_parameter = int(os.environ.get("POS_E2E_SECURITY_PARAMETER", "128"))

    if participant_count < 2:
        raise ValueError("participant_count must be at least 2")
    if threshold < 1 or threshold > participant_count:
        raise ValueError("threshold must satisfy 1 <= threshold <= participant_count")
    if proof_share_count < 2:
        raise ValueError("proof_share_count must be at least 2")

    os.environ["POS_KMS_THRESHOLD"] = str(threshold)

    participants = [
        Participant(
            participant_id=f"P{i + 1}",
            stake_value=(i + 1) * 10,
        )
        for i in range(participant_count)
    ]

    timings: dict[str, float] = {}

    t0 = perf_counter()
    pp = step0_setup(security_parameter)
    timings["Step0_public_parameter_setup"] = perf_counter() - t0
    print("Step0 ok")

    t0 = perf_counter()
    phase2_result = run_phase2_preparation(
        pp=pp,
        participants=participants,
        threshold=threshold,
    )
    timings["Phase2_steps1_2_3_preparation"] = perf_counter() - t0

    transcript = phase2_result.distributed_key_result.dkg_transcript
    if transcript is None:
        raise AssertionError("Phase2 DKG transcript is missing")
    if transcript.threshold != threshold:
        raise AssertionError(
            f"DKG transcript threshold mismatch: {transcript.threshold} != {threshold}"
        )
    if list(transcript.participant_ids) != [p.participant_id for p in participants]:
        raise AssertionError("DKG transcript participant_ids mismatch")

    print("Phase2 ok:", transcript.transcript_hash)

    t0 = perf_counter()
    phase3_result = run_phase3_candidacy(
        pp=pp,
        participants=participants,
        phase2_result=phase2_result,
        proof_share_count=proof_share_count,
    )
    timings["Phase3_steps4_5_6_7_8_candidacy"] = perf_counter() - t0
    _assert_opaque_proofs(phase3_result)
    print("Phase3 ok: opaque proofs generated")

    t0 = perf_counter()
    phase4_result = run_phase4_election(
        phase2_result=phase2_result,
        candidate_messages=phase3_result.candidate_messages,
        t_prime=2,
        T_prime=proof_share_count,
    )
    timings["Phase4_steps9_18_election"] = perf_counter() - t0
    _assert_validation_ok(phase4_result)
    _assert_phase4_no_winner_oracle(phase4_result)
    print("Phase4 ok: encrypted winner ticket selected, no winner oracle")

    t0 = perf_counter()
    phase5_result = run_phase5_reveal(
        pp=pp,
        phase2_result=phase2_result,
        phase3_result=phase3_result,
        phase4_result=phase4_result,
    )
    timings["Phase5_steps19_23_reveal"] = perf_counter() - t0
    _assert_phase5_ok(phase5_result, phase4_result)
    print("Phase5 ok: ticket suffix match + public reveal verification passed")

    out_dir = Path("results/stage_h2_real_kms_full_flow")
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "ok": True,
        "participant_count": participant_count,
        "threshold": threshold,
        "proof_share_count": proof_share_count,
        "dkg_transcript_hash": transcript.transcript_hash,
        "proof_valid_candidate_ids": phase4_result.proof_valid_candidate_ids,
        "winner_id_observed_by_suffix": phase5_result.winner_id,
        "recovered_ticket_suffix": phase5_result.recovered_ticket_suffix,
        "public_verification_passed": phase5_result.public_verification_passed,
        "winning_ticket_chunk_count": len(phase4_result.winning_ticket_ciphertext),
        "decrypted_chunk_indices": sorted(phase5_result.decryption_shares_by_chunk.keys()),
        "timings_seconds": timings,
    }

    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    print("summary:", out_dir / "summary.json")
    print("Stage H-2 real KMS full POS flow correctness check passed.")


if __name__ == "__main__":
    main()
