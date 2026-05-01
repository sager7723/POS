from __future__ import annotations

import json
import os
from pathlib import Path
from time import perf_counter
from typing import Any

from pos.crypto.patent_widths import lottery_modulus
from pos.crypto.setup import step0_setup
from pos.models.stage2 import Participant, Phase2ParticipantArtifact, Phase2Result
from pos.models.stage3 import Phase3ParticipantArtifact, Phase3Result
from pos.models.stage4 import Phase4Result
from pos.models.stage5 import Phase5Result
from pos.protocol.preparation import (
    step1_generate_and_publish_stake_commitments,
    step2_distributed_generate_keys,
    step3_distributed_generate_random_seed,
)
from pos.protocol.candidacy import (
    step4_generate_prf_shares,
    step5_encrypt_prf_shares_and_generate_proof_shares,
    step6_encrypt_stakes_and_generate_proof_shares,
    step7_generate_tickets_and_encrypt_suffixes,
    step8_generate_ticket_proof_shares_and_publish_candidate_messages,
)
from pos.protocol.election import (
    _ciphertext_to_phase4_wire,
    _derive_round_id,
    _step10_derive_reveal_plan,
    step9_generate_random_seed,
    step11_verify_proofs,
)
from pos.protocol.patent_phase4 import _sum_lottery_ciphertexts
from pos.protocol.patent_step18 import (
    _coerce_kms_ciphertext_handle,
    step18_patent_select_winner_ticket_from_candidate_messages,
)
from pos.protocol.reveal import (
    _candidate_message_reference,
    _select_public_ticket_layout,
    step19_generate_decryption_shares,
    step20_recover_ticket_suffix,
    step21_identify_winner,
    step22_reveal_ticket_preimage,
    step23_verify_winner,
)
from pos.crypto.fhe import initialize_fhe_backend


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _require_real_kms_environment() -> None:
    required = [
        "POS_STRICT_PATENT_MODE",
        "POS_FHE_BACKEND",
        "POS_KMS_THRESHOLD",
        "POS_KMS_TFHE_EVAL_BIN",
        "POS_KMS_CORE_CLIENT_BIN",
        "POS_KMS_CORE_CLIENT_CONFIG",
        "POS_KMS_KEY_ID",
    ]
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise RuntimeError("Missing required real KMS env vars: " + ", ".join(missing))

    if not _truthy(os.environ["POS_STRICT_PATENT_MODE"]):
        raise RuntimeError("POS_STRICT_PATENT_MODE=1 is required")

    backend = os.environ["POS_FHE_BACKEND"].strip().lower().replace("_", "-")
    if backend != "kms-threshold":
        raise RuntimeError("POS_FHE_BACKEND=kms-threshold is required")

    for name in ["POS_KMS_TFHE_EVAL_BIN", "POS_KMS_CORE_CLIENT_BIN", "POS_KMS_CORE_CLIENT_CONFIG"]:
        path = Path(os.environ[name])
        if not path.exists():
            raise RuntimeError(f"{name} does not exist: {path}")

    eval_bin = Path(os.environ["POS_KMS_TFHE_EVAL_BIN"])
    if not os.access(eval_bin, os.X_OK):
        raise RuntimeError(f"POS_KMS_TFHE_EVAL_BIN is not executable: {eval_bin}")


class Timer:
    def __init__(self) -> None:
        self.seconds: dict[str, float] = {}

    def run(self, name: str, fn):
        start = perf_counter()
        try:
            result = fn()
        except Exception:
            self.seconds[name] = perf_counter() - start
            print(f"{name}: failed ({self.seconds[name]:.6f}s)")
            raise
        else:
            self.seconds[name] = perf_counter() - start
            print(f"{name}: ok ({self.seconds[name]:.6f}s)")
            return result


def _assert_opaque_proofs(phase3_result: Phase3Result) -> None:
    required = {
        "strict_opaque_kms_binding",
        "opaque_statement_type",
        "dkg_transcript_hash",
        "public_key_sha256",
        "ciphertext_bindings_json",
        "witness_commitment",
    }

    for participant_id, message in phase3_result.candidate_messages.items():
        bundles = {
            "Step5_prf": message.prf_proof_shares,
            "Step6_stake_cipher": message.stake_ciphertext_proof_shares,
            "Step6_stake_pedersen": message.commitment_consistency_proof_shares,
            "Step7_ticket": message.ticket_proof_shares,
        }
        for label, shares in bundles.items():
            if not shares:
                raise AssertionError(f"{participant_id}:{label} has empty proof shares")
            public_data = shares[0].statement_public_data
            missing = required - set(public_data)
            if missing:
                raise AssertionError(f"{participant_id}:{label} missing opaque fields: {sorted(missing)}")
            if public_data["strict_opaque_kms_binding"] != "true":
                raise AssertionError(f"{participant_id}:{label} is not strict opaque binding")


def _assert_validation_ok(phase4_result: Phase4Result) -> None:
    validation = phase4_result.validation_result
    if validation is None:
        raise AssertionError("Step11 validation_result missing from Phase4Result")

    invalid = [pid for pid, ok in validation.valid_participants.items() if not ok]
    if invalid:
        raise AssertionError("Step11 invalid participants: " + ", ".join(invalid))

    for participant_id, records in validation.verification_records.items():
        if not records:
            raise AssertionError(f"{participant_id} has no proof verification records")
        for record in records:
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
                    raise AssertionError(f"{participant_id}:{record.statement_type} failed {flag}")


def _phase2_build_result(
    *,
    participants: list[Participant],
    commitments,
    distributed_key_result,
    random_seed,
    random_seed_commitments,
    random_seed_contributions,
) -> Phase2Result:
    artifacts = []
    for participant in participants:
        pid = participant.participant_id
        artifacts.append(
            Phase2ParticipantArtifact(
                participant=participant,
                stake_commitment=commitments[pid],
                decrypt_key_share=distributed_key_result.decrypt_key_shares[pid],
                share_public_key=distributed_key_result.share_public_keys[pid],
                random_seed_commitment=random_seed_commitments[pid],
                random_seed_contribution=random_seed_contributions[pid],
            )
        )

    return Phase2Result(
        commitments=commitments,
        distributed_key_result=distributed_key_result,
        complete_public_key=distributed_key_result.public_key,
        threshold_fhe_private_key_shares=distributed_key_result.decrypt_key_shares,
        share_public_keys=distributed_key_result.share_public_keys,
        random_seed=random_seed,
        random_seed_commitments=random_seed_commitments,
        random_seed_contributions=random_seed_contributions,
        participant_artifacts=artifacts,
    )


def _phase3_build_result(
    *,
    participants: list[Participant],
    prf_shares,
    encrypted_prf_share_artifacts,
    encrypted_stake_artifacts,
    ticket_artifacts,
    candidate_messages,
) -> Phase3Result:
    artifacts = []
    for participant in participants:
        pid = participant.participant_id
        artifacts.append(
            Phase3ParticipantArtifact(
                participant=participant,
                prf_share=prf_shares[pid],
                encrypted_prf_share_artifact=encrypted_prf_share_artifacts[pid],
                encrypted_stake_artifact=encrypted_stake_artifacts[pid],
                ticket_artifact=ticket_artifacts[pid],
                candidate_message=candidate_messages[pid],
            )
        )

    return Phase3Result(
        candidate_messages=candidate_messages,
        participant_artifacts=artifacts,
    )


def main() -> None:
    print("=== Real KMS POS Full Correctness Test: Step0-Step23 ===")
    _require_real_kms_environment()

    timer = Timer()

    participant_count = int(os.environ.get("POS_E2E_PARTICIPANT_COUNT", "3"))
    threshold = int(os.environ.get("POS_KMS_THRESHOLD", "2"))
    proof_share_count = int(os.environ.get("POS_E2E_PROOF_SHARE_COUNT", "4"))
    security_parameter = int(os.environ.get("POS_E2E_SECURITY_PARAMETER", "128"))

    if threshold < 1 or threshold > participant_count:
        raise ValueError("threshold must satisfy 1 <= threshold <= participant_count")

    participants = [
        Participant(participant_id=f"P{i + 1}", stake_value=(i + 1) * 10)
        for i in range(participant_count)
    ]

    pp = timer.run("Step0_public_parameter_setup", lambda: step0_setup(security_parameter))

    commitments = timer.run(
        "Step1_pedersen_commit",
        lambda: step1_generate_and_publish_stake_commitments(pp, participants),
    )

    distributed_key_result = timer.run(
        "Step2_kms_threshold_dkg",
        lambda: step2_distributed_generate_keys(pp, participants, threshold),
    )

    transcript = distributed_key_result.dkg_transcript
    if transcript is None:
        raise AssertionError("Step2 failed: dkg_transcript is missing")
    if transcript.threshold != threshold:
        raise AssertionError("Step2 failed: transcript threshold mismatch")
    if list(transcript.participant_ids) != [p.participant_id for p in participants]:
        raise AssertionError("Step2 failed: transcript participant ids mismatch")

    random_seed, random_seed_commitments, random_seed_contributions = timer.run(
        "Step3_seed_generation",
        lambda: step3_distributed_generate_random_seed(pp, participants),
    )

    phase2_result = _phase2_build_result(
        participants=participants,
        commitments=commitments,
        distributed_key_result=distributed_key_result,
        random_seed=random_seed,
        random_seed_commitments=random_seed_commitments,
        random_seed_contributions=random_seed_contributions,
    )

    key_shares = {
        pid: share.decrypt_share_key
        for pid, share in distributed_key_result.decrypt_key_shares.items()
    }

    prf_shares = timer.run(
        "Step4_kh_prf_share",
        lambda: step4_generate_prf_shares(pp, participants, random_seed, key_shares),
    )

    encrypted_prf_share_artifacts = timer.run(
        "Step5_encrypt_prf_and_opaque_proof",
        lambda: step5_encrypt_prf_shares_and_generate_proof_shares(
            public_key=phase2_result.complete_public_key,
            prf_shares=prf_shares,
            proof_share_count=proof_share_count,
            distributed_key_result=distributed_key_result,
            pp=pp,
        ),
    )

    encrypted_stake_artifacts = timer.run(
        "Step6_encrypt_stake_and_opaque_proof",
        lambda: step6_encrypt_stakes_and_generate_proof_shares(
            public_key=phase2_result.complete_public_key,
            participants=participants,
            commitments=commitments,
            proof_share_count=proof_share_count,
            distributed_key_result=distributed_key_result,
            pp=pp,
        ),
    )

    ticket_artifacts = timer.run(
        "Step7_ticket_hash_encrypt_suffix_and_opaque_proof",
        lambda: step7_generate_tickets_and_encrypt_suffixes(
            pp=pp,
            public_key=phase2_result.complete_public_key,
            participants=participants,
            proof_share_count=proof_share_count,
            distributed_key_result=distributed_key_result,
        ),
    )

    candidate_messages = timer.run(
        "Step8_candidate_message_build",
        lambda: step8_generate_ticket_proof_shares_and_publish_candidate_messages(
            participants=participants,
            commitments=commitments,
            encrypted_prf_share_artifacts=encrypted_prf_share_artifacts,
            encrypted_stake_artifacts=encrypted_stake_artifacts,
            ticket_artifacts=ticket_artifacts,
        ),
    )

    phase3_result = _phase3_build_result(
        participants=participants,
        prf_shares=prf_shares,
        encrypted_prf_share_artifacts=encrypted_prf_share_artifacts,
        encrypted_stake_artifacts=encrypted_stake_artifacts,
        ticket_artifacts=ticket_artifacts,
        candidate_messages=candidate_messages,
    )
    _assert_opaque_proofs(phase3_result)

    validation_seed = timer.run(
        "Step9_verification_seed",
        lambda: step9_generate_random_seed(candidate_messages),
    )

    reveal_plan = timer.run(
        "Step10_cut_and_choose_open_plan",
        lambda: _step10_derive_reveal_plan(validation_seed, candidate_messages),
    )
    if not reveal_plan:
        raise AssertionError("Step10 failed: reveal plan is empty")

    validation_result = timer.run(
        "Step11_opaque_proof_verify",
        lambda: step11_verify_proofs(validation_seed, candidate_messages),
    )

    phase4_prefix = Phase4Result(
        total_stake_plaintext=0,
        scaled_random_ciphertext="",
        winning_ticket_ciphertext=[],
        validation_result=validation_result,
        round_id=_derive_round_id(validation_seed),
        proof_valid_candidate_ids=sorted(
            pid for pid, ok in validation_result.valid_participants.items() if ok
        ),
    )
    _assert_validation_ok(phase4_prefix)

    valid_msgs = {
        pid: msg
        for pid, msg in candidate_messages.items()
        if validation_result.valid_participants[pid]
    }
    if not valid_msgs:
        raise AssertionError("Step11 failed: no valid candidate messages")

    fhe = initialize_fhe_backend(
        participant_ids=sorted(valid_msgs.keys()),
        threshold=threshold,
    )
    fhe.setup(
        {
            "stage": "stage_h2_real_kms_step0_23",
            "strict_pure_ciphertext_path": True,
            "backend": "kms-threshold",
        }
    )

    encrypted_stakes = [
        _coerce_kms_ciphertext_handle(msg.encrypted_stake)
        for msg in valid_msgs.values()
    ]
    encrypted_prfs = [
        _coerce_kms_ciphertext_handle(msg.encrypted_prf_share)
        for msg in valid_msgs.values()
    ]

    total_stake_ciphertext = timer.run(
        "Step12_homomorphic_sum_stakes",
        lambda: _sum_lottery_ciphertexts(fhe, encrypted_stakes),
    )

    total_stake_plaintext = timer.run(
        "Step13_14_total_stake_threshold_recover",
        lambda: int(fhe.public_decrypt_scalar(total_stake_ciphertext)),
    )
    if total_stake_plaintext <= 0:
        raise AssertionError("Step14 failed: total stake must be positive")

    prf_modulus = lottery_modulus()
    scale_ratio = timer.run(
        "Step15_scaling_ratio",
        lambda: total_stake_plaintext / prf_modulus,
    )
    if scale_ratio <= 0:
        raise AssertionError("Step15 failed: scaling ratio must be positive")

    combined_prf_ciphertext = timer.run(
        "Step16_homomorphic_sum_prf",
        lambda: _sum_lottery_ciphertexts(fhe, encrypted_prfs),
    )

    scaled_random_ciphertext = timer.run(
        "Step17_homomorphic_scale_prf",
        lambda: fhe.eval_scale_prf(
            combined_prf_ciphertext,
            numerator=total_stake_plaintext,
            denominator=prf_modulus,
        ),
    )

    step18_result = timer.run(
        "Step18_compare_locate_select",
        lambda: step18_patent_select_winner_ticket_from_candidate_messages(
            fhe,
            valid_msgs,
            scaled_random_ciphertext,
        ),
    )
    if hasattr(step18_result, "winner_index"):
        raise AssertionError("Step18 exposed forbidden winner_index")
    if not step18_result.winning_ticket_ciphertext:
        raise AssertionError("Step18 failed: winning_ticket_ciphertext is empty")

    phase4_result = Phase4Result(
        total_stake_plaintext=total_stake_plaintext,
        scaled_random_ciphertext=_ciphertext_to_phase4_wire(scaled_random_ciphertext),
        winning_ticket_ciphertext=[
            _ciphertext_to_phase4_wire(chunk)
            for chunk in step18_result.winning_ticket_ciphertext
        ],
        validation_result=validation_result,
        round_id=_derive_round_id(validation_seed),
        proof_valid_candidate_ids=sorted(valid_msgs.keys()),
    )

    proof_valid_candidate_ids = phase4_result.proof_valid_candidate_ids
    ticket_layout = _select_public_ticket_layout(
        phase3_result=phase3_result,
        proof_valid_candidate_ids=proof_valid_candidate_ids,
    )

    reveal_fhe = initialize_fhe_backend(
        distributed_key_result=phase2_result.distributed_key_result
    )

    decryption_shares_by_chunk = timer.run(
        "Step19_ticket_threshold_partial_decrypt",
        lambda: step19_generate_decryption_shares(
            fhe=reveal_fhe,
            participant_ids=[p.participant_id for p in participants],
            winning_ticket_ciphertext=phase4_result.winning_ticket_ciphertext,
        ),
    )

    recovered_ticket_suffix = timer.run(
        "Step20_ticket_suffix_recover",
        lambda: step20_recover_ticket_suffix(
            fhe=reveal_fhe,
            winning_ticket_ciphertext=phase4_result.winning_ticket_ciphertext,
            decryption_shares_by_chunk=decryption_shares_by_chunk,
            ticket_layout=ticket_layout,
        ),
    )
    if not recovered_ticket_suffix:
        raise AssertionError("Step20 failed: recovered suffix is empty")

    winner_id = timer.run(
        "Step21_local_suffix_match_observe_winner",
        lambda: step21_identify_winner(
            phase3_result=phase3_result,
            recovered_ticket_suffix=recovered_ticket_suffix,
            proof_valid_candidate_ids=proof_valid_candidate_ids,
        ),
    )
    if winner_id is None:
        raise AssertionError("Step21 failed: no unique suffix-matching winner")

    public_reveal_object = timer.run(
        "Step22_winner_publish_ticket_preimage",
        lambda: step22_reveal_ticket_preimage(
            phase3_result=phase3_result,
            winner_id=winner_id,
            round_id=phase4_result.round_id,
            recovered_ticket_suffix=recovered_ticket_suffix,
            proof_valid_candidate_ids=proof_valid_candidate_ids,
            validation_seed=validation_seed,
        ),
    )
    if public_reveal_object is None:
        raise AssertionError("Step22 failed: public reveal object is missing")

    public_verification_passed = timer.run(
        "Step23_public_winner_verification",
        lambda: step23_verify_winner(
            pp=pp,
            phase3_result=phase3_result,
            proof_valid_candidate_ids=proof_valid_candidate_ids,
            recovered_ticket_suffix=recovered_ticket_suffix,
            public_reveal_object=public_reveal_object,
        ),
    )
    if not public_verification_passed:
        raise AssertionError("Step23 failed: public verification did not pass")

    phase5_result = Phase5Result(
        winning_ticket_ciphertext=phase4_result.winning_ticket_ciphertext,
        decryption_shares_by_chunk=decryption_shares_by_chunk,
        recovered_ticket_suffix=recovered_ticket_suffix,
        winner_id=winner_id,
        revealed_ticket_preimage=public_reveal_object.revealed_ticket_preimage,
        public_verification_passed=public_verification_passed,
        round_id=phase4_result.round_id,
        proof_valid_candidate_ids=proof_valid_candidate_ids,
        candidate_message_reference=_candidate_message_reference(candidate_messages[winner_id]),
        public_reveal_object=public_reveal_object,
    )

    if phase5_result.winning_ticket_ciphertext != phase4_result.winning_ticket_ciphertext:
        raise AssertionError("Phase5 decrypted a ciphertext other than Step18 winning_ticket_ciphertext")

    out_dir = Path("results/stage_h2_real_kms_step0_23")
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "ok": True,
        "participant_count": participant_count,
        "threshold": threshold,
        "proof_share_count": proof_share_count,
        "dkg_transcript_hash": transcript.transcript_hash,
        "round_id": phase4_result.round_id,
        "proof_valid_candidate_ids": proof_valid_candidate_ids,
        "winner_id_observed_by_suffix": winner_id,
        "recovered_ticket_suffix": recovered_ticket_suffix,
        "public_verification_passed": public_verification_passed,
        "winning_ticket_chunk_count": len(phase4_result.winning_ticket_ciphertext),
        "decrypted_chunk_indices": sorted(decryption_shares_by_chunk.keys()),
        "timings_seconds": timer.seconds,
    }

    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (out_dir / "step_seconds.csv").write_text(
        "step_name,seconds\n"
        + "\n".join(
            f"{name},{seconds}"
            for name, seconds in timer.seconds.items()
        )
        + "\n",
        encoding="utf-8",
    )

    print("summary:", out_dir / "summary.json")
    print("step_csv:", out_dir / "step_seconds.csv")
    print("Real KMS POS full correctness test Step0-Step23 passed.")


if __name__ == "__main__":
    main()
