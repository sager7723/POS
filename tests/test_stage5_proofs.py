from dataclasses import replace

from pos.crypto.proofs import MockProofShareGenerator
from pos.models.stage2 import Participant
from pos.protocol.candidacy import run_phase3_candidacy
from pos.protocol.election import step9_generate_random_seed, step11_verify_proofs
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import run_phase2_preparation


def _prepare_phase3():
    pp = run_phase1_initialization()["public_parameters"]
    participants = [
        Participant("P1", 10),
        Participant("P2", 20),
        Participant("P3", 30),
    ]
    phase2 = run_phase2_preparation(pp, participants, threshold=2)
    phase3 = run_phase3_candidacy(pp, participants, phase2, proof_share_count=3)
    return phase3


def test_cut_and_choose_verification_passes() -> None:
    phase3 = _prepare_phase3()
    seed = step9_generate_random_seed(phase3.candidate_messages)
    validation = step11_verify_proofs(seed, phase3.candidate_messages)

    assert all(validation.valid_participants.values())
    assert len(validation.verification_records["P1"]) == 4
    assert validation.verification_records["P1"][0].statement_type == "prf_share_correctness"


def test_cut_and_choose_recovery_check_with_all_shares() -> None:
    phase3 = _prepare_phase3()
    proof_system = MockProofShareGenerator()

    proof_shares = phase3.candidate_messages["P1"].prf_proof_shares
    record = proof_system.verify_revealed_shares(
        proof_shares,
        proof_shares,  # 揭示全部 share，触发 recovery verification
    )

    assert record.recovery_attempted is True
    assert record.recovery_ok is True


def test_cut_and_choose_tamper_detected() -> None:
    phase3 = _prepare_phase3()

    message = phase3.candidate_messages["P1"]
    tampered_share = replace(
        message.prf_proof_shares[0],
        share_commitment="deadbeef",
    )
    message.prf_proof_shares[0] = tampered_share

    seed = step9_generate_random_seed(phase3.candidate_messages)
    validation = step11_verify_proofs(seed, phase3.candidate_messages)

    assert validation.valid_participants["P1"] is False