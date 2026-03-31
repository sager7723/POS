from pos.models.stage2 import Participant
from pos.protocol.candidacy import (
    run_phase3_candidacy,
    step4_generate_prf_shares,
    step5_encrypt_prf_shares_and_generate_proof_shares,
    step6_encrypt_stakes_and_generate_proof_shares,
    step7_generate_tickets_and_encrypt_suffixes,
    step8_generate_ticket_proof_shares_and_publish_candidate_messages,
)
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import run_phase2_preparation


def build_test_participants() -> list[Participant]:
    return [
        Participant(participant_id="P1", stake_value=10),
        Participant(participant_id="P2", stake_value=20),
        Participant(participant_id="P3", stake_value=30),
    ]


def prepare_phase2_inputs():
    initialization_result = run_phase1_initialization(security_parameter=64)
    pp = initialization_result["public_parameters"]
    participants = build_test_participants()
    phase2_result = run_phase2_preparation(
        pp=pp,
        participants=participants,
        threshold=2,
    )
    return pp, participants, phase2_result


def test_step4_generate_prf_shares() -> None:
    pp, participants, phase2_result = prepare_phase2_inputs()
    prf_shares = step4_generate_prf_shares(
        pp=pp,
        participants=participants,
        random_seed=phase2_result.random_seed,
    )
    assert len(prf_shares) == 3
    assert prf_shares["P1"].participant_id == "P1"
    assert prf_shares["P1"].prf_share.startswith("prf_share(")


def test_step5_encrypt_prf_shares_and_generate_proof_shares() -> None:
    pp, participants, phase2_result = prepare_phase2_inputs()
    prf_shares = step4_generate_prf_shares(
        pp=pp,
        participants=participants,
        random_seed=phase2_result.random_seed,
    )
    result = step5_encrypt_prf_shares_and_generate_proof_shares(
        public_key=phase2_result.distributed_key_result.public_key,
        prf_shares=prf_shares,
        proof_share_count=3,
    )
    assert len(result) == 3
    assert result["P2"].encrypted_prf_share.startswith("enc(")
    assert len(result["P2"].proof_shares) == 3
    assert len(result["P2"].share_public_key_set) == 3


def test_step6_encrypt_stakes_and_generate_proof_shares() -> None:
    _, participants, phase2_result = prepare_phase2_inputs()
    result = step6_encrypt_stakes_and_generate_proof_shares(
        public_key=phase2_result.distributed_key_result.public_key,
        participants=participants,
        commitments=phase2_result.commitments,
        proof_share_count=3,
    )
    assert len(result) == 3
    assert result["P3"].encrypted_stake.startswith("enc(")
    assert len(result["P3"].stake_ciphertext_proof_shares) == 3
    assert len(result["P3"].commitment_consistency_proof_shares) == 3


def test_step7_generate_tickets_and_encrypt_suffixes() -> None:
    pp, participants, phase2_result = prepare_phase2_inputs()
    result = step7_generate_tickets_and_encrypt_suffixes(
        pp=pp,
        public_key=phase2_result.distributed_key_result.public_key,
        participants=participants,
        proof_share_count=3,
    )
    assert len(result) == 3
    assert result["P1"].ticket_hash_prefix != ""
    assert result["P1"].encrypted_ticket_suffix.startswith("enc(")
    assert len(result["P1"].ticket_proof_shares) == 3


def test_step8_generate_ticket_proof_shares_and_publish_candidate_messages() -> None:
    pp, participants, phase2_result = prepare_phase2_inputs()
    prf_shares = step4_generate_prf_shares(
        pp=pp,
        participants=participants,
        random_seed=phase2_result.random_seed,
    )
    encrypted_prf = step5_encrypt_prf_shares_and_generate_proof_shares(
        public_key=phase2_result.distributed_key_result.public_key,
        prf_shares=prf_shares,
        proof_share_count=3,
    )
    encrypted_stake = step6_encrypt_stakes_and_generate_proof_shares(
        public_key=phase2_result.distributed_key_result.public_key,
        participants=participants,
        commitments=phase2_result.commitments,
        proof_share_count=3,
    )
    tickets = step7_generate_tickets_and_encrypt_suffixes(
        pp=pp,
        public_key=phase2_result.distributed_key_result.public_key,
        participants=participants,
        proof_share_count=3,
    )
    candidate_messages = step8_generate_ticket_proof_shares_and_publish_candidate_messages(
        participants=participants,
        commitments=phase2_result.commitments,
        encrypted_prf_share_artifacts=encrypted_prf,
        encrypted_stake_artifacts=encrypted_stake,
        ticket_artifacts=tickets,
    )
    assert len(candidate_messages) == 3
    assert candidate_messages["P1"].participant_id == "P1"
    assert candidate_messages["P1"].encrypted_ticket.startswith("enc(")
    assert len(candidate_messages["P1"].ticket_proof_shares) == 3


def test_run_phase3_candidacy() -> None:
    pp, participants, phase2_result = prepare_phase2_inputs()
    result = run_phase3_candidacy(
        pp=pp,
        participants=participants,
        phase2_result=phase2_result,
        proof_share_count=3,
    )
    assert len(result.candidate_messages) == 3
    assert len(result.participant_artifacts) == 3
    assert result.candidate_messages["P2"].ticket_hash_prefix != ""