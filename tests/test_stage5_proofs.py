import copy

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
    validation_seed = step9_generate_random_seed(phase3.candidate_messages)
    validation = step11_verify_proofs(validation_seed, phase3.candidate_messages)

    assert validation.validation_seed == validation_seed
    assert set(validation.valid_participants.keys()) == set(phase3.candidate_messages.keys())
    assert all(validation.valid_participants.values())
    assert set(validation.verification_records.keys()) == set(phase3.candidate_messages.keys())
    assert all(len(records) == 4 for records in validation.verification_records.values())


def test_cut_and_choose_recovery_check_with_all_shares() -> None:
    phase3 = _prepare_phase3()
    validation_seed = step9_generate_random_seed(phase3.candidate_messages)
    validation = step11_verify_proofs(validation_seed, phase3.candidate_messages)

    for participant_id, records in validation.verification_records.items():
        assert validation.valid_participants[participant_id] is True
        for record in records:
            assert record.polynomial_ok is True
            assert record.share_commitment_ok is True
            assert record.share_public_key_ok is True
            assert record.relation_ok is True
            assert record.noise_ok is True
            assert record.recovery_ok is True
            assert record.secret_recover_ok is True
            assert record.public_binding_ok is True


def test_cut_and_choose_tamper_detected() -> None:
    phase3 = _prepare_phase3()
    tampered_messages = copy.deepcopy(phase3.candidate_messages)

    participant_id = sorted(tampered_messages.keys())[0]
    tampered_message = tampered_messages[participant_id]

    tampered_ticket_proofs = list(tampered_message.ticket_proof_shares)
    original_share = tampered_ticket_proofs[0]
    tampered_public_data = dict(original_share.statement_public_data)
    tampered_public_data["chunk_modulus"] = str(int(tampered_public_data["chunk_modulus"]) + 1)

    from pos.models.stage3 import PublicProofShare, CandidateMessage

    tampered_ticket_proofs[0] = PublicProofShare(
        share_index=original_share.share_index,
        proof_share=original_share.proof_share,
        statement_type=original_share.statement_type,
        statement_public_hash=original_share.statement_public_hash,
        proof_share_count=original_share.proof_share_count,
        reveal_threshold=original_share.reveal_threshold,
        coefficient_commitments=original_share.coefficient_commitments,
        share_commitment=original_share.share_commitment,
        share_public_key=original_share.share_public_key,
        relation_commitment=original_share.relation_commitment,
        noise_estimate=original_share.noise_estimate,
        noise_bound=original_share.noise_bound,
        statement_public_data=tampered_public_data,
        revealed_share_values=original_share.revealed_share_values,
        reveal_nonce=original_share.reveal_nonce,
    )

    tampered_messages[participant_id] = CandidateMessage(
        participant_id=tampered_message.participant_id,
        stake_commitment=tampered_message.stake_commitment,
        encrypted_stake=tampered_message.encrypted_stake,
        encrypted_prf_share=tampered_message.encrypted_prf_share,
        encrypted_ticket=tampered_message.encrypted_ticket,
        prf_proof_shares=tampered_message.prf_proof_shares,
        stake_ciphertext_proof_shares=tampered_message.stake_ciphertext_proof_shares,
        commitment_consistency_proof_shares=tampered_message.commitment_consistency_proof_shares,
        ticket_proof_shares=tampered_ticket_proofs,
        prf_share_public_keys=tampered_message.prf_share_public_keys,
        ticket_hash_prefix=tampered_message.ticket_hash_prefix,
        ticket_cipher_layout=tampered_message.ticket_cipher_layout,
        ticket_layout=tampered_message.ticket_layout,
    )

    validation_seed = step9_generate_random_seed(tampered_messages)
    validation = step11_verify_proofs(validation_seed, tampered_messages)

    assert validation.valid_participants[participant_id] is False
    assert any(record.public_binding_ok is False for record in validation.verification_records[participant_id])