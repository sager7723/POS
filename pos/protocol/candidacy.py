from __future__ import annotations

from typing import Dict, List

from pos.crypto.fhe import MockThresholdFHE
from pos.crypto.key_homomorphic_prf import MockKeyHomomorphicPRF
from pos.crypto.proofs import MockProofShareGenerator
from pos.crypto.ticket import MockTicketBuilder
from pos.models.common import PublicParameters
from pos.models.stage2 import Participant, Phase2Result, StakeCommitment
from pos.models.stage3 import (
    CandidateMessage,
    EncryptedPRFShareArtifact,
    EncryptedStakeArtifact,
    PRFShare,
    Phase3ParticipantArtifact,
    Phase3Result,
    TicketArtifact,
)


def step4_generate_prf_shares(
    pp: PublicParameters,
    participants: List[Participant],
    random_seed: str,
    key_shares: Dict[str, int],
) -> Dict[str, PRFShare]:
    """
    专利约束相关：
    - PRF 分片必须绑定阶段2产生的密钥份额；
    - 不能脱离前一阶段门限密钥材料单独生成。
    """
    prf = MockKeyHomomorphicPRF()
    return {
        participant.participant_id: prf.generate_prf_share(
            pp=pp,
            participant=participant,
            random_seed=random_seed,
            key_share_scalar=key_shares[participant.participant_id],
        )
        for participant in participants
    }


def step5_encrypt_prf_shares_and_generate_proof_shares(
    public_key: str,
    prf_shares: Dict[str, PRFShare],
    proof_share_count: int,
) -> Dict[str, EncryptedPRFShareArtifact]:
    fhe = MockThresholdFHE()
    proof_generator = MockProofShareGenerator()

    artifacts: Dict[str, EncryptedPRFShareArtifact] = {}
    for participant_id, prf_share in prf_shares.items():
        encrypted_prf_share = fhe.encrypt(
            pk=public_key,
            value=prf_share.prf_share,
        ).payload

        prf_scalar = proof_generator.scalarize_value(prf_share.prf_share)
        proof_shares = proof_generator.build_proof_shares(
            statement_type="prf_share_correctness",
            statement_public_data={
                "participant_id": participant_id,
                "public_key": public_key,
                "encrypted_prf_share": encrypted_prf_share,
            },
            witness_values={
                "prf_scalar": prf_scalar,
            },
            proof_share_count=proof_share_count,
            reveal_threshold=max(2, proof_share_count),
            noise_estimate=0,
            noise_bound=0,
        )
        share_public_key_set = proof_generator.build_share_public_keys(proof_shares)

        artifacts[participant_id] = EncryptedPRFShareArtifact(
            participant_id=participant_id,
            encrypted_prf_share=encrypted_prf_share,
            proof_shares=proof_shares,
            share_public_key_set=share_public_key_set,
        )

    return artifacts


def step6_encrypt_stakes_and_generate_proof_shares(
    public_key: str,
    participants: List[Participant],
    commitments: Dict[str, StakeCommitment],
    proof_share_count: int,
) -> Dict[str, EncryptedStakeArtifact]:
    fhe = MockThresholdFHE()
    proof_generator = MockProofShareGenerator()

    artifacts: Dict[str, EncryptedStakeArtifact] = {}
    for participant in participants:
        participant_id = participant.participant_id
        encrypted_stake = fhe.encrypt(
            pk=public_key,
            value=f"stake({participant.stake_value})",
        ).payload

        stake_ciphertext_proof_shares = proof_generator.build_proof_shares(
            statement_type="ciphertext_encryption_correctness",
            statement_public_data={
                "participant_id": participant_id,
                "public_key": public_key,
                "ciphertext": encrypted_stake,
                "plaintext_label": "stake",
            },
            witness_values={
                "plaintext_scalar": participant.stake_value,
            },
            proof_share_count=proof_share_count,
            reveal_threshold=max(2, proof_share_count),
            noise_estimate=0,
            noise_bound=0,
        )
        commitment_consistency_proof_shares = proof_generator.build_proof_shares(
            statement_type="stake_commitment_consistency",
            statement_public_data={
                "participant_id": participant_id,
                "public_key": public_key,
                "ciphertext": encrypted_stake,
                "stake_commitment": commitments[participant_id].stake_commitment,
            },
            witness_values={
                "stake_scalar": participant.stake_value,
                "randomness_scalar": commitments[participant_id].commit_randomness,
            },
            proof_share_count=proof_share_count,
            reveal_threshold=max(2, proof_share_count),
            noise_estimate=0,
            noise_bound=0,
        )

        artifacts[participant_id] = EncryptedStakeArtifact(
            participant_id=participant_id,
            encrypted_stake=encrypted_stake,
            stake_ciphertext_proof_shares=stake_ciphertext_proof_shares,
            commitment_consistency_proof_shares=commitment_consistency_proof_shares,
        )

    return artifacts


def step7_generate_tickets_and_encrypt_suffixes(
    pp: PublicParameters,
    public_key: str,
    participants: List[Participant],
    proof_share_count: int,
) -> Dict[str, TicketArtifact]:
    fhe = MockThresholdFHE()
    proof_generator = MockProofShareGenerator()
    ticket_builder = MockTicketBuilder(
        fhe=fhe,
        proof_generator=proof_generator,
    )

    return {
        participant.participant_id: ticket_builder.build_ticket_artifact(
            pp=pp,
            public_key=public_key,
            participant=participant,
            proof_share_count=proof_share_count,
        )
        for participant in participants
    }


def step8_generate_ticket_proof_shares_and_publish_candidate_messages(
    participants: List[Participant],
    commitments: Dict[str, StakeCommitment],
    encrypted_prf_share_artifacts: Dict[str, EncryptedPRFShareArtifact],
    encrypted_stake_artifacts: Dict[str, EncryptedStakeArtifact],
    ticket_artifacts: Dict[str, TicketArtifact],
) -> Dict[str, CandidateMessage]:
    candidate_messages: Dict[str, CandidateMessage] = {}

    for participant in participants:
        participant_id = participant.participant_id
        prf_artifact = encrypted_prf_share_artifacts[participant_id]
        stake_artifact = encrypted_stake_artifacts[participant_id]
        ticket_artifact = ticket_artifacts[participant_id]

        candidate_messages[participant_id] = CandidateMessage(
            participant_id=participant_id,
            stake_commitment=commitments[participant_id],
            encrypted_stake=stake_artifact.encrypted_stake,
            encrypted_prf_share=prf_artifact.encrypted_prf_share,
            encrypted_ticket=ticket_artifact.encrypted_ticket_suffix_chunks,
            prf_proof_shares=prf_artifact.proof_shares,
            stake_ciphertext_proof_shares=stake_artifact.stake_ciphertext_proof_shares,
            commitment_consistency_proof_shares=stake_artifact.commitment_consistency_proof_shares,
            ticket_proof_shares=ticket_artifact.ticket_proof_shares,
            prf_share_public_keys=prf_artifact.share_public_key_set,
            ticket_hash_prefix=ticket_artifact.ticket_hash_prefix,
        )

    return candidate_messages


def run_phase3_candidacy(
    pp: PublicParameters,
    participants: List[Participant],
    phase2_result: Phase2Result,
    proof_share_count: int,
) -> Phase3Result:
    public_key = phase2_result.distributed_key_result.public_key
    commitments = phase2_result.commitments
    random_seed = phase2_result.random_seed

    # 从阶段2结果中提取密钥份额，供第3阶段 PRF 分片生成使用
    key_shares = {
        participant_id: decrypt_key_share.decrypt_share_key
        for participant_id, decrypt_key_share in phase2_result.distributed_key_result.decrypt_key_shares.items()
    }

    prf_shares = step4_generate_prf_shares(
        pp=pp,
        participants=participants,
        random_seed=random_seed,
        key_shares=key_shares,
    )
    encrypted_prf_share_artifacts = step5_encrypt_prf_shares_and_generate_proof_shares(
        public_key=public_key,
        prf_shares=prf_shares,
        proof_share_count=proof_share_count,
    )
    encrypted_stake_artifacts = step6_encrypt_stakes_and_generate_proof_shares(
        public_key=public_key,
        participants=participants,
        commitments=commitments,
        proof_share_count=proof_share_count,
    )
    ticket_artifacts = step7_generate_tickets_and_encrypt_suffixes(
        pp=pp,
        public_key=public_key,
        participants=participants,
        proof_share_count=proof_share_count,
    )
    candidate_messages = step8_generate_ticket_proof_shares_and_publish_candidate_messages(
        participants=participants,
        commitments=commitments,
        encrypted_prf_share_artifacts=encrypted_prf_share_artifacts,
        encrypted_stake_artifacts=encrypted_stake_artifacts,
        ticket_artifacts=ticket_artifacts,
    )

    participant_artifacts: List[Phase3ParticipantArtifact] = []
    for participant in participants:
        participant_id = participant.participant_id
        participant_artifacts.append(
            Phase3ParticipantArtifact(
                participant=participant,
                prf_share=prf_shares[participant_id],
                encrypted_prf_share_artifact=encrypted_prf_share_artifacts[participant_id],
                encrypted_stake_artifact=encrypted_stake_artifacts[participant_id],
                ticket_artifact=ticket_artifacts[participant_id],
                candidate_message=candidate_messages[participant_id],
            )
        )

    return Phase3Result(
        candidate_messages=candidate_messages,
        participant_artifacts=participant_artifacts,
    )