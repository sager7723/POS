from __future__ import annotations

import json
import secrets
from dataclasses import replace
from typing import Dict, List, Sequence

from pos.crypto.fhe import MockThresholdFHE, initialize_fhe_backend
from pos.crypto.key_homomorphic_prf import MockKeyHomomorphicPRF
from pos.crypto.proofs import MockProofShareGenerator
from pos.crypto.ticket import MockTicketBuilder
from pos.crypto.setup import step0_setup
from pos.models.common import PublicParameters
from pos.models.stage2 import DistributedKeyGenerationResult, Participant, Phase2Result, StakeCommitment
from pos.models.stage3 import (
    CandidateMessage,
    EncryptedPRFShareArtifact,
    EncryptedStakeArtifact,
    PRFShare,
    Phase3ParticipantArtifact,
    Phase3Result,
    TicketArtifact,
)


def _sample_proof_randomizer(proof_generator: MockProofShareGenerator) -> int:
    return secrets.randbelow(proof_generator.params.field_prime)


def _extract_public_noise(ciphertext_payload: str) -> int:
    data = json.loads(ciphertext_payload)
    metadata = dict(data.get("metadata", {}))
    return int(round(float(metadata.get("noise", 0))))


def _sorted_phase2_share_public_keys(
    distributed_key_result: DistributedKeyGenerationResult | None,
) -> list[str]:
    if distributed_key_result is None:
        return []
    return [
        distributed_key_result.share_public_keys[participant_id].share_public_key
        for participant_id in sorted(distributed_key_result.share_public_keys.keys())
    ]


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
    distributed_key_result: DistributedKeyGenerationResult | None = None,
    pp: PublicParameters | None = None,
) -> Dict[str, EncryptedPRFShareArtifact]:
    if pp is None:
        pp = step0_setup(128)
    fhe = MockThresholdFHE(distributed_key_result=distributed_key_result)
    proof_generator = MockProofShareGenerator()
    plaintext_modulus = fhe._facade.get_plaintext_modulus()

    declared_share_public_key_set = _sorted_phase2_share_public_keys(distributed_key_result)
    artifacts: Dict[str, EncryptedPRFShareArtifact] = {}
    for participant_id, prf_share in prf_shares.items():
        encrypted_prf_share = fhe.encrypt(
            pk=public_key,
            value=prf_share.prf_share,
        ).payload
        ciphertext_noise = _extract_public_noise(encrypted_prf_share)

        declared_share_public_key = (
            distributed_key_result.share_public_keys[participant_id].share_public_key
            if distributed_key_result is not None
            else ""
        )
        proof_shares = proof_generator.build_prf_share_proof(
            participant_id=participant_id,
            encrypted_prf_share=encrypted_prf_share,
            public_key=public_key,
            plaintext_modulus=plaintext_modulus,
            prf_share_scalar=proof_generator.scalarize_value(prf_share.prf_share),
            key_share_scalar=prf_share.key_share_scalar,
            dlog_generator=pp.g_prime,
            dlog_modulus=pp.p,
            declared_share_public_key=declared_share_public_key,
            declared_share_public_key_set=declared_share_public_key_set,
            proof_share_count=proof_share_count,
            reveal_threshold=max(2, proof_share_count),
            encryption_randomizer=_sample_proof_randomizer(proof_generator),
            noise_estimate=ciphertext_noise,
            noise_bound=max(ciphertext_noise, 0),
        )

        artifacts[participant_id] = EncryptedPRFShareArtifact(
            participant_id=participant_id,
            encrypted_prf_share=encrypted_prf_share,
            proof_shares=proof_shares,
            share_public_key_set=list(declared_share_public_key_set),
        )

    return artifacts


def step6_encrypt_stakes_and_generate_proof_shares(
    public_key: str,
    participants: List[Participant],
    commitments: Dict[str, StakeCommitment],
    proof_share_count: int,
    distributed_key_result: DistributedKeyGenerationResult | None = None,
    pp: PublicParameters | None = None,
) -> Dict[str, EncryptedStakeArtifact]:
    if pp is None:
        pp = step0_setup(128)
    fhe = MockThresholdFHE(distributed_key_result=distributed_key_result)
    proof_generator = MockProofShareGenerator()
    plaintext_modulus = fhe._facade.get_plaintext_modulus()

    artifacts: Dict[str, EncryptedStakeArtifact] = {}
    for participant in participants:
        participant_id = participant.participant_id
        encrypted_stake = fhe.encrypt(
            pk=public_key,
            value=f"stake({participant.stake_value})",
        ).payload
        ciphertext_noise = _extract_public_noise(encrypted_stake)
        encryption_randomizer = _sample_proof_randomizer(proof_generator)
        noise_bound = max(ciphertext_noise, 0)

        stake_ciphertext_proof_shares = proof_generator.build_ciphertext_encryption_proof(
            participant_id=participant_id,
            ciphertext_payloads=[encrypted_stake],
            public_key=public_key,
            plaintext_modulus=plaintext_modulus,
            plaintext_components=[participant.stake_value],
            encryption_randomizers=[encryption_randomizer],
            noise_values=[ciphertext_noise],
            proof_share_count=proof_share_count,
            reveal_threshold=max(2, proof_share_count),
            proof_label="stake_ciphertext",
            extra_public_data={
                "plaintext_label": "stake",
            },
            noise_bound=noise_bound,
        )
        commitment_consistency_proof_shares = proof_generator.build_stake_commitment_consistency_proof(
            participant_id=participant_id,
            encrypted_stake=encrypted_stake,
            stake_commitment=commitments[participant_id].stake_commitment,
            public_key=public_key,
            plaintext_modulus=plaintext_modulus,
            stake_scalar=participant.stake_value,
            pedersen_randomness=commitments[participant_id].commit_randomness,
            encryption_randomizer=encryption_randomizer,
            ciphertext_noise=ciphertext_noise,
            pedersen_g=pp.g,
            pedersen_h=pp.h,
            pedersen_modulus=pp.p,
            proof_share_count=proof_share_count,
            reveal_threshold=max(2, proof_share_count),
            noise_bound=noise_bound,
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
    distributed_key_result: DistributedKeyGenerationResult | None = None,
) -> Dict[str, TicketArtifact]:
    fhe = MockThresholdFHE(distributed_key_result=distributed_key_result)
    proof_generator = MockProofShareGenerator()
    plaintext_modulus = fhe._facade.get_plaintext_modulus()
    ticket_builder = MockTicketBuilder(
        fhe=fhe,
        proof_generator=proof_generator,
    )

    artifacts: Dict[str, TicketArtifact] = {}
    for participant in participants:
        artifact = ticket_builder.build_ticket_artifact(
            pp=pp,
            public_key=public_key,
            participant=participant,
            proof_share_count=proof_share_count,
        )

        ciphertext_noises = [_extract_public_noise(payload) for payload in artifact.encrypted_ticket_suffix_chunks]
        encryption_randomizers = [_sample_proof_randomizer(proof_generator) for _ in artifact.encrypted_ticket_suffix_chunks]
        ticket_proof_shares = proof_generator.build_ciphertext_encryption_proof(
            participant_id=participant.participant_id,
            ciphertext_payloads=artifact.encrypted_ticket_suffix_chunks,
            public_key=public_key,
            plaintext_modulus=plaintext_modulus,
            plaintext_components=artifact.ticket_hash_suffix_chunks,
            encryption_randomizers=encryption_randomizers,
            noise_values=ciphertext_noises,
            proof_share_count=proof_share_count,
            reveal_threshold=max(2, proof_share_count),
            proof_label="ticket_suffix_ciphertext",
            extra_public_data={
                "plaintext_label": "ticket_hash_suffix_chunk_words",
                "encoding_family": artifact.ticket_cipher_layout.encoding_family,
                "chunk_bit_width": str(artifact.ticket_cipher_layout.chunk_bit_width),
                "chunk_count": str(artifact.ticket_cipher_layout.chunk_count),
                "hex_chars_per_chunk": str(artifact.ticket_cipher_layout.hex_chars_per_chunk),
                "chunk_modulus": str(artifact.ticket_cipher_layout.chunk_modulus),
                "packing_mode": artifact.ticket_cipher_layout.packing_mode,
                "slot_packing": str(artifact.ticket_cipher_layout.slot_packing).lower(),
                "byte_order": artifact.ticket_cipher_layout.byte_order,
                "recovery_format": artifact.ticket_cipher_layout.recovery_format,
            },
            noise_bound=max(ciphertext_noises) if ciphertext_noises else 0,
        )
        artifacts[participant.participant_id] = replace(
            artifact,
            ticket_proof_shares=ticket_proof_shares,
        )

    return artifacts


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
            ticket_cipher_layout=ticket_artifact.ticket_cipher_layout,
        )

    return candidate_messages


def run_phase3_candidacy(
    pp: PublicParameters,
    participants: List[Participant],
    phase2_result: Phase2Result,
    proof_share_count: int,
) -> Phase3Result:
    public_key = phase2_result.complete_public_key
    commitments = phase2_result.commitments
    random_seed = phase2_result.random_seed

    key_shares = {
        participant_id: decrypt_key_share.decrypt_share_key
        for participant_id, decrypt_key_share in phase2_result.distributed_key_result.decrypt_key_shares.items()
    }

    initialize_fhe_backend(distributed_key_result=phase2_result.distributed_key_result)

    prf_shares = step4_generate_prf_shares(
        pp=pp,
        participants=participants,
        random_seed=random_seed,
        key_shares=key_shares,
    )
    encrypted_prf_share_artifacts = step5_encrypt_prf_shares_and_generate_proof_shares(
        pp=pp,
        public_key=public_key,
        prf_shares=prf_shares,
        proof_share_count=proof_share_count,
        distributed_key_result=phase2_result.distributed_key_result,
    )
    encrypted_stake_artifacts = step6_encrypt_stakes_and_generate_proof_shares(
        pp=pp,
        public_key=public_key,
        participants=participants,
        commitments=commitments,
        proof_share_count=proof_share_count,
        distributed_key_result=phase2_result.distributed_key_result,
    )
    ticket_artifacts = step7_generate_tickets_and_encrypt_suffixes(
        pp=pp,
        public_key=public_key,
        participants=participants,
        proof_share_count=proof_share_count,
        distributed_key_result=phase2_result.distributed_key_result,
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
