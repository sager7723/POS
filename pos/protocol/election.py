from __future__ import annotations

import hashlib
import random
from dataclasses import replace
from typing import Dict, List, Optional

from pos.crypto.fhe import FHEThresholdFacade, initialize_fhe_backend
from pos.crypto.proofs import MockProofShareGenerator
from pos.models.stage3 import CandidateMessage, PublicProofShare
from pos.models.stage4 import DecryptionShare, Phase4Result, ProofVerificationRecord, ValidationResult


def step9_generate_random_seed(
    candidate_messages: Optional[Dict[str, CandidateMessage]] = None,
) -> str:
    """
    步骤9：生成验证阶段随机种子。

    两种模式：
    1. 不传 candidate_messages：返回随机种子（兼容主流程调用）
    2. 传 candidate_messages：对候选消息公共字段做确定性哈希（供 cut-and-choose 测试/验证）
    """
    if candidate_messages is None:
        return f"{random.randint(1, 10**6):x}"

    payload_parts: List[str] = []
    for participant_id in sorted(candidate_messages.keys()):
        message = candidate_messages[participant_id]
        ticket_payload = (
            "|".join(message.encrypted_ticket)
            if isinstance(message.encrypted_ticket, list)
            else str(message.encrypted_ticket)
        )
        payload_parts.append(
            "|".join(
                [
                    participant_id,
                    message.encrypted_prf_share,
                    message.encrypted_stake,
                    ticket_payload,
                    message.ticket_hash_prefix,
                ]
            )
        )

    payload = "||".join(payload_parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def step10_cut_and_choose_indices(T_prime: int, t_prime: int) -> List[int]:
    return random.sample(range(T_prime), t_prime - 1)


def _step10_select_revealed_proof_shares(
    validation_seed: str,
    candidate_messages: Dict[str, CandidateMessage],
) -> Dict[str, Dict[str, List[PublicProofShare]]]:
    """
    第5层真实验证支撑：
    根据验证种子，按 proof system 的索引导出逻辑，揭示 t'-1 个 proof shares。
    """
    proof_system = MockProofShareGenerator()
    revealed: Dict[str, Dict[str, List[PublicProofShare]]] = {}

    for participant_id, message in candidate_messages.items():
        participant_reveals: Dict[str, List[PublicProofShare]] = {}

        labeled_bundles = [
            ("prf_share_correctness", message.prf_proof_shares),
            ("stake_ciphertext_correctness", message.stake_ciphertext_proof_shares),
            ("stake_commitment_consistency", message.commitment_consistency_proof_shares),
            ("ticket_ciphertext_correctness", message.ticket_proof_shares),
        ]

        for statement_label, proof_shares in labeled_bundles:
            if not proof_shares:
                participant_reveals[statement_label] = []
                continue

            reveal_indices = proof_system.derive_reveal_indices(
                validation_seed=validation_seed,
                participant_id=participant_id,
                statement_label=statement_label,
                proof_share_count=proof_shares[0].proof_share_count,
                reveal_threshold=proof_shares[0].reveal_threshold,
            )
            participant_reveals[statement_label] = proof_system.reveal_selected_shares(
                proof_shares,
                reveal_indices,
            )

        revealed[participant_id] = participant_reveals

    return revealed


def step11_verify_proofs(
    validation_seed: str,
    candidate_messages: Dict[str, CandidateMessage],
) -> ValidationResult:
    """
    步骤11：验证揭示值。

    验证项：
    - Feldman 多项式承诺一致性
    - share_commitment 一致性
    - share_public_key 一致性
    - PRF public key vector 一致性
    - relation commitment 一致性
    - 噪声范围检查
    - 当揭示份额足够时做恢复验证
    """
    proof_system = MockProofShareGenerator()
    revealed = _step10_select_revealed_proof_shares(validation_seed, candidate_messages)

    valid_participants: Dict[str, bool] = {}
    verification_records: Dict[str, List[ProofVerificationRecord]] = {}

    for participant_id, message in candidate_messages.items():
        participant_records: List[ProofVerificationRecord] = []

        prf_record = proof_system.verify_revealed_shares(
            message.prf_proof_shares,
            revealed[participant_id]["prf_share_correctness"],
        )
        declared_public_key_vector_ok = (
            message.prf_share_public_keys
            == proof_system.build_share_public_keys(message.prf_proof_shares)
        )
        prf_record = replace(
            prf_record,
            declared_public_key_vector_ok=declared_public_key_vector_ok,
        )
        participant_records.append(prf_record)

        stake_cipher_record = proof_system.verify_revealed_shares(
            message.stake_ciphertext_proof_shares,
            revealed[participant_id]["stake_ciphertext_correctness"],
        )
        participant_records.append(stake_cipher_record)

        commitment_record = proof_system.verify_revealed_shares(
            message.commitment_consistency_proof_shares,
            revealed[participant_id]["stake_commitment_consistency"],
        )
        participant_records.append(commitment_record)

        ticket_record = proof_system.verify_revealed_shares(
            message.ticket_proof_shares,
            revealed[participant_id]["ticket_ciphertext_correctness"],
        )
        participant_records.append(ticket_record)

        valid_participants[participant_id] = all(
            record.polynomial_ok
            and record.share_commitment_ok
            and record.share_public_key_ok
            and record.declared_public_key_vector_ok
            and record.relation_ok
            and record.noise_ok
            and record.recovery_ok
            for record in participant_records
        )
        verification_records[participant_id] = participant_records

    return ValidationResult(
        valid_participants=valid_participants,
        verification_records=verification_records,
        validation_seed=validation_seed,
    )


def step12_homomorphic_sum_stakes(
    fhe: FHEThresholdFacade,
    candidate_messages: Dict[str, CandidateMessage],
) -> str:
    ciphertexts = [
        fhe.deserialize_ciphertext(msg.encrypted_stake)
        for msg in candidate_messages.values()
    ]
    total_cipher = fhe.homomorphic_sum(ciphertexts)
    return fhe.serialize_ciphertext(total_cipher)


def step13_generate_decryption_shares(
    fhe: FHEThresholdFacade,
    participant_ids: List[str],
    ciphertext: str,
) -> List[DecryptionShare]:
    ct = fhe.deserialize_ciphertext(ciphertext)
    shares: List[DecryptionShare] = []
    for participant_id in participant_ids:
        share = fhe.decrypt_share(participant_id=participant_id, ciphertext=ct)
        shares.append(
            DecryptionShare(
                participant_id=participant_id,
                share=share,
            )
        )
    return shares


def step14_recover_plaintext(
    fhe: FHEThresholdFacade,
    shares: List[DecryptionShare],
    ciphertext: str,
) -> int:
    ct = fhe.deserialize_ciphertext(ciphertext)
    share_strings = [item.share for item in shares]
    return fhe.decrypt(ciphertext=ct, shares=share_strings)


def step15_compute_scale_ratio(
    total_stake: int,
    prf_modulus: int,
) -> float:
    if total_stake <= 0:
        raise ValueError("total_stake must be positive")
    return total_stake / prf_modulus


def step16_combine_prf_ciphertexts(
    fhe: FHEThresholdFacade,
    candidate_messages: Dict[str, CandidateMessage],
) -> str:
    ciphertexts = [
        fhe.deserialize_ciphertext(msg.encrypted_prf_share)
        for msg in candidate_messages.values()
    ]
    combined_cipher = fhe.homomorphic_sum(ciphertexts)
    return fhe.serialize_ciphertext(combined_cipher)


def step17_scale_random_ciphertext(
    fhe: FHEThresholdFacade,
    combined_cipher: str,
    scale_ratio: float,
) -> str:
    ct = fhe.deserialize_ciphertext(combined_cipher)
    scaled = fhe.scale_ciphertext(ct, scale_ratio)
    return fhe.serialize_ciphertext(scaled)


def step18_select_winner(
    fhe: FHEThresholdFacade,
    candidate_messages: Dict[str, CandidateMessage],
    scaled_random_ciphertext: str,
) -> List[str]:
    participant_ids = list(candidate_messages.keys())

    stake_ciphertexts = [
        fhe.deserialize_ciphertext(candidate_messages[pid].encrypted_stake)
        for pid in participant_ids
    ]
    cumulative_stakes = fhe.prefix_sum(stake_ciphertexts)

    random_ct = fhe.deserialize_ciphertext(scaled_random_ciphertext)
    compare_bits = fhe.compare_lt_vector(random_ct, cumulative_stakes)

    ticket_chunk_count = len(candidate_messages[participant_ids[0]].encrypted_ticket)
    winning_chunks: List[str] = []

    for chunk_index in range(ticket_chunk_count):
        ticket_chunk_ciphertexts = [
            fhe.deserialize_ciphertext(candidate_messages[pid].encrypted_ticket[chunk_index])
            for pid in participant_ids
        ]
        winning_chunk = fhe.select_first_true(compare_bits, ticket_chunk_ciphertexts)
        winning_chunks.append(fhe.serialize_ciphertext(winning_chunk))

    return winning_chunks


def run_phase4_election(
    candidate_messages: Dict[str, CandidateMessage],
    t_prime: int = 2,
    T_prime: int = 3,
) -> Phase4Result:
    if not candidate_messages:
        raise ValueError("candidate_messages must not be empty")

    fhe = initialize_fhe_backend(candidate_messages)

    validation_seed = step9_generate_random_seed(candidate_messages)
    _ = step10_cut_and_choose_indices(T_prime, t_prime)
    validation = step11_verify_proofs(validation_seed, candidate_messages)

    valid_msgs = {
        pid: msg
        for pid, msg in candidate_messages.items()
        if validation.valid_participants[pid]
    }
    if not valid_msgs:
        raise ValueError("no valid candidate messages remain after verification")

    total_cipher = step12_homomorphic_sum_stakes(fhe, valid_msgs)
    shares = step13_generate_decryption_shares(
        fhe,
        list(valid_msgs.keys()),
        total_cipher,
    )
    total_stake = step14_recover_plaintext(fhe, shares, total_cipher)
    scale_ratio = step15_compute_scale_ratio(
        total_stake=total_stake,
        prf_modulus=fhe.get_plaintext_modulus(),
    )
    combined_prf = step16_combine_prf_ciphertexts(fhe, valid_msgs)
    scaled_prf = step17_scale_random_ciphertext(fhe, combined_prf, scale_ratio)
    winner_ticket = step18_select_winner(fhe, valid_msgs, scaled_prf)

    return Phase4Result(
        total_stake_plaintext=total_stake,
        scaled_random_ciphertext=scaled_prf,
        winning_ticket_ciphertext=winner_ticket,
        validation_result=validation,
    )