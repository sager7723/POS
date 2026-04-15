from __future__ import annotations

import random
from typing import Dict, List

from pos.crypto.fhe import (
    CiphertextVector,
    FHEThresholdFacade,
    initialize_fhe_backend,
)
from pos.models.stage3 import CandidateMessage
from pos.models.stage4 import DecryptionShare, Phase4Result, ValidationResult


# ========================
# Step 9
# ========================
def step9_generate_random_seed() -> int:
    return random.randint(1, 10**6)


# ========================
# Step 10
# ========================
def step10_cut_and_choose_indices(T_prime: int, t_prime: int) -> List[int]:
    """
    随机选择 t'-1 个索引。
    这里先保留随机抽样接口，后续第5层再把它与真实 commit-reveal 随机源绑定得更紧。
    """
    return random.sample(range(T_prime), t_prime - 1)


# ========================
# Step 11
# ========================
def step11_verify_proofs(
    candidate_messages: Dict[str, CandidateMessage],
) -> ValidationResult:
    """
    当前仍保留证明验证占位。
    第5层会把这里替换成真实 cut-and-choose / ZK 验证。
    """
    return ValidationResult(
        valid_participants={pid: True for pid in candidate_messages}
    )


# ========================
# Step 12
# ========================
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


# ========================
# Step 13
# ========================
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


# ========================
# Step 14
# ========================
def step14_recover_plaintext(
    fhe: FHEThresholdFacade,
    shares: List[DecryptionShare],
    ciphertext: str,
) -> int:
    ct = fhe.deserialize_ciphertext(ciphertext)
    share_strings = [item.share for item in shares]
    return fhe.decrypt(ciphertext=ct, shares=share_strings)


# ========================
# Step 15
# ========================
def step15_compute_scale_ratio(
    total_stake: int,
    prf_modulus: int,
) -> float:
    if total_stake <= 0:
        raise ValueError("total_stake must be positive")
    return total_stake / prf_modulus


# ========================
# Step 16
# ========================
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


# ========================
# Step 17
# ========================
def step17_scale_random_ciphertext(
    fhe: FHEThresholdFacade,
    combined_cipher: str,
    scale_ratio: float,
) -> str:
    ct = fhe.deserialize_ciphertext(combined_cipher)
    scaled = fhe.scale_ciphertext(ct, scale_ratio)
    return fhe.serialize_ciphertext(scaled)


# ========================
# Step 18
# ========================
def step18_select_winner(
    fhe: FHEThresholdFacade,
    candidate_messages: Dict[str, CandidateMessage],
    scaled_random_ciphertext: str,
) -> str:
    participant_ids = list(candidate_messages.keys())

    stake_ciphertexts = [
        fhe.deserialize_ciphertext(candidate_messages[pid].encrypted_stake)
        for pid in participant_ids
    ]
    cumulative_stakes: CiphertextVector = fhe.prefix_sum(stake_ciphertexts)

    random_ct = fhe.deserialize_ciphertext(scaled_random_ciphertext)
    compare_bits: CiphertextVector = fhe.compare_lt_vector(random_ct, cumulative_stakes)

    ticket_ciphertexts = [
        fhe.deserialize_ciphertext(candidate_messages[pid].encrypted_ticket)
        for pid in participant_ids
    ]
    winning_ticket_cipher = fhe.select_first_true(compare_bits, ticket_ciphertexts)

    return fhe.serialize_ciphertext(winning_ticket_cipher)


# ========================
# Phase4
# ========================
def run_phase4_election(
    candidate_messages: Dict[str, CandidateMessage],
    t_prime: int = 2,
    T_prime: int = 3,
) -> Phase4Result:
    if not candidate_messages:
        raise ValueError("candidate_messages must not be empty")

    # 初始化 FHE 后端。当前会优先尝试真实后端；不可用时退到兼容后端。
    fhe = initialize_fhe_backend(candidate_messages)

    # Step 9
    _ = step9_generate_random_seed()

    # Step 10
    _ = step10_cut_and_choose_indices(T_prime, t_prime)

    # Step 11
    validation = step11_verify_proofs(candidate_messages)

    valid_msgs = {
        pid: msg
        for pid, msg in candidate_messages.items()
        if validation.valid_participants[pid]
    }
    if not valid_msgs:
        raise ValueError("no valid candidate messages remain after verification")

    # Step 12
    total_cipher = step12_homomorphic_sum_stakes(fhe, valid_msgs)

    # Step 13
    shares = step13_generate_decryption_shares(
        fhe,
        list(valid_msgs.keys()),
        total_cipher,
    )

    # Step 14
    total_stake = step14_recover_plaintext(fhe, shares, total_cipher)

    # Step 15
    scale_ratio = step15_compute_scale_ratio(
        total_stake=total_stake,
        prf_modulus=fhe.get_plaintext_modulus(),
    )

    # Step 16
    combined_prf = step16_combine_prf_ciphertexts(fhe, valid_msgs)

    # Step 17
    scaled_prf = step17_scale_random_ciphertext(fhe, combined_prf, scale_ratio)

    # Step 18
    winner_ticket = step18_select_winner(fhe, valid_msgs, scaled_prf)

    return Phase4Result(
        total_stake_plaintext=total_stake,
        scaled_random_ciphertext=scaled_prf,
        winning_ticket_ciphertext=winner_ticket,
    )