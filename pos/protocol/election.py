from __future__ import annotations

import random
from typing import Dict, List

from pos.crypto.fhe import MockThresholdFHE
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
    随机选择 t'-1 个索引
    未在专利中确认具体 PRNG
    """
    return random.sample(range(T_prime), t_prime - 1)


# ========================
# Step 11
# ========================
def step11_verify_proofs(
    candidate_messages: Dict[str, CandidateMessage],
) -> ValidationResult:
    """
    mock：全部通过
    未在专利中确认具体验证逻辑
    """
    return ValidationResult(
        valid_participants={pid: True for pid in candidate_messages}
    )


# ========================
# Step 12
# ========================
def step12_homomorphic_sum_stakes(
    candidate_messages: Dict[str, CandidateMessage],
) -> str:
    fhe = MockThresholdFHE()
    inputs = [msg.encrypted_stake for msg in candidate_messages.values()]
    return fhe.evaluate("sum", inputs).payload


# ========================
# Step 13
# ========================
def step13_generate_decryption_shares(
    participants: List[str],
    ciphertext: str,
) -> List[DecryptionShare]:
    return [
        DecryptionShare(pid, f"share({pid},{ciphertext})")
        for pid in participants
    ]


# ========================
# Step 14
# ========================
def step14_recover_plaintext(
    shares: List[DecryptionShare],
    candidate_messages: Dict[str, CandidateMessage],
) -> int:
    """
    mock：直接用明文 stake 计算
    ❗真实应来自解密
    """
    total = 0
    for msg in candidate_messages.values():
        # 从字符串解析 stake（mock）
        # 未在专利中确认解析方式
        if "stake(" in msg.encrypted_stake:
            val = int(msg.encrypted_stake.split("stake(")[1].split(")")[0])
            total += val
    return total


# ========================
# Step 15
# ========================
def step15_compute_scale_ratio(
    total_stake: int,
) -> float:
    return 1.0 / max(total_stake, 1)


# ========================
# Step 16
# ========================
def step16_combine_prf_ciphertexts(
    candidate_messages: Dict[str, CandidateMessage],
) -> str:
    fhe = MockThresholdFHE()
    inputs = [msg.encrypted_prf_share for msg in candidate_messages.values()]
    return fhe.evaluate("combine_prf", inputs).payload


# ========================
# Step 17
# ========================
def step17_scale_random_ciphertext(
    combined_cipher: str,
    scale_ratio: float,
) -> str:
    return f"scaled({combined_cipher},{scale_ratio})"


# ========================
# Step 18
# ========================
def step18_select_winner(
    candidate_messages: Dict[str, CandidateMessage],
    total_stake: int,
) -> str:
    """
    mock：按 stake 区间选择
    """
    rand = random.randint(0, total_stake - 1)

    cumulative = 0
    for msg in candidate_messages.values():
        stake = int(msg.encrypted_stake.split("stake(")[1].split(")")[0])
        cumulative += stake
        if rand < cumulative:
            return msg.encrypted_ticket

    return list(candidate_messages.values())[0].encrypted_ticket


# ========================
# Phase4
# ========================
def run_phase4_election(
    candidate_messages: Dict[str, CandidateMessage],
    t_prime: int = 2,
    T_prime: int = 3,
) -> Phase4Result:

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

    # Step 12
    total_cipher = step12_homomorphic_sum_stakes(valid_msgs)

    # Step 13
    shares = step13_generate_decryption_shares(list(valid_msgs.keys()), total_cipher)

    # Step 14
    total_stake = step14_recover_plaintext(shares, valid_msgs)

    # Step 15
    ratio = step15_compute_scale_ratio(total_stake)

    # Step 16
    combined_prf = step16_combine_prf_ciphertexts(valid_msgs)

    # Step 17
    scaled_prf = step17_scale_random_ciphertext(combined_prf, ratio)

    # Step 18
    winner_ticket = step18_select_winner(valid_msgs, total_stake)

    return Phase4Result(
        total_stake_plaintext=total_stake,
        scaled_random_ciphertext=scaled_prf,
        winning_ticket_ciphertext=winner_ticket,
    )