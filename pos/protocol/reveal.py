from __future__ import annotations

from typing import Dict, List

from pos.crypto.fhe import MockThresholdFHE
from pos.models.stage3 import CandidateMessage
from pos.models.stage5 import DecryptionShare, Phase5Result


# ========================
# Step 19
# ========================
def step19_generate_decryption_shares(
    participants: List[str],
    ciphertext: str,
) -> List[DecryptionShare]:
    return [
        DecryptionShare(pid, f"dec_share({pid},{ciphertext})")
        for pid in participants
    ]


# ========================
# Step 20
# ========================
def step20_recover_ticket_suffix(
    shares: List[DecryptionShare],
) -> str:
    """
    mock：直接拼接恢复
    未在专利中确认真实恢复方式
    """
    return "recovered_ticket_suffix"


# ========================
# Step 21
# ========================
def step21_identify_winner(
    candidate_messages: Dict[str, CandidateMessage],
    recovered_suffix: str,
    winning_cipher: str,
) -> str:
    """
    mock：通过密文匹配
    """
    for pid, msg in candidate_messages.items():
        if msg.encrypted_ticket == winning_cipher:
            return pid
    return "unknown"


# ========================
# Step 22
# ========================
def step22_reveal_ticket_preimage(
    candidate_messages: Dict[str, CandidateMessage],
    winner_id: str,
) -> str:
    """
    mock：直接返回 prefix + suffix
    未在专利中确认完整恢复方式
    """
    msg = candidate_messages[winner_id]
    return f"revealed_preimage_for_{winner_id}_{msg.ticket_hash_prefix}"


# ========================
# Step 23
# ========================
def step23_verify_winner(
    winner_id: str,
    ticket_preimage: str,
) -> bool:
    """
    mock：简单返回 True
    未在专利中确认验证公式
    """
    return True


# ========================
# Phase5
# ========================
def run_phase5_reveal(
    candidate_messages: Dict[str, CandidateMessage],
    winning_ticket_ciphertext: str,
) -> Phase5Result:

    participant_ids = list(candidate_messages.keys())

    # Step 19
    shares = step19_generate_decryption_shares(
        participant_ids,
        winning_ticket_ciphertext,
    )

    # Step 20
    recovered_suffix = step20_recover_ticket_suffix(shares)

    # Step 21
    winner_id = step21_identify_winner(
        candidate_messages,
        recovered_suffix,
        winning_ticket_ciphertext,
    )

    # Step 22
    ticket_preimage = step22_reveal_ticket_preimage(
        candidate_messages,
        winner_id,
    )

    # Step 23
    verified = step23_verify_winner(
        winner_id,
        ticket_preimage,
    )

    return Phase5Result(
        winner_id=winner_id,
        ticket_preimage=ticket_preimage,
        verification_passed=verified,
    )