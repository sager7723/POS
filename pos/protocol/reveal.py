from __future__ import annotations

from typing import Dict, List, Optional

from pos.crypto.fhe import FHEThresholdFacade, initialize_fhe_backend
from pos.models.common import PublicParameters
from pos.models.stage3 import Phase3Result
from pos.models.stage4 import DecryptionShare
from pos.models.stage5 import Phase5Result
from pos.spec import hash_bytes, split_digest_hex


def step19_generate_decryption_shares(
    fhe: FHEThresholdFacade,
    participant_ids: List[str],
    winning_ticket_ciphertext: List[str],
) -> Dict[int, List[DecryptionShare]]:
    """
    对中签票根密文向量逐 chunk 生成真实门限解密份额。
    """
    shares_by_chunk: Dict[int, List[DecryptionShare]] = {}
    for chunk_index, chunk_ciphertext in enumerate(winning_ticket_ciphertext):
        ct = fhe.deserialize_ciphertext(chunk_ciphertext)
        shares_by_chunk[chunk_index] = [
            DecryptionShare(
                participant_id=participant_id,
                share=fhe.decrypt_share(participant_id=participant_id, ciphertext=ct),
            )
            for participant_id in participant_ids
        ]
    return shares_by_chunk


def step20_recover_ticket_suffix(
    fhe: FHEThresholdFacade,
    winning_ticket_ciphertext: List[str],
    decryption_shares_by_chunk: Dict[int, List[DecryptionShare]],
) -> str:
    """
    精确恢复票根后半哈希：
    - 每个 chunk 独立门限解密
    - 每个 chunk 结果约束在 0..255
    - 最终恢复为 hex 串
    """
    recovered_chunks: List[int] = []
    for chunk_index, chunk_ciphertext in enumerate(winning_ticket_ciphertext):
        ct = fhe.deserialize_ciphertext(chunk_ciphertext)
        share_strings = [item.share for item in decryption_shares_by_chunk[chunk_index]]
        recovered_value = fhe.decrypt(ciphertext=ct, shares=share_strings)
        recovered_value = max(0, min(255, recovered_value))
        recovered_chunks.append(recovered_value)

    return "".join(f"{value:02x}" for value in recovered_chunks)


def step21_identify_winner(
    phase3_result: Phase3Result,
    recovered_ticket_suffix: str,
) -> Optional[str]:
    """
    每个候选人本地根据自己保存的 ticket_hash_suffix 判断是否中签。
    """
    matched = [
        artifact.participant.participant_id
        for artifact in phase3_result.participant_artifacts
        if artifact.ticket_artifact.ticket_hash_suffix == recovered_ticket_suffix
    ]

    if len(matched) != 1:
        return None
    return matched[0]


def step22_reveal_ticket_preimage(
    phase3_result: Phase3Result,
    winner_id: Optional[str],
) -> Optional[str]:
    """
    中签者公开 ticket_preimage。
    """
    if winner_id is None:
        return None

    for artifact in phase3_result.participant_artifacts:
        if artifact.participant.participant_id == winner_id:
            return artifact.ticket_artifact.ticket_preimage

    return None


def step23_verify_winner(
    pp: PublicParameters,
    phase3_result: Phase3Result,
    winner_id: Optional[str],
    recovered_ticket_suffix: str,
    revealed_ticket_preimage: Optional[str],
) -> bool:
    """
    公开验证闭环：
    1. 用公开的 preimage 重新计算 hash
    2. 拆成 prefix / suffix
    3. 与 candidate message 中公开的 prefix 和解密恢复的 suffix 对比
    4. 同时要求本地匹配 winner 唯一
    """
    if winner_id is None or revealed_ticket_preimage is None:
        return False

    winner_message = phase3_result.candidate_messages.get(winner_id)
    if winner_message is None:
        return False

    try:
        ticket_preimage_bytes = bytes.fromhex(revealed_ticket_preimage)
    except ValueError:
        return False

    recomputed_ticket_hash = hash_bytes(ticket_preimage_bytes, pp.hash_name)
    recomputed_prefix, recomputed_suffix = split_digest_hex(recomputed_ticket_hash)

    if recomputed_prefix != winner_message.ticket_hash_prefix:
        return False
    if recomputed_suffix != recovered_ticket_suffix:
        return False

    matching_candidates = [
        artifact.participant.participant_id
        for artifact in phase3_result.participant_artifacts
        if artifact.ticket_artifact.ticket_hash_suffix == recovered_ticket_suffix
    ]
    return matching_candidates == [winner_id]


def run_phase5_reveal(
    pp: PublicParameters,
    phase3_result: Phase3Result,
    winning_ticket_ciphertext: List[str],
) -> Phase5Result:
    candidate_messages = phase3_result.candidate_messages
    participant_ids = list(candidate_messages.keys())

    fhe = initialize_fhe_backend(candidate_messages)

    decryption_shares_by_chunk = step19_generate_decryption_shares(
        fhe=fhe,
        participant_ids=participant_ids,
        winning_ticket_ciphertext=winning_ticket_ciphertext,
    )
    recovered_ticket_suffix = step20_recover_ticket_suffix(
        fhe=fhe,
        winning_ticket_ciphertext=winning_ticket_ciphertext,
        decryption_shares_by_chunk=decryption_shares_by_chunk,
    )
    winner_id = step21_identify_winner(
        phase3_result=phase3_result,
        recovered_ticket_suffix=recovered_ticket_suffix,
    )
    revealed_ticket_preimage = step22_reveal_ticket_preimage(
        phase3_result=phase3_result,
        winner_id=winner_id,
    )
    public_verification_passed = step23_verify_winner(
        pp=pp,
        phase3_result=phase3_result,
        winner_id=winner_id,
        recovered_ticket_suffix=recovered_ticket_suffix,
        revealed_ticket_preimage=revealed_ticket_preimage,
    )

    return Phase5Result(
        winning_ticket_ciphertext=winning_ticket_ciphertext,
        decryption_shares_by_chunk=decryption_shares_by_chunk,
        recovered_ticket_suffix=recovered_ticket_suffix,
        winner_id=winner_id,
        revealed_ticket_preimage=revealed_ticket_preimage,
        public_verification_passed=public_verification_passed,
    )