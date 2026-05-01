from __future__ import annotations

import hashlib
from typing import Dict, List, Optional

from pos.crypto.fhe import FHEThresholdFacade, initialize_fhe_backend
from pos.models.common import PublicParameters
from pos.models.stage2 import Phase2Result
from pos.models.stage3 import CandidateMessage, Phase3Result, TicketCipherLayout
from pos.models.stage4 import DecryptionShare, Phase4Result, ValidationResult
from pos.models.stage5 import Phase5Result, PublicRevealObject
from pos.spec import hash_bytes, split_digest_hex


def _candidate_message_reference(message: CandidateMessage) -> str:
    payload = "||".join(
        [
            message.participant_id,
            message.encrypted_prf_share,
            message.encrypted_stake,
            "|".join(message.encrypted_ticket),
            message.stake_commitment.stake_commitment,
            message.ticket_hash_prefix,
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _extract_proof_valid_candidate_ids(
    phase3_result: Phase3Result,
    phase4_result: Phase4Result | None,
    validation_result: ValidationResult | None,
) -> List[str]:
    if phase4_result is not None and phase4_result.proof_valid_candidate_ids:
        return list(phase4_result.proof_valid_candidate_ids)

    if validation_result is not None:
        return sorted(
            participant_id
            for participant_id, is_valid in validation_result.valid_participants.items()
            if is_valid
        )

    # 向后兼容路径；终版主流程应优先传 phase4_result
    return sorted(phase3_result.candidate_messages.keys())


def _extract_validation_seed(
    phase4_result: Phase4Result | None,
    validation_result: ValidationResult | None,
) -> str:
    if phase4_result is not None and phase4_result.validation_result is not None:
        return phase4_result.validation_result.validation_seed
    if validation_result is not None:
        return validation_result.validation_seed
    return ""


def _extract_round_id(
    phase4_result: Phase4Result | None,
    validation_seed: str,
) -> str:
    if phase4_result is not None and phase4_result.round_id:
        return phase4_result.round_id
    return f"round-{validation_seed[:12]}" if validation_seed else "round-unknown"


def _select_public_ticket_layout(
    phase3_result: Phase3Result,
    proof_valid_candidate_ids: List[str],
) -> TicketCipherLayout:
    if not proof_valid_candidate_ids:
        raise ValueError("proof_valid_candidate_ids must not be empty")

    layouts: List[TicketCipherLayout] = []
    for participant_id in proof_valid_candidate_ids:
        message = phase3_result.candidate_messages.get(participant_id)
        if message is None:
            raise KeyError(f"participant_id {participant_id} missing from phase3_result.candidate_messages")
        layouts.append(message.ticket_cipher_layout)

    first_layout = layouts[0]
    for other_layout in layouts[1:]:
        if other_layout != first_layout:
            raise ValueError("proof-valid candidate set does not share a single public ticket layout")

    return first_layout


def step19_generate_decryption_shares(
    fhe: FHEThresholdFacade,
    participant_ids: List[str],
    winning_ticket_ciphertext: List[str],
) -> Dict[int, List[DecryptionShare]]:
    """
    必须直接调用统一门限 FHE 的真实 share 算法。
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
    ticket_layout: TicketCipherLayout,
) -> str:
    """
    必须只依赖门限份额恢复。
    这里不再使用任何调试回退路径；恢复格式完全由公开 ticket_layout 决定。
    """
    if len(winning_ticket_ciphertext) != ticket_layout.chunk_count:
        raise ValueError("winning_ticket_ciphertext length does not match public ticket layout")

    recovered_hex_parts: List[str] = []
    chunk_bytes = ticket_layout.chunk_bytes
    hex_width = ticket_layout.hex_chars_per_chunk
    max_value = ticket_layout.chunk_modulus - 1

    for chunk_index, chunk_ciphertext in enumerate(winning_ticket_ciphertext):
        ct = fhe.deserialize_ciphertext(chunk_ciphertext)
        share_strings = [item.share for item in decryption_shares_by_chunk[chunk_index]]
        recovered_value = fhe.decrypt(ciphertext=ct, shares=share_strings)

        if recovered_value < 0 or recovered_value > max_value:
            return ""

        recovered_hex_parts.append(f"{recovered_value:0{hex_width}x}")

    return "".join(recovered_hex_parts)


def step21_identify_winner(
    phase3_result: Phase3Result,
    recovered_ticket_suffix: str,
    proof_valid_candidate_ids: List[str],
) -> Optional[str]:
    """
    必须在“唯一匹配”基础上检查验证状态。
    这里只允许在 proof-valid candidate set 中寻找 winner。
    """
    matched = [
        participant_id
        for participant_id in proof_valid_candidate_ids
        if phase3_result.candidate_messages[participant_id].ticket_hash_prefix is not None
        and any(
            artifact.participant.participant_id == participant_id
            and artifact.ticket_artifact.ticket_hash_suffix == recovered_ticket_suffix
            for artifact in phase3_result.participant_artifacts
        )
    ]

    if len(matched) != 1:
        return None
    return matched[0]


def step22_reveal_ticket_preimage(
    phase3_result: Phase3Result,
    winner_id: Optional[str],
    round_id: str,
    recovered_ticket_suffix: str,
    proof_valid_candidate_ids: List[str],
    validation_seed: str,
) -> Optional[PublicRevealObject]:
    """
    winner 公开的不只是 ticket_preimage，而是固定格式的公开验证对象。
    """
    if winner_id is None:
        return None

    winner_message = phase3_result.candidate_messages.get(winner_id)
    if winner_message is None:
        return None

    for artifact in phase3_result.participant_artifacts:
        if artifact.participant.participant_id != winner_id:
            continue

        ticket_preimage = artifact.ticket_artifact.ticket_preimage
        ticket_preimage_bytes = bytes.fromhex(ticket_preimage)
        recomputed_ticket_hash = hash_bytes(ticket_preimage_bytes, "sha256")
        recomputed_prefix, _ = split_digest_hex(recomputed_ticket_hash)

        return PublicRevealObject(
            round_id=round_id,
            participant_id=winner_id,
            candidate_message_reference=_candidate_message_reference(winner_message),
            revealed_ticket_preimage=ticket_preimage,
            recomputed_ticket_hash=recomputed_ticket_hash,
            recomputed_ticket_hash_prefix=recomputed_prefix,
            recovered_ticket_suffix=recovered_ticket_suffix,
            proof_valid_candidate_ids=list(proof_valid_candidate_ids),
            validation_seed=validation_seed,
        )

    return None


def step23_verify_winner(
    pp: PublicParameters,
    phase3_result: Phase3Result,
    proof_valid_candidate_ids: List[str],
    recovered_ticket_suffix: str,
    public_reveal_object: Optional[PublicRevealObject],
) -> bool:
    """
    公开验证必须同时纳入：
    - reveal 正确性
    - prefix 一致性
    - suffix 一致性
    - proof-valid candidate set
    """
    if public_reveal_object is None:
        return False

    winner_id = public_reveal_object.participant_id
    if winner_id not in proof_valid_candidate_ids:
        return False

    winner_message = phase3_result.candidate_messages.get(winner_id)
    if winner_message is None:
        return False

    expected_reference = _candidate_message_reference(winner_message)
    if public_reveal_object.candidate_message_reference != expected_reference:
        return False

    if public_reveal_object.recovered_ticket_suffix != recovered_ticket_suffix:
        return False

    try:
        ticket_preimage_bytes = bytes.fromhex(public_reveal_object.revealed_ticket_preimage)
    except ValueError:
        return False

    recomputed_ticket_hash = hash_bytes(ticket_preimage_bytes, pp.hash_name)
    recomputed_prefix, recomputed_suffix = split_digest_hex(recomputed_ticket_hash)

    if public_reveal_object.recomputed_ticket_hash != recomputed_ticket_hash:
        return False
    if public_reveal_object.recomputed_ticket_hash_prefix != recomputed_prefix:
        return False
    if recomputed_prefix != winner_message.ticket_hash_prefix:
        return False
    if recomputed_suffix != recovered_ticket_suffix:
        return False

    matching_candidates = [
        participant_id
        for participant_id in proof_valid_candidate_ids
        if any(
            artifact.participant.participant_id == participant_id
            and artifact.ticket_artifact.ticket_hash_suffix == recovered_ticket_suffix
            for artifact in phase3_result.participant_artifacts
        )
    ]
    if matching_candidates != [winner_id]:
        return False

    if sorted(public_reveal_object.proof_valid_candidate_ids) != sorted(proof_valid_candidate_ids):
        return False

    return True


def run_phase5_reveal(
    pp: PublicParameters,
    phase2_result: Phase2Result,
    phase3_result: Phase3Result,
    winning_ticket_ciphertext: Optional[List[str]] = None,
    phase4_result: Optional[Phase4Result] = None,
    validation_result: Optional[ValidationResult] = None,
) -> Phase5Result:
    """
    第6层公开验证闭环终版：
    - 建立在统一门限 FHE 密钥体系之上
    - 建立在第5层正式证明系统通过的 candidate set 之上
    - 输出固定格式 public reveal object
    """
    participant_ids = [
        artifact.participant.participant_id
        for artifact in phase2_result.participant_artifacts
    ]

    if phase4_result is not None:
        winning_ticket_ciphertext = phase4_result.winning_ticket_ciphertext

    if winning_ticket_ciphertext is None:
        raise ValueError("winning_ticket_ciphertext or phase4_result must be provided")

    proof_valid_candidate_ids = _extract_proof_valid_candidate_ids(
        phase3_result=phase3_result,
        phase4_result=phase4_result,
        validation_result=validation_result,
    )
    validation_seed = _extract_validation_seed(
        phase4_result=phase4_result,
        validation_result=validation_result,
    )
    round_id = _extract_round_id(
        phase4_result=phase4_result,
        validation_seed=validation_seed,
    )
    ticket_layout = _select_public_ticket_layout(
        phase3_result=phase3_result,
        proof_valid_candidate_ids=proof_valid_candidate_ids,
    )

    fhe = initialize_fhe_backend(
        distributed_key_result=phase2_result.distributed_key_result
    )

    decryption_shares_by_chunk = step19_generate_decryption_shares(
        fhe=fhe,
        participant_ids=participant_ids,
        winning_ticket_ciphertext=winning_ticket_ciphertext,
    )
    recovered_ticket_suffix = step20_recover_ticket_suffix(
        fhe=fhe,
        winning_ticket_ciphertext=winning_ticket_ciphertext,
        decryption_shares_by_chunk=decryption_shares_by_chunk,
        ticket_layout=ticket_layout,
    )
    winner_id = step21_identify_winner(
        phase3_result=phase3_result,
        recovered_ticket_suffix=recovered_ticket_suffix,
        proof_valid_candidate_ids=proof_valid_candidate_ids,
    )
    public_reveal_object = step22_reveal_ticket_preimage(
        phase3_result=phase3_result,
        winner_id=winner_id,
        round_id=round_id,
        recovered_ticket_suffix=recovered_ticket_suffix,
        proof_valid_candidate_ids=proof_valid_candidate_ids,
        validation_seed=validation_seed,
    )

    candidate_message_reference = (
        public_reveal_object.candidate_message_reference
        if public_reveal_object is not None
        else None
    )
    revealed_ticket_preimage = (
        public_reveal_object.revealed_ticket_preimage
        if public_reveal_object is not None
        else None
    )

    public_verification_passed = step23_verify_winner(
        pp=pp,
        phase3_result=phase3_result,
        proof_valid_candidate_ids=proof_valid_candidate_ids,
        recovered_ticket_suffix=recovered_ticket_suffix,
        public_reveal_object=public_reveal_object,
    )

    return Phase5Result(
        winning_ticket_ciphertext=winning_ticket_ciphertext,
        decryption_shares_by_chunk=decryption_shares_by_chunk,
        recovered_ticket_suffix=recovered_ticket_suffix,
        winner_id=winner_id,
        revealed_ticket_preimage=revealed_ticket_preimage,
        public_verification_passed=public_verification_passed,
        round_id=round_id,
        proof_valid_candidate_ids=proof_valid_candidate_ids,
        candidate_message_reference=candidate_message_reference,
        public_reveal_object=public_reveal_object,
    )