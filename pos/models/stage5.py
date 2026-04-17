from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from pos.models.stage4 import DecryptionShare


@dataclass(frozen=True)
class PublicRevealObject:
    """
    公开验证对象（专利终版闭环）：
    - 不只公开 ticket_preimage
    - 还固定绑定轮次、候选引用、证明通过候选集合、prefix/suffix 等公开验证输入
    """
    round_id: str
    participant_id: str
    candidate_message_reference: str
    revealed_ticket_preimage: str
    recomputed_ticket_hash: str
    recomputed_ticket_hash_prefix: str
    recovered_ticket_suffix: str
    proof_valid_candidate_ids: List[str] = field(default_factory=list)
    validation_seed: str = ""


@dataclass(frozen=True)
class Phase5Result:
    winning_ticket_ciphertext: List[str]
    decryption_shares_by_chunk: Dict[int, List[DecryptionShare]]
    recovered_ticket_suffix: str
    winner_id: Optional[str]
    revealed_ticket_preimage: Optional[str]
    public_verification_passed: bool

    # 第4步专利终版闭环新增
    round_id: str = ""
    proof_valid_candidate_ids: List[str] = field(default_factory=list)
    candidate_message_reference: Optional[str] = None
    public_reveal_object: Optional[PublicRevealObject] = None