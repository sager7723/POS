from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass(frozen=True)
class ProofVerificationRecord:
    statement_type: str
    revealed_indices: List[int]
    polynomial_ok: bool
    share_commitment_ok: bool
    share_public_key_ok: bool
    declared_public_key_vector_ok: bool = True
    relation_ok: bool = True
    noise_ok: bool = True
    recovery_attempted: bool = False
    recovery_ok: bool = True
    ciphertext_equation_ok: bool = True
    commitment_equation_ok: bool = True
    discrete_log_key_ok: bool = True
    secret_recover_ok: bool = True
    public_binding_ok: bool = True


@dataclass(frozen=True)
class ValidationResult:
    valid_participants: Dict[str, bool]
    verification_records: Dict[str, List[ProofVerificationRecord]] = field(default_factory=dict)
    validation_seed: str = ""


@dataclass(frozen=True)
class DecryptionShare:
    participant_id: str
    share: str


@dataclass(frozen=True)
class Phase4Result:
    total_stake_plaintext: int
    scaled_random_ciphertext: str
    winning_ticket_ciphertext: List[str]
    validation_result: ValidationResult | None = None

    # 第4步专利终版闭环新增：
    round_id: str = ""
    proof_valid_candidate_ids: List[str] = field(default_factory=list)