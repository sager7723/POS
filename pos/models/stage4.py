from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class ValidationResult:
    valid_participants: Dict[str, bool]


@dataclass(frozen=True)
class DecryptionShare:
    participant_id: str
    share: str


@dataclass(frozen=True)
class Phase4Result:
    total_stake_plaintext: int
    scaled_random_ciphertext: str
    winning_ticket_ciphertext: str