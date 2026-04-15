from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any


@dataclass(frozen=True)
class ValidationResult:
    valid_participants: Dict[str, bool]


@dataclass(frozen=True)
class DecryptionShare:
    participant_id: str
    share: Any


@dataclass(frozen=True)
class Phase4Result:
    total_stake_plaintext: int
    scaled_random_ciphertext: Any
    winning_ticket_ciphertext: Any