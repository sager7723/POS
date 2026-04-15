from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DecryptionShare:
    participant_id: str
    share: Any


@dataclass(frozen=True)
class Phase5Result:
    winner_id: str
    ticket_preimage: str
    verification_passed: bool