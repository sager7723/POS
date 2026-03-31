from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class DecryptionShare:
    participant_id: str
    share: str


@dataclass(frozen=True)
class Phase5Result:
    winner_id: str
    ticket_preimage: str
    verification_passed: bool