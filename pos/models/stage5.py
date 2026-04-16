from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from pos.models.stage4 import DecryptionShare


@dataclass(frozen=True)
class Phase5Result:
    winning_ticket_ciphertext: List[str]
    decryption_shares_by_chunk: Dict[int, List[DecryptionShare]]
    recovered_ticket_suffix: str
    winner_id: Optional[str]
    revealed_ticket_preimage: Optional[str]
    public_verification_passed: bool