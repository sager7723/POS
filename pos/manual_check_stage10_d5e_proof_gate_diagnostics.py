from __future__ import annotations

import json
import os
from dataclasses import asdict, is_dataclass
from typing import Any

os.environ["POS_FHE_BACKEND"] = "kms-threshold"
os.environ["POS_STRICT_PATENT_MODE"] = "1"
os.environ["POS_LOTTERY_WORD_BITS"] = "32"
os.environ["POS_TICKET_CHUNK_BITS"] = "16"

from pos.crypto.fhe import reset_fhe_backend_cache
from pos.models.stage2 import Participant
from pos.protocol.candidacy import run_phase3_candidacy
from pos.protocol.election import step9_generate_random_seed, step11_verify_proofs
from pos.protocol.initialization import run_phase1_initialization
from pos.protocol.preparation import run_phase2_preparation


BOOL_FIELDS = [
    "polynomial_ok",
    "share_commitment_ok",
    "share_public_key_ok",
    "declared_public_key_vector_ok",
    "relation_ok",
    "noise_ok",
    "recovery_ok",
    "ciphertext_equation_ok",
    "commitment_equation_ok",
    "discrete_log_key_ok",
    "secret_recover_ok",
    "public_binding_ok",
]


def compact(value: Any, max_len: int = 220) -> Any:
    if isinstance(value, dict):
        return {str(k): compact(v, max_len=max_len) for k, v in value.items()}
    if isinstance(value, list):
        return [compact(v, max_len=max_len) for v in value[:8]]
    if is_dataclass(value):
        return compact(asdict(value), max_len=max_len)
    text = str(value)
    if len(text) > max_len:
        return text[:max_len] + "...<truncated>"
    return value


def object_dict(obj: Any) -> dict[str, Any]:
    if is_dataclass(obj):
        return asdict(obj)
    if hasattr(obj, "__dict__"):
        return dict(obj.__dict__)
    return {"repr": repr(obj)}


def print_proof_bundle(label: str, shares: list[Any]) -> None:
    print(f"\n  proof_bundle={label}")
    print(f"  share_count={len(shares)}")
    if not shares:
        return

    first = object_dict(shares[0])
    interesting = {}
    for key, value in first.items():
        key_text = str(key)
        if (
            "statement" in key_text
            or "public" in key_text
            or "cipher" in key_text
            or "commit" in key_text
            or "proof_share_count" in key_text
            or "reveal_threshold" in key_text
            or "type" in key_text
        ):
            interesting[key_text] = compact(value)

    if not interesting:
        interesting = compact(first)

    print("  first_share_interesting_fields:")
    print(json.dumps(interesting, ensure_ascii=False, indent=2, default=str))


def main() -> None:
    reset_fhe_backend_cache()

    phase1 = run_phase1_initialization()
    pp = phase1["public_parameters"]

    participants = [
        Participant("P1", 10),
        Participant("P2", 20),
        Participant("P3", 30),
    ]

    phase2 = run_phase2_preparation(
        pp=pp,
        participants=participants,
        threshold=int(os.environ.get("POS_KMS_THRESHOLD", "1")),
    )

    phase3 = run_phase3_candidacy(
        pp=pp,
        participants=participants,
        phase2_result=phase2,
        proof_share_count=3,
    )

    validation_seed = step9_generate_random_seed(phase3.candidate_messages)
    validation = step11_verify_proofs(validation_seed, phase3.candidate_messages)

    print("=== Stage-10-D5-E proof gate diagnostics ===")
    print("validation_seed:", validation_seed)
    print("valid_participants:", validation.valid_participants)

    for participant_id, message in phase3.candidate_messages.items():
        print("\n============================================================")
        print("participant:", participant_id)
        print("encrypted_stake_prefix:", str(message.encrypted_stake)[:220])
        print("encrypted_prf_share_prefix:", str(message.encrypted_prf_share)[:220])
        print("ticket_layout:", compact(message.ticket_cipher_layout))

        print_proof_bundle("prf_proof_shares", list(message.prf_proof_shares))
        print_proof_bundle("stake_ciphertext_proof_shares", list(message.stake_ciphertext_proof_shares))
        print_proof_bundle("commitment_consistency_proof_shares", list(message.commitment_consistency_proof_shares))
        print_proof_bundle("ticket_proof_shares", list(message.ticket_proof_shares))

        records = validation.verification_records[participant_id]
        for record in records:
            data = object_dict(record)
            failing = [field for field in BOOL_FIELDS if data.get(field) is False]
            print("\n  verification_record:", data.get("statement_type"))
            print("  failing_fields:", failing)
            print("  all_fields:")
            print(json.dumps(compact(data), ensure_ascii=False, indent=2, default=str))

    if any(validation.valid_participants.values()):
        print("\nAt least one candidate passed step11.")
    else:
        print("\nNo candidate passed step11. Fix the failing proof binding fields above.")


if __name__ == "__main__":
    main()
