from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import secrets
from typing import Dict, List, Sequence

from pos.models.stage3 import PublicProofShare
from pos.models.stage4 import ProofVerificationRecord

PROOF_GROUP_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
PROOF_GROUP_Q = (PROOF_GROUP_P - 1) // 2
PROOF_GENERATOR = 4


@dataclass(frozen=True)
class ProofSystemParameters:
    field_prime: int = PROOF_GROUP_Q
    group_modulus: int = PROOF_GROUP_P
    generator: int = PROOF_GENERATOR


class CutAndChooseProofSystem:
    def __init__(self, params: ProofSystemParameters | None = None) -> None:
        self._params = params or ProofSystemParameters()

    @property
    def params(self) -> ProofSystemParameters:
        return self._params

    @staticmethod
    def _canonical_json(data: Dict[str, str]) -> str:
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def _hash_hex(payload: str) -> str:
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _hash_to_field(self, payload: str) -> int:
        return int(self._hash_hex(payload), 16) % self._params.field_prime

    def scalarize_value(self, value: object) -> int:
        if isinstance(value, bool):
            return int(value) % self._params.field_prime
        if isinstance(value, int):
            return value % self._params.field_prime
        if isinstance(value, str):
            if value.startswith("prf_share(") and value.endswith(")"):
                inner = value[len("prf_share("):-1]
                return int(inner, 16) % self._params.field_prime
            if value.startswith("prf_share:0x"):
                return int(value.split(":0x", 1)[1], 16) % self._params.field_prime
            if value.startswith("pedersen_commit("):
                return self._hash_to_field(value)
            if value.startswith("enc("):
                return self._hash_to_field(value)
            try:
                return int(value, 16) % self._params.field_prime
            except ValueError:
                return self._hash_to_field(value)
        return self._hash_to_field(repr(value))

    def _sample_polynomial(self, constant_term: int, degree: int) -> List[int]:
        coefficients = [constant_term % self._params.field_prime]
        for _ in range(degree):
            coefficients.append(secrets.randbelow(self._params.field_prime))
        return coefficients

    def _evaluate_polynomial(self, coefficients: Sequence[int], x: int) -> int:
        value = 0
        for coefficient in reversed(coefficients):
            value = (value * x + coefficient) % self._params.field_prime
        return value

    def _lagrange_coefficient_at_zero(self, x_i: int, xs: Sequence[int]) -> int:
        numerator = 1
        denominator = 1
        for x_j in xs:
            if x_j == x_i:
                continue
            numerator = (numerator * (-x_j % self._params.field_prime)) % self._params.field_prime
            denominator = (denominator * (x_i - x_j)) % self._params.field_prime
        denominator_inv = pow(denominator % self._params.field_prime, -1, self._params.field_prime)
        return numerator * denominator_inv % self._params.field_prime

    def _commit_coefficients(self, coefficients: Sequence[int]) -> List[str]:
        return [
            f"0x{pow(self._params.generator, coefficient, self._params.group_modulus):x}"
            for coefficient in coefficients
        ]

    def _verify_feldman_share(self, commitments: Sequence[str], share_value: int, share_index: int) -> bool:
        left = pow(self._params.generator, share_value % self._params.field_prime, self._params.group_modulus)
        right = 1
        exponent_power = 1
        for commitment_hex in commitments:
            commitment_value = int(commitment_hex, 16)
            right = (right * pow(commitment_value, exponent_power, self._params.group_modulus)) % self._params.group_modulus
            exponent_power = (exponent_power * share_index) % self._params.field_prime
        return left == right

    def _derive_share_public_key(self, share_values: Dict[str, int]) -> str:
        aggregate_scalar = self._hash_to_field(
            self._canonical_json({name: str(value) for name, value in share_values.items()})
        )
        return f"0x{pow(self._params.generator, aggregate_scalar, self._params.group_modulus):x}"

    def _share_commitment(
        self,
        statement_public_hash: str,
        statement_type: str,
        share_index: int,
        share_values: Dict[str, int],
        reveal_nonce: str,
    ) -> str:
        payload = self._canonical_json(
            {
                "statement_public_hash": statement_public_hash,
                "statement_type": statement_type,
                "share_index": str(share_index),
                "share_values": self._canonical_json({name: str(value) for name, value in share_values.items()}),
                "reveal_nonce": reveal_nonce,
            }
        )
        return self._hash_hex(payload)

    def _relation_commitment(
        self,
        statement_type: str,
        statement_public_hash: str,
        statement_public_data: Dict[str, str],
        share_index: int,
        share_values: Dict[str, int],
        share_public_key: str,
    ) -> str:
        if statement_type == "prf_share_correctness":
            relation_payload = {
                "statement_public_hash": statement_public_hash,
                "statement_type": statement_type,
                "participant_id": statement_public_data.get("participant_id", ""),
                "public_key": statement_public_data.get("public_key", ""),
                "encrypted_prf_share": statement_public_data.get("encrypted_prf_share", ""),
                "share_index": str(share_index),
                "prf_scalar_share": str(share_values["prf_scalar"]),
                "share_public_key": share_public_key,
            }
        elif statement_type == "ciphertext_encryption_correctness":
            relation_payload = {
                "statement_public_hash": statement_public_hash,
                "statement_type": statement_type,
                "participant_id": statement_public_data.get("participant_id", ""),
                "public_key": statement_public_data.get("public_key", ""),
                "ciphertext": statement_public_data.get("ciphertext", ""),
                "plaintext_label": statement_public_data.get("plaintext_label", ""),
                "share_index": str(share_index),
                "plaintext_scalar_share": str(share_values["plaintext_scalar"]),
                "share_public_key": share_public_key,
            }
        elif statement_type == "stake_commitment_consistency":
            relation_payload = {
                "statement_public_hash": statement_public_hash,
                "statement_type": statement_type,
                "participant_id": statement_public_data.get("participant_id", ""),
                "public_key": statement_public_data.get("public_key", ""),
                "ciphertext": statement_public_data.get("ciphertext", ""),
                "stake_commitment": statement_public_data.get("stake_commitment", ""),
                "share_index": str(share_index),
                "stake_scalar_share": str(share_values["stake_scalar"]),
                "randomness_scalar_share": str(share_values["randomness_scalar"]),
                "share_public_key": share_public_key,
            }
        else:
            raise ValueError(f"Unsupported statement_type: {statement_type}")

        return self._hash_hex(self._canonical_json(relation_payload))

    def build_proof_shares(
        self,
        *,
        statement_type: str,
        statement_public_data: Dict[str, str],
        witness_values: Dict[str, int],
        proof_share_count: int,
        reveal_threshold: int,
        noise_estimate: int = 0,
        noise_bound: int = 0,
    ) -> List[PublicProofShare]:
        if proof_share_count < 2:
            raise ValueError("proof_share_count must be at least 2")
        if reveal_threshold < 2 or reveal_threshold > proof_share_count:
            raise ValueError("reveal_threshold must satisfy 2 <= reveal_threshold <= proof_share_count")

        statement_public_hash = self._hash_hex(self._canonical_json(statement_public_data))
        degree = reveal_threshold - 1

        coefficient_commitments: Dict[str, List[str]] = {}
        component_shares: Dict[str, Dict[int, int]] = {name: {} for name in witness_values}

        for component_name, witness_value in witness_values.items():
            coefficients = self._sample_polynomial(witness_value % self._params.field_prime, degree)
            coefficient_commitments[component_name] = self._commit_coefficients(coefficients)
            for share_index in range(1, proof_share_count + 1):
                component_shares[component_name][share_index] = self._evaluate_polynomial(coefficients, share_index)

        proof_shares: List[PublicProofShare] = []
        for share_index in range(1, proof_share_count + 1):
            share_values = {
                component_name: component_shares[component_name][share_index]
                for component_name in witness_values
            }
            reveal_nonce = f"0x{secrets.randbelow(self._params.field_prime):x}"
            share_public_key = self._derive_share_public_key(share_values)
            share_commitment = self._share_commitment(
                statement_public_hash=statement_public_hash,
                statement_type=statement_type,
                share_index=share_index,
                share_values=share_values,
                reveal_nonce=reveal_nonce,
            )
            relation_commitment = self._relation_commitment(
                statement_type=statement_type,
                statement_public_hash=statement_public_hash,
                statement_public_data=statement_public_data,
                share_index=share_index,
                share_values=share_values,
                share_public_key=share_public_key,
            )

            proof_shares.append(
                PublicProofShare(
                    share_index=share_index,
                    proof_share=f"{statement_type}_proof({share_commitment})",
                    statement_type=statement_type,
                    statement_public_hash=statement_public_hash,
                    proof_share_count=proof_share_count,
                    reveal_threshold=reveal_threshold,
                    coefficient_commitments=coefficient_commitments,
                    share_commitment=share_commitment,
                    share_public_key=share_public_key,
                    relation_commitment=relation_commitment,
                    noise_estimate=noise_estimate,
                    noise_bound=noise_bound,
                    statement_public_data=statement_public_data,
                    revealed_share_values=share_values,
                    reveal_nonce=reveal_nonce,
                )
            )

        return proof_shares

    def build_share_public_keys(self, proof_shares: Sequence[PublicProofShare]) -> List[str]:
        return [share.share_public_key for share in proof_shares]

    def derive_reveal_indices(
        self,
        *,
        validation_seed: str,
        participant_id: str,
        statement_label: str,
        proof_share_count: int,
        reveal_threshold: int,
    ) -> List[int]:
        reveal_count = max(1, reveal_threshold - 1)
        selected: List[int] = []
        counter = 0

        while len(selected) < reveal_count:
            payload = f"{validation_seed}|{participant_id}|{statement_label}|{counter}"
            index = (int(hashlib.sha256(payload.encode('utf-8')).hexdigest(), 16) % proof_share_count) + 1
            if index not in selected:
                selected.append(index)
            counter += 1

        return selected

    def reveal_selected_shares(
        self,
        proof_shares: Sequence[PublicProofShare],
        reveal_indices: Sequence[int],
    ) -> List[PublicProofShare]:
        share_map = {share.share_index: share for share in proof_shares}
        return [share_map[index] for index in reveal_indices]

    def recover_witness_scalars(self, revealed_shares: Sequence[PublicProofShare]) -> Dict[str, int]:
        if not revealed_shares:
            raise ValueError("revealed_shares must not be empty")

        first = revealed_shares[0]
        if len(revealed_shares) < first.reveal_threshold:
            raise ValueError("not enough shares for recovery")

        xs = [share.share_index for share in revealed_shares]
        recovered: Dict[str, int] = {}

        component_names = list(first.revealed_share_values.keys())
        for component_name in component_names:
            value = 0
            for share in revealed_shares:
                coefficient = self._lagrange_coefficient_at_zero(share.share_index, xs)
                value = (
                    value + share.revealed_share_values[component_name] * coefficient
                ) % self._params.field_prime
            recovered[component_name] = value

        return recovered

    def _verify_share_bundle_integrity(
        self,
        proof_shares: Sequence[PublicProofShare],
    ) -> tuple[bool, bool, bool, bool]:
        """
        当前工程原型里，每个 proof share 都携带了 revealed_share_values / reveal_nonce。
        因此可以对整个已发布 bundle 做完整性检查，而不只是检查被抽中的 subset。
        这样任何一个 share_commitment / share_public_key / relation_commitment 的篡改都会被发现。
        """
        share_commitment_ok = True
        share_public_key_ok = True
        relation_ok = True
        noise_ok = True

        for share in proof_shares:
            recomputed_share_commitment = self._share_commitment(
                share.statement_public_hash,
                share.statement_type,
                share.share_index,
                share.revealed_share_values,
                share.reveal_nonce,
            )
            if recomputed_share_commitment != share.share_commitment:
                share_commitment_ok = False

            recomputed_share_public_key = self._derive_share_public_key(share.revealed_share_values)
            if recomputed_share_public_key != share.share_public_key:
                share_public_key_ok = False

            recomputed_relation_commitment = self._relation_commitment(
                share.statement_type,
                share.statement_public_hash,
                share.statement_public_data,
                share.share_index,
                share.revealed_share_values,
                share.share_public_key,
            )
            if recomputed_relation_commitment != share.relation_commitment:
                relation_ok = False

            if share.noise_estimate > share.noise_bound:
                noise_ok = False

        return share_commitment_ok, share_public_key_ok, relation_ok, noise_ok

    def verify_revealed_shares(
        self,
        proof_shares: Sequence[PublicProofShare],
        revealed_shares: Sequence[PublicProofShare],
    ) -> ProofVerificationRecord:
        if not proof_shares:
            raise ValueError("proof_shares must not be empty")

        first = proof_shares[0]
        revealed_indices = [share.share_index for share in revealed_shares]

        polynomial_ok = True
        share_commitment_ok, share_public_key_ok, relation_ok, noise_ok = self._verify_share_bundle_integrity(
            proof_shares
        )

        recovery_attempted = len(revealed_shares) >= first.reveal_threshold
        recovery_ok = True

        for share in revealed_shares:
            for component_name, share_value in share.revealed_share_values.items():
                commitments = share.coefficient_commitments[component_name]
                if not self._verify_feldman_share(commitments, share_value, share.share_index):
                    polynomial_ok = False

        if recovery_attempted:
            try:
                recovered = self.recover_witness_scalars(revealed_shares[: first.reveal_threshold])
                for component_name, recovered_value in recovered.items():
                    constant_commitment = int(first.coefficient_commitments[component_name][0], 16)
                    expected_constant_commitment = pow(
                        self._params.generator,
                        recovered_value % self._params.field_prime,
                        self._params.group_modulus,
                    )
                    if constant_commitment != expected_constant_commitment:
                        recovery_ok = False
                        break
            except ValueError:
                recovery_ok = False

        return ProofVerificationRecord(
            statement_type=first.statement_type,
            revealed_indices=revealed_indices,
            polynomial_ok=polynomial_ok,
            share_commitment_ok=share_commitment_ok,
            share_public_key_ok=share_public_key_ok,
            relation_ok=relation_ok,
            noise_ok=noise_ok,
            recovery_attempted=recovery_attempted,
            recovery_ok=recovery_ok,
        )


MockProofShareGenerator = CutAndChooseProofSystem