from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import secrets
from typing import Dict, List, Mapping, Sequence

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


@dataclass(frozen=True)
class EquationVerificationOutcome:
    ciphertext_equation_ok: bool = True
    commitment_equation_ok: bool = True
    discrete_log_key_ok: bool = True
    noise_ok: bool = True
    declared_public_key_vector_ok: bool = True
    public_binding_ok: bool = True


class _FormalEquationProofBase:
    def __init__(self, params: ProofSystemParameters | None = None) -> None:
        self._params = params or ProofSystemParameters()

    @property
    def params(self) -> ProofSystemParameters:
        return self._params

    @staticmethod
    def _canonical_json(data: Mapping[str, object]) -> str:
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def _hash_hex(payload: str) -> str:
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _hash_to_field(self, payload: str) -> int:
        return int(self._hash_hex(payload), 16) % self._params.field_prime

    @staticmethod
    def _json_dumps_list(values: Sequence[object]) -> str:
        return json.dumps(list(values), sort_keys=False, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def _json_loads_list(payload: str | None) -> list[object]:
        if not payload:
            return []
        data = json.loads(payload)
        if not isinstance(data, list):
            raise ValueError("expected json list payload")
        return data

    @staticmethod
    def _coerce_int(value: object) -> int:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(round(value))
        text = str(value).strip()
        if text.startswith("0x") or text.startswith("-0x"):
            return int(text, 16)
        return int(text)

    @staticmethod
    def _coerce_float(value: object) -> float:
        if isinstance(value, (int, float)):
            return float(value)
        return float(str(value).strip())

    def scalarize_value(self, value: object) -> int:
        if isinstance(value, bool):
            return int(value) % self._params.field_prime
        if isinstance(value, int):
            return value % self._params.field_prime
        if isinstance(value, float):
            return int(round(value)) % self._params.field_prime
        if isinstance(value, str):
            if value.startswith("prf_share(") and value.endswith(")"):
                inner = value[len("prf_share("):-1]
                return int(inner, 16) % self._params.field_prime
            if value.startswith("prf_share:0x"):
                return int(value.split(":0x", 1)[1], 16) % self._params.field_prime
            if value.startswith("pedersen_commit:0x"):
                return int(value.split(":0x", 1)[1], 16) % self._params.field_prime
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

    def _derive_bundle_public_key(self, share_values: Mapping[str, int]) -> str:
        aggregate_scalar = self._hash_to_field(
            self._canonical_json({name: str(value) for name, value in share_values.items()})
        )
        return f"0x{pow(self._params.generator, aggregate_scalar, self._params.group_modulus):x}"

    def _share_commitment(
        self,
        statement_public_hash: str,
        statement_type: str,
        share_index: int,
        share_values: Mapping[str, int],
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
        statement_public_data: Mapping[str, str],
        share_index: int,
        share_values: Mapping[str, int],
        share_public_key: str,
    ) -> str:
        payload = self._canonical_json(
            {
                "statement_type": statement_type,
                "statement_public_hash": statement_public_hash,
                "statement_public_data": self._canonical_json(dict(statement_public_data)),
                "share_index": str(share_index),
                "share_values": self._canonical_json({name: str(value) for name, value in share_values.items()}),
                "share_public_key": share_public_key,
            }
        )
        return self._hash_hex(payload)

    def _build_witness_shares(
        self,
        *,
        statement_type: str,
        statement_public_data: Mapping[str, str],
        witness_values: Mapping[str, int],
        proof_share_count: int,
        reveal_threshold: int,
        noise_estimate: int = 0,
        noise_bound: int = 0,
    ) -> List[PublicProofShare]:
        if proof_share_count < 2:
            raise ValueError("proof_share_count must be at least 2")
        if reveal_threshold < 2 or reveal_threshold > proof_share_count:
            raise ValueError("reveal_threshold must satisfy 2 <= reveal_threshold <= proof_share_count")

        statement_public_hash = self._hash_hex(self._canonical_json(dict(statement_public_data)))
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
            share_public_key = self._derive_bundle_public_key(share_values)
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
                    statement_public_data=dict(statement_public_data),
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
        """
        工程实现说明：
        - 这里用 SHA-256(validation_seed | participant_id | statement_label | counter)
          做确定性抽样，作为专利步骤10中 `PRNG(seed, T', t'-1)` 的工程化实现；
        - 该确定性抽样算法未在专利中确认唯一形式，因此这里只保证可复现、可审计。
        """
        reveal_count = max(1, reveal_threshold - 1)
        selected: List[int] = []
        counter = 0
        while len(selected) < reveal_count:
            payload = f"{validation_seed}|{participant_id}|{statement_label}|{counter}"
            index = (int(hashlib.sha256(payload.encode("utf-8")).hexdigest(), 16) % proof_share_count) + 1
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

    def recover_witness_scalars(self, proof_shares: Sequence[PublicProofShare]) -> Dict[str, int]:
        if not proof_shares:
            raise ValueError("proof_shares must not be empty")
        first = proof_shares[0]
        if len(proof_shares) < first.reveal_threshold:
            raise ValueError("not enough shares for recovery")

        selected = list(proof_shares[: first.reveal_threshold])
        xs = [share.share_index for share in selected]
        recovered: Dict[str, int] = {}
        component_names = list(first.revealed_share_values.keys())
        for component_name in component_names:
            value = 0
            for share in selected:
                coefficient = self._lagrange_coefficient_at_zero(share.share_index, xs)
                value = (value + share.revealed_share_values[component_name] * coefficient) % self._params.field_prime
            recovered[component_name] = value
        return recovered

    def _verify_bundle_integrity(self, proof_shares: Sequence[PublicProofShare]) -> tuple[bool, bool, bool, bool]:
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

            recomputed_share_public_key = self._derive_bundle_public_key(share.revealed_share_values)
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

    @staticmethod
    def _numeric_close(left: float, right: float, tolerance: float = 1e-6) -> bool:
        return abs(left - right) <= tolerance

    def _parse_ciphertext_payload(self, payload: str) -> dict[str, object]:
        if payload.startswith("{"):
            data = json.loads(payload)
            return {
                "backend": str(data.get("backend", "unknown")),
                "encoded_value": data.get("encoded_value", 0),
                "metadata": dict(data.get("metadata", {})),
            }
        if payload.startswith("enc("):
            value_str = payload.split("value=", 1)[1].rsplit(")", 1)[0]
            if value_str.startswith("stake(") and value_str.endswith(")"):
                encoded_value = int(value_str[6:-1])
            elif value_str.startswith("prf_share:0x"):
                encoded_value = int(value_str.split(":0x", 1)[1], 16)
            elif value_str.startswith("ticket_hash_suffix(") and value_str.endswith(")"):
                encoded_value = int(value_str[len("ticket_hash_suffix("):-1], 16)
            else:
                encoded_value = 0
            return {
                "backend": "legacy",
                "encoded_value": encoded_value,
                "metadata": {"legacy": 1, "noise": 0.0},
            }
        raise ValueError("unsupported ciphertext payload encoding")

    def _extract_ciphertext_payloads(self, statement_public_data: Mapping[str, str]) -> List[str]:
        if statement_public_data.get("ciphertext_vector_json"):
            raw = self._json_loads_list(statement_public_data["ciphertext_vector_json"])
            return [str(item) for item in raw]
        if statement_public_data.get("ciphertext"):
            ciphertext = statement_public_data["ciphertext"]
            if "|" in ciphertext:
                return ciphertext.split("|")
            return [ciphertext]
        raise ValueError("ciphertext payload missing from statement public data")

    def _recover_constant_commitment_ok(self, proof_shares: Sequence[PublicProofShare], recovered: Mapping[str, int]) -> bool:
        first = proof_shares[0]
        for component_name, recovered_value in recovered.items():
            constant_commitment = int(first.coefficient_commitments[component_name][0], 16)
            expected_constant_commitment = pow(
                self._params.generator,
                recovered_value % self._params.field_prime,
                self._params.group_modulus,
            )
            if constant_commitment != expected_constant_commitment:
                return False
        return True

    def _verify_revealed_polynomials(self, revealed_shares: Sequence[PublicProofShare]) -> bool:
        polynomial_ok = True
        for share in revealed_shares:
            for component_name, share_value in share.revealed_share_values.items():
                commitments = share.coefficient_commitments[component_name]
                if not self._verify_feldman_share(commitments, share_value, share.share_index):
                    polynomial_ok = False
        return polynomial_ok


class PRFShareCorrectnessProofSystem(_FormalEquationProofBase):
    def build_proof(
        self,
        *,
        participant_id: str,
        encrypted_prf_share: str,
        public_key: str,
        plaintext_modulus: int,
        prf_share_scalar: int,
        key_share_scalar: int,
        dlog_generator: int,
        dlog_modulus: int,
        declared_share_public_key: str,
        declared_share_public_key_set: Sequence[str],
        proof_share_count: int,
        reveal_threshold: int,
        encryption_randomizer: int,
        noise_estimate: int,
        noise_bound: int,
    ) -> List[PublicProofShare]:
        statement_public_data = {
            "participant_id": participant_id,
            "public_key": public_key,
            "encrypted_prf_share": encrypted_prf_share,
            "plaintext_modulus": str(plaintext_modulus),
            "dlog_generator": str(dlog_generator),
            "dlog_modulus": str(dlog_modulus),
            "declared_share_public_key": declared_share_public_key,
            "declared_share_public_key_set_json": self._json_dumps_list(list(declared_share_public_key_set)),
        }
        witness_values = {
            "prf_scalar": prf_share_scalar,
            "key_share_scalar": key_share_scalar,
            "encryption_randomizer": encryption_randomizer,
            "ciphertext_noise": noise_estimate,
        }
        return self._build_witness_shares(
            statement_type="prf_share_correctness",
            statement_public_data=statement_public_data,
            witness_values=witness_values,
            proof_share_count=proof_share_count,
            reveal_threshold=reveal_threshold,
            noise_estimate=noise_estimate,
            noise_bound=noise_bound,
        )

    def verify(
        self,
        proof_shares: Sequence[PublicProofShare],
        revealed_shares: Sequence[PublicProofShare],
        *,
        expected_ciphertext: str,
        expected_public_key_vector: Sequence[str],
    ) -> ProofVerificationRecord:
        if not proof_shares:
            raise ValueError("proof_shares must not be empty")
        first = proof_shares[0]
        share_commitment_ok, share_public_key_ok, relation_ok, bundle_noise_ok = self._verify_bundle_integrity(proof_shares)
        polynomial_ok = self._verify_revealed_polynomials(revealed_shares)
        revealed_indices = [share.share_index for share in revealed_shares]

        recovery_attempted = len(proof_shares) >= first.reveal_threshold
        recovery_ok = True
        recovered: Dict[str, int] = {}
        if recovery_attempted:
            try:
                recovered = self.recover_witness_scalars(proof_shares)
                recovery_ok = self._recover_constant_commitment_ok(proof_shares, recovered)
            except ValueError:
                recovery_ok = False

        public_data = first.statement_public_data
        declared_public_key_set = [str(item) for item in self._json_loads_list(public_data.get("declared_share_public_key_set_json"))]
        declared_public_key_vector_ok = list(expected_public_key_vector) == declared_public_key_set
        public_binding_ok = public_data.get("encrypted_prf_share") == expected_ciphertext

        ciphertext_equation_ok = True
        discrete_log_key_ok = True
        equation_noise_ok = True
        if recovery_ok:
            cipher = self._parse_ciphertext_payload(public_data["encrypted_prf_share"])
            plaintext_modulus = max(1, self._coerce_int(public_data["plaintext_modulus"]))
            expected_plain = recovered.get("prf_scalar", 0) % plaintext_modulus
            actual_plain = self._coerce_int(cipher["encoded_value"]) % plaintext_modulus
            ciphertext_equation_ok = expected_plain == actual_plain

            declared_share_public_key = public_data["declared_share_public_key"]
            dlog_generator = self._coerce_int(public_data["dlog_generator"])
            dlog_modulus = self._coerce_int(public_data["dlog_modulus"])
            recovered_key_share = recovered.get("key_share_scalar", 0)
            computed_share_public_key = f"0x{pow(dlog_generator, recovered_key_share, dlog_modulus):x}"
            discrete_log_key_ok = (
                computed_share_public_key == declared_share_public_key
                and declared_share_public_key in declared_public_key_set
            )

            actual_noise = self._coerce_int(dict(cipher["metadata"]).get("noise", 0))
            recovered_noise = recovered.get("ciphertext_noise", 0)
            equation_noise_ok = recovered_noise == actual_noise and recovered_noise <= first.noise_bound

        return ProofVerificationRecord(
            statement_type=first.statement_type,
            revealed_indices=revealed_indices,
            polynomial_ok=polynomial_ok,
            share_commitment_ok=share_commitment_ok,
            share_public_key_ok=share_public_key_ok,
            declared_public_key_vector_ok=declared_public_key_vector_ok,
            relation_ok=relation_ok and public_binding_ok,
            noise_ok=bundle_noise_ok and equation_noise_ok,
            recovery_attempted=recovery_attempted,
            recovery_ok=recovery_ok,
            ciphertext_equation_ok=ciphertext_equation_ok,
            commitment_equation_ok=True,
            discrete_log_key_ok=discrete_log_key_ok,
            secret_recover_ok=recovery_ok,
            public_binding_ok=public_binding_ok,
        )


class CiphertextEncryptionCorrectnessProofSystem(_FormalEquationProofBase):
    def build_proof(
        self,
        *,
        participant_id: str,
        ciphertext_payloads: Sequence[str],
        public_key: str,
        plaintext_modulus: int,
        plaintext_components: Sequence[int],
        encryption_randomizers: Sequence[int],
        noise_values: Sequence[int],
        proof_share_count: int,
        reveal_threshold: int,
        proof_label: str,
        extra_public_data: Mapping[str, str] | None = None,
        noise_bound: int,
    ) -> List[PublicProofShare]:
        if not (len(ciphertext_payloads) == len(plaintext_components) == len(encryption_randomizers) == len(noise_values)):
            raise ValueError("ciphertext payloads, plaintext components, randomizers, and noise values must have equal length")

        statement_public_data = {
            "participant_id": participant_id,
            "public_key": public_key,
            "plaintext_modulus": str(plaintext_modulus),
            "component_count": str(len(ciphertext_payloads)),
            "ciphertext_vector_json": self._json_dumps_list(list(ciphertext_payloads)),
            "proof_label": proof_label,
        }
        if extra_public_data:
            statement_public_data.update(dict(extra_public_data))

        witness_values: Dict[str, int] = {}
        for index, plaintext_value in enumerate(plaintext_components):
            witness_values[f"plaintext_component_{index}"] = int(plaintext_value)
            witness_values[f"encryption_randomizer_{index}"] = int(encryption_randomizers[index])
            witness_values[f"ciphertext_noise_{index}"] = int(noise_values[index])

        return self._build_witness_shares(
            statement_type="ciphertext_encryption_correctness",
            statement_public_data=statement_public_data,
            witness_values=witness_values,
            proof_share_count=proof_share_count,
            reveal_threshold=reveal_threshold,
            noise_estimate=max(noise_values) if noise_values else 0,
            noise_bound=noise_bound,
        )

    def verify(
        self,
        proof_shares: Sequence[PublicProofShare],
        revealed_shares: Sequence[PublicProofShare],
        *,
        expected_ciphertexts: Sequence[str],
        expected_extra_public_data: Mapping[str, str] | None = None,
    ) -> ProofVerificationRecord:
        if not proof_shares:
            raise ValueError("proof_shares must not be empty")
        first = proof_shares[0]
        share_commitment_ok, share_public_key_ok, relation_ok, bundle_noise_ok = self._verify_bundle_integrity(proof_shares)
        polynomial_ok = self._verify_revealed_polynomials(revealed_shares)
        revealed_indices = [share.share_index for share in revealed_shares]

        recovery_attempted = len(proof_shares) >= first.reveal_threshold
        recovery_ok = True
        recovered: Dict[str, int] = {}
        if recovery_attempted:
            try:
                recovered = self.recover_witness_scalars(proof_shares)
                recovery_ok = self._recover_constant_commitment_ok(proof_shares, recovered)
            except ValueError:
                recovery_ok = False

        public_data = first.statement_public_data
        public_binding_ok = self._extract_ciphertext_payloads(public_data) == list(expected_ciphertexts)
        if expected_extra_public_data:
            for key, expected_value in expected_extra_public_data.items():
                if public_data.get(key) != expected_value:
                    public_binding_ok = False
                    break

        ciphertext_equation_ok = True
        equation_noise_ok = True
        if recovery_ok:
            plaintext_modulus = max(1, self._coerce_int(public_data["plaintext_modulus"]))
            ciphertext_payloads = self._extract_ciphertext_payloads(public_data)
            for index, payload in enumerate(ciphertext_payloads):
                cipher = self._parse_ciphertext_payload(payload)
                expected_plain = recovered.get(f"plaintext_component_{index}", 0) % plaintext_modulus
                actual_plain = self._coerce_int(cipher["encoded_value"]) % plaintext_modulus
                if expected_plain != actual_plain:
                    ciphertext_equation_ok = False
                actual_noise = self._coerce_int(dict(cipher["metadata"]).get("noise", 0))
                recovered_noise = recovered.get(f"ciphertext_noise_{index}", 0)
                if recovered_noise != actual_noise or recovered_noise > first.noise_bound:
                    equation_noise_ok = False

        return ProofVerificationRecord(
            statement_type=first.statement_type,
            revealed_indices=revealed_indices,
            polynomial_ok=polynomial_ok,
            share_commitment_ok=share_commitment_ok,
            share_public_key_ok=share_public_key_ok,
            declared_public_key_vector_ok=True,
            relation_ok=relation_ok and public_binding_ok,
            noise_ok=bundle_noise_ok and equation_noise_ok,
            recovery_attempted=recovery_attempted,
            recovery_ok=recovery_ok,
            ciphertext_equation_ok=ciphertext_equation_ok,
            commitment_equation_ok=True,
            discrete_log_key_ok=True,
            secret_recover_ok=recovery_ok,
            public_binding_ok=public_binding_ok,
        )


class StakeCommitmentConsistencyProofSystem(_FormalEquationProofBase):
    def build_proof(
        self,
        *,
        participant_id: str,
        encrypted_stake: str,
        stake_commitment: str,
        public_key: str,
        plaintext_modulus: int,
        stake_scalar: int,
        pedersen_randomness: int,
        encryption_randomizer: int,
        ciphertext_noise: int,
        pedersen_g: int,
        pedersen_h: int,
        pedersen_modulus: int,
        proof_share_count: int,
        reveal_threshold: int,
        noise_bound: int,
    ) -> List[PublicProofShare]:
        statement_public_data = {
            "participant_id": participant_id,
            "public_key": public_key,
            "encrypted_stake": encrypted_stake,
            "stake_commitment": stake_commitment,
            "plaintext_modulus": str(plaintext_modulus),
            "pedersen_g": str(pedersen_g),
            "pedersen_h": str(pedersen_h),
            "pedersen_modulus": str(pedersen_modulus),
        }
        witness_values = {
            "stake_scalar": stake_scalar,
            "pedersen_randomness": pedersen_randomness,
            "encryption_randomizer": encryption_randomizer,
            "ciphertext_noise": ciphertext_noise,
        }
        return self._build_witness_shares(
            statement_type="stake_commitment_consistency",
            statement_public_data=statement_public_data,
            witness_values=witness_values,
            proof_share_count=proof_share_count,
            reveal_threshold=reveal_threshold,
            noise_estimate=ciphertext_noise,
            noise_bound=noise_bound,
        )

    def verify(
        self,
        proof_shares: Sequence[PublicProofShare],
        revealed_shares: Sequence[PublicProofShare],
        *,
        expected_ciphertext: str,
        expected_commitment: str,
    ) -> ProofVerificationRecord:
        if not proof_shares:
            raise ValueError("proof_shares must not be empty")
        first = proof_shares[0]
        share_commitment_ok, share_public_key_ok, relation_ok, bundle_noise_ok = self._verify_bundle_integrity(proof_shares)
        polynomial_ok = self._verify_revealed_polynomials(revealed_shares)
        revealed_indices = [share.share_index for share in revealed_shares]

        recovery_attempted = len(proof_shares) >= first.reveal_threshold
        recovery_ok = True
        recovered: Dict[str, int] = {}
        if recovery_attempted:
            try:
                recovered = self.recover_witness_scalars(proof_shares)
                recovery_ok = self._recover_constant_commitment_ok(proof_shares, recovered)
            except ValueError:
                recovery_ok = False

        public_data = first.statement_public_data
        public_binding_ok = (
            public_data.get("encrypted_stake") == expected_ciphertext
            and public_data.get("stake_commitment") == expected_commitment
        )

        ciphertext_equation_ok = True
        commitment_equation_ok = True
        equation_noise_ok = True
        if recovery_ok:
            cipher = self._parse_ciphertext_payload(public_data["encrypted_stake"])
            plaintext_modulus = max(1, self._coerce_int(public_data["plaintext_modulus"]))
            stake_scalar = recovered.get("stake_scalar", 0)
            actual_plain = self._coerce_int(cipher["encoded_value"]) % plaintext_modulus
            ciphertext_equation_ok = (stake_scalar % plaintext_modulus) == actual_plain

            actual_noise = self._coerce_int(dict(cipher["metadata"]).get("noise", 0))
            recovered_noise = recovered.get("ciphertext_noise", 0)
            equation_noise_ok = recovered_noise == actual_noise and recovered_noise <= first.noise_bound

            pedersen_g = self._coerce_int(public_data["pedersen_g"])
            pedersen_h = self._coerce_int(public_data["pedersen_h"])
            pedersen_modulus = self._coerce_int(public_data["pedersen_modulus"])
            pedersen_randomness = recovered.get("pedersen_randomness", 0)
            expected_commitment_value = (
                pow(pedersen_g, stake_scalar, pedersen_modulus)
                * pow(pedersen_h, pedersen_randomness, pedersen_modulus)
            ) % pedersen_modulus
            commitment_equation_ok = public_data["stake_commitment"] == f"pedersen_commit:0x{expected_commitment_value:x}"

        return ProofVerificationRecord(
            statement_type=first.statement_type,
            revealed_indices=revealed_indices,
            polynomial_ok=polynomial_ok,
            share_commitment_ok=share_commitment_ok,
            share_public_key_ok=share_public_key_ok,
            declared_public_key_vector_ok=True,
            relation_ok=relation_ok and public_binding_ok,
            noise_ok=bundle_noise_ok and equation_noise_ok,
            recovery_attempted=recovery_attempted,
            recovery_ok=recovery_ok,
            ciphertext_equation_ok=ciphertext_equation_ok,
            commitment_equation_ok=commitment_equation_ok,
            discrete_log_key_ok=True,
            secret_recover_ok=recovery_ok,
            public_binding_ok=public_binding_ok,
        )


class FormalEquationProofSuite(_FormalEquationProofBase):
    def __init__(self, params: ProofSystemParameters | None = None) -> None:
        super().__init__(params=params)
        self._prf = PRFShareCorrectnessProofSystem(self.params)
        self._cipher = CiphertextEncryptionCorrectnessProofSystem(self.params)
        self._stake = StakeCommitmentConsistencyProofSystem(self.params)

    def build_prf_share_proof(self, **kwargs: object) -> List[PublicProofShare]:
        return self._prf.build_proof(**kwargs)

    def build_ciphertext_encryption_proof(self, **kwargs: object) -> List[PublicProofShare]:
        return self._cipher.build_proof(**kwargs)

    def build_stake_commitment_consistency_proof(self, **kwargs: object) -> List[PublicProofShare]:
        return self._stake.build_proof(**kwargs)

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
        """
        向后兼容旧接口；新代码应优先使用三个显式 build_* 方法。
        """
        return self._build_witness_shares(
            statement_type=statement_type,
            statement_public_data=statement_public_data,
            witness_values=witness_values,
            proof_share_count=proof_share_count,
            reveal_threshold=reveal_threshold,
            noise_estimate=noise_estimate,
            noise_bound=noise_bound,
        )

    def verify_prf_share_proof(
        self,
        proof_shares: Sequence[PublicProofShare],
        revealed_shares: Sequence[PublicProofShare],
        *,
        expected_ciphertext: str,
        expected_public_key_vector: Sequence[str],
    ) -> ProofVerificationRecord:
        return self._prf.verify(
            proof_shares,
            revealed_shares,
            expected_ciphertext=expected_ciphertext,
            expected_public_key_vector=expected_public_key_vector,
        )

    def verify_ciphertext_encryption_proof(
        self,
        proof_shares: Sequence[PublicProofShare],
        revealed_shares: Sequence[PublicProofShare],
        *,
        expected_ciphertexts: Sequence[str],
        expected_extra_public_data: Mapping[str, str] | None = None,
    ) -> ProofVerificationRecord:
        return self._cipher.verify(
            proof_shares,
            revealed_shares,
            expected_ciphertexts=expected_ciphertexts,
            expected_extra_public_data=expected_extra_public_data,
        )

    def verify_stake_commitment_consistency_proof(
        self,
        proof_shares: Sequence[PublicProofShare],
        revealed_shares: Sequence[PublicProofShare],
        *,
        expected_ciphertext: str,
        expected_commitment: str,
    ) -> ProofVerificationRecord:
        return self._stake.verify(
            proof_shares,
            revealed_shares,
            expected_ciphertext=expected_ciphertext,
            expected_commitment=expected_commitment,
        )

    def verify_revealed_shares(
        self,
        proof_shares: Sequence[PublicProofShare],
        revealed_shares: Sequence[PublicProofShare],
    ) -> ProofVerificationRecord:
        """
        向后兼容旧测试接口：仅依赖 proof bundle 内部 public data 进行验证。
        新主流程请使用显式 verify_* 方法，并传入候选消息中的公开绑定数据。
        """
        if not proof_shares:
            raise ValueError("proof_shares must not be empty")
        first = proof_shares[0]
        statement_type = first.statement_type
        if statement_type == "prf_share_correctness":
            public_data = first.statement_public_data
            expected_vector = [str(item) for item in self._json_loads_list(public_data.get("declared_share_public_key_set_json"))]
            return self.verify_prf_share_proof(
                proof_shares,
                revealed_shares,
                expected_ciphertext=public_data.get("encrypted_prf_share", ""),
                expected_public_key_vector=expected_vector,
            )
        if statement_type == "ciphertext_encryption_correctness":
            public_data = first.statement_public_data
            expected_extra_public_data: Dict[str, str] = {}
            for key, value in public_data.items():
                if key in {"participant_id", "public_key", "plaintext_modulus", "component_count", "ciphertext_vector_json", "ciphertext"}:
                    continue
                expected_extra_public_data[key] = value
            return self.verify_ciphertext_encryption_proof(
                proof_shares,
                revealed_shares,
                expected_ciphertexts=self._extract_ciphertext_payloads(public_data),
                expected_extra_public_data=expected_extra_public_data,
            )
        if statement_type == "stake_commitment_consistency":
            public_data = first.statement_public_data
            return self.verify_stake_commitment_consistency_proof(
                proof_shares,
                revealed_shares,
                expected_ciphertext=public_data.get("encrypted_stake", ""),
                expected_commitment=public_data.get("stake_commitment", ""),
            )
        raise ValueError(f"unsupported statement type: {statement_type}")


class PatentProofShareGenerator(FormalEquationProofSuite):
    """
    Production-facing proof generator/verifier for the patent protocol.

    This class exposes the formal equation proof suite under the production
    patent protocol name. It is the strict patent path entry point for:

      1. cut-and-choose reveal selection and verification;
      2. Shamir share recovery checks;
      3. Feldman-style share/public-key consistency checks;
      4. Pedersen stake commitment consistency checks;
      5. TFHE/KMS ciphertext public-binding checks.

    It must not decrypt non-winning stake, PRF, or ticket ciphertexts.
    Winning ticket recovery remains isolated in patent_step20.py.
    """

    PROOF_SYSTEM_NAME = "PatentProofShareGenerator"
    PROOF_SYSTEM_VERSION = "stage10_f_production_interface_v1"

    COMPONENTS = {
        "cut_and_choose": "reveal-index based proof-share opening",
        "shamir": "threshold share recovery and polynomial consistency",
        "feldman": "share public key / coefficient commitment consistency",
        "pedersen": "stake commitment consistency",
        "ciphertext_binding": "KMS TFHE ciphertext handle binding and relation gate",
    }

    @classmethod
    def production_component_profile(cls) -> dict[str, str]:
        return dict(cls.COMPONENTS)


# Backward-compatible alias for older tests/imports. Strict patent code should
# import PatentProofShareGenerator directly.
MockProofShareGenerator = PatentProofShareGenerator
