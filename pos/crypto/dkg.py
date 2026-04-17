from __future__ import annotations

import secrets
from typing import Dict, List

from pos.crypto.fhe import build_threshold_key_material
from pos.models.common import PublicParameters
from pos.models.stage2 import (
    DistributedKeyGenerationResult,
    Participant,
    PolynomialCommitmentBroadcast,
    PrivateShareDelivery,
    SharePublicKey,
    ThresholdFHEPrivateKeyShare,
)


class DistributedKeyGenerator:
    """
    阶段2统一 DKG。

    当前实现策略：
    1. 先保留 Feldman/VSS 风格的真实分布式秘密共享流程，得到每个参与者的聚合标量分片；
    2. 再把这组参与者集合交给同一个门限 FHE 后端，生成唯一的一套完整公钥与私钥份额句柄；
    3. 最终输出统一的 DistributedKeyGenerationResult，供阶段3/4/5 直接消费。

    这样阶段2就同时承担：
    - DKG 数学分片/承诺生成；
    - 终版门限 FHE 密钥材料落地；
    - 阶段4/5 解密份额来源固定为阶段2，而不是后续再次自建会话。
    """

    @staticmethod
    def _sample_polynomial(q: int, degree: int) -> List[int]:
        coefficients = [secrets.randbelow(q) for _ in range(degree + 1)]
        if coefficients[0] == 0:
            coefficients[0] = secrets.randbelow(q - 1) + 1
        return coefficients

    @staticmethod
    def _evaluate_polynomial(coefficients: List[int], x: int, q: int) -> int:
        value = 0
        for coefficient in reversed(coefficients):
            value = (value * x + coefficient) % q
        return value

    @staticmethod
    def _commit_coefficients(pp: PublicParameters, coefficients: List[int]) -> List[int]:
        return [pow(pp.g_prime, coefficient, pp.p) for coefficient in coefficients]

    @staticmethod
    def _verify_share(
        pp: PublicParameters,
        recipient_index: int,
        share_value: int,
        coefficient_commitments: List[int],
    ) -> bool:
        left = pow(pp.g_prime, share_value % pp.q, pp.p)

        right = 1
        exponent_power = 1
        for commitment in coefficient_commitments:
            right = (right * pow(commitment, exponent_power, pp.p)) % pp.p
            exponent_power = (exponent_power * recipient_index) % pp.q

        return left == right

    def distributed_keygen(
        self,
        pp: PublicParameters,
        threshold: int,
        participants: List[Participant],
    ) -> DistributedKeyGenerationResult:
        participant_count = len(participants)
        if participant_count < 2:
            raise ValueError("participant_count must be at least 2")
        if threshold < 2 or threshold > participant_count:
            raise ValueError("threshold must satisfy 2 <= threshold <= participant_count")

        degree = threshold - 1
        participant_index_by_id = {
            participant.participant_id: index + 1
            for index, participant in enumerate(participants)
        }
        participant_ids = [participant.participant_id for participant in participants]

        polynomial_commitments: Dict[str, PolynomialCommitmentBroadcast] = {}
        private_share_deliveries: Dict[str, Dict[str, PrivateShareDelivery]] = {
            participant.participant_id: {}
            for participant in participants
        }

        for sender in participants:
            sender_id = sender.participant_id
            coefficients = self._sample_polynomial(pp.q, degree)
            commitments = self._commit_coefficients(pp, coefficients)

            polynomial_commitments[sender_id] = PolynomialCommitmentBroadcast(
                participant_id=sender_id,
                coefficient_commitments=[f"0x{value:x}" for value in commitments],
            )

            for recipient in participants:
                recipient_id = recipient.participant_id
                recipient_index = participant_index_by_id[recipient_id]
                share_value = self._evaluate_polynomial(coefficients, recipient_index, pp.q)

                private_share_deliveries[recipient_id][sender_id] = PrivateShareDelivery(
                    sender_id=sender_id,
                    recipient_id=recipient_id,
                    share_value=share_value,
                )

        aggregated_shares: Dict[str, int] = {}
        share_public_keys: Dict[str, SharePublicKey] = {}

        for recipient in participants:
            recipient_id = recipient.participant_id
            recipient_index = participant_index_by_id[recipient_id]
            aggregated_share = 0

            for sender in participants:
                sender_id = sender.participant_id
                delivery = private_share_deliveries[recipient_id][sender_id]
                commitments_hex = polynomial_commitments[sender_id].coefficient_commitments
                commitment_values = [int(value, 16) for value in commitments_hex]

                if not self._verify_share(
                    pp=pp,
                    recipient_index=recipient_index,
                    share_value=delivery.share_value,
                    coefficient_commitments=commitment_values,
                ):
                    raise ValueError(
                        f"Invalid private share from sender {sender_id} to recipient {recipient_id}"
                    )

                aggregated_share = (aggregated_share + delivery.share_value) % pp.q

            aggregated_shares[recipient_id] = aggregated_share
            share_public_keys[recipient_id] = SharePublicKey(
                participant_id=recipient_id,
                share_public_key=f"0x{pow(pp.g_prime, aggregated_share, pp.p):x}",
            )

        public_commitment_value = 1
        for sender in participants:
            sender_id = sender.participant_id
            constant_commitment = int(
                polynomial_commitments[sender_id].coefficient_commitments[0],
                16,
            )
            public_commitment_value = (public_commitment_value * constant_commitment) % pp.p

        generated_key_material = build_threshold_key_material(
            participant_ids=participant_ids,
            threshold=threshold,
        )

        threshold_fhe_private_key_shares: Dict[str, ThresholdFHEPrivateKeyShare] = {}
        for participant_id in participant_ids:
            threshold_fhe_private_key_shares[participant_id] = ThresholdFHEPrivateKeyShare(
                participant_id=participant_id,
                secret_share_scalar=aggregated_shares[participant_id],
                fhe_private_key_share=generated_key_material.participant_private_share_handles[participant_id],
                corresponding_share_public_key=share_public_keys[participant_id].share_public_key,
                backend_name=generated_key_material.backend_name,
                key_material_reference=generated_key_material.keyset_reference,
            )

        return DistributedKeyGenerationResult(
            public_key=generated_key_material.public_key,
            threshold_fhe_private_key_shares=threshold_fhe_private_key_shares,
            share_public_keys=share_public_keys,
            polynomial_commitments=polynomial_commitments,
            private_share_deliveries=private_share_deliveries,
            threshold=threshold,
            fhe_backend_name=generated_key_material.backend_name,
            fhe_keyset_reference=generated_key_material.keyset_reference,
            secret_commitment_public_key=f"0x{public_commitment_value:x}",
        )


MockDistributedKeyGenerator = DistributedKeyGenerator
