from __future__ import annotations

import secrets
from typing import Dict, List

from pos.models.common import PublicParameters
from pos.models.stage2 import (
    DecryptKeyShare,
    DistributedKeyGenerationResult,
    Participant,
    PolynomialCommitmentBroadcast,
    PrivateShareDelivery,
    SharePublicKey,
)


class DistributedKeyGenerator:
    """
    基于整数群和 Feldman VSS 风格承诺的分布式密钥生成。

    本实现对应专利步骤2中的真实数学流程：
    1. 每个参与者 P_i 在 Z_q 上采样一个 (t-1) 次秘密多项式 f_i(x)
    2. 广播系数承诺 C_{i,k} = g'^{a_{i,k}} mod p
    3. 向每个接收方 P_j 私下发送分片 s_{i->j} = f_i(j) mod q
    4. 接收方验证 g'^{s_{i->j}} == Π_k C_{i,k}^{j^k} mod p
    5. 接收方把所有通过验证的分片求和，得到自己的解密份额 sk_j
    6. 输出：
       - 完整公钥 PK = Π_i C_{i,0} = g'^{Σ_i a_{i,0}} mod p
       - 各方解密密钥分片 sk_j
       - 各方分片公钥 pk_j = g'^{sk_j} mod p

    说明：
    - 这是一个真实的多项式分发 + 指数承诺 + 份额验证过程；
    - 由于当前项目的 FHE 还未替换为真实门限 FHE，本阶段的 public_key / decrypt_share_key
      先作为后续 FHE 层的输入占位，但其生成过程本身已经具备真实数学基础；
    - 当前先实现半诚实/同步模型，不处理投诉、重发和恶意广播回滚。
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

        decrypt_key_shares: Dict[str, DecryptKeyShare] = {}
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

            decrypt_key_shares[recipient_id] = DecryptKeyShare(
                participant_id=recipient_id,
                decrypt_share_key=aggregated_share,
            )
            share_public_keys[recipient_id] = SharePublicKey(
                participant_id=recipient_id,
                share_public_key=f"0x{pow(pp.g_prime, aggregated_share, pp.p):x}",
            )

        public_key_value = 1
        for sender in participants:
            sender_id = sender.participant_id
            constant_commitment = int(
                polynomial_commitments[sender_id].coefficient_commitments[0],
                16,
            )
            public_key_value = (public_key_value * constant_commitment) % pp.p

        return DistributedKeyGenerationResult(
            public_key=f"0x{public_key_value:x}",
            decrypt_key_shares=decrypt_key_shares,
            share_public_keys=share_public_keys,
            polynomial_commitments=polynomial_commitments,
            private_share_deliveries=private_share_deliveries,
            threshold=threshold,
        )


MockDistributedKeyGenerator = DistributedKeyGenerator