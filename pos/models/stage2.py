from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class Participant:
    participant_id: str
    stake_value: int


@dataclass(frozen=True)
class StakeCommitment:
    participant_id: str
    stake_commitment: str
    commit_randomness: int


@dataclass(frozen=True)
class PolynomialCommitmentBroadcast:
    participant_id: str
    coefficient_commitments: List[str]


@dataclass(frozen=True)
class PrivateShareDelivery:
    sender_id: str
    recipient_id: str
    share_value: int


@dataclass(frozen=True)
class SharePublicKey:
    participant_id: str
    share_public_key: str
    key_material_reference: str | None = None


@dataclass(frozen=True)
class ThresholdFHEPrivateKeyShare:
    """
    阶段2统一产生的门限 FHE 私钥份额。

    说明：
    - secret_share_scalar：当前实现中保留的 DKG 聚合标量；
      既可继续服务于阶段3 的 KH-PRF 绑定，也便于检查与已有测试兼容。
    - fhe_private_key_share：真实门限 FHE 私钥份额的后端引用句柄；
      compatibility/openfhe 都统一走这一字段，不再由阶段4/5 自建第二套会话。
    - corresponding_share_public_key：与该私钥份额对应的公开分片公钥描述。
    """

    participant_id: str
    secret_share_scalar: int
    fhe_private_key_share: str
    corresponding_share_public_key: str
    backend_name: str
    key_material_reference: str | None = None

    @property
    def decrypt_share_key(self) -> int:
        """
        向后兼容旧实现中对 decrypt_share_key 标量的访问方式。
        """
        return self.secret_share_scalar

    @property
    def private_key_handle(self) -> str:
        return self.fhe_private_key_share


DecryptKeyShare = ThresholdFHEPrivateKeyShare


@dataclass(frozen=True)
class DistributedKeyGenerationResult:
    """
    阶段2统一产出的门限 FHE 密钥体系。

    public_key:
        阶段2分布式生成得到的完整门限 FHE 公钥描述；阶段3/4/5 统一消费此字段。
    threshold_fhe_private_key_shares:
        每个参与者对应的终版门限 FHE 私钥份额对象。
    share_public_keys:
        与每个私钥份额对应的分片公钥。
    secret_commitment_public_key:
        Feldman/VSS 风格承诺下的聚合公开承诺，保留作审计/调试用途；
        不再替代真正的 FHE 完整公钥。
    fhe_keyset_reference:
        运行期引用，由 FHE 后端解析为真实 native key material。
    """

    public_key: str
    threshold_fhe_private_key_shares: Dict[str, ThresholdFHEPrivateKeyShare]
    share_public_keys: Dict[str, SharePublicKey]
    polynomial_commitments: Dict[str, PolynomialCommitmentBroadcast]
    private_share_deliveries: Dict[str, Dict[str, PrivateShareDelivery]]
    threshold: int
    fhe_backend_name: str
    fhe_keyset_reference: str | None = None
    secret_commitment_public_key: str | None = None

    @property
    def decrypt_key_shares(self) -> Dict[str, ThresholdFHEPrivateKeyShare]:
        return self.threshold_fhe_private_key_shares


@dataclass(frozen=True)
class RandomSeedCommitment:
    participant_id: str
    seed_commitment: str


@dataclass(frozen=True)
class RandomSeedContribution:
    participant_id: str
    local_random_value: int
    reveal_randomness: int


@dataclass(frozen=True)
class Phase2ParticipantArtifact:
    participant: Participant
    stake_commitment: StakeCommitment
    decrypt_key_share: ThresholdFHEPrivateKeyShare
    share_public_key: SharePublicKey
    random_seed_commitment: RandomSeedCommitment
    random_seed_contribution: RandomSeedContribution


@dataclass(frozen=True)
class Phase2Result:
    commitments: Dict[str, StakeCommitment]
    distributed_key_result: DistributedKeyGenerationResult
    complete_public_key: str
    threshold_fhe_private_key_shares: Dict[str, ThresholdFHEPrivateKeyShare]
    share_public_keys: Dict[str, SharePublicKey]
    random_seed: str
    random_seed_commitments: Dict[str, RandomSeedCommitment]
    random_seed_contributions: Dict[str, RandomSeedContribution]
    participant_artifacts: List[Phase2ParticipantArtifact]
