from __future__ import annotations

from pos.models.common import PublicParameters
from pos.models.stage2 import Participant
from pos.models.stage3 import PRFShare
from pos.spec import (
    bit_decompose_bytes,
    derive_field_vector,
    encode_length_prefixed_bytes,
    hash_bytes,
)


class LWEKeyHomomorphicPRF:
    """
    基于 LWE / Flwe 思路的线性 key-homomorphic PRF 工程实现。

    设计说明：
    1. 输入 x 由 (random_seed, participant_id, stake_value) 统一编码得到；
    2. 对 x 做位分解，得到 bit string；
    3. 为每个 bit 位置 i 确定性派生公开向量 a_i ∈ Z_q^k；
    4. 使用 DKG 生成的标量密钥份额 k_i，结合公开 gadget 向量 g_vec，
       构造秘密向量份额：
           s_i = k_i * g_vec mod q
    5. 计算：
           a_x = a_0 + Σ bit_i * a_i mod q
           F_{s_i}(x) = <a_x, s_i> mod q

    这样：
    - 对密钥份额是线性的；
    - 具备 key-homomorphic 性质；
    - 输入经过位分解，结构上更贴近 Flwe/LWE 风格 PRF；
    - 与阶段2真实 DKG 的整数份额直接兼容。
    """

    def _encode_input(
        self,
        pp: PublicParameters,
        participant: Participant,
        random_seed: str,
    ) -> bytes:
        participant_bytes = participant.participant_id.encode("utf-8")
        stake_bytes = participant.stake_value.to_bytes(32, pp.serialization_byte_order, signed=False)
        seed_bytes = random_seed.encode("utf-8")

        payload = bytearray()
        payload.extend(b"PSSLE-LWE-KH-PRF")
        payload.extend(
            encode_length_prefixed_bytes(
                participant_bytes,
                pp.serialization_length_bytes,
                pp.serialization_byte_order,
            )
        )
        payload.extend(stake_bytes)
        payload.extend(
            encode_length_prefixed_bytes(
                seed_bytes,
                pp.serialization_length_bytes,
                pp.serialization_byte_order,
            )
        )
        return bytes(payload)

    def _derive_gadget_vector(self, pp: PublicParameters) -> list[int]:
        return derive_field_vector(
            domain_label="PSSLE-LWE-KH-PRF-GADGET",
            index=0,
            dimension=pp.k,
            modulus=pp.q,
            hash_name=pp.hash_name,
        )

    def _derive_input_public_vector(
        self,
        pp: PublicParameters,
        input_bits: list[int],
    ) -> tuple[list[int], str]:
        accumulator = derive_field_vector(
            domain_label="PSSLE-LWE-KH-PRF-A0",
            index=0,
            dimension=pp.k,
            modulus=pp.q,
            hash_name=pp.hash_name,
        )

        for bit_index, bit_value in enumerate(input_bits):
            if bit_value == 0:
                continue
            basis_vector = derive_field_vector(
                domain_label="PSSLE-LWE-KH-PRF-AI",
                index=bit_index + 1,
                dimension=pp.k,
                modulus=pp.q,
                hash_name=pp.hash_name,
            )
            accumulator = [
                (accumulator_value + basis_value) % pp.q
                for accumulator_value, basis_value in zip(accumulator, basis_vector)
            ]

        digest_payload = ",".join(str(value) for value in accumulator).encode("utf-8")
        public_vector_digest = hash_bytes(digest_payload, pp.hash_name)
        return accumulator, public_vector_digest

    @staticmethod
    def _inner_product_mod_q(
        vector_a: list[int],
        vector_b: list[int],
        q: int,
    ) -> int:
        if len(vector_a) != len(vector_b):
            raise ValueError("inner product vectors must have same length")
        total = 0
        for value_a, value_b in zip(vector_a, vector_b):
            total = (total + (value_a * value_b)) % q
        return total

    def generate_prf_share(
        self,
        pp: PublicParameters,
        participant: Participant,
        random_seed: str,
        key_share_scalar: int,
    ) -> PRFShare:
        input_bytes = self._encode_input(
            pp=pp,
            participant=participant,
            random_seed=random_seed,
        )
        input_bits = bit_decompose_bytes(input_bytes)

        gadget_vector = self._derive_gadget_vector(pp)
        secret_vector = tuple((key_share_scalar % pp.q) * value % pp.q for value in gadget_vector)

        public_vector, public_vector_digest = self._derive_input_public_vector(
            pp=pp,
            input_bits=input_bits,
        )

        prf_share_value = self._inner_product_mod_q(
            vector_a=public_vector,
            vector_b=list(secret_vector),
            q=pp.q,
        )

        return PRFShare(
            participant_id=participant.participant_id,
            key_share_scalar=key_share_scalar % pp.q,
            secret_vector=secret_vector,
            input_bits_length=len(input_bits),
            public_vector_digest=public_vector_digest,
            prf_share_value=prf_share_value,
            prf_share=f"prf_share:0x{prf_share_value:x}",
        )


MockKeyHomomorphicPRF = LWEKeyHomomorphicPRF