from __future__ import annotations

import hashlib

from pos.models.common import PublicParameters


RFC3526_GROUP14_P = int(
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

RFC3526_GROUP15_P = int(
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
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    16,
)


def _derive_q(p: int) -> int:
    return (p - 1) // 2


def _derive_generator_of_order_q(p: int, q: int, domain_label: str) -> int:
    counter = 1
    while True:
        digest = hashlib.sha256(f"{domain_label}:{counter}".encode("utf-8")).digest()
        candidate = int.from_bytes(digest, "big") % p
        if candidate in (0, 1, p - 1):
            counter += 1
            continue
        generator = pow(candidate, 2, p)
        if generator != 1 and pow(generator, q, p) == 1:
            return generator
        counter += 1


def step0_setup(security_parameter: int) -> PublicParameters:
    """
    对应专利步骤0：生成公共参数。

    本版把承诺/分享/随机源依赖的群参数固定成真正可用的 safe-prime 模乘群配置，
    从而让 Pedersen 承诺与后续指数型恢复有真实数学基础。
    """
    if security_parameter <= 128:
        p = RFC3526_GROUP14_P
        k = 630
        m = 4096
        N = 1024
    else:
        p = RFC3526_GROUP15_P
        k = 750
        m = 6144
        N = 2048

    q = _derive_q(p)
    g = _derive_generator_of_order_q(p, q, "PSSLE:G:g")
    h = _derive_generator_of_order_q(p, q, "PSSLE:G:h")
    if h == g:
        h = _derive_generator_of_order_q(p, q, "PSSLE:G:h:alt")
    g_prime = _derive_generator_of_order_q(p, q, "PSSLE:Gprime:g")

    return PublicParameters(
        security_parameter=128 if security_parameter <= 128 else 192,
        p=p,
        q=q,
        G="SafePrimeSubgroupG",
        G_prime="SafePrimeSubgroupGPrime",
        g=g,
        h=h,
        g_prime=g_prime,
        k=k,
        m=m,
        N=N,
        sigma=3.2,
        mu=0.0,
    )