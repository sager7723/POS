from __future__ import annotations

from pos.models.common import PublicParameters
from pos.spec import compute_noise_bound, derive_generator_of_order_q, resolve_security_profile


SUPPORTED_SECURITY_PARAMETERS = (128, 192)


def step0_setup(security_parameter: int) -> PublicParameters:
    """
    对应专利步骤0：生成公共参数。

    这一版不再随机拼装参数，而是把第0层“实现规范”固化为可复用的工程配置：
    - λ：当前支持 128 / 192 两档；较小测试值统一映射到 128 档配置。
    - p, q：采用固定 safe-prime 群参数，q = (p - 1) / 2。
    - G / G'：都表示为 p 上的 q 阶子群，只是域分离标签不同。
    - g, g'：通过域分离标签确定性派生生成元。
    - h：由独立域分离标签确定性派生，满足 h != g。
    - 哈希、票根编码、cut-and-choose 默认参数也一并进入 pp。
    """
    profile = resolve_security_profile(security_parameter)

    g = derive_generator_of_order_q(profile.p, profile.q, f"{profile.group_name}:G:g")
    h = derive_generator_of_order_q(profile.p, profile.q, f"{profile.group_name}:G:h")
    if h == g:
        h = derive_generator_of_order_q(profile.p, profile.q, f"{profile.group_name}:G:h:alt")
    g_prime = derive_generator_of_order_q(profile.p, profile.q, f"{profile.group_name}:Gprime:g")

    return PublicParameters(
        security_parameter=profile.security_parameter,
        p=profile.p,
        q=profile.q,
        G=f"Subgroup(order=q,modulus={profile.group_name},domain=G)",
        G_prime=f"Subgroup(order=q,modulus={profile.group_name},domain=G_prime)",
        g=g,
        h=h,
        g_prime=g_prime,
        k=profile.k,
        m=profile.m,
        N=profile.N,
        sigma=profile.sigma,
        mu=profile.mu,
        hash_name=profile.hash_name,
        ticket_nonce_bytes=profile.ticket_nonce_bytes,
        proof_share_count=profile.proof_share_count,
        proof_recover_threshold=profile.proof_recover_threshold,
        serialization_byte_order=profile.serialization_byte_order,
        serialization_length_bytes=profile.serialization_length_bytes,
        recommended_threshold_numerator=profile.participant_threshold_ratio[0],
        recommended_threshold_denominator=profile.participant_threshold_ratio[1],
        noise_bound=compute_noise_bound(profile),
        quantization_step=profile.quantization_step,
    )