from __future__ import annotations

from pos.models.common import PublicParameters
from pos.spec import derive_generator_of_order_q, resolve_security_profile


def step0_setup(security_parameter: int) -> PublicParameters:
    """
    对应专利步骤0：生成公共参数。
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
        ticket_version=1,
    )