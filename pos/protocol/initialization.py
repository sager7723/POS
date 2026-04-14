from __future__ import annotations

from pos.crypto.setup import step0_setup
from pos.spec import SUPPORTED_SECURITY_PARAMETERS, recommend_decryption_threshold


def run_phase1_initialization(security_parameter: int = 128) -> dict[str, object]:
    """
    阶段1入口。

    返回值中除公共参数外，还显式暴露第0层规范里会被后续阶段复用的两个决策：
    - supported_security_parameters：当前允许的 λ 档位；
    - recommend_decryption_threshold：t 与参与方数量 T 的推荐关系函数。
    """
    pp = step0_setup(security_parameter)
    return {
        "public_parameters": pp,
        "supported_security_parameters": SUPPORTED_SECURITY_PARAMETERS,
        "recommend_decryption_threshold": recommend_decryption_threshold,
    }