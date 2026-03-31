import random
from pos.models.common import PublicParameters


def step0_setup(security_parameter: int) -> PublicParameters:
    """
    对应专利步骤0：生成公共参数
    """

    # ❗以下为mock实现（未在专利中确认具体构造方式）
    p = random.getrandbits(security_parameter)
    q = random.getrandbits(security_parameter - 1)

    G = "MockGroupG"
    G_prime = "MockGroupGPrime"

    g = random.randint(2, p - 1)
    h = random.randint(2, p - 1)
    g_prime = random.randint(2, p - 1)

    k = 10  # ❗未在专利中确认
    m = 100  # ❗未在专利中确认
    N = 1024  # ❗未在专利中确认

    sigma = 3.2
    mu = 0.0

    return PublicParameters(
        security_parameter=security_parameter,
        p=p,
        q=q,
        G=G,
        G_prime=G_prime,
        g=g,
        h=h,
        g_prime=g_prime,
        k=k,
        m=m,
        N=N,
        sigma=sigma,
        mu=mu
    )