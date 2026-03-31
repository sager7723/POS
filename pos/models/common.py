from dataclasses import dataclass
from typing import Any


@dataclass
class PublicParameters:
    security_parameter: int
    p: int
    q: int
    G: Any
    G_prime: Any
    g: int
    h: int
    g_prime: int
    k: int
    m: int
    N: int
    sigma: float
    mu: float