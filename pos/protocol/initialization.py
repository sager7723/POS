from pos.crypto.setup import step0_setup


def run_phase1_initialization(security_parameter: int = 128):
    """
    阶段1入口
    """
    pp = step0_setup(security_parameter)

    return {
        "public_parameters": pp
    }