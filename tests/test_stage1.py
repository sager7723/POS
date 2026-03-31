from pos.protocol.initialization import run_phase1_initialization


def test_stage1():
    result = run_phase1_initialization()
    assert "public_parameters" in result