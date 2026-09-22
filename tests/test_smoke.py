import alert2attack


def test_version_is_exposed() -> None:
    assert alert2attack.__version__ == "0.1.0"
