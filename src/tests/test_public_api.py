from dataclasses import fields

import litestar_security


def test_package_root_exports_scaffold_contract() -> None:
    assert litestar_security.__all__ == ("SecurityConfig", "SecurityPlugin", "__project__", "__version__")
    assert litestar_security.__project__ == "litestar-security"
    assert litestar_security.__version__ == "0.1.0"


def test_security_config_is_empty_and_slotted() -> None:
    config = litestar_security.SecurityConfig()

    assert fields(config) == ()
    assert config.__slots__ == ()
    assert not hasattr(config, "__dict__")
