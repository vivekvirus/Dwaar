"""Smoke test: the dwaar_ai_gateway package imports and the shared library is wired in."""

import dwaar_ai_gateway
import dwaar_common


def test_package_imports() -> None:
    assert dwaar_ai_gateway.SERVICE_NAME == "dwaar_ai_gateway"
    assert dwaar_ai_gateway.__version__


def test_shared_library_available() -> None:
    assert dwaar_common.__version__
