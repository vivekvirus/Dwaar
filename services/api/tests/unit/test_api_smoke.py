"""Smoke test: the dwaar_api package imports and the shared library is wired in."""

import dwaar_api
import dwaar_common


def test_package_imports() -> None:
    assert dwaar_api.SERVICE_NAME == "dwaar_api"
    assert dwaar_api.__version__


def test_shared_library_available() -> None:
    assert dwaar_common.__version__
