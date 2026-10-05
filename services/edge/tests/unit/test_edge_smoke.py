"""Smoke test: the dwaar_edge package imports and the shared library is wired in."""

import dwaar_common
import dwaar_edge


def test_package_imports() -> None:
    assert dwaar_edge.SERVICE_NAME == "dwaar_edge"
    assert dwaar_edge.__version__


def test_shared_library_available() -> None:
    assert dwaar_common.__version__
