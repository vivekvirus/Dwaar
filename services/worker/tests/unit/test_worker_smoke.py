"""Smoke test: the dwaar_worker package imports and the shared library is wired in."""

import dwaar_common
import dwaar_worker


def test_package_imports() -> None:
    assert dwaar_worker.SERVICE_NAME == "dwaar_worker"
    assert dwaar_worker.__version__


def test_shared_library_available() -> None:
    assert dwaar_common.__version__
