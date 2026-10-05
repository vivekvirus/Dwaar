"""Feature modules. Each sub-package ``<name>/`` is discovered by ``dwaar_api.core.registry``.

A module package exposes (all optional, at least one required):

* ``router``       a FastAPI ``APIRouter`` mounted as-is (declare the full ``/v1/...`` paths in it)
* ``permissions``  an iterable of ``dwaar_api.core.authz.Permission`` for the actions it protects
* ``register(app)`` a hook called once while the app is assembled (state, extra middleware, providers)

Adding a module therefore never edits a shared file.
"""
