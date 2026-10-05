"""Module auto-discovery: ``dwaar_api/modules/<name>/`` plugs in without editing any shared file.

REQ: ADR-0006 (modular monolith), BUILD_BRIEF section 4.3 (auto-discovery over shared edits).

A module is a sub-package of ``dwaar_api.modules`` (or of the package passed to ``create_app``) that exposes
any of ``router`` (``APIRouter``), ``permissions`` (iterable of ``Permission``) and ``register(app)``.
Discovery is strict: an import error, a module that exposes nothing, or a wrongly typed attribute stops the
app from starting. A broken module never silently disappears.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from types import ModuleType
from typing import Any

from fastapi import APIRouter, FastAPI

from .authz import Permission, PermissionRegistry
from .config import ConfigError

log = logging.getLogger("dwaar_api.registry")

DEFAULT_PACKAGE = "dwaar_api.modules"


class ModuleError(ConfigError):
    """A feature module is malformed."""


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    router: APIRouter | None
    permissions: tuple[Permission, ...]
    register: Callable[[FastAPI], None] | None


def discover_modules(package: str = DEFAULT_PACKAGE) -> list[ModuleSpec]:
    """Import every sub-package of ``package`` (sorted by name) and read its public attributes."""
    try:
        root = importlib.import_module(package)
    except ModuleNotFoundError as exc:
        if exc.name == package:
            return []
        raise
    search = getattr(root, "__path__", None)
    if search is None:
        raise ModuleError(f"{package} is not a package")
    specs: list[ModuleSpec] = []
    for info in sorted(pkgutil.iter_modules(search), key=lambda i: i.name):
        if info.name.startswith("_") or not info.ispkg:
            continue
        module = importlib.import_module(f"{package}.{info.name}")
        specs.append(_read(info.name, module))
    return specs


def _read(name: str, module: ModuleType) -> ModuleSpec:
    router = getattr(module, "router", None)
    register = getattr(module, "register", None)
    raw_permissions: Any = getattr(module, "permissions", None)
    if router is None and register is None and raw_permissions is None:
        raise ModuleError(f"module {name!r} exposes none of router / permissions / register")
    if router is not None and not isinstance(router, APIRouter):
        raise ModuleError(f"module {name!r}: router must be a fastapi.APIRouter")
    if register is not None and not callable(register):
        raise ModuleError(f"module {name!r}: register must be callable")
    permissions: tuple[Permission, ...] = ()
    if raw_permissions is not None:
        try:
            permissions = tuple(raw_permissions)
        except TypeError:
            raise ModuleError(
                f"module {name!r}: permissions must be an iterable of Permission"
            ) from None
        if not all(isinstance(p, Permission) for p in permissions):
            raise ModuleError(f"module {name!r}: permissions must contain only Permission objects")
    return ModuleSpec(name, router, permissions, register)


def load_modules(
    app: FastAPI, registry: PermissionRegistry, package: str | None = DEFAULT_PACKAGE
) -> list[ModuleSpec]:
    """Mount routers, collect permissions, run ``register(app)`` hooks. Returns what was loaded."""
    if package is None:
        return []
    specs = discover_modules(package)
    for spec in specs:
        registry.extend(spec.permissions)
    for spec in specs:
        if spec.router is not None:
            app.include_router(spec.router)
        if spec.register is not None:
            spec.register(app)
        log.info("module loaded", extra={"module_name": spec.name})
    return specs


def module_names(specs: Iterable[ModuleSpec]) -> list[str]:
    return [s.name for s in specs]
