"""Deeply immutable containers for pack data (INV-10: one handler must not be able to change the law).

REQ: INV-10.

``FrozenDict`` / ``FrozenList`` subclass ``dict`` / ``list`` so equality, ``isinstance`` checks, JSON
serialisation and pydantic dumping keep working, but every mutating method raises ``TypeError``.
``freeze`` converts nested JSON-like data. ``copy.deepcopy`` of a frozen value returns an equal frozen value;
to obtain a mutable copy use ``thaw``.
"""

from __future__ import annotations

from typing import Any, NoReturn


def _immutable(self: object, *_args: Any, **_kwargs: Any) -> NoReturn:
    raise TypeError(f"{type(self).__name__} is immutable (packs are read-only law)")


class FrozenDict(dict[str, Any]):
    __slots__ = ()
    __setitem__ = __delitem__ = __ior__ = _immutable
    clear = pop = popitem = setdefault = update = _immutable

    def __reduce__(self) -> tuple[Any, ...]:
        return (FrozenDict, (dict(self),))

    def __deepcopy__(self, memo: dict[int, Any]) -> FrozenDict:
        return self

    def __copy__(self) -> FrozenDict:
        return self

    def __hash__(self) -> int:  # type: ignore[override]
        return hash(tuple(sorted((k, repr(v)) for k, v in self.items())))


class FrozenList(list[Any]):
    __slots__ = ()
    __setitem__ = __delitem__ = __iadd__ = __imul__ = _immutable
    append = extend = insert = pop = remove = clear = sort = reverse = _immutable

    def __reduce__(self) -> tuple[Any, ...]:
        return (FrozenList, (list(self),))

    def __deepcopy__(self, memo: dict[int, Any]) -> FrozenList:
        return self

    def __copy__(self) -> FrozenList:
        return self

    def __hash__(self) -> int:  # type: ignore[override]
        return hash(tuple(repr(v) for v in self))


def freeze(value: Any) -> Any:
    """Recursively replace dicts/lists/sets by their frozen equivalents (tuples stay tuples)."""
    if isinstance(value, FrozenDict | FrozenList):
        return value
    if isinstance(value, dict):
        return FrozenDict({k: freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return FrozenList(freeze(v) for v in value)
    if isinstance(value, tuple):
        return tuple(freeze(v) for v in value)
    if isinstance(value, set | frozenset):
        return frozenset(freeze(v) for v in value)
    return value


def thaw(value: Any) -> Any:
    """Mutable deep copy of (possibly frozen) JSON-like data."""
    if isinstance(value, dict):
        return {k: thaw(v) for k, v in value.items()}
    if isinstance(value, list):
        return [thaw(v) for v in value]
    if isinstance(value, tuple):
        return tuple(thaw(v) for v in value)
    return value
