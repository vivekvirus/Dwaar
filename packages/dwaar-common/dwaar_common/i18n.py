"""Translator over flat dotted JSON catalogs.

REQ: INV-11 / PRD i18n (all user-visible strings via keys; en, hi, mr at M1), D-04.

Catalog layout: ``packages/i18n/locales/<lang>/<namespace>.json`` holding flat dotted keys,
e.g. ``guard.json`` ``{"tile.guest": "Guest"}`` => full key ``guard.tile.guest``.
Values may contain ``{param}`` placeholders. Lookup falls back requested lang -> ``en`` ->
the key itself, and every miss is recorded so tests/CI can report missing translations.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Final

DEFAULT_LANG: Final = "en"
_LANG = re.compile(r"^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})?$")
_NAMESPACE = re.compile(r"^[A-Za-z0-9_-]+$")
_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


class CatalogError(ValueError):
    """A catalog file is malformed."""


def find_locales_dir() -> Path:
    """`$DWAAR_LOCALES_DIR`, else the first `packages/i18n/locales` found above this file."""
    override = os.environ.get("DWAAR_LOCALES_DIR")
    if override:
        return Path(override)
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "packages" / "i18n" / "locales"
        if candidate.is_dir():
            return candidate
    return Path.cwd() / "packages" / "i18n" / "locales"


class Translator:
    def __init__(self, locales_dir: Path | str | None = None, default_lang: str = DEFAULT_LANG):
        self.locales_dir = Path(locales_dir) if locales_dir is not None else find_locales_dir()
        self.default_lang = self._check_lang(default_lang)
        self._cache: dict[tuple[str, str], dict[str, str]] = {}
        #: (lang, key) pairs for which the requested language had no entry.
        self.missing: set[tuple[str, str]] = set()
        #: keys missing from every language (rendered as the key itself).
        self.unresolved: set[str] = set()
        #: (key, placeholder) pairs for which a placeholder had no supplied value.
        self.missing_params: set[tuple[str, str]] = set()

    @staticmethod
    def _check_lang(lang: str) -> str:
        if not isinstance(lang, str) or not _LANG.match(lang):
            raise ValueError(f"invalid language code {lang!r}")
        return lang

    @staticmethod
    def split_key(key: str) -> tuple[str, str]:
        namespace, sep, rest = key.partition(".")
        if not sep or not rest or not _NAMESPACE.match(namespace):
            raise ValueError(f"i18n key must be '<namespace>.<name>', got {key!r}")
        return namespace, rest

    def _namespace(self, lang: str, namespace: str) -> dict[str, str]:
        cache_key = (lang, namespace)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        path = self.locales_dir / lang / f"{namespace}.json"
        data: dict[str, str] = {}
        if path.is_file():
            try:
                raw: Any = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise CatalogError(f"{path}: invalid JSON ({exc.msg})") from exc
            if not isinstance(raw, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in raw.items()
            ):
                raise CatalogError(f"{path}: expected a flat object of string values")
            data = raw
        self._cache[cache_key] = data
        return data

    def lookup(self, key: str, lang: str) -> str | None:
        namespace, rest = self.split_key(key)
        return self._namespace(self._check_lang(lang), namespace).get(rest)

    def t(self, key: str, lang: str | None = None, **params: object) -> str:
        """Translate `key` into `lang` with `{param}` substitution (fallback lang -> en -> key)."""
        wanted = self._check_lang(lang or self.default_lang)
        template = self.lookup(key, wanted)
        if template is None:
            self.missing.add((wanted, key))
            if wanted != self.default_lang:
                template = self.lookup(key, self.default_lang)
        if template is None:
            self.unresolved.add(key)
            return key

        def substitute(match: re.Match[str]) -> str:
            name = match.group(1)
            if name in params:
                return str(params[name])
            self.missing_params.add((key, name))
            return match.group(0)

        return _PLACEHOLDER.sub(substitute, template)

    # ------------------------------------------------------------------ introspection

    def languages(self) -> list[str]:
        if not self.locales_dir.is_dir():
            return []
        return sorted(p.name for p in self.locales_dir.iterdir() if p.is_dir())

    def namespaces(self, lang: str) -> list[str]:
        folder = self.locales_dir / self._check_lang(lang)
        if not folder.is_dir():
            return []
        return sorted(p.stem for p in folder.glob("*.json"))

    def keys(self, lang: str) -> set[str]:
        """All full keys (``namespace.name``) defined for `lang`."""
        found: set[str] = set()
        for namespace in self.namespaces(lang):
            found.update(f"{namespace}.{k}" for k in self._namespace(lang, namespace))
        return found

    def missing_keys(self, lang: str, reference: str | None = None) -> set[str]:
        """Keys defined in the reference language (default en) but absent in `lang`."""
        return self.keys(reference or self.default_lang) - self.keys(lang)

    def placeholders(self, key: str, lang: str) -> set[str]:
        template = self.lookup(key, lang)
        return set(_PLACEHOLDER.findall(template)) if template else set()

    def placeholder_mismatches(
        self, lang: str, reference: str | None = None
    ) -> dict[str, tuple[set[str], set[str]]]:
        """Keys whose placeholder set differs from the reference language."""
        ref = reference or self.default_lang
        result: dict[str, tuple[set[str], set[str]]] = {}
        for key in self.keys(lang) & self.keys(ref):
            expected, actual = self.placeholders(key, ref), self.placeholders(key, lang)
            if expected != actual:
                result[key] = (expected, actual)
        return result

    def report(self) -> dict[str, Any]:
        """Serializable summary of misses recorded so far."""
        return {
            "missing": sorted(f"{lang}:{key}" for lang, key in self.missing),
            "unresolved": sorted(self.unresolved),
            "missing_params": sorted(f"{key}:{name}" for key, name in self.missing_params),
        }
