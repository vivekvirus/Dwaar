"""YAML loading, JSON-Schema validation and typed model construction for every pack type.

Dates stay strings through schema validation (a YAML loader without implicit timestamps), so the JSON
Schema is the single source of truth for the file format and pydantic converts afterwards.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from .errors import PackValidationError
from .frozen import freeze
from .models import CascadeOfflinePack, LegalPack, PackHeader, RetentionPack
from .paths import legal_packs_dir, tax_packs_dir
from .tax_models import FeeSchedule, GstEinvoicePack, GstRwaPack, TdsPack


class _NoTimestampLoader(yaml.SafeLoader):
    """SafeLoader without implicit timestamps that REJECTS duplicate mapping keys.

    PyYAML keeps the last of two equal keys without a warning, so a reviewer reading ``interest: 12`` near the
    top could be overruled by ``interest: 1200`` further down. Law files must say each thing once.
    """

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            key = self.construct_object(key_node, deep=True)
            try:
                duplicate = key in seen
                seen.add(key)
            except TypeError:  # unhashable key: the base class raises its own, clearer error
                break
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
        return super().construct_mapping(node, deep=deep)


_NoTimestampLoader.yaml_implicit_resolvers = {
    k: [(tag, rx) for tag, rx in v if tag != "tag:yaml.org,2002:timestamp"]
    for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


@dataclass(frozen=True)
class PackKind:
    pack_type: str
    schema_dir: str  # "legal" or "tax"
    schema_file: str
    model: type[PackHeader]


KINDS: dict[str, PackKind] = {
    k.pack_type: k
    for k in (
        PackKind("legal-pack", "legal", "legal-pack.schema.json", LegalPack),
        PackKind("retention", "legal", "retention-classes.schema.json", RetentionPack),
        PackKind("cascade-offline", "legal", "cascade-offline.schema.json", CascadeOfflinePack),
        PackKind("tds", "tax", "tds.schema.json", TdsPack),
        PackKind("gst-rwa", "tax", "gst-rwa.schema.json", GstRwaPack),
        PackKind("gst-einvoice", "tax", "gst-einvoice.schema.json", GstEinvoicePack),
        PackKind("fee-schedule", "tax", "fee-schedule.schema.json", FeeSchedule),
    )
}


def read_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.load(path.read_text(encoding="utf-8"), Loader=_NoTimestampLoader)  # noqa: S506
    except yaml.YAMLError as exc:
        raise PackValidationError(str(path), [f"YAML parse error: {exc}"]) from exc
    if not isinstance(data, dict):
        raise PackValidationError(str(path), ["top level must be a mapping"])
    return data


@cache
def _schema(kind: PackKind) -> Draft202012Validator:
    base = legal_packs_dir() if kind.schema_dir == "legal" else tax_packs_dir()
    schema = json.loads((base / "schema" / kind.schema_file).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def schema_problems(doc: Mapping[str, Any], kind: PackKind) -> list[str]:
    errs = sorted(_schema(kind).iter_errors(dict(doc)), key=lambda e: list(e.absolute_path))
    return [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in errs]


def kind_of(doc: Mapping[str, Any], source: str = "<memory>") -> PackKind:
    pt = doc.get("pack_type")
    if not isinstance(pt, str) or pt not in KINDS:
        raise PackValidationError(source, [f"unknown or missing pack_type: {pt!r}"])
    return KINDS[pt]


def build_pack(doc: Mapping[str, Any], source: str = "<memory>") -> PackHeader:
    """Validate a parsed document (JSON Schema first, then the typed model) and return the model."""
    kind = kind_of(doc, source)
    problems = schema_problems(doc, kind)
    if problems:
        raise PackValidationError(source, problems)
    try:
        pack = kind.model.model_validate(dict(doc))
    except ValidationError as exc:
        raise PackValidationError(
            source, [f"{'/'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()]
        ) from exc
    if isinstance(pack, RetentionPack):
        fixed = {k: v.model_copy(update={"record_class": k}) for k, v in pack.classes.items()}
        pack = pack.model_copy(update={"classes": freeze(fixed)})
    return pack


def load_pack(path: Path | str) -> PackHeader:
    p = Path(path)
    return build_pack(read_yaml(p), str(p))


def load_typed[T: BaseModel](path: Path | str, model: type[T]) -> T:
    pack = load_pack(path)
    if not isinstance(pack, model):
        raise PackValidationError(
            str(path), [f"expected {model.__name__}, got {type(pack).__name__}"]
        )
    return pack


def discover_pack_files() -> Iterator[Path]:
    """Every shipped pack YAML file, in a stable order."""
    lp, tp = legal_packs_dir(), tax_packs_dir()
    for d in (lp / "packs", lp / "retention", lp / "defaults", tp / "packs", tp / "fee-schedules"):
        yield from sorted(d.glob("*.yaml"))
