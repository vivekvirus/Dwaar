import json
from pathlib import Path

import pytest

from dwaar_common.i18n import CatalogError, Translator


def write(root: Path, lang: str, namespace: str, data: dict[str, str]) -> None:
    folder = root / lang
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{namespace}.json").write_text(
        json.dumps(data, ensure_ascii=False), encoding="utf-8"
    )


@pytest.fixture
def locales(tmp_path: Path) -> Path:
    write(tmp_path, "en", "guard", {"tile.guest": "Guest", "greet": "Hello {name}, gate {gate}"})
    write(tmp_path, "hi", "guard", {"tile.guest": "अतिथि"})
    write(tmp_path, "en", "error", {"not_found": "Not found"})
    write(tmp_path, "mr", "error", {"not_found": "सापडले नाही"})
    return tmp_path


def test_namespace_dotted_flat_lookup(locales: Path) -> None:
    tr = Translator(locales)
    assert tr.t("guard.tile.guest") == "Guest"
    assert tr.t("guard.tile.guest", "hi") == "अतिथि"
    assert tr.t("error.not_found", "mr").startswith("स")


def test_fallback_lang_then_en_then_key(locales: Path) -> None:
    tr = Translator(locales)
    assert tr.t("guard.greet", "hi", name="A", gate="1") == "Hello A, gate 1"  # hi lacks it -> en
    assert ("hi", "guard.greet") in tr.missing
    assert tr.t("guard.absent", "hi") == "guard.absent"  # nowhere -> key
    assert "guard.absent" in tr.unresolved
    assert tr.t("nosuchns.key") == "nosuchns.key"
    assert tr.t("guard.tile.guest", "kn") == "Guest"  # unknown language dir -> en


def test_param_formatting_and_missing_params(locales: Path) -> None:
    tr = Translator(locales)
    assert tr.t("guard.greet", name="Asha", gate="2") == "Hello Asha, gate 2"
    assert tr.t("guard.greet", name="Asha") == "Hello Asha, gate {gate}"
    assert ("guard.greet", "gate") in tr.missing_params
    assert tr.t("guard.greet", name=5, gate=None) == "Hello 5, gate None"


def test_report_shape(locales: Path) -> None:
    tr = Translator(locales)
    tr.t("guard.absent", "hi")
    tr.t("guard.greet", "hi", name="x")
    report = tr.report()
    assert report["unresolved"] == ["guard.absent"]
    assert "hi:guard.greet" in report["missing"]
    assert report["missing_params"] == ["guard.greet:gate"]


def test_missing_keys_against_reference(locales: Path) -> None:
    tr = Translator(locales)
    assert tr.missing_keys("hi") == {"guard.greet", "error.not_found"}
    assert tr.missing_keys("mr") == {"guard.tile.guest", "guard.greet"}
    assert tr.missing_keys("en") == set()
    assert tr.languages() == ["en", "hi", "mr"]
    assert tr.keys("en") == {"guard.tile.guest", "guard.greet", "error.not_found"}


def test_placeholder_mismatch_report(tmp_path: Path) -> None:
    write(tmp_path, "en", "a", {"k": "Hi {name}"})
    write(tmp_path, "hi", "a", {"k": "Namaste"})
    assert Translator(tmp_path).placeholder_mismatches("hi") == {"a.k": ({"name"}, set())}


def test_invalid_inputs(locales: Path) -> None:
    tr = Translator(locales)
    for bad_key in ["nodots", ".x", "ns.", "../etc.passwd"]:
        with pytest.raises(ValueError, match="key"):
            tr.t(bad_key)
    for bad_lang in ["../en", "EN", "e", "en/../x"]:
        with pytest.raises(ValueError, match="language"):
            tr.t("guard.tile.guest", bad_lang)


def test_malformed_catalog_raises(tmp_path: Path) -> None:
    (tmp_path / "en").mkdir()
    (tmp_path / "en" / "bad.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "en" / "nested.json").write_text('{"a": {"b": "c"}}', encoding="utf-8")
    tr = Translator(tmp_path)
    with pytest.raises(CatalogError, match="invalid JSON"):
        tr.t("bad.x")
    with pytest.raises(CatalogError, match="flat"):
        tr.t("nested.a")


def test_missing_locales_dir_degrades_to_keys(tmp_path: Path) -> None:
    tr = Translator(tmp_path / "does-not-exist")
    assert tr.t("guard.tile.guest") == "guard.tile.guest"
    assert tr.languages() == []


def test_env_override(monkeypatch: pytest.MonkeyPatch, locales: Path) -> None:
    monkeypatch.setenv("DWAAR_LOCALES_DIR", str(locales))
    assert Translator().t("guard.tile.guest") == "Guest"


def test_default_discovery_finds_repo_catalogs_or_degrades() -> None:
    # packages/i18n is owned by another build step; discovery must never raise.
    tr = Translator()
    assert isinstance(tr.languages(), list)
