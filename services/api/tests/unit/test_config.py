"""Configuration fails closed: local defaults only for DWAAR_ENV=local, secrets never echoed."""

from __future__ import annotations

import pytest

from dwaar_api.core.config import ConfigError, Environment, Settings, get_settings, load_settings

pytestmark = pytest.mark.req("ARCH-03", "ARCH-04")

CURSOR_KEY = "Zk3vQ9xL2mPd7RtYb1HnWs8Ue4JgAc6F"  # 32 distinct characters: passes the entropy rule
APP_URL = "postgresql://dwaar_app:s3cr3t-pw@db.example.invalid:5432/dwaar"
FULL: dict[str, str] = {
    "DWAAR_ENV": "production",
    "DWAAR_DATABASE_URL": APP_URL,
    "DWAAR_CURSOR_SIGNING_KEY": CURSOR_KEY,
    "DWAAR_OIDC_ISSUER_URL": "https://idp.example.invalid",
    "DWAAR_OIDC_JWKS_URL": "https://idp.example.invalid/.well-known/jwks.json",
    "DWAAR_CORS_ORIGINS": "https://admin.example.invalid, https://app.example.invalid",
}


def test_env_is_mandatory_and_validated() -> None:
    with pytest.raises(ConfigError, match="DWAAR_ENV must be set"):
        load_settings({})
    with pytest.raises(ConfigError, match="DWAAR_ENV must be set"):
        load_settings({"DWAAR_ENV": "  "})
    with pytest.raises(ConfigError, match="env"):
        load_settings({"DWAAR_ENV": "prod"})  # near miss is not production


def test_local_gets_documented_defaults_and_allows_simulators() -> None:
    settings = load_settings({"DWAAR_ENV": "local"})
    assert settings.env is Environment.LOCAL
    assert settings.simulation is True
    assert settings.database_url is not None
    assert settings.database_url.get_secret_value().startswith("postgresql://dwaar_app:")
    assert settings.database_worker_url is not None
    assert "dwaar_worker" in settings.database_worker_url.get_secret_value()
    assert settings.require_cursor_key()


def test_local_defaults_do_not_override_explicit_values() -> None:
    settings = load_settings({"DWAAR_ENV": "local", "DWAAR_DATABASE_URL": APP_URL})
    assert settings.database_url is not None
    assert settings.database_url.get_secret_value() == APP_URL


@pytest.mark.parametrize("env", ["test", "staging", "production"])
def test_other_environments_get_no_defaults(env: str) -> None:
    with pytest.raises(ConfigError) as exc:
        load_settings({"DWAAR_ENV": env})
    message = str(exc.value)
    assert "DWAAR_DATABASE_URL" in message
    assert "DWAAR_CURSOR_SIGNING_KEY" in message
    assert "127.0.0.1" not in message  # no local default sneaked in


def test_production_requires_identity_provider_and_cors() -> None:
    with pytest.raises(ConfigError) as exc:
        load_settings(
            {
                "DWAAR_ENV": "production",
                "DWAAR_DATABASE_URL": APP_URL,
                "DWAAR_CURSOR_SIGNING_KEY": "k",
            }
        )
    message = str(exc.value)
    for name in ("DWAAR_OIDC_ISSUER_URL", "DWAAR_OIDC_JWKS_URL", "DWAAR_CORS_ORIGINS"):
        assert name in message


def test_test_environment_allows_simulators_without_an_issuer() -> None:
    settings = load_settings(
        {"DWAAR_ENV": "test", "DWAAR_DATABASE_URL": APP_URL, "DWAAR_CURSOR_SIGNING_KEY": "k"}
    )
    assert settings.simulation is True
    assert settings.oidc_issuer_url == ""


def test_full_production_configuration_is_valid() -> None:
    settings = load_settings(FULL)
    assert settings.simulation is False
    assert settings.cors_origin_list == [
        "https://admin.example.invalid",
        "https://app.example.invalid",
    ]
    assert settings.jwt_algorithms == ("RS256", "ES256", "EdDSA")
    assert settings.max_page_size == 100


def test_secrets_never_appear_in_repr_or_errors() -> None:
    settings = load_settings(FULL)
    assert "s3cr3t-pw" not in repr(settings)
    assert "s3cr3t-pw" not in str(settings)
    assert CURSOR_KEY not in repr(settings)
    broken = {**FULL, "DWAAR_OIDC_ALGORITHMS": "HS256", "DWAAR_LOG_LEVEL": "loud"}
    with pytest.raises(ConfigError) as exc:
        load_settings(broken)
    assert "s3cr3t-pw" not in str(exc.value)
    assert CURSOR_KEY not in str(exc.value)


@pytest.mark.parametrize("user", ["dwaar_owner", "postgres", "root"])
def test_api_must_not_use_the_owner_or_a_superuser(user: str) -> None:
    env = {**FULL, "DWAAR_DATABASE_URL": f"postgresql://{user}:pw-123@db.example.invalid/dwaar"}
    with pytest.raises(ConfigError, match="restricted application role") as exc:
        load_settings(env)
    assert "pw-123" not in str(exc.value)
    worker = {
        **FULL,
        "DWAAR_DATABASE_WORKER_URL": "postgresql://dwaar_owner:pw-456@db.example.invalid/dwaar",
    }
    with pytest.raises(ConfigError, match="WORKER"):
        load_settings(worker)


def test_malformed_database_url_does_not_echo_it() -> None:
    with pytest.raises(ConfigError) as exc:
        load_settings({**FULL, "DWAAR_DATABASE_URL": "not a url with password:hunter2@"})
    assert "hunter2" not in str(exc.value)


def test_jwt_algorithm_allow_list_is_asymmetric_only() -> None:
    for bad in ("none", "HS256", "RS256,HS512", "", " , "):
        with pytest.raises(ConfigError):
            load_settings({**FULL, "DWAAR_OIDC_ALGORITHMS": bad})
    assert load_settings({**FULL, "DWAAR_OIDC_ALGORITHMS": "ES256, PS256"}).jwt_algorithms == (
        "ES256",
        "PS256",
    )


def test_cors_must_list_explicit_origins() -> None:
    with pytest.raises(ConfigError, match="explicit origins"):
        load_settings({**FULL, "DWAAR_CORS_ORIGINS": "*"})


def test_issuer_must_be_https_outside_local_and_test() -> None:
    with pytest.raises(ConfigError, match="https"):
        load_settings({**FULL, "DWAAR_OIDC_ISSUER_URL": "http://idp.example.invalid"})
    local = load_settings({"DWAAR_ENV": "local", "DWAAR_OIDC_ISSUER_URL": "http://localhost:9000"})
    assert local.oidc_issuer_url == "http://localhost:9000"


def test_limits_are_bounded() -> None:
    for name, value in (
        ("MAX_PAGE_SIZE", "101"),
        ("IDEMPOTENCY_TTL_SECONDS", "5"),
        ("DB_POOL_SIZE", "0"),
    ):
        with pytest.raises(ConfigError):
            load_settings({**FULL, f"DWAAR_{name}": value})


def test_overrides_and_non_dwaar_variables() -> None:
    settings = load_settings({**FULL, "HOME": "/root", "PATH": "/bin"}, log_level="debug")
    assert settings.log_level == "DEBUG"
    assert isinstance(settings, Settings)


def test_get_settings_reads_the_process_environment_and_caches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    get_settings.cache_clear()
    monkeypatch.setenv("DWAAR_ENV", "local")
    try:
        first = get_settings()
        assert first is get_settings()
        monkeypatch.delenv("DWAAR_ENV")
        assert get_settings() is first  # cached
        get_settings.cache_clear()
        with pytest.raises(ConfigError):
            get_settings()
    finally:
        get_settings.cache_clear()


def test_cursor_signing_key_must_have_real_entropy_outside_local() -> None:
    """Cursors are HMAC-signed with it: ``DWAAR_CURSOR_SIGNING_KEY=a`` must not boot in production."""
    for weak in ("a", "k" * 40, "short-key-value", "ab" * 20):
        with pytest.raises(ConfigError, match="DWAAR_CURSOR_SIGNING_KEY") as exc:
            load_settings({**FULL, "DWAAR_CURSOR_SIGNING_KEY": weak})
        if len(weak) > 3:
            assert weak not in str(exc.value)  # never echoed
    assert load_settings(FULL).require_cursor_key()  # the strong key is fine
    # local and test keep their convenience defaults and short test keys
    assert load_settings({"DWAAR_ENV": "local"}).require_cursor_key()
    assert load_settings(
        {"DWAAR_ENV": "test", "DWAAR_DATABASE_URL": APP_URL, "DWAAR_CURSOR_SIGNING_KEY": "k"}
    )


def test_jwks_url_must_be_https_outside_local() -> None:
    """The issuer URL was checked but the JWKS URL was not: an http JWKS lets anyone on the path swap the
    signing keys and mint tokens for any person id."""
    with pytest.raises(ConfigError, match="DWAAR_OIDC_JWKS_URL must be https"):
        load_settings({**FULL, "DWAAR_OIDC_JWKS_URL": "http://idp.example.invalid/jwks"})
    local = load_settings(
        {"DWAAR_ENV": "local", "DWAAR_OIDC_JWKS_URL": "http://127.0.0.1:9000/jwks"}
    )
    assert local.simulation  # plain http is fine for the labelled local/test simulators


def test_blank_values_count_as_unset() -> None:
    """``DWAAR_CURSOR_SIGNING_KEY=`` in a .env file must not boot with an empty signing key."""
    local = load_settings(
        {"DWAAR_ENV": "local", "DWAAR_CURSOR_SIGNING_KEY": "", "DWAAR_DATABASE_URL": "  "}
    )
    assert local.require_cursor_key()  # the local default applied
    assert local.database_url is not None
    assert local.database_url.get_secret_value().startswith("postgresql://dwaar_app:")
    with pytest.raises(ConfigError, match="DWAAR_CURSOR_SIGNING_KEY"):
        load_settings({**FULL, "DWAAR_CURSOR_SIGNING_KEY": ""})
