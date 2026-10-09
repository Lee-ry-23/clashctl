"""Discover the installed macOS Clash Verge configuration without copying its secrets."""

import hashlib
import os
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from clashctl.models import (
    ConfigurationError,
    JsonObject,
    JsonValue,
    Settings,
    as_object,
    as_string,
    json_value,
)


def read_yaml(path: Path) -> JsonObject:
    try:
        contents: str = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ConfigurationError(f"Cannot read {path}: {error}") from error
    try:
        decoded: object = yaml.safe_load(contents)
    except yaml.YAMLError as error:
        raise ConfigurationError(f"Invalid YAML in {path}; check its syntax locally") from error
    return as_object(json_value(decoded, str(path)), str(path))


def discover_config(home: Path) -> Path:
    path: Path = (
        home
        / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev"
        / "clash-verge.yaml"
    )
    if not path.is_file():
        raise ConfigurationError(
            "Clash Verge runtime configuration not found. Supply --config /path/to/runtime.yaml."
        )
    return path


def controller_url(address: str) -> str:
    url: str = address if "://" in address else f"http://{address}"
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigurationError(f"Invalid HTTP controller address: {address}")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigurationError("Controller URL must not contain credentials, query, or fragment")
    host: str = parsed.hostname
    if host in {"0.0.0.0", "::"}:
        host = "127.0.0.1" if host == "0.0.0.0" else "[::1]"
        return f"{parsed.scheme}://{host}:{parsed.port}"
    return url.rstrip("/")


def discover_core(config_path: Path) -> Path | None:
    verge_path: Path = config_path.parent / "verge.yaml"
    core_name: str = "verge-mihomo"
    if verge_path.is_file():
        data: JsonObject = read_yaml(verge_path)
        value: JsonValue = data.get("clash_core")
        if value is not None:
            core_name = as_string(value, "verge.clash_core")
    if core_name not in {"verge-mihomo", "verge-mihomo-alpha"}:
        raise ConfigurationError(
            f"Unsupported configured core {core_name}; supply --core explicitly"
        )
    path: Path = Path("/Applications/Clash Verge.app/Contents/MacOS") / core_name
    return path if path.is_file() else None


def load_settings(
    config_path: Path | None,
    controller: str | None,
    secret_env: str | None,
    core: Path | None,
    timeout: float,
) -> Settings:
    path: Path = discover_config(Path.home()) if config_path is None else config_path.expanduser()
    data: JsonObject = read_yaml(path)
    address: str = (
        as_string(data.get("external-controller"), "external-controller")
        if controller is None
        else controller
    )
    secret: str = as_string(data.get("secret", ""), "secret")
    if secret_env is not None:
        if secret_env not in os.environ:
            raise ConfigurationError(f"Environment variable {secret_env} is not set")
        secret = os.environ[secret_env]
    binary: Path | None = discover_core(path) if core is None else core.expanduser()
    if binary is not None and not os.access(binary, os.X_OK):
        raise ConfigurationError(f"Core is not executable: {binary}")
    return Settings(path.resolve(), controller_url(address), secret, binary, timeout)


def source_digest(path: Path) -> str:
    """Include local provider caches so a subscription refresh invalidates old measurements."""
    digest = hashlib.sha256(path.read_bytes())
    providers: JsonObject = as_object(read_yaml(path).get("proxy-providers", {}), "proxy-providers")
    for name, value in sorted(providers.items()):
        provider: JsonObject = as_object(value, f"provider {name}")
        if provider.get("type") != "inline":
            cache: Path = Path(as_string(provider.get("path"), f"provider {name}.path"))
            resolved: Path = cache if cache.is_absolute() else path.parent / cache
            if not resolved.is_file():
                raise ConfigurationError(f"Provider {name} cache is missing: {resolved}")
            digest.update(name.encode("utf-8"))
            digest.update(hashlib.sha256(resolved.read_bytes()).digest())
    return digest.hexdigest()
