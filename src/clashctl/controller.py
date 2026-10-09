"""The authenticated local Mihomo API connector, with bounded idempotent retries."""

import json
import logging
import sys
import time
from types import TracebackType
from typing import Self
from urllib.parse import quote

import httpx

from clashctl.models import (
    ConfigurationError,
    ControllerError,
    JsonObject,
    JsonValue,
    Proxy,
    Settings,
    Snapshot,
    StateConflictError,
    as_int,
    as_list,
    as_object,
    as_string,
    json_value,
    parse_proxy,
    proxy_by_name,
    selection_path,
)
from clashctl.routing_models import Connection, RuntimeRule, parse_connection, parse_rule


class ClashClient:
    """Perform controller I/O without inheriting the system's HTTP proxy environment."""

    def __init__(self, settings: Settings) -> None:
        self.settings: Settings = settings
        self.transport: httpx.Client | None = None

    def __enter__(self) -> Self:
        if self.transport is not None:
            raise StateConflictError("Controller session is already open")
        self.transport = httpx.Client(trust_env=False, timeout=self.settings.timeout)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self.transport is None:
            raise StateConflictError("Controller session is not open")
        self.transport.close()
        self.transport = None

    def request(
        self, method: str, path: str, params: dict[str, str], payload: JsonObject | None
    ) -> JsonValue:
        if self.transport is not None:
            return self.request_with_client(self.transport, method, path, params, payload)
        with httpx.Client(trust_env=False, timeout=self.settings.timeout) as client:
            return self.request_with_client(client, method, path, params, payload)

    def request_with_client(
        self,
        client: httpx.Client,
        method: str,
        path: str,
        params: dict[str, str],
        payload: JsonObject | None,
    ) -> JsonValue:
        headers: dict[str, str] = {"Authorization": f"Bearer {self.settings.secret}"}
        for attempt in range(1, 4):
            try:
                response: httpx.Response = client.request(
                    method,
                    self.settings.controller + path,
                    headers=headers,
                    params=params,
                    json=payload,
                )
            except httpx.TransportError as error:
                failure: ControllerError = ControllerError(
                    f"{method} {self.settings.controller}{path}, params={params}: {error}"
                )
                if attempt == 3:
                    raise failure from error
            else:
                if response.is_success:
                    if response.status_code == 204 or not response.content:
                        return None
                    try:
                        decoded: object = json.loads(response.content)
                    except json.JSONDecodeError as error:
                        raise ControllerError(
                            f"{method} {path}: HTTP {response.status_code}, invalid JSON response"
                        ) from error
                    return json_value(decoded, f"{method} {path}")
                body: str = response.text[:1000]
                if self.settings.secret:
                    body = body.replace(self.settings.secret, "[REDACTED]")
                payload_context: object = (
                    "[configuration omitted]"
                    if payload is not None and "payload" in payload
                    else payload
                )
                failure = ControllerError(
                    f"{method} {path}, params={params}, payload={payload_context}: "
                    f"HTTP {response.status_code}, response={body}"
                )
                if response.status_code < 500 or attempt == 3:
                    raise failure
            logging.getLogger(__name__).warning(
                "controller_request_retry",
                extra={"method": method, "path": path, "attempt": attempt, "error": str(failure)},
            )
            time.sleep(0.2 * attempt)
        raise ControllerError(f"Request retries exhausted: {method} {path}")

    def proxies(self) -> tuple[Proxy, ...]:
        response: JsonObject = as_object(self.request("GET", "/proxies", {}, None), "proxies")
        items: JsonObject = as_object(response.get("proxies"), "proxies.proxies")
        return tuple(parse_proxy(name, value) for name, value in items.items())

    def rules(self) -> tuple[RuntimeRule, ...]:
        response: JsonObject = as_object(self.request("GET", "/rules", {}, None), "rules")
        return tuple(
            parse_rule(value, index)
            for index, value in enumerate(as_list(response.get("rules"), "rules.rules"), 1)
        )

    def connections(self) -> tuple[Connection, ...]:
        response: JsonObject = as_object(
            self.request("GET", "/connections", {}, None), "connections"
        )
        values: JsonValue = response.get("connections")
        if values is None:
            return ()
        return tuple(
            parse_connection(value) for value in as_list(values, "connections.connections")
        )

    def reload(self, payload: str) -> None:
        self.request("PUT", "/configs", {"force": "true"}, {"payload": payload})

    def snapshot(self) -> Snapshot:
        config: JsonObject = as_object(self.request("GET", "/configs", {}, None), "configs")
        version: JsonObject = as_object(self.request("GET", "/version", {}, None), "version")
        rules_response: JsonObject = as_object(self.request("GET", "/rules", {}, None), "rules")
        rules: list[JsonValue] = as_list(rules_response.get("rules"), "rules.rules")
        targets: tuple[str, ...] = tuple(
            dict.fromkeys(
                as_string(as_object(rule, "rule").get("proxy"), "rule.proxy") for rule in rules
            )
        )
        tun: JsonObject = as_object(config.get("tun", {}), "configs.tun")
        tun_enabled: JsonValue = tun.get("enable", False)
        if not isinstance(tun_enabled, bool):
            raise ConfigurationError("configs.tun.enable must be a boolean")
        mode: str = as_string(config.get("mode"), "configs.mode").lower()
        if mode not in {"rule", "global", "direct"}:
            raise ConfigurationError(f"Unknown live mode: {mode}")
        return Snapshot(
            mode,
            as_string(version.get("version"), "version.version"),
            as_int(config.get("mixed-port", 0), "configs.mixed-port"),
            tun_enabled,
            self.proxies(),
            targets,
            len(rules),
        )

    def set_mode(self, mode: str) -> None:
        self.request("PATCH", "/configs", {}, {"mode": mode})
        config: JsonObject = as_object(self.request("GET", "/configs", {}, None), "configs")
        if config.get("mode") != mode:
            raise StateConflictError(f"Mode verification failed: requested {mode}")

    def select(self, group: str, member: str) -> None:
        path: str = f"/proxies/{quote(group, safe='')}"
        self.request("PUT", path, {}, {"name": member})
        current: Proxy = proxy_by_name(self.proxies(), group)
        if current.selected != member:
            raise StateConflictError(
                f"Selection verification failed: {group} expected {member}, got {current.selected}"
            )

    def select_node(self, group: str, node: str) -> tuple[tuple[str, str], ...]:
        """Apply the deepest group first and roll back on a known API or state failure."""
        before: tuple[Proxy, ...] = self.proxies()
        path: tuple[tuple[str, str], ...] = selection_path(before, group, node)
        changed: tuple[tuple[str, str], ...] = ()
        committed: bool = False
        try:
            for group_name, member in reversed(path):
                # Include an attempted write: a lost HTTP response may still mean it committed.
                changed = (*changed, (group_name, member))
                self.select(group_name, member)
            committed = True
        finally:
            if not committed:
                error: BaseException | None = sys.exception()
                for group_name, _ in reversed(changed):
                    original: Proxy = proxy_by_name(before, group_name)
                    try:
                        if original.kind in {"URLTest", "Fallback"} and not original.fixed:
                            self.request(
                                "DELETE", f"/proxies/{quote(group_name, safe='')}", {}, None
                            )
                        elif original.selected is not None:
                            self.select(group_name, original.fixed or original.selected)
                    except (ControllerError, StateConflictError) as rollback_error:
                        raise StateConflictError(
                            f"Selection failed: {error}; rollback also failed: {rollback_error}. "
                            "Inspect your groups immediately."
                        ) from rollback_error
        return path
