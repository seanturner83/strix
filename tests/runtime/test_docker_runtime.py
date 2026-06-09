from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from docker.errors import NotFound

from strix.runtime import SandboxInitializationError
from strix.runtime.docker_runtime import HOST_GATEWAY_HOSTNAME, DockerRuntime


def test_get_extra_hosts_includes_host_gateway(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_SANDBOX_EXTRA_HOSTS", raising=False)

    runtime = DockerRuntime.__new__(DockerRuntime)

    assert runtime._get_extra_hosts() == {HOST_GATEWAY_HOSTNAME: "host-gateway"}


def test_get_extra_hosts_merges_configured_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "STRIX_SANDBOX_EXTRA_HOSTS",
        "test.internal.lan=host-gateway, api.local = 192.168.1.20",
    )

    runtime = DockerRuntime.__new__(DockerRuntime)

    assert runtime._get_extra_hosts() == {
        HOST_GATEWAY_HOSTNAME: "host-gateway",
        "test.internal.lan": "host-gateway",
        "api.local": "192.168.1.20",
    }


def test_get_extra_hosts_rejects_invalid_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_EXTRA_HOSTS", "test.internal.lan")

    runtime = DockerRuntime.__new__(DockerRuntime)

    with pytest.raises(ValueError, match="hostname=address"):
        runtime._get_extra_hosts()


def test_get_extra_hosts_rejects_multiple_equals(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_EXTRA_HOSTS", "test.internal.lan==host-gateway")

    runtime = DockerRuntime.__new__(DockerRuntime)

    with pytest.raises(ValueError, match="hostname=address"):
        runtime._get_extra_hosts()


def test_create_container_passes_configured_extra_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_EXTRA_HOSTS", "test.internal.lan=host-gateway")

    run = MagicMock(return_value=object())
    containers = SimpleNamespace(get=MagicMock(side_effect=NotFound("missing")), run=run)
    runtime = DockerRuntime.__new__(DockerRuntime)
    runtime.client = SimpleNamespace(containers=containers)
    runtime._verify_image_available = MagicMock()
    runtime._find_available_port = MagicMock(side_effect=[12345, 12346])
    runtime._wait_for_tool_server = MagicMock()
    runtime._scan_container = None

    runtime._create_container("scan-id")

    assert run.call_args.kwargs["extra_hosts"] == {
        HOST_GATEWAY_HOSTNAME: "host-gateway",
        "test.internal.lan": "host-gateway",
    }


def test_create_container_wraps_invalid_extra_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_SANDBOX_EXTRA_HOSTS", "test.internal.lan")

    run = MagicMock()
    containers = SimpleNamespace(get=MagicMock(side_effect=NotFound("missing")), run=run)
    runtime = DockerRuntime.__new__(DockerRuntime)
    runtime.client = SimpleNamespace(containers=containers)
    runtime._verify_image_available = MagicMock()
    runtime._find_available_port = MagicMock(side_effect=[12345, 12346])
    runtime._wait_for_tool_server = MagicMock()
    runtime._scan_container = None

    with pytest.raises(SandboxInitializationError, match="Invalid Docker sandbox host mapping"):
        runtime._create_container("scan-id")

    run.assert_not_called()


def _runtime_with_mock_run(run: MagicMock) -> DockerRuntime:
    containers = SimpleNamespace(get=MagicMock(side_effect=NotFound("missing")), run=run)
    runtime = DockerRuntime.__new__(DockerRuntime)
    runtime.client = SimpleNamespace(containers=containers)
    runtime._verify_image_available = MagicMock()
    runtime._find_available_port = MagicMock(side_effect=[12345, 12346])
    runtime._wait_for_tool_server = MagicMock()
    runtime._scan_container = None
    return runtime


def test_create_container_forwards_go_private_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    # SEC-6848: scip-go needs GOPROXY/GOPRIVATE etc. to resolve private
    # seedcx modules during indexing. The orchestrator's env -> sandbox
    # forwarding should pick these up at container creation.
    monkeypatch.setenv("GOPROXY", "https://go.infra.0hash.com,direct")
    monkeypatch.setenv("GOPRIVATE", "github.com/seedcx/*")
    monkeypatch.setenv("GOSUMDB", "off")
    monkeypatch.setenv("GOFLAGS", "-mod=mod")
    monkeypatch.setenv("GONOPROXY", "github.com/seedcx/private-only/*")
    # Negative control: GOROOT must NOT leak through — it's not in the
    # allowlist and the sandbox image sets its own.
    monkeypatch.setenv("GOROOT", "/usr/local/go")

    run = MagicMock(return_value=object())
    runtime = _runtime_with_mock_run(run)
    runtime._create_container("scan-id")

    env = run.call_args.kwargs["environment"]
    assert env["GOPROXY"] == "https://go.infra.0hash.com,direct"
    assert env["GOPRIVATE"] == "github.com/seedcx/*"
    assert env["GOSUMDB"] == "off"
    assert env["GOFLAGS"] == "-mod=mod"
    assert env["GONOPROXY"] == "github.com/seedcx/private-only/*"
    assert "GOROOT" not in env


def test_create_container_forwards_npm_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    # SEC-6848: scip-typescript runs `npm install` before indexing,
    # which needs NPM_TOKEN / NODE_AUTH_TOKEN / NPM_CONFIG_* for
    # private @seedcx packages.
    monkeypatch.setenv("NPM_TOKEN", "npm_aaaaaaaa")
    monkeypatch.setenv("NODE_AUTH_TOKEN", "ghp_bbbbbbbb")
    monkeypatch.setenv("NPM_CONFIG_REGISTRY", "https://npm.pkg.github.com")
    monkeypatch.setenv("NPM_CONFIG__AUTH", "abc123")
    # Negative control: NPM_LIFECYCLE_EVENT is npm-internal noise, not
    # auth/config — must not leak.
    monkeypatch.setenv("NPM_LIFECYCLE_EVENT", "install")

    run = MagicMock(return_value=object())
    runtime = _runtime_with_mock_run(run)
    runtime._create_container("scan-id")

    env = run.call_args.kwargs["environment"]
    assert env["NPM_TOKEN"] == "npm_aaaaaaaa"
    assert env["NODE_AUTH_TOKEN"] == "ghp_bbbbbbbb"
    assert env["NPM_CONFIG_REGISTRY"] == "https://npm.pkg.github.com"
    assert env["NPM_CONFIG__AUTH"] == "abc123"
    assert "NPM_LIFECYCLE_EVENT" not in env


def test_create_container_absent_env_vars_not_forwarded(monkeypatch: pytest.MonkeyPatch) -> None:
    # When the orchestrator runs locally / on GH-hosted without these
    # vars set, the container env dict must not have stray keys —
    # indexer paths degrade gracefully to no-private-deps mode.
    for key in ("GOPROXY", "GOPRIVATE", "GOSUMDB", "GOFLAGS", "GONOPROXY",
                "NPM_TOKEN", "NODE_AUTH_TOKEN", "NPM_CONFIG_REGISTRY"):
        monkeypatch.delenv(key, raising=False)

    run = MagicMock(return_value=object())
    runtime = _runtime_with_mock_run(run)
    runtime._create_container("scan-id")

    env = run.call_args.kwargs["environment"]
    for key in ("GOPROXY", "GOPRIVATE", "GOSUMDB", "GOFLAGS", "GONOPROXY",
                "NPM_TOKEN", "NODE_AUTH_TOKEN", "NPM_CONFIG_REGISTRY"):
        assert key not in env, f"{key} leaked when unset in orchestrator env"
