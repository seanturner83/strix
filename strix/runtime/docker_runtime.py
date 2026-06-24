import contextlib
import logging
import os
import secrets
import socket
import subprocess
import sys
import tarfile
import time
from io import BytesIO
from pathlib import Path
from typing import cast
from urllib.parse import urlparse

import docker
import httpx
from docker.errors import DockerException, ImageNotFound, NotFound
from docker.models.containers import Container
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import Timeout as RequestsTimeout

from strix.config import Config

from . import SandboxInitializationError
from .runtime import AbstractRuntime, SandboxInfo


HOST_GATEWAY_HOSTNAME = "host.docker.internal"
DOCKER_TIMEOUT = 60
CONTAINER_TOOL_SERVER_PORT = 48081
CONTAINER_CAIDO_PORT = 48080

logger = logging.getLogger(__name__)


class DockerRuntime(AbstractRuntime):
    def __init__(self) -> None:
        try:
            self.client = docker.from_env(timeout=DOCKER_TIMEOUT)
        except (DockerException, RequestsConnectionError, RequestsTimeout) as e:
            raise SandboxInitializationError(
                "Docker is not available",
                "Please ensure Docker Desktop is installed and running.",
            ) from e

        self._scan_container: Container | None = None
        self._tool_server_port: int | None = None
        self._tool_server_token: str | None = None
        self._caido_port: int | None = None

    def _find_available_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            return cast("int", s.getsockname()[1])

    def _get_scan_id(self, agent_id: str) -> str:
        try:
            from strix.telemetry.tracer import get_global_tracer  # noqa: PLC0415

            tracer = get_global_tracer()
            if tracer and tracer.scan_config:
                return str(tracer.scan_config.get("scan_id", "default-scan"))
        except (ImportError, AttributeError):
            pass
        return f"scan-{agent_id.split('-', maxsplit=1)[0]}"

    def _verify_image_available(self, image_name: str, max_retries: int = 3) -> None:
        for attempt in range(max_retries):
            try:
                image = self.client.images.get(image_name)
                if not image.id or not image.attrs:
                    raise ImageNotFound(f"Image {image_name} metadata incomplete")  # noqa: TRY301
            except (ImageNotFound, DockerException):
                if attempt == max_retries - 1:
                    raise
                time.sleep(2**attempt)
            else:
                return

    def _recover_container_state(self, container: Container) -> None:
        for env_var in container.attrs["Config"]["Env"]:
            if env_var.startswith("TOOL_SERVER_TOKEN="):
                self._tool_server_token = env_var.split("=", 1)[1]
                break

        port_bindings = container.attrs.get("NetworkSettings", {}).get("Ports", {})
        port_key = f"{CONTAINER_TOOL_SERVER_PORT}/tcp"
        if port_bindings.get(port_key):
            self._tool_server_port = int(port_bindings[port_key][0]["HostPort"])

        caido_port_key = f"{CONTAINER_CAIDO_PORT}/tcp"
        if port_bindings.get(caido_port_key):
            self._caido_port = int(port_bindings[caido_port_key][0]["HostPort"])

    def _wait_for_tool_server(self, max_retries: int = 30, timeout: int = 5) -> None:
        host = self._resolve_docker_host()
        health_url = f"http://{host}:{self._tool_server_port}/health"

        time.sleep(5)

        for attempt in range(max_retries):
            try:
                with httpx.Client(trust_env=False, timeout=timeout) as client:
                    response = client.get(health_url)
                    if response.status_code == 200:
                        data = response.json()
                        if data.get("status") == "healthy":
                            return
            except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError):
                pass

            time.sleep(min(2**attempt * 0.5, 5))

        raise SandboxInitializationError(
            "Tool server failed to start",
            "Container initialization timed out. Please try again.",
        )

    def _force_free_container_name(self, name: str, max_passes: int = 6) -> None:
        """Best-effort guarantee that no container with `name` exists.

        The previous inline cleanup (get → stop → remove(force=True) → sleep 1)
        races against Docker's lagged name-release: when a container fails
        partway through init (e.g. the tool-server-port wait times out),
        remove() returns "success" but Docker keeps the name reserved for a
        moment while the underlying container is torn down. The next
        containers.run() with the same name then 409s. We observed this
        consistently on busy ARC pods (seedcx infra, 2026-05-15 → 05-18,
        ~6% strix-pr-dispatch failure rate, all the same 409 pattern).

        This helper polls until the name is genuinely free, killing + removing
        any container holding it on each pass. Idempotent and safe to call
        even when no container exists.
        """
        for _ in range(max_passes):
            try:
                existing = self.client.containers.get(name)
            except NotFound:
                return
            except DockerException:
                # Transient API error — back off + retry the get
                time.sleep(0.3)
                continue
            # Container exists; kill + remove. Both are best-effort —
            # a kill-then-remove on a container that's already stopping
            # may raise APIError, which we silently ignore so the next
            # pass can retry the get/remove cycle.
            with contextlib.suppress(Exception):
                existing.kill()
            with contextlib.suppress(Exception):
                existing.remove(force=True, v=True)
            time.sleep(0.5)
        # Final check: if the name is STILL taken, escalate. This is a
        # genuine "Docker is wedged" state — runner reboot territory.
        try:
            self.client.containers.get(name)
        except NotFound:
            return
        raise SandboxInitializationError(
            "Could not free container name",
            f"After {max_passes} cleanup passes, container {name!r} still exists "
            "and could not be removed. Docker daemon may be in a wedged state — "
            "consider restarting the runner or its docker daemon.",
        )

    def _get_extra_hosts(self) -> dict[str, str]:
        extra_hosts = {HOST_GATEWAY_HOSTNAME: "host-gateway"}
        configured_hosts = Config.get("strix_sandbox_extra_hosts")
        if not configured_hosts:
            return extra_hosts

        for raw_host_entry in configured_hosts.split(","):
            host_entry = raw_host_entry.strip()
            if not host_entry:
                continue

            parts = [part.strip() for part in host_entry.split("=")]
            if len(parts) != 2:
                raise ValueError(
                    "STRIX_SANDBOX_EXTRA_HOSTS entries must use hostname=address format"
                )

            hostname, address = parts
            if not hostname or not address:
                raise ValueError(
                    "STRIX_SANDBOX_EXTRA_HOSTS entries must include both hostname and address"
                )

            extra_hosts[hostname] = address

        return extra_hosts

    def _create_container(self, scan_id: str, max_retries: int = 2) -> Container:
        base_name = f"strix-scan-{scan_id}"
        image_name = Config.get("strix_image")
        if not image_name:
            raise ValueError("STRIX_IMAGE must be configured")

        self._verify_image_available(image_name)

        last_error: Exception | None = None
        for attempt in range(max_retries + 1):
            # Unique name per attempt. The previous fix (poll-until-name-freed
            # cleanup) was insufficient: Docker has a known quirk where a
            # container in a partial/dying init state can reserve its name
            # internally without appearing in containers.get() — so our
            # cleanup helper sees "name free" but the subsequent
            # containers.run() still 409s. Empirically observed on
            # seedcx infra 2026-05-18: zh-global-infrastructure scan with
            # the previous fix in place still hit the 409 on first
            # attempt's retry.
            #
            # Suffixing the name on retry sidesteps the issue entirely:
            # each attempt uses a different name, so name-reservation
            # collision is impossible. The strix-scan-id label is stable
            # across the suffix variation, so _get_or_create_container's
            # label-based lookup (line ~252) still finds the resulting
            # container on later calls.
            container_name = base_name if attempt == 0 else f"{base_name}-r{attempt}"
            try:
                # Still run the cleanup helper for the FIRST attempt, in
                # case there's a leftover from an earlier scan_id collision
                # on the same ARC pod. Useful but not load-bearing — the
                # unique-name guarantees correctness even if cleanup fails.
                if attempt == 0:
                    self._force_free_container_name(container_name)

                self._tool_server_port = self._find_available_port()
                self._caido_port = self._find_available_port()
                self._tool_server_token = secrets.token_urlsafe(32)
                execution_timeout = Config.get("strix_sandbox_execution_timeout") or "120"

                container = self.client.containers.run(
                    image_name,
                    command="sleep infinity",
                    detach=True,
                    name=container_name,
                    hostname=container_name,
                    ports={
                        f"{CONTAINER_TOOL_SERVER_PORT}/tcp": self._tool_server_port,
                        f"{CONTAINER_CAIDO_PORT}/tcp": self._caido_port,
                    },
                    cap_add=["NET_ADMIN", "NET_RAW"],
                    labels={"strix-scan-id": scan_id},
                    environment={
                        "PYTHONUNBUFFERED": "1",
                        "TOOL_SERVER_PORT": str(CONTAINER_TOOL_SERVER_PORT),
                        "TOOL_SERVER_TOKEN": self._tool_server_token,
                        "STRIX_SANDBOX_EXECUTION_TIMEOUT": str(execution_timeout),
                        "HOST_GATEWAY": HOST_GATEWAY_HOSTNAME,
                        # SEC-6848: forward CodeArtifact tokens for the
                        # SCIP indexer's `cargo fetch` step. Minted by
                        # the strix-scan composite via IRSA before
                        # sandbox launch (composite-actions
                        # rw-security.yml + strix-scan-workflow
                        # action.yml). Absent on local docker runs and
                        # GH-hosted runners — indexer's _index_rust
                        # degrades to no-Rust-code_graph cleanly.
                        **{
                            k: v
                            for k, v in os.environ.items()
                            if k.startswith("CARGO_REGISTRIES_") and k.endswith("_TOKEN")
                        },
                        # SEC-6848: forward Go module-resolution env vars
                        # so scip-go's `go list` / `go mod download` step
                        # can fetch private seedcx modules during the
                        # SCIP index build. Without these scip-go falls
                        # back to "github.com/golang/go/src" monikers on
                        # private deps — symbols are still indexed but
                        # module/version disambiguation is lost (~92%
                        # symbol coverage vs full GOPROXY-enabled local
                        # build; observed on connection-service
                        # 2026-06-09). Setting GOPROXY=internal mirror +
                        # GOSUMDB=off matches the precedent landed by
                        # composite-actions PR #1148 for e2e tests.
                        # Absent on local / GH-hosted — scip-go degrades
                        # gracefully (in-tree symbols still indexed).
                        **{
                            k: v
                            for k, v in os.environ.items()
                            if k in ("GOPROXY", "GOPRIVATE", "GOSUMDB", "GONOPROXY", "GOFLAGS")
                        },
                        # SEC-6848: forward npm auth + config env vars
                        # for scip-typescript's `npm install` step.
                        # Without these, npm install can't resolve
                        # private @seedcx packages or
                        # CodeArtifact-mirrored ones, scip-typescript
                        # runs against the bare tree, and the SCIP
                        # index is partial (cross-package refs to
                        # private deps are missing). NPM_TOKEN /
                        # NODE_AUTH_TOKEN are the standard names;
                        # NPM_CONFIG_* lets npm CLI read registry +
                        # other config overrides from env without a
                        # baked .npmrc in the sandbox image.
                        **{
                            k: v
                            for k, v in os.environ.items()
                            if k in ("NPM_TOKEN", "NODE_AUTH_TOKEN") or k.startswith("NPM_CONFIG_")
                        },
                    },
                    extra_hosts=self._get_extra_hosts(),
                    tty=True,
                )

                self._scan_container = container
                self._wait_for_tool_server()

            except (DockerException, RequestsConnectionError, RequestsTimeout) as e:
                last_error = e
                if attempt < max_retries:
                    self._tool_server_port = None
                    self._tool_server_token = None
                    self._caido_port = None
                    time.sleep(2**attempt)
            except ValueError as e:
                raise SandboxInitializationError(
                    "Invalid Docker sandbox host mapping",
                    str(e),
                ) from e
            else:
                return container

        raise SandboxInitializationError(
            "Failed to create container",
            f"Container creation failed after {max_retries + 1} attempts: {last_error}",
        ) from last_error

    def _get_or_create_container(self, scan_id: str) -> Container:
        container_name = f"strix-scan-{scan_id}"

        if self._scan_container:
            try:
                self._scan_container.reload()
                if self._scan_container.status == "running":
                    return self._scan_container
            except NotFound:
                self._scan_container = None
                self._tool_server_port = None
                self._tool_server_token = None
                self._caido_port = None

        try:
            container = self.client.containers.get(container_name)
            container.reload()

            if container.status != "running":
                container.start()
                time.sleep(2)

            self._scan_container = container
            self._recover_container_state(container)
        except NotFound:
            pass
        else:
            return container

        try:
            containers = self.client.containers.list(
                all=True, filters={"label": f"strix-scan-id={scan_id}"}
            )
            if containers:
                container = containers[0]
                if container.status != "running":
                    container.start()
                    time.sleep(2)

                self._scan_container = container
                self._recover_container_state(container)
                return container
        except DockerException:
            pass

        return self._create_container(scan_id)

    def _copy_local_directory_to_container(
        self, container: Container, local_path: str, target_name: str | None = None
    ) -> None:
        try:
            local_path_obj = Path(local_path).resolve()
            if not local_path_obj.exists() or not local_path_obj.is_dir():
                return

            tar_buffer = BytesIO()
            with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
                for item in local_path_obj.rglob("*"):
                    if item.is_file():
                        rel_path = item.relative_to(local_path_obj)
                        arcname = Path(target_name) / rel_path if target_name else rel_path
                        tar.add(item, arcname=arcname)

            tar_buffer.seek(0)
            container.put_archive("/workspace", tar_buffer.getvalue())
            container.exec_run(
                "chown -R pentester:pentester /workspace && chmod -R 755 /workspace",
                user="root",
            )
        except (OSError, DockerException):
            pass

    def _build_code_graph_index(
        self,
        container: Container,
        target_name: str,
        *,
        repo: str | None = None,
        head_sha: str | None = None,
    ) -> None:
        """Pre-build the SCIP code-graph index for a target. Invoked once
        per source after copy-into-container; failure warn-and-continues.

        Runs as `pentester` user inside the container. The indexer module
        is part of strix/tools/code_graph/ which is COPYed into /app at
        build time. Cache key is consulted when (repo, head_sha) are
        supplied by the dispatcher; otherwise build is uncached.

        SEC-6848 W1.3.
        """
        # SEC-6848 + SEC-6671: short-circuit when the sandbox image
        # doesn't carry our code_graph overlay. Weekly-merges runs on
        # GH-hosted runners that can't pull the private ECR image, so
        # they fall back to the upstream public sandbox (per
        # strix-weekly-merges.yml comment). The upstream image has no
        # /app/strix/tools/code_graph, so the indexer subprocess would
        # crash with ModuleNotFoundError and emit a giant stderr block
        # on every cron scan. Detect the overlay's absence and skip
        # silently — code_graph_* tools degrade to "graph not available"
        # which is the correct fallback for those scans.
        try:
            probe_rc, _ = container.exec_run(
                ["sh", "-c", "test -d /app/strix/tools/code_graph"],
                user="pentester",
            )
        except (OSError, DockerException):
            probe_rc = 1
        if probe_rc != 0:
            # Image doesn't have the overlay — common on the upstream
            # public sandbox. Quiet exit; the scan continues normally.
            return

        # SEC-6848 dev diagnostic: stderr print bypasses strix's root-logger
        # ERROR-level suppression (set in strix/interface/main.py). Confirms
        # the hook is reached on every scan; remove once integration is
        # stable and ship a real verdict line via logger.error or events.
        print(
            f"[code_graph hook] entry target={target_name} repo={repo} head_sha={head_sha}",
            file=sys.stderr,
            flush=True,
        )
        target_path = f"/workspace/{target_name}"
        out_dir = f"/app/runtime/code_graph/{target_name}"
        # Upstream Strix sandbox image (0.1.13) ships a venv at
        # /app/venv/ (no dot). We pin the python interpreter directly
        # via full path, and wrap the cmd in `sh -c` so PATH only gets
        # /home/pentester/go/bin PREPENDED (for scip-go) without
        # stripping the container's default PATH — which is what holds
        # the npm-global bin where scip-typescript lives. Confirmed
        # via funding-service probe v2 (2026-06-05): scip-typescript
        # disappeared from `which` when PATH was set explicitly.
        indexer_cmd = (
            "/app/venv/bin/python3 -m strix.tools.code_graph.indexer "
            f"--target {target_path} --out-dir {out_dir}"
        )
        if repo:
            indexer_cmd += f" --repo {repo}"
        if head_sha:
            indexer_cmd += f" --head-sha {head_sha}"
        cmd_parts = [
            "sh",
            "-c",
            f"export PATH=/home/pentester/go/bin:$PATH; {indexer_cmd}",
        ]
        try:
            container.exec_run(
                ["sh", "-c", f"mkdir -p {out_dir}"],
                user="pentester",
            )
            # SEC-6848 diagnostic: probe which scip-* binaries exist
            # and where. funding-service whitebox runs are exiting with
            # ls='total 0' even with venv-python pinned — the indexer
            # falls through silently when scip-go isn't on PATH. Print
            # the probe results so we can see what shutil.which sees
            # from inside the container, with the same env+user as the
            # indexer subprocess.
            # SEC-6848 probe v1-v4 retired — root cause identified
            # (scip-typescript needs npm install for tsconfig extends
            # chain resolution on zh repos extending seed-tsconfig-*).
            # Fix lives in strix/tools/code_graph/indexer.py:_index_typescript.
            # Cleanup happens post-indexer below.
            # Pre-LLM-loop step: cap at 10 min so a runaway indexer can't
            # stall the scan. scip-typescript ran in ~0.5s on portal-api
            # and scip-go in ~32s on payment-orchestrator during W1 smoke;
            # the cap is generous headroom for monorepo-shaped targets we
            # haven't yet measured.
            exit_code, output = container.exec_run(
                cmd_parts,
                user="pentester",
                workdir="/app",
                environment={
                    # Strix module is at /app/strix from the build-time
                    # COPY overlay. Put /app on the import path so
                    # `python3 -m strix.tools.code_graph.indexer`
                    # resolves regardless of how the upstream image's
                    # Python is configured.
                    "PYTHONPATH": "/app",
                    # NOTE: PATH is no longer set explicitly. The cmd
                    # is wrapped in `sh -c "export PATH=/home/pentester/
                    # go/bin:$PATH; ..."` which prepends the Go-bin to
                    # the container's default PATH rather than replacing
                    # it. This preserves the npm-global bin dir where
                    # scip-typescript lives. Confirmed via probe v2 on
                    # funding-service (2026-06-05): explicit PATH=... in
                    # env dict stripped scip-typescript visibility.
                    # Surface the env-keyed cache root to the indexer
                    # subprocess. Default unset → NullCache; the GHA
                    # workflow sets this to a host-mounted dir it syncs
                    # to/from S3 if cross-run caching is desired.
                    "STRIX_CODE_GRAPH_CACHE_DIR": os.environ.get(
                        "STRIX_CODE_GRAPH_CACHE_DIR", ""
                    ),
                },
            )
            # SEC-6848 dev-loop visibility: surface stdout+stderr and an
            # ls of the output dir on EVERY run, regardless of exit code.
            # The indexer's _main swallows IndexerError and exits 0 even
            # when no SCIP is produced (eg. tsconfig.json/package.json
            # absent at repo root, or scip-typescript off-PATH for
            # pentester). Without this the query layer's
            # _render_unavailable() fallback fires silently and the
            # integration looks like it's working when it isn't.
            output_str = (
                output.decode("utf-8", errors="replace") if output else ""
            )[:2000]
            try:
                ls_code, ls_output = container.exec_run(
                    ["sh", "-c", f"ls -la {out_dir} 2>&1 || true"],
                    user="pentester",
                )
                ls_str = (
                    ls_output.decode("utf-8", errors="replace") if ls_output else ""
                )[:500]
            except (OSError, DockerException):
                ls_str = "(ls failed)"
            # SEC-6848 dev diagnostic: stderr print bypasses log-level
            # suppression. Always visible in GHA `tee -a run.log` output.
            # output_str captures up to 2000 chars; print all of it
            # (textblob/runpy module warnings alone fill ~600 chars on
            # import, so we need to surface what comes after them).
            print(
                f"[code_graph hook] exit={exit_code} target={target_name} "
                f"out={output_str!r} ls={ls_str!r}",
                file=sys.stderr,
                flush=True,
            )
            # SEC-6848 follow-up: persist SCIP outputs to host FS for
            # S3 upload + post-hoc inspection. /app/runtime/code_graph/
            # <target>/ lives inside the ephemeral sandbox container —
            # containers.run() above takes no volumes=, so without an
            # explicit get_archive the SCIP index dies with the
            # container and the integration is unobservable post-run.
            # When STRIX_CODE_GRAPH_PERSIST_DIR is set by the calling
            # workflow (strix-scan composite passes work/$RUN_DIR/
            # code_graph), the existing `aws s3 cp --recursive
            # work/$RUN_DIR` upload picks the extracted tree up for
            # free. Unset on local dev runs → no-op.
            persist_dir = os.environ.get("STRIX_CODE_GRAPH_PERSIST_DIR", "")
            if persist_dir:
                try:
                    bits, _ = container.get_archive(
                        f"/app/runtime/code_graph/{target_name}"
                    )
                    Path(persist_dir).mkdir(parents=True, exist_ok=True)
                    with tarfile.open(
                        fileobj=BytesIO(b"".join(bits)), mode="r"
                    ) as tar:
                        # filter="data" guards against tarfile path
                        # traversal — sandbox container is pen-test
                        # scope and not fully trusted from a strict
                        # view, even though the SCIP indexer writes
                        # known filenames.
                        tar.extractall(persist_dir, filter="data")
                    print(
                        f"[code_graph hook] persist OK target={target_name} "
                        f"dest={persist_dir}",
                        file=sys.stderr,
                        flush=True,
                    )
                except (
                    OSError,
                    DockerException,
                    NotFound,
                    tarfile.TarError,
                    ValueError,
                ) as exc:
                    print(
                        f"[code_graph hook] persist FAILED target={target_name} "
                        f"exc={exc!r}",
                        file=sys.stderr,
                        flush=True,
                    )
            # SEC-6848: clean up TS indexer scaffolding so the LLM scan
            # loop sees a pristine target tree. _index_typescript runs
            # `npm install` inside /workspace/<target>/ to resolve the
            # tsconfig extends chain — that leaves a multi-GB
            # node_modules + package-lock.json behind. Strip both
            # before the agent loop starts so list_files / search_files
            # don't drown in vendored code.
            try:
                # Sweep indexer-side scaffolding so the agent loop sees a
                # pristine target tree:
                #   - node_modules (TS path)
                #   - .venv / venv / __pycache__ (Python path)
                #   - target/ (Rust path)
                # Don't remove tsconfig.json/package.json/pyproject.toml/
                # go.mod/Cargo.toml — those are real source artifacts the
                # LLM may need to read.
                #
                # Lockfiles need care: `npm install` / `cargo fetch` regenerate
                # a committed lockfile in place, and `rm`-ing it unconditionally
                # makes the agent loop's `git diff` see the COMMITTED, tracked
                # lockfile as DELETED — raising a phantom "package-lock.json
                # removed -> supply-chain tampering" (CWE-494) for a file the PR
                # never touched (trade-api#4309 / GHAS#775: a real 4-line dep
                # bump reported as a 13,877-line deletion). So rm the lockfiles
                # (to drop indexer churn) then RESTORE any that were committed.
                # Two subtleties, both load-bearing:
                #   1. `git checkout HEAD --` (not bare `checkout --`): on git
                #      >=2.23 the bare form does NOT restore a DELETED tracked
                #      path; the explicit HEAD source does.
                #   2. Restore each lockfile in its OWN checkout. A combined
                #      `checkout HEAD -- a b` ABORTS (restoring nothing) if any
                #      pathspec is absent from HEAD — and Node repos have no
                #      Cargo.lock / Rust repos no package-lock.json, so a
                #      combined call fails for nearly every repo. Per-file +
                #      `|| true` makes a missing/untracked path a no-op for that
                #      file only (untracked, indexer-generated lockfiles stay
                #      swept; committed ones come back byte-for-byte).
                container.exec_run(
                    [
                        "sh",
                        "-c",
                        f"cd /workspace/{target_name} && "
                        "rm -rf node_modules package-lock.json Cargo.lock "
                        ".venv venv __pycache__ "
                        "target 2>&1 || true; "
                        "for lf in package-lock.json Cargo.lock; do "
                        'git checkout HEAD -- "$lf" 2>/dev/null || true; '
                        "done",
                    ],
                    user="pentester",
                )
            except (OSError, DockerException) as exc:
                print(
                    f"[code_graph hook] cleanup FAILED target={target_name} exc={exc!r}",
                    file=sys.stderr,
                    flush=True,
                )
        except (OSError, DockerException) as exc:
            print(
                f"[code_graph hook] EXCEPTION target={target_name} exc={exc!r}",
                file=sys.stderr,
                flush=True,
            )

    async def create_sandbox(
        self,
        agent_id: str,
        existing_token: str | None = None,
        local_sources: list[dict[str, str]] | None = None,
    ) -> SandboxInfo:
        scan_id = self._get_scan_id(agent_id)
        container = self._get_or_create_container(scan_id)

        source_copied_key = f"_source_copied_{scan_id}"
        if local_sources and not hasattr(self, source_copied_key):
            for index, source in enumerate(local_sources, start=1):
                source_path = source.get("source_path")
                if not source_path:
                    continue
                target_name = (
                    source.get("workspace_subdir") or Path(source_path).name or f"target_{index}"
                )
                self._copy_local_directory_to_container(container, source_path, target_name)
                # SEC-6848 W1.3: pre-build the SCIP code-graph index for the
                # target. Cache key is (repo, head_sha) when the dispatcher
                # provides them; otherwise build uncached. Failure here
                # warn-and-continues — a missing index degrades the W2
                # graph tools to no-ops but does not break the scan.
                self._build_code_graph_index(
                    container,
                    target_name=target_name,
                    repo=source.get("repo"),
                    head_sha=source.get("head_sha"),
                )
            setattr(self, source_copied_key, True)

        if container.id is None:
            raise RuntimeError("Docker container ID is unexpectedly None")

        token = existing_token or self._tool_server_token
        if self._tool_server_port is None or self._caido_port is None or token is None:
            raise RuntimeError("Tool server not initialized")

        host = self._resolve_docker_host()
        api_url = f"http://{host}:{self._tool_server_port}"

        await self._register_agent(api_url, agent_id, token)

        return {
            "workspace_id": container.id,
            "api_url": api_url,
            "auth_token": token,
            "tool_server_port": self._tool_server_port,
            "caido_port": self._caido_port,
            "agent_id": agent_id,
        }

    async def _register_agent(self, api_url: str, agent_id: str, token: str) -> None:
        try:
            async with httpx.AsyncClient(trust_env=False) as client:
                response = await client.post(
                    f"{api_url}/register_agent",
                    params={"agent_id": agent_id},
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=30,
                )
                response.raise_for_status()
        except httpx.RequestError:
            pass

    async def get_sandbox_url(self, container_id: str, port: int) -> str:
        try:
            self.client.containers.get(container_id)
            return f"http://{self._resolve_docker_host()}:{port}"
        except NotFound:
            raise ValueError(f"Container {container_id} not found.") from None

    def _resolve_docker_host(self) -> str:
        docker_host = os.getenv("DOCKER_HOST", "")
        if docker_host:
            parsed = urlparse(docker_host)
            if parsed.scheme in ("tcp", "http", "https") and parsed.hostname:
                return parsed.hostname
        return "127.0.0.1"

    async def destroy_sandbox(self, container_id: str) -> None:
        try:
            container = self.client.containers.get(container_id)
            container.stop()
            container.remove()
            self._scan_container = None
            self._tool_server_port = None
            self._tool_server_token = None
            self._caido_port = None
        except (NotFound, DockerException):
            pass

    def cleanup(self) -> None:
        if self._scan_container is not None:
            container_name = self._scan_container.name
            self._scan_container = None
            self._tool_server_port = None
            self._tool_server_token = None
            self._caido_port = None

            if container_name is None:
                return

            subprocess.Popen(  # noqa: S603
                ["docker", "rm", "-f", container_name],  # noqa: S607
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
