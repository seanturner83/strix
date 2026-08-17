"""STRIX_MAX_ITERATIONS restores the pre-v1.x env-var turn-cap override.

Regression coverage for the fleet-wiring gap: seedcx/strix-scan-workflow's
dynamic per-diff-shape cap (resolve_turn_cap in strix-pr-dispatch.yml) has
only ever exported STRIX_MAX_ITERATIONS as an env var, never --max-turns as
a CLI flag. The v1.x SDK-harness rewrite moved the turn cap to --max-turns
(argparse default DEFAULT_MAX_TURNS=500) and dropped the env-var read
entirely, so the computed cap silently stopped reaching the agent loop.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from strix.config import loader


if TYPE_CHECKING:
    from pathlib import Path
from strix.config.settings import RuntimeSettings
from strix.core.inputs import DEFAULT_MAX_TURNS, resolve_default_max_turns
from strix.interface.main import parse_arguments


@pytest.fixture(autouse=True)
def _reset_settings_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("STRIX_MAX_ITERATIONS", raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    # Point the JSON-override fallback at a path that doesn't exist, not
    # None (which falls through to the real ~/.strix/cli-config.json on
    # disk). Without this, these tests are only hermetic on a machine
    # that's never run `strix` locally with a persisted config -- any
    # real ambient value (e.g. a prior local STRIX_MAX_ITERATIONS=2 run)
    # silently leaks in as the "unset" case's answer.
    monkeypatch.setattr(loader, "_override", tmp_path / "unused-cli-config.json")


def test_runtime_settings_reads_strix_max_iterations(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_MAX_ITERATIONS", "8")
    assert RuntimeSettings().max_turns == 8


def test_runtime_settings_max_turns_defaults_to_none() -> None:
    assert RuntimeSettings().max_turns is None


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_runtime_settings_blank_env_means_unset(
    monkeypatch: pytest.MonkeyPatch, blank: str
) -> None:
    """strix-scan-workflow's composite action declares max_iterations with
    default: "" and unconditionally exports it as STRIX_MAX_ITERATIONS, so
    most callers set this to a present-but-blank string, not an absent one.
    A blank value must mean "no override", not a pydantic int-coercion crash
    on every invocation including --help (SEC-7400 follow-up, weekly-scan
    outage 2026-08-15)."""
    monkeypatch.setenv("STRIX_MAX_ITERATIONS", blank)
    assert RuntimeSettings().max_turns is None


def test_runtime_settings_rejects_non_positive_max_turns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_MAX_ITERATIONS", "0")
    with pytest.raises(ValidationError):
        RuntimeSettings()


def test_resolve_default_max_turns_uses_env_when_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_MAX_ITERATIONS", "30")
    assert resolve_default_max_turns() == 30


def test_resolve_default_max_turns_falls_back_when_unset() -> None:
    assert resolve_default_max_turns() == DEFAULT_MAX_TURNS == 500


def test_cli_default_max_turns_follows_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """Composite action's real invocation shape: env var set, --max-turns omitted."""
    monkeypatch.setenv("STRIX_MAX_ITERATIONS", "8")
    monkeypatch.setattr(sys, "argv", ["strix", "--target", "https://example.com"])
    args = parse_arguments()
    assert args.max_turns == 8


def test_cli_explicit_max_turns_wins_over_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit --max-turns flag always overrides the env-var default."""
    monkeypatch.setenv("STRIX_MAX_ITERATIONS", "8")
    monkeypatch.setattr(
        sys, "argv", ["strix", "--target", "https://example.com", "--max-turns", "50"]
    )
    args = parse_arguments()
    assert args.max_turns == 50


def test_cli_default_max_turns_is_500_without_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["strix", "--target", "https://example.com"])
    args = parse_arguments()
    assert args.max_turns == 500
