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

import pytest
from pydantic import ValidationError

from strix.config import loader
from strix.config.settings import RuntimeSettings
from strix.core.inputs import DEFAULT_MAX_TURNS, resolve_default_max_turns
from strix.interface.main import parse_arguments


@pytest.fixture(autouse=True)
def _reset_settings_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_MAX_ITERATIONS", raising=False)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)


def test_runtime_settings_reads_strix_max_iterations(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_MAX_ITERATIONS", "8")
    assert RuntimeSettings().max_turns == 8


def test_runtime_settings_max_turns_defaults_to_none() -> None:
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
