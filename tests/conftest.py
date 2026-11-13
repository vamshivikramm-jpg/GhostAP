"""Shared test setup: keep the developer's own dashboard settings out of the tests."""
import pytest

import ghostap.config


@pytest.fixture(autouse=True)
def _isolated_settings_overlay(tmp_path, monkeypatch):
    monkeypatch.setattr(ghostap.config, "SETTINGS_OVERLAY", str(tmp_path / "settings.yaml"))
