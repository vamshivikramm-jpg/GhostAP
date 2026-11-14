"""Shared test setup: keep the developer's own dashboard settings and data out of the tests."""
import os

import pytest

import ghostap.config


@pytest.fixture(autouse=True)
def _isolated_settings_overlay(tmp_path, monkeypatch):
    monkeypatch.setattr(ghostap.config, "SETTINGS_OVERLAY", str(tmp_path / "settings.yaml"))
    # saved-baseline signing key (ghostap/baselines.py): never the developer's real one
    monkeypatch.setenv("GHOSTAP_BASELINE_KEY_FILE", str(tmp_path / "keys" / "baseline.key"))


_REAL_ADMIN_DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "admin.db")


def _fingerprint(path):
    """Schema version, tables and CLI audit rows: what a test could change by mistake. (Not the
    file time: a dashboard running next to the tests may write to it legitimately.)"""
    if not os.path.exists(path):
        return None
    import sqlite3
    con = sqlite3.connect("file:{}?mode=ro".format(path), uri=True)
    try:
        return (con.execute("PRAGMA user_version").fetchone()[0],
                sorted(r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")),
                con.execute("SELECT COUNT(*) FROM audit WHERE actor LIKE 'cli:%'").fetchone()[0])
    except sqlite3.OperationalError:
        return "unreadable"
    finally:
        con.close()


@pytest.fixture(autouse=True, scope="session")
def _real_admin_db_untouched():
    """No test may write the real data/admin.db (accounts, audit, baseline versions). One did
    once: it upgraded the schema under a running dashboard, which then refused every request."""
    before = _fingerprint(_REAL_ADMIN_DB)
    yield
    assert _fingerprint(_REAL_ADMIN_DB) == before, "a test wrote the real data/admin.db"
