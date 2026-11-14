"""GhostAP 2.0 Phase 0 (P6): versioned database migrations."""
import sqlite3

import pytest

from ghostap.storage import MIGRATIONS, SCHEMA_VERSION, SchemaError, Store


def test_versions_are_ordered_and_new_databases_are_current(tmp_path):
    versions = [v for v, _ in MIGRATIONS]
    assert versions == sorted(set(versions)) and versions[0] == 1 and SCHEMA_VERSION == versions[-1]
    with Store(str(tmp_path / "new.db")) as s:
        assert s.schema_version() == SCHEMA_VERSION


def test_pre_versioning_database_is_upgraded(tmp_path):
    db = str(tmp_path / "old.db")
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE observations (id INTEGER PRIMARY KEY, ts REAL NOT NULL, frame_type TEXT NOT NULL, "
                "ssid TEXT NOT NULL, bssid TEXT NOT NULL, oui TEXT, channel INTEGER, security TEXT, rssi INTEGER, "
                "beacon_interval INTEGER, tsf INTEGER, seq INTEGER)")
    con.execute("INSERT INTO observations (ts, frame_type, ssid, bssid) "
                "VALUES (1, 'beacon', 'Lab', 'aa:bb:cc:dd:ee:ff')")
    con.commit()
    con.close()
    with Store(db) as s:
        assert s.schema_version() == SCHEMA_VERSION
        cols = {r[1] for r in s.conn.execute("PRAGMA table_info(observations)")}
        assert {"fingerprint", "rsn", "freq"} <= cols
        assert s.observations()[0]["ssid"] == "Lab"                  # data kept
    with Store(db) as s:                                                # opening again changes nothing
        assert s.schema_version() == SCHEMA_VERSION


def test_database_from_a_newer_ghostap_is_refused(tmp_path):
    db = str(tmp_path / "future.db")
    with Store(db):
        pass
    con = sqlite3.connect(db)
    con.execute("PRAGMA user_version = {:d}".format(SCHEMA_VERSION + 1))
    con.commit()
    con.close()
    with pytest.raises(SchemaError, match="newer GhostAP"):
        Store(db)
