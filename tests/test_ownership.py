"""Files made under sudo (live capture) go back to the user who ran sudo."""
import os

import pytest

from ghostap import ownership


def _tree(tmp_path):
    lab = tmp_path / "data" / "lab"
    lab.mkdir(parents=True)
    pcap = lab / "run1.pcap"
    pcap.write_bytes(b"x")
    sess = tmp_path / "data" / "sessions" / "s1"
    sess.mkdir(parents=True)
    (sess / "session.db").write_bytes(b"x")
    (sess / "session.db-wal").write_bytes(b"x")
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir(exist_ok=True)
    (outside / "keep.txt").write_bytes(b"x")
    os.symlink(str(outside), str(sess / "link"))
    return pcap, sess, outside


@pytest.fixture
def as_root(monkeypatch, tmp_path):
    """Pretend: euid 0, started by sudo from uid 1000; every file appears root-owned."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1001")
    real_lstat = os.lstat

    class St:
        def __init__(self, st):
            self.st_mode, self.st_uid = st.st_mode, 0

    monkeypatch.setattr(os, "lstat", lambda p: St(real_lstat(p)))
    changed = []
    monkeypatch.setattr(os, "chown", lambda p, u, g, follow_symlinks=True: changed.append(
        (os.path.relpath(p, tmp_path), u, g, follow_symlinks)))
    monkeypatch.chdir(tmp_path)
    return changed


def test_sudo_user(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1001")
    assert ownership.sudo_user() == (1000, 1001)
    monkeypatch.setenv("SUDO_UID", "0")                 # sudo from root: nothing to give back
    assert ownership.sudo_user() is None
    monkeypatch.setenv("SUDO_UID", "junk")
    assert ownership.sudo_user() is None
    monkeypatch.delenv("SUDO_UID")                       # root without sudo (service, Docker)
    assert ownership.sudo_user() is None
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setattr(os, "geteuid", lambda: 1000)     # not root at all
    assert ownership.sudo_user() is None


def test_not_under_sudo_does_nothing(monkeypatch, tmp_path):
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.setattr(os, "chown", lambda *a, **k: pytest.fail("chown called"))
    pcap, sess, _ = _tree(tmp_path)
    assert ownership.give_back(files=[str(pcap)], trees=[str(sess)]) == 0


def test_files_trees_and_project_parents(as_root, tmp_path):
    pcap, sess, outside = _tree(tmp_path)
    n = ownership.give_back(files=["data/lab/run1.pcap", None, "data/missing.db"],
                            trees=["data/sessions", None, "data/no-such-dir"])
    got = {c[0] for c in as_root}
    assert n == len(as_root)
    assert {"data/lab/run1.pcap", "data/lab", "data", "data/sessions", "data/sessions/s1",
            "data/sessions/s1/session.db", "data/sessions/s1/session.db-wal"} <= got
    # the symlink and what it points to are never touched; nothing outside the project
    assert not any("link" in p or "outside" in p for p in got)
    assert "." not in got
    assert all(c[1:] == (1000, 1001, False) for c in as_root)


def test_database_companions(as_root, tmp_path):
    (tmp_path / "live.db").write_bytes(b"x")
    (tmp_path / "live.db-shm").write_bytes(b"x")
    ownership.give_back(files=["live.db"])
    assert {c[0] for c in as_root} == {"live.db", "live.db-shm"}


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root")
def test_real_chown_when_root(monkeypatch, tmp_path):
    monkeypatch.setenv("SUDO_UID", "54321")
    monkeypatch.setenv("SUDO_GID", "54322")
    monkeypatch.chdir(tmp_path)
    pcap, sess, outside = _tree(tmp_path)
    ownership.give_back(files=["data/lab/run1.pcap"], trees=["data/sessions"])
    for p in (pcap, pcap.parent, tmp_path / "data", sess / "session.db"):
        st = os.lstat(p)
        assert (st.st_uid, st.st_gid) == (54321, 54322), p
    assert os.lstat(outside / "keep.txt").st_uid == 0
    assert os.lstat(tmp_path).st_uid == 0
