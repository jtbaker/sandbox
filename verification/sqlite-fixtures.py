import shutil
import sqlite3
import sys
import tempfile
from contextlib import closing
from pathlib import Path


if sys.argv[1] == "prepare":
    for agent in ("pi", "omp"):
        with tempfile.TemporaryDirectory(prefix="sqlite-fixture-") as temporary:
            database = Path(temporary) / "state.db"
            connection = sqlite3.connect(database)
            try:
                assert connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
                connection.execute("CREATE TABLE snapshot_fixture(value TEXT)")
                connection.commit()
                assert connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
                connection.execute(
                    "INSERT INTO snapshot_fixture(value) VALUES (?)",
                    (f"{agent}-wal-committed",),
                )
                connection.commit()
                # Prove the committed row really requires WAL replay, rather
                # than accidentally testing an already-checkpointed database.
                with closing(sqlite3.connect(f"{database.as_uri()}?immutable=1", uri=True)) as main_only:
                    assert main_only.execute("SELECT count(*) FROM snapshot_fixture").fetchone() == (0,)
                assert Path(f"{database}-wal").stat().st_size > 32
                for suffix in ("", "-wal", "-shm"):
                    target = Path("/fixtures") / agent / f"state.db{suffix}"
                    shutil.copyfile(Path(f"{database}{suffix}"), target)
                    target.chmod(0o666)
                # A host runtime WAL database without its SHM must not be
                # opened through the read-only configuration mount at all.
                for root in (Path("/fixtures") / agent,
                             Path("/fixtures") / agent / "profiles" / "work"):
                    shutil.copyfile(database, root / "run" / "browser-cache.db")
            finally:
                connection.close()
    Path("/fixtures/sqlite-prepared").write_text("complete\n")
elif sys.argv[1] == "check":
    for agent in ("pi", "omp"):
        database = Path.home() / f".{agent}" / "state.db"
        assert database.is_file()
        # Assert before connecting: opening a WAL-mode database can itself
        # create sidecars, which must not disguise files copied from the host.
        assert not Path(f"{database}-wal").exists()
        assert not Path(f"{database}-shm").exists()
        with closing(sqlite3.connect(f"{database.as_uri()}?mode=ro&immutable=1", uri=True)) as snapshot:
            assert snapshot.execute("PRAGMA quick_check").fetchall() == [("ok",)]
            assert snapshot.execute("SELECT value FROM snapshot_fixture").fetchall() == [
                (f"{agent}-wal-committed",)
            ]
elif sys.argv[1] == "stress":
    import runpy
    module = runpy.run_path("/usr/local/bin/vm-seed.py")
    connect = sqlite3.connect
    with tempfile.TemporaryDirectory(prefix="sqlite-changing-") as temporary:
        source = Path(temporary) / "models.db"
        destination = Path(temporary) / "snapshot.db"
        with closing(connect(source)) as writer:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("CREATE TABLE revision(value INTEGER)")
            writer.execute("INSERT INTO revision VALUES(0)")
            writer.execute("CREATE TABLE payload(data BLOB)")
            writer.executemany("INSERT INTO payload VALUES(?)", [(b"x" * 4096,)] * 4096)
            writer.commit()
            steps = []

            class ChangingSource(sqlite3.Connection):
                def backup(self, target, *, pages, progress):
                    def advance(status, remaining, total):
                        steps.append(remaining)
                        assert len(steps) <= 40, "snapshot restarted under concurrent writes"
                        if remaining:
                            writer.execute("UPDATE revision SET value=value+1")
                            writer.commit()
                        progress(status, remaining, total)
                    return super().backup(target, pages=pages, progress=advance)

            def changing_connect(database, *args, **kwargs):
                if str(database).endswith("?mode=ro"):
                    kwargs["factory"] = ChangingSource
                return connect(database, *args, **kwargs)

            # Commit a real write between every backup batch. This makes the
            # host-writer race deterministic without relying on thread timing.
            sqlite3.connect = changing_connect
            try:
                module["backup_database"](source, destination)
            finally:
                sqlite3.connect = connect
            with closing(connect(destination)) as snapshot:
                assert snapshot.execute("SELECT value FROM revision").fetchone() == (0,)
                assert snapshot.execute("SELECT count(*) FROM payload").fetchone() == (4096,)
                assert snapshot.execute("PRAGMA quick_check").fetchall() == [("ok",)]
            assert writer.execute("SELECT value FROM revision").fetchone()[0] > 0
else:
    raise SystemExit("unsupported fixture operation")
