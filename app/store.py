import json
import os
import sqlite3
import threading


class Store:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("pragma journal_mode=wal")
        self.db.execute(
            "create table if not exists runs("
            "run_id text primary key, req_hash text not null, "
            "state text not null, secrets text not null)"
        )
        self.db.commit()
        self.lock = threading.Lock()

    def get(self, run_id: str):
        with self.lock:
            row = self.db.execute(
                "select req_hash, state, secrets from runs where run_id=?", (run_id,)
            ).fetchone()
        if not row:
            return None
        return row[0], json.loads(row[1]), json.loads(row[2])

    def put(self, run_id: str, req_hash: str, state: dict, secret_list: list):
        with self.lock:
            self.db.execute(
                "insert into runs(run_id, req_hash, state, secrets) values(?,?,?,?) "
                "on conflict(run_id) do update set req_hash=excluded.req_hash, "
                "state=excluded.state, secrets=excluded.secrets",
                (run_id, req_hash, json.dumps(state), json.dumps(secret_list)),
            )
            self.db.commit()
