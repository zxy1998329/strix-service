"""Intentionally vulnerable training app. Synthetic data, loopback only."""
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


def database():
    db = sqlite3.connect(":memory:")
    db.executescript("""
        CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, body TEXT);
        INSERT INTO notes VALUES (1, 'alice', 'Shopping', 'Demo apples');
        INSERT INTO notes VALUES (2, 'bob', 'Private', 'DEMO_BOB_PRIVATE_NOTE');
    """)
    return db


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        status = 200
        result = None
        db = database()
        try:
            if parsed.path == "/":
                result = {"app": "Training notes", "user": "alice",
                          "routes": ["/search?q=Shopping", "/notes?id=1"],
                          "launch": "python3 app.py (127.0.0.1:8765 only)"}
            elif parsed.path == "/search":
                query = params.get("q", [""])[0]
                rows = db.execute(
                    f"SELECT id,owner,title,body FROM notes WHERE owner='alice' AND title LIKE '%{query}%'"
                ).fetchall()
                result = {"notes": rows}
            elif parsed.path == "/notes":
                note_id = params.get("id", ["1"])[0]
                result = {"current_user": "alice", "note": db.execute(
                    "SELECT id,owner,title,body FROM notes WHERE id=?", (note_id,)
                ).fetchone()}
            else:
                status, result = 404, {"error": "not found"}
        except sqlite3.Error:
            status, result = 400, {"error": "invalid query"}
        finally:
            db.close()
        body = json.dumps(result).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
