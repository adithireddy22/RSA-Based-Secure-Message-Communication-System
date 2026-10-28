"""RSA-based secure message communication system (Flask + SQLite)."""
import os
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, g, jsonify, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import crypto_utils

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(32)
app.config["DATABASE"] = os.environ.get("CHAT_DB", "chat.db")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    public_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL REFERENCES users(id),
    receiver_id INTEGER NOT NULL REFERENCES users(id),
    enc_key TEXT NOT NULL,
    nonce TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.executescript(SCHEMA)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if "user_id" not in session:
            return jsonify(error="Login required"), 401
        return fn(*a, **kw)
    return wrapper


@app.route("/")
def index():
    return render_template("index.html")


@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not (3 <= len(username) <= 32) or not username.replace("_", "").isalnum():
        return jsonify(error="Username must be 3-32 letters/digits/underscores"), 400
    if len(password) < 8:
        return jsonify(error="Password must be at least 8 characters"), 400
    private_pem, public_pem = crypto_utils.generate_keypair()
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), public_pem),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Username already taken"), 409
    # The private key is returned ONCE and never stored on the server.
    return jsonify(username=username, public_key=public_pem, private_key=private_pem), 201


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    row = get_db().execute(
        "SELECT * FROM users WHERE username = ?", (data.get("username") or "",)
    ).fetchone()
    if not row or not check_password_hash(row["password_hash"], data.get("password") or ""):
        return jsonify(error="Invalid username or password"), 401
    session.clear()
    session["user_id"], session["username"] = row["id"], row["username"]
    return jsonify(username=row["username"])


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    return jsonify(username=session.get("username"))


@app.get("/api/users")
@login_required
def users():
    rows = get_db().execute("SELECT username FROM users WHERE id != ? ORDER BY username",
                            (session["user_id"],)).fetchall()
    return jsonify(users=[r["username"] for r in rows])


@app.get("/api/users/<username>/public_key")
@login_required
def public_key(username):
    row = get_db().execute("SELECT public_key FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        return jsonify(error="User not found"), 404
    return jsonify(username=username, public_key=row["public_key"])


@app.post("/api/send")
@login_required
def send():
    data = request.get_json(silent=True) or {}
    message = data.get("message") or ""
    if not message or len(message) > 10_000:
        return jsonify(error="Message must be 1-10000 characters"), 400
    db = get_db()
    receiver = db.execute("SELECT id, public_key FROM users WHERE username = ?",
                          (data.get("receiver") or "",)).fetchone()
    if not receiver:
        return jsonify(error="Receiver not found"), 404
    enc = crypto_utils.encrypt_message(receiver["public_key"], message)
    db.execute(
        "INSERT INTO messages (sender_id, receiver_id, enc_key, nonce, ciphertext, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (session["user_id"], receiver["id"], enc["enc_key"], enc["nonce"], enc["ciphertext"],
         datetime.now(timezone.utc).isoformat(timespec="seconds")),
    )
    db.commit()
    return jsonify(ok=True, **enc), 201


def _box(column_me, column_other):
    rows = get_db().execute(
        f"SELECT m.id, u.username AS other, m.ciphertext, m.enc_key, m.created_at "
        f"FROM messages m JOIN users u ON u.id = m.{column_other} "
        f"WHERE m.{column_me} = ? ORDER BY m.id DESC", (session["user_id"],)).fetchall()
    return jsonify(messages=[dict(r) for r in rows])


@app.get("/api/inbox")
@login_required
def inbox():
    return _box("receiver_id", "sender_id")


@app.get("/api/sent")
@login_required
def sent():
    return _box("sender_id", "receiver_id")


@app.post("/api/decrypt")
@login_required
def decrypt():
    data = request.get_json(silent=True) or {}
    row = get_db().execute(
        "SELECT * FROM messages WHERE id = ? AND receiver_id = ?",
        (data.get("message_id"), session["user_id"])).fetchone()
    if not row:  # also covers messages addressed to someone else
        return jsonify(error="Message not found"), 404
    try:
        plain = crypto_utils.decrypt_message(
            data.get("private_key") or "", row["enc_key"], row["nonce"], row["ciphertext"])
    except ValueError:
        return jsonify(error="Decryption failed: wrong private key or corrupted message"), 400
    return jsonify(message=plain)


if __name__ == "__main__":
    app.run(debug=False)
