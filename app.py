import os
import sqlite3
import time
from collections import defaultdict
from contextlib import contextmanager

from flask import (
    Flask, jsonify, redirect, render_template, request,
    session, url_for
)
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash


# ---------------------------------------------------------------------------
# Application configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-this-secret"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)

DATABASE = os.path.join(app.root_path, "chat.db")
MAX_MESSAGE_LENGTH = 2000
MAX_USERNAME_LENGTH = 30
MAX_GROUP_NAME_LENGTH = 60
MAX_GROUP_MEMBERS = 50
MESSAGE_HISTORY_LIMIT = 100
SOCKET_MESSAGE_COOLDOWN = 0.35

socketio = SocketIO(
    app,
    async_mode=os.environ.get("SOCKETIO_ASYNC_MODE") or None,
    cors_allowed_origins=os.environ.get("CORS_ALLOWED_ORIGINS") or None,
)


# ---------------------------------------------------------------------------
# Database layer
# ---------------------------------------------------------------------------

@contextmanager
def get_db():
    """Open a short-lived SQLite connection and always close it."""
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Keep the old messages table so existing data is not destroyed.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                msg TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                type TEXT NOT NULL CHECK(type IN ('private', 'group')),
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(created_by) REFERENCES users(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS conversation_members (
                conversation_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                joined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(conversation_id, user_id),
                FOREIGN KEY(conversation_id) REFERENCES conversations(id)
                    ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                sender_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(conversation_id) REFERENCES conversations(id)
                    ON DELETE CASCADE,
                FOREIGN KEY(sender_id) REFERENCES users(id)
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation
            ON chat_messages(conversation_id, id)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_members_user
            ON conversation_members(user_id, conversation_id)
        """)


init_db()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def current_user():
    username = session.get("user")
    if not username:
        return None
    with get_db() as conn:
        return conn.execute(
            "SELECT id, username FROM users WHERE username = ?",
            (username,)
        ).fetchone()


def conversation_for_user(conn, conversation_id, user_id):
    return conn.execute("""
        SELECT c.id, c.name, c.type, c.created_by
        FROM conversations c
        JOIN conversation_members cm
          ON cm.conversation_id = c.id
        WHERE c.id = ? AND cm.user_id = ?
    """, (conversation_id, user_id)).fetchone()


def is_conversation_member(conn, conversation_id, user_id):
    return conn.execute("""
        SELECT 1 FROM conversation_members
        WHERE conversation_id = ? AND user_id = ?
    """, (conversation_id, user_id)).fetchone() is not None


def conversation_payload(conn, conversation_id, viewer_id):
    conversation = conversation_for_user(conn, conversation_id, viewer_id)
    if not conversation:
        return None

    members = conn.execute("""
        SELECT u.id, u.username
        FROM users u
        JOIN conversation_members cm ON cm.user_id = u.id
        WHERE cm.conversation_id = ?
        ORDER BY u.username COLLATE NOCASE
    """, (conversation_id,)).fetchall()

    last_message = conn.execute("""
        SELECT m.id, m.body, m.created_at, u.username AS sender
        FROM chat_messages m
        JOIN users u ON u.id = m.sender_id
        WHERE m.conversation_id = ?
        ORDER BY m.id DESC LIMIT 1
    """, (conversation_id,)).fetchone()

    return {
        "id": conversation["id"],
        "name": conversation["name"],
        "type": conversation["type"],
        "members": [dict(member) for member in members],
        "last_message": dict(last_message) if last_message else None,
    }


def error_response(message, status=400):
    return jsonify({"ok": False, "error": message}), status


# ---------------------------------------------------------------------------
# Authentication and page routes
# ---------------------------------------------------------------------------

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or len(username) > MAX_USERNAME_LENGTH:
            return "Username must be 1-30 characters.", 400
        if len(password) < 8:
            return "Password must be at least 8 characters.", 400

        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password))
                )
        except sqlite3.IntegrityError:
            return "Username already exists.", 409

        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as conn:
            user = conn.execute(
                "SELECT id, username, password FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            valid = False
            if user:
                stored_password = user["password"]
                try:
                    valid = check_password_hash(stored_password, password)
                except (ValueError, TypeError):
                    valid = False

                # One-time migration for accounts created by the old version,
                # which stored passwords as plain text. Remove after migration.
                if not valid and stored_password == password:
                    valid = True
                    conn.execute(
                        "UPDATE users SET password = ? WHERE id = ?",
                        (generate_password_hash(password), user["id"])
                    )

        if valid:
            session.clear()
            session["user"] = username
            return redirect(url_for("home"))

        return "Invalid username or password.", 401

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    # Preserve compatibility with the existing chat.html template.
    # New conversation-aware frontends should use /api/conversations.
    with get_db() as conn:
        old_messages = conn.execute("""
            SELECT username, msg, created_at
            FROM messages
            ORDER BY id DESC LIMIT 100
        """).fetchall()

    return render_template(
        "chat.html",
        username=user["username"],
        messages=list(reversed(old_messages)),
    )


# ---------------------------------------------------------------------------
# REST API: users and conversations
# ---------------------------------------------------------------------------

@app.get("/api/me")
def api_me():
    user = current_user()
    if not user:
        return error_response("Authentication required.", 401)
    return jsonify({"ok": True, "user": dict(user)})


@app.get("/api/users")
def api_users():
    user = current_user()
    if not user:
        return error_response("Authentication required.", 401)

    search = request.args.get("q", "").strip()
    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, username FROM users
            WHERE id != ? AND username LIKE ?
            ORDER BY username COLLATE NOCASE
            LIMIT 50
        """, (user["id"], f"%{search}%")).fetchall()

    return jsonify({"ok": True, "users": [dict(row) for row in rows]})


@app.get("/api/conversations")
def api_conversations():
    user = current_user()
    if not user:
        return error_response("Authentication required.", 401)

    with get_db() as conn:
        ids = conn.execute("""
            SELECT conversation_id FROM conversation_members
            WHERE user_id = ?
        """, (user["id"],)).fetchall()
        conversations = [
            conversation_payload(conn, row["conversation_id"], user["id"])
            for row in ids
        ]

    conversations.sort(
        key=lambda item: (
            item["last_message"]["created_at"] if item["last_message"] else ""
        ),
        reverse=True
    )
    return jsonify({"ok": True, "conversations": conversations})


@app.post("/api/conversations/private")
def create_private_conversation():
    user = current_user()
    if not user:
        return error_response("Authentication required.", 401)

    data = request.get_json(silent=True) or {}
    target_username = str(data.get("username", "")).strip()

    if not target_username or target_username == user["username"]:
        return error_response("Provide another user's username.")

    with get_db() as conn:
        target = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (target_username,)
        ).fetchone()
        if not target:
            return error_response("User not found.", 404)

        # Reuse an existing private conversation between these two users.
        existing = conn.execute("""
            SELECT c.id
            FROM conversations c
            JOIN conversation_members a ON a.conversation_id = c.id
            JOIN conversation_members b ON b.conversation_id = c.id
            WHERE c.type = 'private'
              AND a.user_id = ? AND b.user_id = ?
              AND (
                SELECT COUNT(*) FROM conversation_members x
                WHERE x.conversation_id = c.id
              ) = 2
            LIMIT 1
        """, (user["id"], target["id"])).fetchone()

        if existing:
            conversation_id = existing["id"]
        else:
            cursor = conn.execute("""
                INSERT INTO conversations (type, created_by)
                VALUES ('private', ?)
            """, (user["id"],))
            conversation_id = cursor.lastrowid
            conn.executemany("""
                INSERT INTO conversation_members (conversation_id, user_id)
                VALUES (?, ?)
            """, [
                (conversation_id, user["id"]),
                (conversation_id, target["id"]),
            ])

        payload = conversation_payload(conn, conversation_id, user["id"])

    return jsonify({"ok": True, "conversation": payload}), 201


@app.post("/api/conversations/group")
def create_group_conversation():
    user = current_user()
    if not user:
        return error_response("Authentication required.", 401)

    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    usernames = data.get("members", [])

    if not name or len(name) > MAX_GROUP_NAME_LENGTH:
        return error_response("Group name must be 1-60 characters.")
    if not isinstance(usernames, list):
        return error_response("'members' must be a list of usernames.")

    usernames = list(dict.fromkeys(
        str(item).strip() for item in usernames if str(item).strip()
    ))
    if user["username"] not in usernames:
        usernames.append(user["username"])
    if len(usernames) > MAX_GROUP_MEMBERS:
        return error_response(f"A group can have at most {MAX_GROUP_MEMBERS} members.")

    with get_db() as conn:
        placeholders = ",".join("?" for _ in usernames)
        rows = conn.execute(
            f"SELECT id, username FROM users WHERE username IN ({placeholders})",
            usernames
        ).fetchall()

        found = {row["username"]: row["id"] for row in rows}
        missing = [name for name in usernames if name not in found]
        if missing:
            return error_response(
                "Unknown username(s): " + ", ".join(missing), 404
            )

        cursor = conn.execute("""
            INSERT INTO conversations (name, type, created_by)
            VALUES (?, 'group', ?)
        """, (name, user["id"]))
        conversation_id = cursor.lastrowid

        conn.executemany("""
            INSERT INTO conversation_members (conversation_id, user_id)
            VALUES (?, ?)
        """, [
            (conversation_id, member_id)
            for member_id in found.values()
        ])

        payload = conversation_payload(conn, conversation_id, user["id"])

    return jsonify({"ok": True, "conversation": payload}), 201


@app.get("/api/conversations/<int:conversation_id>/messages")
def api_conversation_messages(conversation_id):
    user = current_user()
    if not user:
        return error_response("Authentication required.", 401)

    with get_db() as conn:
        if not is_conversation_member(conn, conversation_id, user["id"]):
            return error_response("Conversation not found.", 404)

        rows = conn.execute("""
            SELECT m.id, m.conversation_id, m.body, m.created_at,
                   u.id AS sender_id, u.username AS sender
            FROM chat_messages m
            JOIN users u ON u.id = m.sender_id
            WHERE m.conversation_id = ?
            ORDER BY m.id DESC LIMIT ?
        """, (conversation_id, MESSAGE_HISTORY_LIMIT)).fetchall()

    messages = [dict(row) for row in reversed(rows)]
    return jsonify({"ok": True, "messages": messages})


# ---------------------------------------------------------------------------
# Socket.IO presence tracking
# ---------------------------------------------------------------------------

# These dictionaries are process-local. For multiple workers/servers, use
# Socket.IO's Redis message queue and shared presence storage.
user_sids = defaultdict(set)       # username -> set of connected socket IDs
sid_users = {}                     # socket ID -> username
last_message_at = {}               # socket ID -> timestamp


def online_usernames():
    return sorted(user_sids.keys(), key=str.lower)


def emit_presence():
    socketio.emit("presence_update", {"online_users": online_usernames()})


@socketio.on("connect")
def handle_connect(auth=None):
    user = current_user()
    if not user:
        return False

    username = user["username"]
    sid_users[request.sid] = username
    user_sids[username].add(request.sid)

    emit("connected", {"username": username})
    emit_presence()


@socketio.on("disconnect")
def handle_disconnect(reason=None):
    username = sid_users.pop(request.sid, None)
    last_message_at.pop(request.sid, None)

    if username:
        user_sids[username].discard(request.sid)
        if not user_sids[username]:
            user_sids.pop(username, None)
        emit_presence()


@socketio.on("join_conversation")
def handle_join_conversation(data):
    username = sid_users.get(request.sid)
    if not username or not isinstance(data, dict):
        return

    conversation_id = data.get("conversation_id")
    try:
        conversation_id = int(conversation_id)
    except (TypeError, ValueError):
        emit("chat_error", {"msg": "Invalid conversation ID."})
        return

    user = current_user()
    if not user:
        return

    with get_db() as conn:
        allowed = is_conversation_member(conn, conversation_id, user["id"])

    if not allowed:
        emit("chat_error", {"msg": "You are not a member of this conversation."})
        return

    join_room(f"conversation:{conversation_id}")
    emit("joined_conversation", {"conversation_id": conversation_id})


@socketio.on("leave_conversation")
def handle_leave_conversation(data):
    if not isinstance(data, dict):
        return
    try:
        conversation_id = int(data.get("conversation_id"))
    except (TypeError, ValueError):
        return
    leave_room(f"conversation:{conversation_id}")
    emit("left_conversation", {"conversation_id": conversation_id})


@socketio.on("chat_message")
def handle_chat_message(data):
    username = sid_users.get(request.sid)
    if not username or not isinstance(data, dict):
        return

    body = data.get("msg", data.get("body"))
    try:
        conversation_id = int(data.get("conversation_id"))
    except (TypeError, ValueError):
        emit("chat_error", {"msg": "A valid conversation_id is required."})
        return

    if not isinstance(body, str):
        emit("chat_error", {"msg": "Message must be text."})
        return

    body = body.strip()
    if not body or len(body) > MAX_MESSAGE_LENGTH:
        emit("chat_error", {
            "msg": f"Message must be 1-{MAX_MESSAGE_LENGTH} characters."
        })
        return

    now = time.monotonic()
    previous = last_message_at.get(request.sid, 0)
    if now - previous < SOCKET_MESSAGE_COOLDOWN:
        emit("chat_error", {"msg": "You're sending messages too quickly."})
        return
    last_message_at[request.sid] = now

    user = current_user()
    if not user:
        return

    with get_db() as conn:
        if not is_conversation_member(conn, conversation_id, user["id"]):
            emit("chat_error", {"msg": "You cannot send to this conversation."})
            return

        cursor = conn.execute("""
            INSERT INTO chat_messages (conversation_id, sender_id, body)
            VALUES (?, ?, ?)
        """, (conversation_id, user["id"], body))

        row = conn.execute("""
            SELECT m.id, m.conversation_id, m.body, m.created_at,
                   u.id AS sender_id, u.username AS sender
            FROM chat_messages m
            JOIN users u ON u.id = m.sender_id
            WHERE m.id = ?
        """, (cursor.lastrowid,)).fetchone()

    # Only sockets that joined this conversation room receive the message.
    socketio.emit(
        "new_message",
        dict(row),
        room=f"conversation:{conversation_id}"
    )


@socketio.on("typing")
def handle_typing(data):
    username = sid_users.get(request.sid)
    if not username or not isinstance(data, dict):
        return

    try:
        conversation_id = int(data.get("conversation_id"))
    except (TypeError, ValueError):
        return

    user = current_user()
    if not user:
        return

    with get_db() as conn:
        if not is_conversation_member(conn, conversation_id, user["id"]):
            return

    socketio.emit(
        "user_typing",
        {
            "conversation_id": conversation_id,
            "username": username,
            "is_typing": bool(data.get("is_typing", True)),
        },
        room=f"conversation:{conversation_id}",
        include_self=False,
    )


@socketio.on("get_presence")
def handle_get_presence():
    if request.sid not in sid_users:
        return
    emit("presence_update", {"online_users": online_usernames()})


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    socketio.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
