import os
import sqlite3
from collections import defaultdict

from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-this-secret")
socketio = SocketIO(app, cors_allowed_origins=None)

DATABASE = os.path.join(app.root_path, "chat.db")
MAX_MESSAGE_LENGTH = 2000

# Tracks active Socket.IO connections per authenticated user.
online_sockets = defaultdict(set)
socket_users = {}


def get_db():
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                msg TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Add columns safely to databases created by the earlier app versions.
        message_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(messages)")
        }
        additions = {
            "sender_id": "INTEGER",
            "receiver_id": "INTEGER",
            "conversation_id": "INTEGER",
            "is_read": "INTEGER NOT NULL DEFAULT 0",
        }
        for column, definition in additions.items():
            if column not in message_columns:
                conn.execute(f"ALTER TABLE messages ADD COLUMN {column} {definition}")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL DEFAULT 'private',
                private_key TEXT UNIQUE,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS conversation_members (
                conversation_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                PRIMARY KEY (conversation_id, user_id)
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_conversation
            ON messages(conversation_id, id)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_receiver
            ON messages(receiver_id, is_read, id)
        """)

        # Migrate one-to-one messages saved by the previous updated backend.
        # The original global-chat messages have no recipient and are left untouched.
        old_rows = conn.execute("""
            SELECT id, sender_id, receiver_id
            FROM messages
            WHERE conversation_id IS NULL
              AND sender_id IS NOT NULL
              AND receiver_id IS NOT NULL
        """).fetchall()

        for row in old_rows:
            a, b = sorted((row["sender_id"], row["receiver_id"]))
            key = f"{a}:{b}"
            conn.execute("""
                INSERT OR IGNORE INTO conversations (type, private_key)
                VALUES ('private', ?)
            """, (key,))
            conversation = conn.execute(
                "SELECT id FROM conversations WHERE private_key = ?", (key,)
            ).fetchone()
            cid = conversation["id"]
            conn.execute("""
                INSERT OR IGNORE INTO conversation_members (conversation_id, user_id)
                VALUES (?, ?), (?, ?)
            """, (cid, a, cid, b))
            conn.execute(
                "UPDATE messages SET conversation_id = ? WHERE id = ?",
                (cid, row["id"])
            )


init_db()


def get_logged_in_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_db() as conn:
        return conn.execute(
            "SELECT id, username FROM users WHERE id = ?", (user_id,)
        ).fetchone()


def is_member(conn, conversation_id, user_id):
    return conn.execute("""
        SELECT 1 FROM conversation_members
        WHERE conversation_id = ? AND user_id = ?
    """, (conversation_id, user_id)).fetchone() is not None


def conversation_payload(conn, conversation_id, current_user_id):
    conversation = conn.execute(
        "SELECT id, type FROM conversations WHERE id = ?", (conversation_id,)
    ).fetchone()
    if not conversation:
        return None

    members = conn.execute("""
        SELECT u.id, u.username
        FROM conversation_members cm
        JOIN users u ON u.id = cm.user_id
        WHERE cm.conversation_id = ?
        ORDER BY u.username COLLATE NOCASE
    """, (conversation_id,)).fetchall()

    last = conn.execute("""
        SELECT m.username AS sender, m.msg AS body, m.created_at
        FROM messages m
        WHERE m.conversation_id = ?
        ORDER BY m.id DESC LIMIT 1
    """, (conversation_id,)).fetchone()

    return {
        "id": conversation["id"],
        "type": conversation["type"],
        "members": [{"id": m["id"], "username": m["username"]} for m in members],
        "last_message": dict(last) if last else None,
    }


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or len(username) > 30:
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
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            valid = False
            if user:
                stored = user["password"]
                if check_password_hash(stored, password):
                    valid = True
                elif stored == password:  # Upgrade a legacy plain-text password.
                    valid = True
                    conn.execute(
                        "UPDATE users SET password = ? WHERE id = ?",
                        (generate_password_hash(password), user["id"])
                    )
        if valid:
            session.clear()
            session["user_id"] = user["id"]
            session["user"] = user["username"]
            return redirect(url_for("home"))
        return "Invalid username or password.", 401
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    user = get_logged_in_user()
    if not user:
        return redirect(url_for("login"))
    return render_template("chat.html", username=user["username"])


@app.route("/api/conversations")
def api_conversations():
    user = get_logged_in_user()
    if not user:
        return jsonify({"error": "Login required"}), 401

    with get_db() as conn:
        ids = conn.execute("""
            SELECT conversation_id
            FROM conversation_members
            WHERE user_id = ?
        """, (user["id"],)).fetchall()
        conversations = [
            conversation_payload(conn, row["conversation_id"], user["id"])
            for row in ids
        ]
    conversations.sort(
        key=lambda c: (c["last_message"] or {}).get("created_at", ""),
        reverse=True
    )
    return jsonify({"conversations": conversations})


@app.route("/api/conversations/private", methods=["POST"])
def create_private_conversation():
    user = get_logged_in_user()
    if not user:
        return jsonify({"error": "Login required"}), 401

    data = request.get_json(silent=True) or {}
    other_username = data.get("username")
    if not isinstance(other_username, str) or not other_username.strip():
        return jsonify({"error": "Enter a username."}), 400

    with get_db() as conn:
        other = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (other_username.strip(),)
        ).fetchone()
        if not other:
            return jsonify({"error": "That user does not exist."}), 404
        if other["id"] == user["id"]:
            return jsonify({"error": "You cannot start a chat with yourself."}), 400

        low, high = sorted((user["id"], other["id"]))
        key = f"{low}:{high}"
        conn.execute("""
            INSERT OR IGNORE INTO conversations (type, private_key)
            VALUES ('private', ?)
        """, (key,))
        conv = conn.execute(
            "SELECT id FROM conversations WHERE private_key = ?", (key,)
        ).fetchone()
        cid = conv["id"]
        conn.execute("""
            INSERT OR IGNORE INTO conversation_members (conversation_id, user_id)
            VALUES (?, ?), (?, ?)
        """, (cid, user["id"], cid, other["id"]))

        result = conversation_payload(conn, cid, user["id"])
    return jsonify({"conversation": result})


@app.route("/api/conversations/<int:conversation_id>/messages")
def api_messages(conversation_id):
    user = get_logged_in_user()
    if not user:
        return jsonify({"error": "Login required"}), 401

    with get_db() as conn:
        if not is_member(conn, conversation_id, user["id"]):
            return jsonify({"error": "Conversation not found."}), 404

        rows = conn.execute("""
            SELECT id, conversation_id, username AS sender,
                   msg AS body, created_at
            FROM messages
            WHERE conversation_id = ?
            ORDER BY id ASC
            LIMIT 500
        """, (conversation_id,)).fetchall()

        conn.execute("""
            UPDATE messages SET is_read = 1
            WHERE conversation_id = ? AND receiver_id = ? AND is_read = 0
        """, (conversation_id, user["id"]))

    return jsonify({"messages": [dict(row) for row in rows]})


@socketio.on("connect")
def socket_connect(auth=None):
    user = get_logged_in_user()
    if not user:
        return False

    uid = user["id"]
    socket_users[request.sid] = uid
    online_sockets[uid].add(request.sid)
    join_room(f"user:{uid}")
    emit("presence_update", {
        "online_users": get_online_usernames()
    }, broadcast=True)


@socketio.on("disconnect")
def socket_disconnect():
    uid = socket_users.pop(request.sid, None)
    if uid is not None:
        online_sockets[uid].discard(request.sid)
        if not online_sockets[uid]:
            online_sockets.pop(uid, None)
        socketio.emit("presence_update", {
            "online_users": get_online_usernames()
        })


def get_online_usernames():
    ids = list(online_sockets.keys())
    if not ids:
        return []
    placeholders = ",".join("?" for _ in ids)
    with get_db() as conn:
        rows = conn.execute(
            f"SELECT username FROM users WHERE id IN ({placeholders}) ORDER BY username",
            ids
        ).fetchall()
    return [row["username"] for row in rows]


@socketio.on("get_presence")
def get_presence():
    emit("presence_update", {"online_users": get_online_usernames()})


@socketio.on("join_conversation")
def join_conversation(data):
    uid = socket_users.get(request.sid)
    cid = (data or {}).get("conversation_id") if isinstance(data, dict) else None
    if uid is None or not isinstance(cid, int):
        return
    with get_db() as conn:
        if not is_member(conn, cid, uid):
            emit("chat_error", {"msg": "You are not a member of this conversation."})
            return
    join_room(f"conversation:{cid}")
    emit("joined_conversation", {"conversation_id": cid})


@socketio.on("leave_conversation")
def leave_conversation(data):
    cid = (data or {}).get("conversation_id") if isinstance(data, dict) else None
    if isinstance(cid, int):
        leave_room(f"conversation:{cid}")


@socketio.on("chat_message")
def handle_chat_message(data):
    uid = socket_users.get(request.sid)
    if uid is None or not isinstance(data, dict):
        emit("chat_error", {"msg": "Please log in again."})
        return

    cid = data.get("conversation_id")
    msg = data.get("msg")
    if not isinstance(cid, int):
        emit("chat_error", {"msg": "Select a conversation first."})
        return
    if not isinstance(msg, str):
        emit("chat_error", {"msg": "Message must be text."})
        return
    msg = msg.strip()
    if not msg or len(msg) > MAX_MESSAGE_LENGTH:
        emit("chat_error", {"msg": f"Message must contain 1-{MAX_MESSAGE_LENGTH} characters."})
        return

    try:
        with get_db() as conn:
            if not is_member(conn, cid, uid):
                emit("chat_error", {"msg": "You are not allowed to message this conversation."})
                return

            members = conn.execute("""
                SELECT u.id, u.username
                FROM conversation_members cm
                JOIN users u ON u.id = cm.user_id
                WHERE cm.conversation_id = ?
            """, (cid,)).fetchall()
            recipient = next((m for m in members if m["id"] != uid), None)
            sender = next((m for m in members if m["id"] == uid), None)
            if not recipient or not sender:
                emit("chat_error", {"msg": "Invalid private conversation."})
                return

            cursor = conn.execute("""
                INSERT INTO messages
                    (username, msg, sender_id, receiver_id, conversation_id, is_read)
                VALUES (?, ?, ?, ?, ?, 0)
            """, (sender["username"], msg, uid, recipient["id"], cid))
            message_id = cursor.lastrowid
            saved = conn.execute(
                "SELECT created_at FROM messages WHERE id = ?", (message_id,)
            ).fetchone()

        payload = {
            "id": message_id,
            "conversation_id": cid,
            "sender": sender["username"],
            "body": msg,
            "created_at": saved["created_at"],
        }

        # Recipient gets the message on every active tab, without opening the chat first.
        socketio.emit("new_message", payload, room=f"user:{recipient['id']}")
        # Sender gets a confirmation on the sending socket only.
        emit("message_sent", payload)

    except sqlite3.Error as error:
        app.logger.exception("Database error while saving message: %s", error)
        emit("chat_error", {"msg": "Message could not be saved. Please try again."})


@socketio.on("typing")
def handle_typing(data):
    uid = socket_users.get(request.sid)
    if uid is None or not isinstance(data, dict):
        return
    cid = data.get("conversation_id")
    is_typing = bool(data.get("is_typing"))
    if not isinstance(cid, int):
        return
    with get_db() as conn:
        if not is_member(conn, cid, uid):
            return
        user = conn.execute(
            "SELECT username FROM users WHERE id = ?", (uid,)
        ).fetchone()
    socketio.emit("user_typing", {
        "conversation_id": cid,
        "username": user["username"],
        "is_typing": is_typing,
    }, room=f"conversation:{cid}", skip_sid=request.sid)


if __name__ == "__main__":
    socketio.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
