import os
import sqlite3
import uuid
from pathlib import Path
from collections import defaultdict

from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-this-secret")
socketio = SocketIO(app, cors_allowed_origins=None)

DATABASE = os.path.join(app.root_path, "chat.db")
MAX_MESSAGE_LENGTH = 2000
MAX_VOICE_BYTES = 8 * 1024 * 1024
MAX_AVATAR_BYTES = 3 * 1024 * 1024
AVATAR_FOLDER = os.path.join(app.root_path, "static", "profile_photos")
os.makedirs(AVATAR_FOLDER, exist_ok=True)
ALLOWED_AVATAR_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif"}
VOICE_FOLDER = os.path.join(app.root_path, "static", "voice_uploads")
os.makedirs(VOICE_FOLDER, exist_ok=True)
ALLOWED_AUDIO_EXTENSIONS = {".webm", ".ogg", ".mp4", ".m4a", ".wav"}

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
                password TEXT NOT NULL,
                display_name TEXT NOT NULL DEFAULT '',
                bio TEXT NOT NULL DEFAULT '',
                avatar_url TEXT,
                last_seen TEXT
            )
        """)
        user_columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
        user_additions = {
            "display_name": "TEXT NOT NULL DEFAULT ''",
            "bio": "TEXT NOT NULL DEFAULT ''",
            "avatar_url": "TEXT",
            "last_seen": "TEXT",
        }
        for column, definition in user_additions.items():
            if column not in user_columns:
                conn.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")
        conn.execute("UPDATE users SET display_name = username WHERE display_name = ''")

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
            "message_type": "TEXT NOT NULL DEFAULT 'text'",
            "media_url": "TEXT",
            "duration": "REAL",
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


def user_profile_payload(conn, user_id):
    row = conn.execute("""
        SELECT id, username, display_name, bio, avatar_url, last_seen
        FROM users WHERE id = ?
    """, (user_id,)).fetchone()
    if not row:
        return None
    return dict(row)


def conversation_payload(conn, conversation_id, current_user_id):
    conversation = conn.execute(
        "SELECT id, type FROM conversations WHERE id = ?", (conversation_id,)
    ).fetchone()
    if not conversation:
        return None

    members = conn.execute("""
        SELECT u.id, u.username, u.display_name, u.bio, u.avatar_url, u.last_seen
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
        "members": [dict(m) for m in members],
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
            with get_db() as conn:
                conn.execute("UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?", (user["id"],))
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


@app.route("/api/profile", methods=["GET", "PUT"])
def api_my_profile():
    user = get_logged_in_user()
    if not user:
        return jsonify({"error": "Login required"}), 401
    if request.method == "GET":
        with get_db() as conn:
            profile = user_profile_payload(conn, user["id"])
        profile["is_online"] = bool(online_sockets.get(user["id"]))
        return jsonify({"profile": profile})

    data = request.get_json(silent=True) or {}
    display_name = data.get("display_name", "")
    bio = data.get("bio", "")
    if not isinstance(display_name, str) or not display_name.strip() or len(display_name.strip()) > 40:
        return jsonify({"error": "Display name must be 1-40 characters."}), 400
    if not isinstance(bio, str) or len(bio) > 160:
        return jsonify({"error": "Bio must be 160 characters or fewer."}), 400
    with get_db() as conn:
        conn.execute("UPDATE users SET display_name = ?, bio = ? WHERE id = ?",
                     (display_name.strip(), bio.strip(), user["id"]))
        profile = user_profile_payload(conn, user["id"])
    profile["is_online"] = bool(online_sockets.get(user["id"]))
    return jsonify({"profile": profile})


@app.route("/api/profile/avatar", methods=["POST"])
def upload_profile_avatar():
    user = get_logged_in_user()
    if not user:
        return jsonify({"error": "Login required"}), 401
    photo = request.files.get("photo")
    if not photo or not photo.filename:
        return jsonify({"error": "Choose an image first."}), 400
    extension = Path(photo.filename).suffix.lower()
    if extension not in ALLOWED_AVATAR_EXTENSIONS or not (photo.mimetype or "").startswith("image/"):
        return jsonify({"error": "Use a PNG, JPG, WEBP or GIF image."}), 400
    content = photo.stream.read(MAX_AVATAR_BYTES + 1)
    if not content:
        return jsonify({"error": "The image is empty."}), 400
    if len(content) > MAX_AVATAR_BYTES:
        return jsonify({"error": "Profile photos must be 3 MB or smaller."}), 413
    filename = f"{uuid.uuid4().hex}{extension}"
    with open(os.path.join(AVATAR_FOLDER, filename), "wb") as output:
        output.write(content)
    avatar_url = url_for("static", filename=f"profile_photos/{filename}")
    with get_db() as conn:
        conn.execute("UPDATE users SET avatar_url = ? WHERE id = ?", (avatar_url, user["id"]))
        profile = user_profile_payload(conn, user["id"])
    profile["is_online"] = bool(online_sockets.get(user["id"]))
    return jsonify({"profile": profile})


@app.route("/api/users/<int:user_id>/profile")
def api_user_profile(user_id):
    user = get_logged_in_user()
    if not user:
        return jsonify({"error": "Login required"}), 401
    with get_db() as conn:
        profile = user_profile_payload(conn, user_id)
    if not profile:
        return jsonify({"error": "User not found."}), 404
    profile["is_online"] = bool(online_sockets.get(user_id))
    return jsonify({"profile": profile})


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
                   msg AS body, created_at, message_type, media_url, duration
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
            with get_db() as conn:
                conn.execute("UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?", (uid,))
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


@app.route("/api/voice-upload", methods=["POST"])
def upload_voice_message():
    user = get_logged_in_user()
    if not user:
        return jsonify({"error": "Login required"}), 401
    audio = request.files.get("audio")
    if not audio or not audio.filename:
        return jsonify({"error": "No audio file was uploaded."}), 400
    extension = Path(audio.filename).suffix.lower()
    if extension not in ALLOWED_AUDIO_EXTENSIONS:
        return jsonify({"error": "Unsupported audio format."}), 400
    content = audio.stream.read(MAX_VOICE_BYTES + 1)
    if not content:
        return jsonify({"error": "The voice recording is empty."}), 400
    if len(content) > MAX_VOICE_BYTES:
        return jsonify({"error": "Voice messages must be 8 MB or smaller."}), 413
    filename = f"{uuid.uuid4().hex}{extension}"
    with open(os.path.join(VOICE_FOLDER, filename), "wb") as output:
        output.write(content)
    return jsonify({"media_url": url_for("static", filename=f"voice_uploads/{filename}")})


@socketio.on("voice_message")
def handle_voice_message(data):
    uid = socket_users.get(request.sid)
    if uid is None or not isinstance(data, dict):
        emit("chat_error", {"msg": "Please log in again."})
        return
    cid, media_url = data.get("conversation_id"), data.get("media_url")
    try:
        duration = max(0, min(float(data.get("duration", 0)), 600))
    except (TypeError, ValueError):
        duration = 0
    if not isinstance(cid, int) or not isinstance(media_url, str):
        emit("chat_error", {"msg": "Invalid voice message."})
        return
    if not media_url.startswith("/static/voice_uploads/") or ".." in media_url:
        emit("chat_error", {"msg": "Invalid audio location."})
        return
    try:
        with get_db() as conn:
            if not is_member(conn, cid, uid):
                emit("chat_error", {"msg": "You are not a member of this conversation."})
                return
            members = conn.execute("""
                SELECT u.id, u.username FROM conversation_members cm
                JOIN users u ON u.id = cm.user_id WHERE cm.conversation_id = ?
            """, (cid,)).fetchall()
            sender = next((m for m in members if m["id"] == uid), None)
            others = [m for m in members if m["id"] != uid]
            if not sender or not others:
                emit("chat_error", {"msg": "Invalid conversation."})
                return
            kind = conn.execute("SELECT type FROM conversations WHERE id = ?", (cid,)).fetchone()["type"]
            receiver_id = others[0]["id"] if kind == "private" else None
            cur = conn.execute("""
                INSERT INTO messages
                (username, msg, sender_id, receiver_id, conversation_id,
                 is_read, message_type, media_url, duration)
                VALUES (?, 'Voice message', ?, ?, ?, 0, 'voice', ?, ?)
            """, (sender["username"], uid, receiver_id, cid, media_url, duration))
            mid = cur.lastrowid
            created = conn.execute("SELECT created_at FROM messages WHERE id = ?", (mid,)).fetchone()["created_at"]
        payload = {
            "id": mid, "conversation_id": cid, "sender": sender["username"],
            "body": "Voice message", "created_at": created, "message_type": "voice",
            "media_url": media_url, "duration": duration
        }
        for member in others:
            socketio.emit("new_message", payload, room=f"user:{member['id']}")
        emit("message_sent", payload)
    except sqlite3.Error:
        app.logger.exception("Could not save voice message")
        emit("chat_error", {"msg": "Voice message could not be saved."})


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
