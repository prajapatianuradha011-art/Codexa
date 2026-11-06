import os
import sqlite3
import uuid
import time
import secrets
import threading
from pathlib import Path
from collections import defaultdict

from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    _secret = secrets.token_hex(32)
    app.logger.warning("SECRET_KEY is unset; sessions reset on restart. Set a stable SECRET_KEY in production.")
app.config.update(
    SECRET_KEY=_secret,
    MAX_CONTENT_LENGTH=51 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=__import__("datetime").timedelta(hours=12),
)
socketio = SocketIO(app, cors_allowed_origins=None, max_http_buffer_size=1_000_000)

# Basic per-process abuse throttling. Use a shared limiter/WAF with multiple workers.
_rate_lock = threading.Lock()
_rate_events = defaultdict(list)
RATE_RULES = {"auth": (8, 15 * 60), "uploads": (30, 10 * 60)}

@app.before_request
def security_request_guard():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        token = session.get("_csrf_token")
        supplied = request.headers.get("X-CSRFToken") or request.form.get("_csrf_token")
        if not token or not supplied or not secrets.compare_digest(str(token), str(supplied)):
            return jsonify({"error": "Security token expired. Refresh the page and try again."}), 403
    bucket = None
    if request.method == "POST" and request.endpoint in ("login", "signup"):
        bucket = "auth"
    elif request.method == "POST" and request.path in (
        "/api/voice-upload", "/api/image-upload", "/api/video-upload", "/api/profile/avatar"
    ):
        bucket = "uploads"
    if bucket:
        limit, window = RATE_RULES[bucket]
        key = (bucket, request.remote_addr or "unknown")
        now = time.time()
        with _rate_lock:
            recent = [stamp for stamp in _rate_events[key] if now - stamp < window]
            if len(recent) >= limit:
                return jsonify({"error": "Too many attempts. Please wait and try again."}), 429
            recent.append(now)
            _rate_events[key] = recent

@app.before_request
def ensure_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)

@app.context_processor
def inject_security_template_values():
    return {"csrf_token": session.get("_csrf_token", "")}

@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(self), microphone=(self), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.socket.io; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
        "media-src 'self' blob:; connect-src 'self' ws: wss:; "
        "font-src 'self' data:; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    if app.config["SESSION_COOKIE_SECURE"]:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response

DATABASE = os.path.join(app.root_path, "chat.db")
MAX_MESSAGE_LENGTH = 2000
MAX_VOICE_BYTES = 8 * 1024 * 1024
MAX_IMAGE_BYTES = 8 * 1024 * 1024
MAX_VIDEO_BYTES = 50 * 1024 * 1024
MAX_AVATAR_BYTES = 3 * 1024 * 1024
AVATAR_FOLDER = os.path.join(app.root_path, "static", "profile_photos")
os.makedirs(AVATAR_FOLDER, exist_ok=True)
ALLOWED_AVATAR_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif"}
VOICE_FOLDER = os.path.join(app.root_path, "static", "voice_uploads")
os.makedirs(VOICE_FOLDER, exist_ok=True)
ALLOWED_AUDIO_EXTENSIONS = {".webm", ".ogg", ".mp4", ".m4a", ".wav"}
IMAGE_FOLDER = os.path.join(app.root_path, "static", "chat_images")
os.makedirs(IMAGE_FOLDER, exist_ok=True)
ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
VIDEO_FOLDER = os.path.join(app.root_path, "static", "chat_videos")
os.makedirs(VIDEO_FOLDER, exist_ok=True)
ALLOWED_VIDEO_EXTENSIONS = {".mp4", ".webm", ".mov"}

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
        # Usernames are unique regardless of letter case (e.g. Raghav == raghav).
        # Existing databases may already contain case-only duplicates; signup also
        # checks under a write lock so new duplicates are blocked in that case too.
        try:
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_nocase ON users(username COLLATE NOCASE)")
        except sqlite3.IntegrityError:
            # Do not modify existing accounts automatically. The signup route below
            # still prevents any additional case-insensitive duplicates.
            pass

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
            "edited": "INTEGER NOT NULL DEFAULT 0",
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
        if len(password) < 10 or len(password) > 128:
            return "Password must be 10-128 characters.", 400
        try:
            with get_db() as conn:
                # Serialize registration attempts to avoid two simultaneous signups
                # passing the duplicate check at the same time.
                conn.execute("BEGIN IMMEDIATE")
                existing = conn.execute(
                    "SELECT id FROM users WHERE username = ? COLLATE NOCASE LIMIT 1",
                    (username,)
                ).fetchone()
                if existing:
                    conn.rollback()
                    return "This username is already taken. Please choose another username.", 409
                conn.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password))
                )
                conn.commit()
        except sqlite3.IntegrityError:
            return "This username is already taken. Please choose another username.", 409
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
            session.permanent = True
            session["_csrf_token"] = secrets.token_urlsafe(32)
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
    if extension not in ALLOWED_AVATAR_EXTENSIONS:
        return jsonify({"error": "Use a PNG, JPG, WEBP or GIF image."}), 400
    content = photo.stream.read(MAX_AVATAR_BYTES + 1)
    if not content:
        return jsonify({"error": "The image is empty."}), 400
    if len(content) > MAX_AVATAR_BYTES:
        return jsonify({"error": "Profile photos must be 3 MB or smaller."}), 413
    avatar_valid = (
        (extension == ".png" and content.startswith(b"\x89PNG\r\n\x1a\n"))
        or (extension in (".jpg", ".jpeg") and content.startswith(b"\xff\xd8\xff"))
        or (extension == ".gif" and content[:6] in (b"GIF87a", b"GIF89a"))
        or (extension == ".webp" and content[:4] == b"RIFF" and content[8:12] == b"WEBP")
    )
    if not avatar_valid:
        return jsonify({"error": "The uploaded profile photo is not a valid supported image."}), 400
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
                   msg AS body, created_at, message_type, media_url, duration, edited
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


def call_participants(cid, uid):
    """Return the other member only for a valid one-to-one conversation."""
    with get_db() as conn:
        row = conn.execute("SELECT type FROM conversations WHERE id = ?", (cid,)).fetchone()
        if not row or row["type"] != "private" or not is_member(conn, cid, uid):
            return None
        members = [r["user_id"] for r in conn.execute(
            "SELECT user_id FROM conversation_members WHERE conversation_id = ?", (cid,)
        ).fetchall()]
        if len(members) != 2:
            return None
        peer = next((member for member in members if member != uid), None)
        return peer


@socketio.on("call_invite")
def call_invite(data):
    uid = socket_users.get(request.sid)
    data = data if isinstance(data, dict) else {}
    cid, mode = data.get("conversation_id"), data.get("mode")
    if uid is None or not isinstance(cid, int) or mode not in ("audio", "video"):
        return emit("call_error", {"message": "Invalid call request."})
    peer = call_participants(cid, uid)
    if peer is None:
        return emit("call_error", {"message": "Calls are available only in one-to-one chats."})
    if not online_sockets.get(peer):
        return emit("call_error", {"message": "This user is offline."})
    with get_db() as conn:
        caller = conn.execute("SELECT username, display_name FROM users WHERE id = ?", (uid,)).fetchone()
    socketio.emit("incoming_call", {
        "conversation_id": cid, "mode": mode, "caller_id": uid,
        "caller_name": caller["display_name"] or caller["username"]
    }, room=f"user:{peer}")
    emit("call_ringing", {"conversation_id": cid, "mode": mode})


@socketio.on("call_response")
def call_response(data):
    uid = socket_users.get(request.sid)
    data = data if isinstance(data, dict) else {}
    cid, accepted = data.get("conversation_id"), data.get("accepted") is True
    if uid is None or not isinstance(cid, int): return
    peer = call_participants(cid, uid)
    if peer is None: return
    socketio.emit("call_response", {"conversation_id": cid, "accepted": accepted}, room=f"user:{peer}")


@socketio.on("call_signal")
def call_signal(data):
    uid = socket_users.get(request.sid)
    data = data if isinstance(data, dict) else {}
    cid, signal = data.get("conversation_id"), data.get("signal")
    if uid is None or not isinstance(cid, int) or not isinstance(signal, dict): return
    peer = call_participants(cid, uid)
    if peer is None: return
    # Only relay the WebRTC offer, answer and ICE candidate payloads.
    if signal.get("type") not in ("offer", "answer", "ice"):
        return
    socketio.emit("call_signal", {"conversation_id": cid, "signal": signal}, room=f"user:{peer}")


@socketio.on("call_end")
def call_end(data):
    uid = socket_users.get(request.sid)
    data = data if isinstance(data, dict) else {}
    cid = data.get("conversation_id")
    if uid is None or not isinstance(cid, int): return
    peer = call_participants(cid, uid)
    if peer is not None:
        socketio.emit("call_ended", {"conversation_id": cid}, room=f"user:{peer}")


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


@socketio.on("edit_message")
def handle_edit_message(data):
    uid = socket_users.get(request.sid)
    if uid is None or not isinstance(data, dict):
        emit("chat_error", {"msg": "Please log in again."})
        return
    mid, body = data.get("message_id"), data.get("body")
    if not isinstance(mid, int) or not isinstance(body, str):
        emit("chat_error", {"msg": "Invalid edit request."})
        return
    body = body.strip()
    if not body or len(body) > MAX_MESSAGE_LENGTH:
        emit("chat_error", {"msg": f"Edited message must contain 1-{MAX_MESSAGE_LENGTH} characters."})
        return
    with get_db() as conn:
        row = conn.execute("""SELECT id, conversation_id, sender_id, username, message_type
                              FROM messages WHERE id = ?""", (mid,)).fetchone()
        if not row or row["sender_id"] != uid or not is_member(conn, row["conversation_id"], uid):
            emit("chat_error", {"msg": "You can edit only your own messages."})
            return
        if row["message_type"] != "text":
            emit("chat_error", {"msg": "Only text messages can be edited."})
            return
        conn.execute("UPDATE messages SET msg = ?, edited = 1 WHERE id = ?", (body, mid))
        members = [r["user_id"] for r in conn.execute(
            "SELECT user_id FROM conversation_members WHERE conversation_id = ?", (row["conversation_id"],)
        ).fetchall()]
        created = conn.execute("SELECT created_at FROM messages WHERE id = ?", (mid,)).fetchone()["created_at"]
    payload = {"id": mid, "conversation_id": row["conversation_id"], "sender": row["username"],
               "body": body, "created_at": created, "message_type": "text", "edited": 1}
    for member_id in members:
        socketio.emit("message_updated", payload, room=f"user:{member_id}")


@socketio.on("delete_message")
def handle_delete_message(data):
    uid = socket_users.get(request.sid)
    if uid is None or not isinstance(data, dict):
        emit("chat_error", {"msg": "Please log in again."})
        return
    mid = data.get("message_id")
    if not isinstance(mid, int):
        emit("chat_error", {"msg": "Invalid delete request."})
        return
    with get_db() as conn:
        row = conn.execute("""SELECT id, conversation_id, sender_id, username
                              FROM messages WHERE id = ?""", (mid,)).fetchone()
        if not row or row["sender_id"] != uid or not is_member(conn, row["conversation_id"], uid):
            emit("chat_error", {"msg": "You can delete only your own messages."})
            return
        conn.execute("""UPDATE messages SET msg = 'This message was deleted',
                       message_type = 'deleted', media_url = NULL, duration = NULL, edited = 0
                       WHERE id = ?""", (mid,))
        members = [r["user_id"] for r in conn.execute(
            "SELECT user_id FROM conversation_members WHERE conversation_id = ?", (row["conversation_id"],)
        ).fetchall()]
    payload = {"id": mid, "conversation_id": row["conversation_id"], "sender": row["username"],
               "body": "This message was deleted", "message_type": "deleted", "deleted": True}
    for member_id in members:
        socketio.emit("message_deleted", payload, room=f"user:{member_id}")


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
    audio_valid = (
        (extension == ".webm" and content.startswith(bytes.fromhex("1A45DFA3")))
        or (extension == ".ogg" and content.startswith(b"OggS"))
        or (extension == ".wav" and len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WAVE")
        or (extension in (".mp4", ".m4a") and len(content) >= 12 and content[4:8] == b"ftyp")
    )
    if not audio_valid:
        return jsonify({"error": "The uploaded file is not a valid supported audio file."}), 400
    filename = f"{uuid.uuid4().hex}{extension}"
    with open(os.path.join(VOICE_FOLDER, filename), "wb") as output:
        output.write(content)
    return jsonify({"media_url": url_for("static", filename=f"voice_uploads/{filename}")})


@app.route("/api/image-upload", methods=["POST"])
def upload_chat_image():
    user = get_logged_in_user()
    if not user:
        return jsonify({"error": "Login required"}), 401

    try:
        cid = int(request.form.get("conversation_id", ""))
    except (TypeError, ValueError):
        return jsonify({"error": "Select a conversation first."}), 400

    with get_db() as conn:
        if not is_member(conn, cid, user["id"]):
            return jsonify({"error": "Conversation not found."}), 404

    image_file = request.files.get("image")
    if not image_file or not image_file.filename:
        return jsonify({"error": "Choose an image to send."}), 400
    extension = Path(image_file.filename).suffix.lower()
    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        return jsonify({"error": "Use PNG, JPG, GIF or WEBP images."}), 400

    content = image_file.stream.read(MAX_IMAGE_BYTES + 1)
    if not content:
        return jsonify({"error": "The selected image is empty."}), 400
    if len(content) > MAX_IMAGE_BYTES:
        return jsonify({"error": "Images must be 8 MB or smaller."}), 413

    # Verify the actual file signature instead of trusting the filename or browser MIME type.
    valid = (
        (extension == ".png" and content.startswith(b"\x89PNG\r\n\x1a\n"))
        or (extension in (".jpg", ".jpeg") and content.startswith(b"\xff\xd8\xff"))
        or (extension == ".gif" and content[:6] in (b"GIF87a", b"GIF89a"))
        or (extension == ".webp" and content[:4] == b"RIFF" and content[8:12] == b"WEBP")
    )
    if not valid:
        return jsonify({"error": "The uploaded file is not a valid image of that type."}), 400

    filename = f"{uuid.uuid4().hex}{extension}"
    with open(os.path.join(IMAGE_FOLDER, filename), "wb") as output:
        output.write(content)
    return jsonify({"media_url": url_for("static", filename=f"chat_images/{filename}")})


@app.route("/api/video-upload", methods=["POST"])
def upload_chat_video():
    user = get_logged_in_user()
    if not user:
        return jsonify({"error": "Login required"}), 401
    try:
        cid = int(request.form.get("conversation_id", ""))
    except (TypeError, ValueError):
        return jsonify({"error": "Select a conversation first."}), 400
    with get_db() as conn:
        if not is_member(conn, cid, user["id"]):
            return jsonify({"error": "Conversation not found."}), 404
    video_file = request.files.get("video")
    if not video_file or not video_file.filename:
        return jsonify({"error": "Choose a video to send."}), 400
    extension = Path(video_file.filename).suffix.lower()
    if extension not in ALLOWED_VIDEO_EXTENSIONS:
        return jsonify({"error": "Use MP4, WEBM or MOV video files."}), 400
    content = video_file.stream.read(MAX_VIDEO_BYTES + 1)
    if not content:
        return jsonify({"error": "The selected video is empty."}), 400
    if len(content) > MAX_VIDEO_BYTES:
        return jsonify({"error": "Videos must be 50 MB or smaller."}), 413
    # Check container signatures; browser MIME type and filename are not trusted.
    valid = ((extension in (".mp4", ".mov") and len(content) >= 12 and content[4:8] == b"ftyp")
             or (extension == ".webm" and content.startswith(bytes.fromhex("1A45DFA3"))))
    if not valid:
        return jsonify({"error": "The uploaded file is not a valid video of that type."}), 400
    filename = f"{uuid.uuid4().hex}{extension}"
    with open(os.path.join(VIDEO_FOLDER, filename), "wb") as output:
        output.write(content)
    return jsonify({"media_url": url_for("static", filename=f"chat_videos/{filename}")})


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


@socketio.on("image_message")
def handle_image_message(data):
    uid = socket_users.get(request.sid)
    if uid is None or not isinstance(data, dict):
        emit("chat_error", {"msg": "Please log in again."})
        return
    cid, media_url = data.get("conversation_id"), data.get("media_url")
    if not isinstance(cid, int) or not isinstance(media_url, str):
        emit("chat_error", {"msg": "Invalid image message."})
        return
    if not media_url.startswith("/static/chat_images/") or ".." in media_url:
        emit("chat_error", {"msg": "Invalid image location."})
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
                (username, msg, sender_id, receiver_id, conversation_id, is_read, message_type, media_url)
                VALUES (?, 'Image', ?, ?, ?, 0, 'image', ?)
            """, (sender["username"], uid, receiver_id, cid, media_url))
            mid = cur.lastrowid
            created = conn.execute("SELECT created_at FROM messages WHERE id = ?", (mid,)).fetchone()["created_at"]
        payload = {
            "id": mid, "conversation_id": cid, "sender": sender["username"],
            "body": "Image", "created_at": created, "message_type": "image",
            "media_url": media_url
        }
        for member in others:
            socketio.emit("new_message", payload, room=f"user:{member['id']}")
        emit("message_sent", payload)
    except sqlite3.Error:
        app.logger.exception("Could not save image message")
        emit("chat_error", {"msg": "Image message could not be saved."})


@socketio.on("video_message")
def handle_video_message(data):
    uid = socket_users.get(request.sid)
    if uid is None or not isinstance(data, dict):
        emit("chat_error", {"msg": "Please log in again."})
        return
    cid, media_url = data.get("conversation_id"), data.get("media_url")
    if not isinstance(cid, int) or not isinstance(media_url, str):
        emit("chat_error", {"msg": "Invalid video message."})
        return
    if not media_url.startswith("/static/chat_videos/") or ".." in media_url:
        emit("chat_error", {"msg": "Invalid video location."})
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
                (username, msg, sender_id, receiver_id, conversation_id, is_read, message_type, media_url)
                VALUES (?, 'Video', ?, ?, ?, 0, 'video', ?)
            """, (sender["username"], uid, receiver_id, cid, media_url))
            mid = cur.lastrowid
            created = conn.execute("SELECT created_at FROM messages WHERE id = ?", (mid,)).fetchone()["created_at"]
        payload = {"id": mid, "conversation_id": cid, "sender": sender["username"],
                   "body": "Video", "created_at": created, "message_type": "video", "media_url": media_url}
        for member in others:
            socketio.emit("new_message", payload, room=f"user:{member['id']}")
        emit("message_sent", payload)
    except sqlite3.Error:
        app.logger.exception("Could not save video message")
        emit("chat_error", {"msg": "Video message could not be saved."})


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
