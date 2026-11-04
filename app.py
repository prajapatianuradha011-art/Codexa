import os
import sqlite3

from flask import (
    Flask, render_template, request, redirect, session,
    url_for, jsonify
)
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "dev-only-change-this-secret"
)

# threading mode is broadly compatible with the standard Flask-SocketIO install.
socketio = SocketIO(app, cors_allowed_origins=None)

DATABASE = os.path.join(app.root_path, "chat.db")
MAX_MESSAGE_LENGTH = 2000


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

        # Keep the original columns so an existing chat.db is not destroyed.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                msg TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(messages)")
        }

        migrations = {
            "sender_id": "INTEGER",
            "receiver_id": "INTEGER",
            "is_read": "INTEGER NOT NULL DEFAULT 0",
        }
        for column, definition in migrations.items():
            if column not in columns:
                conn.execute(
                    f"ALTER TABLE messages ADD COLUMN {column} {definition}"
                )

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_conversation
            ON messages(sender_id, receiver_id, id)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_messages_receiver_unread
            ON messages(receiver_id, is_read, id)
        """)


init_db()


def current_user():
    """Return the logged-in user row, or None."""
    user_id = session.get("user_id")
    if not user_id:
        return None

    with get_db() as conn:
        return conn.execute(
            "SELECT id, username FROM users WHERE id = ?", (user_id,)
        ).fetchone()


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
                stored_password = user["password"]
                if check_password_hash(stored_password, password):
                    valid = True
                # Upgrade legacy plain-text passwords, if any.
                elif stored_password == password:
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
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    # Show only this user's conversations, not everybody's messages.
    with get_db() as conn:
        messages = conn.execute("""
            SELECT
                m.id,
                m.msg,
                m.created_at,
                m.sender_id,
                m.receiver_id,
                sender.username AS username,
                receiver.username AS receiver_username,
                CASE WHEN m.sender_id = ? THEN 1 ELSE 0 END AS is_mine
            FROM messages AS m
            JOIN users AS sender ON sender.id = m.sender_id
            JOIN users AS receiver ON receiver.id = m.receiver_id
            WHERE m.sender_id = ? OR m.receiver_id = ?
            ORDER BY m.id ASC
            LIMIT 500
        """, (user["id"], user["id"], user["id"])).fetchall()

        # Mark messages delivered to this user as read when their chat page loads.
        conn.execute("""
            UPDATE messages
            SET is_read = 1
            WHERE receiver_id = ? AND is_read = 0
        """, (user["id"],))

    return render_template(
        "chat.html",
        username=user["username"],
        messages=messages
    )


@app.route("/api/users")
def list_users():
    """Frontend can use this endpoint to populate its recipient/contact list."""
    user = current_user()
    if not user:
        return jsonify({"error": "Login required"}), 401

    with get_db() as conn:
        users = conn.execute("""
            SELECT id, username
            FROM users
            WHERE id != ?
            ORDER BY username COLLATE NOCASE
        """, (user["id"],)).fetchall()

    return jsonify([
        {"id": row["id"], "username": row["username"]}
        for row in users
    ])


@socketio.on("connect")
def handle_connect(auth=None):
    user = current_user()
    if not user:
        return False

    # Every authenticated socket joins its own private room.
    join_room(f"user:{user['id']}")
    print(f"Chat connected: {user['username']} (user_id={user['id']})")


@socketio.on("chat_message")
def handle_message(data):
    user = current_user()
    if not user:
        emit("chat_error", {"msg": "Please log in again."})
        return

    if not isinstance(data, dict):
        emit("chat_error", {"msg": "Invalid message format."})
        return

    msg = data.get("msg")
    # Accept common frontend key names for the recipient username.
    recipient = (
        data.get("to")
        or data.get("receiver")
        or data.get("recipient")
        or data.get("receiver_username")
    )

    if not isinstance(msg, str):
        emit("chat_error", {"msg": "Message must be text."})
        return

    msg = msg.strip()
    if not msg or len(msg) > MAX_MESSAGE_LENGTH:
        emit("chat_error", {
            "msg": f"Message must contain 1-{MAX_MESSAGE_LENGTH} characters."
        })
        return

    if not isinstance(recipient, str) or not recipient.strip():
        emit("chat_error", {
            "msg": "Choose a recipient. Send {msg: 'Hello', to: 'username'}."
        })
        return

    recipient = recipient.strip()

    try:
        with get_db() as conn:
            target = conn.execute(
                "SELECT id, username FROM users WHERE username = ?",
                (recipient,)
            ).fetchone()

            if not target:
                emit("chat_error", {"msg": "That user does not exist."})
                return

            if target["id"] == user["id"]:
                emit("chat_error", {"msg": "You cannot message yourself."})
                return

            cursor = conn.execute("""
                INSERT INTO messages
                    (username, msg, sender_id, receiver_id, is_read)
                VALUES (?, ?, ?, ?, 0)
            """, (user["username"], msg, user["id"], target["id"]))
            message_id = cursor.lastrowid

            saved = conn.execute("""
                SELECT created_at FROM messages WHERE id = ?
            """, (message_id,)).fetchone()

        payload = {
            "id": message_id,
            "username": user["username"],
            "sender": user["username"],
            "receiver": target["username"],
            "msg": msg,
            "created_at": saved["created_at"],
            "is_mine": False
        }

        # Emit only to the recipient's private room. If offline, no socket
        # receives it, but the database row remains for their next login.
        socketio.emit("new_message", payload, room=f"user:{target['id']}")

        # Confirm to the sender so their UI can show the sent message.
        emit("message_sent", {
            **payload,
            "is_mine": True
        })

        print(f"Message {message_id}: {user['username']} -> {target['username']}")

    except sqlite3.Error as error:
        print("Database error:", error)
        emit("chat_error", {
            "msg": "Message could not be saved. Please try again."
        })


if __name__ == "__main__":
    socketio.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
