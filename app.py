
import os
import sqlite3

from flask import (
    Flask, render_template, request,
    redirect, session, url_for
)
from flask_socketio import SocketIO, emit
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "dev-only-change-this-secret"
)

# For local development. Same-origin connections work by default.
socketio = SocketIO(app)

DATABASE = os.path.join(app.root_path, "chat.db")
MAX_MESSAGE_LENGTH = 2000


def get_db():
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row
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

        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(messages)"
            )
        }

        if "created_at" not in columns:
            conn.execute("""
                ALTER TABLE messages
                ADD COLUMN created_at TEXT
            """)


init_db()


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or len(username) > 30:
            return "Username must be 1-30 characters.", 400

        if len(password) < 8:
            return "Password must be at least 8 characters.", 400

        password_hash = generate_password_hash(password)

        try:
            with get_db() as conn:
                conn.execute(
                    """INSERT INTO users (username, password)
                       VALUES (?, ?)""",
                    (username, password_hash)
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
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            valid = False

            if user:
                stored_password = user["password"]

                if check_password_hash(stored_password, password):
                    valid = True

                # Upgrade old plain-text passwords if applicable.
                elif stored_password == password:
                    valid = True
                    conn.execute(
                        "UPDATE users SET password = ? WHERE id = ?",
                        (
                            generate_password_hash(password),
                            user["id"]
                        )
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
    username = session.get("user")

    if not username:
        return redirect(url_for("login"))

    with get_db() as conn:
        messages = conn.execute("""
            SELECT username, msg, created_at
            FROM messages
            ORDER BY id DESC
            LIMIT 100
        """).fetchall()

    messages = list(reversed(messages))

    return render_template(
        "chat.html",
        username=username,
        messages=messages
    )


@socketio.on("connect")
def handle_connect(auth=None):
    if not session.get("user"):
        return False

    print(f"Chat connected: {session['user']}")


@socketio.on("chat_message")
def handle_message(data):
    username = session.get("user")

    if not username:
        print("Message rejected: user is not logged in")
        return

    if not isinstance(data, dict):
        return

    msg = data.get("msg")

    if not isinstance(msg, str):
        return

    msg = msg.strip()

    if not msg or len(msg) > MAX_MESSAGE_LENGTH:
        return

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO messages (username, msg) VALUES (?, ?)",
                (username, msg)
            )

        # Broadcast once, using the event expected by the frontend.
        socketio.emit("new_message", {
            "username": username,
            "msg": msg
        })

        print(f"Message sent by {username}: {msg}")

    except sqlite3.Error as error:
        print("Database error:", error)
        emit("chat_error", {
            "msg": "Message could not be saved. Please try again."
        })


if __name__ == "__main__":
    socketio.run(
        app,
        host="127.0.0.1",
        port=5000,
        debug=True
    )
