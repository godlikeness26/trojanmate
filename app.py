import hashlib
import os
import secrets
import sqlite3
from functools import wraps
from datetime import datetime, timedelta
from uuid import uuid4
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "trojanmate.db")

app = Flask(__name__)
app.secret_key = os.environ.get("TROJANMATE_SECRET", "change-this-secret-key")

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('student','tutor','admin')),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tutor_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    bio TEXT DEFAULT '',
    qualifications TEXT DEFAULT '',
    experience TEXT DEFAULT '',
    verified INTEGER NOT NULL DEFAULT 0,
    hourly_rate REAL NOT NULL DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS subjects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS tutor_subjects (
    tutor_id INTEGER NOT NULL,
    subject_id INTEGER NOT NULL,
    PRIMARY KEY(tutor_id, subject_id),
    FOREIGN KEY(tutor_id) REFERENCES tutor_profiles(id) ON DELETE CASCADE,
    FOREIGN KEY(subject_id) REFERENCES subjects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS availability (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tutor_id INTEGER NOT NULL,
    day TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    FOREIGN KEY(tutor_id) REFERENCES tutor_profiles(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    tutor_id INTEGER NOT NULL,
    subject_id INTEGER NOT NULL,
    session_date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    request_note TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','confirmed','completed','cancelled','rejected')),
    payment_status TEXT NOT NULL DEFAULT 'unpaid'
        CHECK(payment_status IN ('unpaid','pending','paid','not_applicable')),
    created_at TEXT NOT NULL,
    FOREIGN KEY(student_id) REFERENCES users(id),
    FOREIGN KEY(tutor_id) REFERENCES tutor_profiles(id),
    FOREIGN KEY(subject_id) REFERENCES subjects(id)
);

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    booking_id INTEGER NOT NULL UNIQUE,
    student_id INTEGER NOT NULL,
    tutor_id INTEGER NOT NULL,
    rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
    comment TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY(booking_id) REFERENCES bookings(id) ON DELETE CASCADE,
    FOREIGN KEY(student_id) REFERENCES users(id),
    FOREIGN KEY(tutor_id) REFERENCES tutor_profiles(id)
);

CREATE TABLE IF NOT EXISTS session_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    booking_id INTEGER NOT NULL UNIQUE,
    notes TEXT DEFAULT '',
    updated_at TEXT NOT NULL,
    FOREIGN KEY(booking_id) REFERENCES bookings(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    kind TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    link TEXT DEFAULT '/dashboard',
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(receiver_id) REFERENCES users(id) ON DELETE CASCADE
);
"""

DEFAULT_SUBJECTS = [
    "Mathematics", "Calculus", "Physics", "Chemistry", "Programming",
    "Computer Engineering", "English", "Research", "Electronics", "Other"
]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def column_exists(db, table_name, column_name):
    cols = db.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(col[1] == column_name for col in cols)


def table_exists(db, table_name):
    row = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,)).fetchone()
    return row is not None


def migrate_db_schema():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")

    if not table_exists(db, "password_reset_tokens"):
        db.execute("""
            CREATE TABLE password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used_at TEXT DEFAULT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

    if not table_exists(db, "tutor_requests"):
        db.execute("""
            CREATE TABLE tutor_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                subject_id INTEGER NOT NULL,
                topic TEXT NOT NULL,
                description TEXT NOT NULL,
                preferred_date TEXT DEFAULT '',
                preferred_time TEXT DEFAULT '',
                preferred_mode TEXT DEFAULT 'Online',
                budget REAL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','matched','closed')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(subject_id) REFERENCES subjects(id) ON DELETE CASCADE
            )
        """)

    if not table_exists(db, "tutor_request_offers"):
        db.execute("""
            CREATE TABLE tutor_request_offers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER NOT NULL,
                tutor_id INTEGER NOT NULL,
                message TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'interested' CHECK(status IN ('interested','accepted','declined')),
                created_at TEXT NOT NULL,
                FOREIGN KEY(request_id) REFERENCES tutor_requests(id) ON DELETE CASCADE,
                FOREIGN KEY(tutor_id) REFERENCES tutor_profiles(id) ON DELETE CASCADE
            )
        """)

    if not column_exists(db, "users", "profile_picture"):
        db.execute("ALTER TABLE users ADD COLUMN profile_picture TEXT DEFAULT ''")
    if not column_exists(db, "users", "tutor_enabled"):
        db.execute("ALTER TABLE users ADD COLUMN tutor_enabled INTEGER NOT NULL DEFAULT 0")

    db.commit()
    db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA)
    migrate_db_schema()
    for subject in DEFAULT_SUBJECTS:
        db.execute("INSERT OR IGNORE INTO subjects(name) VALUES (?)", (subject,))
    admin = db.execute("SELECT id FROM users WHERE email=?", ("admin@trojanmate.local",)).fetchone()
    if not admin:
        db.execute(
            "INSERT INTO users(name,email,password_hash,role,created_at,profile_picture,tutor_enabled) VALUES (?,?,?,?,?,?,?)",
            ("System Administrator", "admin@trojanmate.local",
             generate_password_hash("Admin123!"), "admin", now(), "", 0)
        )
    db.commit()
    db.close()


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def hash_reset_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def send_password_reset_email(user_email, reset_url):
    smtp_host = os.getenv("SMTP_HOST")
    if not smtp_host:
        print(f"Password reset link: {reset_url}")
        return True

    email_from = os.getenv("EMAIL_FROM", "no-reply@trojanmate.local")
    app.logger.info("Password reset email would be sent from %s to %s with SMTP host %s", email_from, user_email, smtp_host)
    app.logger.info("Password reset link: %s", reset_url)
    return True


def ensure_tutor_profile(user_id):
    db = get_db()
    profile = db.execute("SELECT * FROM tutor_profiles WHERE user_id=?", (user_id,)).fetchone()
    if profile is not None:
        return profile
    db.execute(
        "INSERT INTO tutor_profiles(user_id, bio, qualifications, experience, verified, hourly_rate) VALUES (?,?,?,?,?,?)",
        (user_id, '', '', '', 0, 0),
    )
    db.commit()
    return db.execute("SELECT * FROM tutor_profiles WHERE user_id=?", (user_id,)).fetchone()


def is_tutor_user(user_row):
    if not user_row:
        return False
    if user_row["role"] == "admin":
        return False
    if user_row["role"] == "tutor":
        return True
    if int(user_row["tutor_enabled"] if "tutor_enabled" in user_row.keys() else 0 or 0) == 1:
        return True
    db = get_db()
    profile = db.execute("SELECT id FROM tutor_profiles WHERE user_id=?", (user_row["id"],)).fetchone()
    return profile is not None


def get_avatar_url(user_row):
    if not user_row:
        return url_for("static", filename="default-avatar.svg")
    picture = (user_row["profile_picture"] if "profile_picture" in user_row.keys() else "") or ""
    picture = picture.strip()
    if picture:
        return url_for("static", filename=f"uploads/{picture}")
    return url_for("static", filename="default-avatar.svg")


def get_profile_picture_url(user_row):
    return get_avatar_url(user_row)


def format_hourly_rate(value):
    if value is None or value == "":
        return "Not specified"
    try:
        amount = float(value)
    except (TypeError, ValueError):
        return "Not specified"
    if amount <= 0:
        return "Free"
    return f"₱{amount:,.2f}/hour"


def time_to_minutes(value):
    if not value:
        return None
    try:
        time_obj = datetime.strptime(value, "%H:%M")
    except ValueError:
        return None
    return time_obj.hour * 60 + time_obj.minute


def time_ranges_overlap(start_a, end_a, start_b, end_b):
    return time_to_minutes(start_a) is not None and time_to_minutes(end_a) is not None and time_to_minutes(start_b) is not None and time_to_minutes(end_b) is not None and time_to_minutes(start_a) < time_to_minutes(end_b) and time_to_minutes(end_a) > time_to_minutes(start_b)


def generate_time_slots(start_time, end_time, slot_minutes=60):
    start_total = time_to_minutes(start_time)
    end_total = time_to_minutes(end_time)
    if start_total is None or end_total is None or end_total <= start_total:
        return []

    slots = []
    current = start_total
    while current + slot_minutes <= end_total:
        next_start = (datetime.min + timedelta(minutes=current)).strftime("%H:%M")
        next_end = (datetime.min + timedelta(minutes=current + slot_minutes)).strftime("%H:%M")
        slots.append({"start": next_start, "end": next_end})
        current += slot_minutes
    return slots


def add_notification(user_id, kind, title, body, link="/dashboard"):
    db = get_db()
    db.execute(
        "INSERT INTO notifications(user_id, kind, title, body, link, is_read, created_at) VALUES (?,?,?,?,?,?,?)",
        (user_id, kind, title, body, link, 0, now())
    )
    db.commit()


def user_is_student(user_row):
    return bool(user_row) and user_row["role"] != "admin"


def user_can_use_tutor_mode(user_row):
    if not user_row or user_row["role"] == "admin":
        return False
    profile = get_db().execute(
        "SELECT * FROM tutor_profiles WHERE user_id=? LIMIT 1",
        (user_row["id"],),
    ).fetchone()
    if not profile:
        return False
    return int(profile["verified"] or 0) == 1


def user_is_tutor(user_row):
    if not user_row or user_row["role"] == "admin":
        return False
    if user_row["role"] == "tutor":
        return True
    tutor_enabled = user_row["tutor_enabled"] if "tutor_enabled" in user_row.keys() else 0
    if int(tutor_enabled or 0) == 1:
        return True
    profile = get_db().execute(
        "SELECT id FROM tutor_profiles WHERE user_id=? LIMIT 1",
        (user_row["id"],),
    ).fetchone()
    return profile is not None


def get_active_mode():
    mode = session.get("active_mode")
    if mode not in {"tutee", "tutor"}:
        mode = "tutee"
    if mode == "tutor" and not user_can_use_tutor_mode(g.user):
        session["active_mode"] = "tutee"
        return "tutee"
    return mode


def build_conversation_list(user_id):
    db = get_db()
    rows = db.execute("""
        SELECT m.*, u.name AS other_name, u.role AS other_role
        FROM messages m
        JOIN users u ON u.id = CASE WHEN m.sender_id = ? THEN m.receiver_id ELSE m.sender_id END
        WHERE m.sender_id = ? OR m.receiver_id = ?
        ORDER BY m.created_at DESC
    """, (user_id, user_id, user_id)).fetchall()

    conversations = {}
    for row in rows:
        other_id = row["receiver_id"] if row["sender_id"] == user_id else row["sender_id"]
        current = conversations.setdefault(
            other_id,
            {
                "id": other_id,
                "name": row["other_name"],
                "role": row["other_role"],
                "unread_count": 0,
                "last_message_at": row["created_at"],
            },
        )
        if row["receiver_id"] == user_id and row["is_read"] == 0:
            current["unread_count"] += 1
        if row["created_at"] > current["last_message_at"]:
            current["last_message_at"] = row["created_at"]
    return sorted(conversations.values(), key=lambda item: item["last_message_at"], reverse=True)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not g.user:
                return redirect(url_for("login"))
            allows_student = "student" in roles and user_is_student(g.user)
            allows_tutor = "tutor" in roles and user_is_tutor(g.user)
            if g.user["role"] in roles or allows_student or allows_tutor:
                return view(*args, **kwargs)
            abort(403)
        return wrapped
    return decorator


@app.before_request
def load_user():
    g.user = None
    if "user_id" in session:
        g.user = get_db().execute(
            "SELECT id, name, email, role, created_at, profile_picture, tutor_enabled FROM users WHERE id=?",
            (session["user_id"],)
        ).fetchone()
        if g.user:
            current_mode = session.get("active_mode")
            if current_mode not in {"tutee", "tutor"}:
                session["active_mode"] = "tutee"
            if current_mode == "tutor" and not user_can_use_tutor_mode(g.user):
                session["active_mode"] = "tutee"


@app.context_processor
def inject_globals():
    unread_count = 0
    if g.user:
        unread_count = get_db().execute(
            "SELECT COUNT(*) AS c FROM notifications WHERE user_id=? AND is_read=0",
            (g.user["id"],),
        ).fetchone()["c"]
    return {
        "current_user": g.user,
        "unread_notifications": unread_count,
        "avatar_url": get_avatar_url,
        "user_is_student": user_is_student,
        "user_is_tutor": user_is_tutor,
        "user_can_use_tutor_mode": user_can_use_tutor_mode,
        "active_mode": get_active_mode,
        "format_hourly_rate": format_hourly_rate,
    }


@app.route("/")
def index():
    db = get_db()
    tutors = db.execute("""
        SELECT tp.*, u.name, u.email,
               COALESCE(ROUND(AVG(f.rating),1),0) AS rating,
               COUNT(f.id) AS rating_count
        FROM tutor_profiles tp
        JOIN users u ON u.id=tp.user_id
        LEFT JOIN feedback f ON f.tutor_id=tp.id
        WHERE tp.verified=1
        GROUP BY tp.id
        ORDER BY rating DESC, u.name
        LIMIT 6
    """).fetchall()
    return render_template("index.html", tutors=tutors)


@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        role = request.form["role"]
        if role not in ("student", "tutor"):
            flash("Invalid account type.", "danger")
            return redirect(url_for("register"))
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return redirect(url_for("register"))
        db = get_db()
        try:
            cur = db.execute(
                "INSERT INTO users(name,email,password_hash,role,created_at) VALUES (?,?,?,?,?)",
                (name, email, generate_password_hash(password), role, now())
            )
            user_id = cur.lastrowid
            if role == "tutor":
                db.execute("INSERT INTO tutor_profiles(user_id) VALUES (?)", (user_id,))
            db.commit()
            flash("Account created. You can now log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That email is already registered.", "danger")
    return render_template("register.html")


@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        user = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["active_mode"] = "tutee"
            flash("Welcome to TrojanMate.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "danger")
    return render_template("login.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        db = get_db()
        user = db.execute("SELECT id, email FROM users WHERE email=?", (email,)).fetchone()

        if user:
            token = secrets.token_urlsafe(32)
            token_hash = hash_reset_token(token)
            expires_at = (datetime.now() + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
            db.execute("DELETE FROM password_reset_tokens WHERE user_id=?", (user["id"],))
            db.execute(
                "INSERT INTO password_reset_tokens(user_id, token_hash, expires_at, used_at, created_at) VALUES (?,?,?,?,?)",
                (user["id"], token_hash, expires_at, None, now()),
            )
            db.commit()
            reset_url = url_for("reset_password", token=token, _external=True)
            send_password_reset_email(user["email"], reset_url)

        flash("If an account exists for that email, password reset instructions have been provided.", "info")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hash_reset_token(token)
    db = get_db()
    reset_record = db.execute(
        "SELECT * FROM password_reset_tokens WHERE token_hash=? ORDER BY created_at DESC LIMIT 1",
        (token_hash,),
    ).fetchone()

    if not reset_record:
        flash("This password reset link is invalid or has already been used.", "danger")
        return render_template("reset_password.html", valid=False)

    expires_at = datetime.strptime(reset_record["expires_at"], "%Y-%m-%d %H:%M:%S")
    if reset_record["used_at"] is not None or expires_at < datetime.now():
        db.execute("DELETE FROM password_reset_tokens WHERE id=?", (reset_record["id"],))
        db.commit()
        flash("This password reset link is invalid or has expired.", "danger")
        return render_template("reset_password.html", valid=False)

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", valid=True, token=token)

        if len(new_password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template("reset_password.html", valid=True, token=token)

        user = db.execute("SELECT id FROM users WHERE id=?", (reset_record["user_id"],)).fetchone()
        if not user:
            db.execute("DELETE FROM password_reset_tokens WHERE id=?", (reset_record["id"],))
            db.commit()
            flash("This password reset link is invalid.", "danger")
            return render_template("reset_password.html", valid=False)

        db.execute(
            "UPDATE users SET password_hash=? WHERE id=?",
            (generate_password_hash(new_password), user["id"]),
        )
        db.execute("DELETE FROM password_reset_tokens WHERE id=?", (reset_record["id"],))
        db.commit()
        flash("Your password has been reset successfully. Please log in with your new password.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", valid=True, token=token)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/profile/picture", methods=["POST"])
@login_required
def update_profile_picture():
    file = request.files.get("profile_picture")
    if not file or file.filename == "":
        flash("Please choose an image to upload.", "warning")
        return redirect(url_for("dashboard"))

    filename = secure_filename(file.filename)
    if "." not in filename:
        flash("Profile picture must be a valid image file.", "danger")
        return redirect(url_for("dashboard"))
    ext = filename.rsplit(".", 1)[1].lower()
    if ext not in {"png", "jpg", "jpeg", "webp"}:
        flash("Only PNG, JPG, JPEG, and WEBP images are allowed.", "danger")
        return redirect(url_for("dashboard"))

    upload_dir = os.path.join(BASE_DIR, "static", "uploads")
    os.makedirs(upload_dir, exist_ok=True)

    file.stream.seek(0, os.SEEK_END)
    size = file.stream.tell()
    file.stream.seek(0)
    if size > 2 * 1024 * 1024:
        flash("Profile picture must be 2MB or smaller.", "danger")
        return redirect(url_for("dashboard"))

    unique_name = f"{uuid4().hex}.{ext}"
    file.save(os.path.join(upload_dir, unique_name))

    old_name = (g.user["profile_picture"] if "profile_picture" in g.user.keys() else "") or ""
    old_name = old_name.strip()
    if old_name:
        old_path = os.path.join(upload_dir, old_name)
        if os.path.exists(old_path):
            try:
                os.remove(old_path)
            except OSError:
                pass

    db = get_db()
    db.execute("UPDATE users SET profile_picture=? WHERE id=?", (unique_name, g.user["id"]))
    db.commit()
    g.user["profile_picture"] = unique_name
    flash("Profile picture updated successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/account/mode", methods=["POST"])
@login_required
def set_active_mode():
    requested_mode = request.form.get("mode")
    if requested_mode not in {"tutee", "tutor"}:
        abort(400)

    if requested_mode == "tutor" and not user_can_use_tutor_mode(g.user):
        flash("Complete your tutor profile before switching to Tutor Mode.", "warning")
        return redirect(url_for("dashboard"))

    session["active_mode"] = requested_mode
    flash(f"{requested_mode.title()} Mode enabled.", "success")
    return redirect(url_for("dashboard"))


@app.route("/account/toggle-tutor", methods=["POST"])
@login_required
def toggle_tutor_mode():
    if g.user["role"] == "admin":
        abort(403)

    db = get_db()
    profile = db.execute("SELECT * FROM tutor_profiles WHERE user_id=? LIMIT 1", (g.user["id"],)).fetchone()
    if profile is None:
        ensure_tutor_profile(g.user["id"])

    if int((g.user["tutor_enabled"] if "tutor_enabled" in g.user.keys() else 0) or 0) == 0:
        db.execute("UPDATE users SET tutor_enabled=? WHERE id=?", (1, g.user["id"]))
        db.commit()
        g.user = db.execute(
            "SELECT id, name, email, role, created_at, profile_picture, tutor_enabled FROM users WHERE id=?",
            (g.user["id"],),
        ).fetchone()
        flash("Tutor access enabled. Complete your tutor profile to unlock Tutor Mode.", "success")
        return redirect(url_for("tutor_profile"))

    if not user_can_use_tutor_mode(g.user):
        flash("Complete your tutor profile and wait for verification before using Tutor Mode.", "warning")
        return redirect(url_for("tutor_profile"))

    session["active_mode"] = "tutor" if session.get("active_mode") != "tutor" else "tutee"
    flash(f"{session['active_mode'].title()} Mode enabled.", "success")
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()

    if g.user["role"] == "admin":
        stats = {
            "students": db.execute("SELECT COUNT(*) c FROM users WHERE role='student'").fetchone()["c"],
            "tutors": db.execute("SELECT COUNT(*) c FROM users WHERE role='tutor'").fetchone()["c"],
            "verified": db.execute("SELECT COUNT(*) c FROM tutor_profiles WHERE verified=1").fetchone()["c"],
            "pending": db.execute("SELECT COUNT(*) c FROM tutor_profiles WHERE verified=0").fetchone()["c"],
            "bookings": db.execute("SELECT COUNT(*) c FROM bookings").fetchone()["c"],
            "completed": db.execute("SELECT COUNT(*) c FROM bookings WHERE status='completed'").fetchone()["c"],
        }
        recent_activity = db.execute("""
            SELECT b.id, b.status, b.session_date, b.created_at, su.name AS student_name, tu.name AS tutor_name
            FROM bookings b
            JOIN users su ON su.id=b.student_id
            JOIN tutor_profiles tp ON tp.id=b.tutor_id
            JOIN users tu ON tu.id=tp.user_id
            ORDER BY b.created_at DESC LIMIT 8
        """).fetchall()
        pending_tutors = db.execute("""
            SELECT tp.id, tp.verified, tp.qualifications, tp.experience, u.name, u.email
            FROM tutor_profiles tp
            JOIN users u ON u.id=tp.user_id
            WHERE tp.verified=0
            ORDER BY tp.id DESC
        """).fetchall()
        recent_users = db.execute("SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC LIMIT 8").fetchall()
        return render_template("admin_dashboard.html", stats=stats, recent_activity=recent_activity,
                               pending_tutors=pending_tutors, recent_users=recent_users)

    active_mode = get_active_mode()
    if active_mode == "tutor" and user_can_use_tutor_mode(g.user):
        profile = db.execute("SELECT * FROM tutor_profiles WHERE user_id=?", (g.user["id"],)).fetchone()
        if not profile:
            profile = db.execute("INSERT INTO tutor_profiles(user_id,bio,qualifications,experience,verified,hourly_rate) VALUES (?,?,?,?,?,?)",
                                 (g.user["id"], '', '', '', 0, 0))
            db.commit()
            profile = db.execute("SELECT * FROM tutor_profiles WHERE user_id=?", (g.user["id"],)).fetchone()

        bookings = db.execute("""
            SELECT b.*, u.name AS student_name, s.name AS subject_name
            FROM bookings b
            JOIN users u ON u.id=b.student_id
            JOIN subjects s ON s.id=b.subject_id
            WHERE b.tutor_id=?
            ORDER BY b.session_date DESC, b.start_time DESC
        """, (profile["id"],)).fetchall()

        pending = [b for b in bookings if b["status"] == "pending"]
        confirmed = [b for b in bookings if b["status"] == "confirmed"]
        completed = [b for b in bookings if b["status"] == "completed"]

        total_earnings = db.execute(
            "SELECT COUNT(*) c, COALESCE(SUM(CASE WHEN status='completed' THEN hourly_rate ELSE 0 END), 0) AS sum_value FROM (SELECT b.status, tp.hourly_rate FROM bookings b JOIN tutor_profiles tp ON tp.id=b.tutor_id WHERE b.tutor_id=? )",
            (profile["id"],),
        ).fetchone()

        earnings = float(total_earnings["sum_value"] or 0)
        recent_feedback = db.execute("""
            SELECT f.*, u.name AS student_name
            FROM feedback f
            JOIN users u ON u.id=f.student_id
            WHERE f.tutor_id=?
            ORDER BY f.created_at DESC LIMIT 5
        """, (profile["id"],)).fetchall()

        profile_complete = db.execute("SELECT COUNT(*) AS c FROM tutor_subjects WHERE tutor_id=?", (profile["id"],)).fetchone()["c"] > 0
        return render_template(
            "tutor_dashboard.html",
            profile=profile,
            bookings=bookings,
            pending=pending,
            confirmed=confirmed,
            completed=completed,
            earnings=earnings,
            recent_feedback=recent_feedback,
            profile_complete=profile_complete,
        )

    bookings = db.execute("""
        SELECT b.*, u.name AS tutor_name, s.name AS subject_name
        FROM bookings b
        JOIN tutor_profiles tp ON tp.id=b.tutor_id
        JOIN users u ON u.id=tp.user_id
        JOIN subjects s ON s.id=b.subject_id
        WHERE b.student_id=?
        ORDER BY b.session_date DESC, b.start_time DESC
    """, (g.user["id"],)).fetchall()

    upcoming = [b for b in bookings if b["status"] in ("pending", "confirmed")]
    recent = bookings[:4]
    tutors = db.execute("""
        SELECT tp.id, tp.hourly_rate, tp.bio, tp.verified,
               u.name, u.profile_picture,
               COALESCE(ROUND(AVG(f.rating),1),0) AS rating,
               COUNT(f.id) AS rating_count,
               GROUP_CONCAT(s.name, ', ') AS subject_names
        FROM tutor_profiles tp
        JOIN users u ON u.id=tp.user_id
        LEFT JOIN feedback f ON f.tutor_id=tp.id
        LEFT JOIN tutor_subjects ts ON ts.tutor_id=tp.id
        LEFT JOIN subjects s ON s.id=ts.subject_id
        WHERE tp.verified=1 AND tp.id IN (
            SELECT tutor_id FROM tutor_subjects GROUP BY tutor_id
        )
        GROUP BY tp.id
        ORDER BY rating DESC, u.name
        LIMIT 4
    """).fetchall()

    ratings = db.execute("""
        SELECT ROUND(AVG(rating),1) AS avg_rating, COUNT(*) AS review_count
        FROM feedback f
        JOIN bookings b ON b.id = f.booking_id
        WHERE b.student_id=?
    """, (g.user["id"],)).fetchone()

    avg_rating = float(ratings["avg_rating"] or 0)
    review_count = ratings["review_count"] or 0

    return render_template(
        "student_dashboard.html",
        bookings=bookings,
        upcoming=upcoming,
        recent=recent,
        tutors=tutors,
        avg_rating=avg_rating,
        review_count=review_count,
    )


@app.route("/tutors")
@login_required
def tutors():
    db = get_db()
    q = request.args.get("q", "").strip()
    subject = request.args.get("subject", "").strip()
    rating_min = request.args.get("rating_min", "0")
    price_max = request.args.get("price_max", "")
    availability = request.args.get("availability", "all")
    sort = request.args.get("sort", "rating_desc")
    params = []

    sql = """
        SELECT tp.*, u.name, u.email,
               COALESCE(ROUND(AVG(f.rating),1),0) rating,
               COUNT(f.id) rating_count,
               GROUP_CONCAT(s.name, ', ') subject_names,
               tp.hourly_rate
        FROM tutor_profiles tp
        JOIN users u ON u.id=tp.user_id
        LEFT JOIN feedback f ON f.tutor_id=tp.id
        LEFT JOIN tutor_subjects ts ON ts.tutor_id=tp.id
        LEFT JOIN subjects s ON s.id=ts.subject_id
        WHERE tp.verified=1
    """
    sql += " AND tp.id IN (SELECT tutor_id FROM tutor_subjects GROUP BY tutor_id)"
    if q:
        sql += " AND (u.name LIKE ? OR tp.bio LIKE ? OR tp.qualifications LIKE ?)"
        like = f"%{q}%"
        params += [like, like, like]
    if subject:
        sql += " AND tp.id IN (SELECT ts2.tutor_id FROM tutor_subjects ts2 JOIN subjects s2 ON s2.id=ts2.subject_id WHERE s2.name=?)"
        params.append(subject)
    if rating_min and rating_min != "0":
        sql += " AND COALESCE(AVG(f.rating),0) >= ?"
        params.append(float(rating_min))
    if price_max:
        sql += " AND tp.hourly_rate <= ?"
        params.append(float(price_max))
    if availability and availability != "all":
        sql += " AND tp.id IN (SELECT DISTINCT tutor_id FROM availability WHERE day=?)"
        params.append(availability)

    sql += " GROUP BY tp.id"

    if sort == "rating_desc":
        sql += " ORDER BY rating DESC, u.name"
    elif sort == "rating_asc":
        sql += " ORDER BY rating ASC, u.name"
    elif sort == "name_asc":
        sql += " ORDER BY u.name ASC"
    elif sort == "name_desc":
        sql += " ORDER BY u.name DESC"
    elif sort == "price_asc":
        sql += " ORDER BY tp.hourly_rate ASC, u.name"
    elif sort == "price_desc":
        sql += " ORDER BY tp.hourly_rate DESC, u.name"
    else:
        sql += " ORDER BY rating DESC, u.name"

    tutor_rows = db.execute(sql, params).fetchall()
    subjects = db.execute("SELECT * FROM subjects ORDER BY name").fetchall()
    availability_days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    return render_template(
        "tutors.html",
        tutors=tutor_rows,
        subjects=subjects,
        q=q,
        selected_subject=subject,
        rating_min=rating_min,
        price_max=price_max,
        availability=availability,
        sort=sort,
        availability_days=availability_days,
    )


@app.route("/tutor-requests")
@login_required
def tutor_requests():
    if not user_can_use_tutor_mode(g.user):
        flash("Complete your tutor profile before using Tutor Mode.", "warning")
        session["active_mode"] = "tutee"
        return redirect(url_for("dashboard"))

    session["active_mode"] = "tutor"
    db = get_db()
    rows = db.execute("""
        SELECT tr.*, s.name AS subject_name, u.name AS student_name
        FROM tutor_requests tr
        JOIN subjects s ON s.id = tr.subject_id
        JOIN users u ON u.id = tr.student_id
        WHERE tr.status IN ('open', 'matched')
        ORDER BY tr.created_at DESC
    """).fetchall()
    return render_template("tutor_requests.html", requests=rows)


@app.route("/tutor-requests/<int:request_id>")
@login_required
def tutor_request_detail(request_id):
    if not user_can_use_tutor_mode(g.user):
        flash("Complete your tutor profile before using Tutor Mode.", "warning")
        session["active_mode"] = "tutee"
        return redirect(url_for("dashboard"))

    db = get_db()
    request_row = db.execute("""
        SELECT tr.*, s.name AS subject_name, u.name AS student_name, u.id AS student_id
        FROM tutor_requests tr
        JOIN subjects s ON s.id = tr.subject_id
        JOIN users u ON u.id = tr.student_id
        WHERE tr.id = ?
    """, (request_id,)).fetchone()
    if not request_row:
        abort(404)

    offers = db.execute("""
        SELECT tro.*, tp.user_id, u.name AS tutor_name
        FROM tutor_request_offers tro
        JOIN tutor_profiles tp ON tp.id = tro.tutor_id
        JOIN users u ON u.id = tp.user_id
        WHERE tro.request_id = ?
        ORDER BY tro.created_at DESC
    """, (request_id,)).fetchall()

    return render_template("tutor_request_detail.html", request=request_row, offers=offers)


@app.route("/tutor-requests/<int:request_id>/offer", methods=["POST"])
@login_required
def tutor_request_offer(request_id):
    if not user_can_use_tutor_mode(g.user):
        flash("Complete your tutor profile before using Tutor Mode.", "warning")
        session["active_mode"] = "tutee"
        return redirect(url_for("dashboard"))

    db = get_db()
    request_row = db.execute("SELECT * FROM tutor_requests WHERE id=?", (request_id,)).fetchone()
    if not request_row:
        abort(404)

    profile = db.execute("SELECT id FROM tutor_profiles WHERE user_id=? LIMIT 1", (g.user["id"],)).fetchone()
    if not profile:
        flash("You need a valid tutor profile before offering help.", "warning")
        return redirect(url_for("tutor_request_detail", request_id=request_id))

    message = request.form.get("message", "").strip()
    if not message:
        message = f"I can help with {request_row['topic']} and am available for tutoring."

    existing = db.execute(
        "SELECT id FROM tutor_request_offers WHERE request_id=? AND tutor_id=?",
        (request_id, profile["id"]),
    ).fetchone()
    if existing:
        flash("You already expressed interest in this request.", "info")
        return redirect(url_for("tutor_request_detail", request_id=request_id))

    db.execute(
        "INSERT INTO tutor_request_offers(request_id, tutor_id, message, status, created_at) VALUES (?,?,?,?,?)",
        (request_id, profile["id"], message, "interested", now()),
    )
    db.commit()
    flash("Your interest was sent to the student.", "success")
    return redirect(url_for("tutor_request_detail", request_id=request_id))


@app.route("/tutor-requests/new", methods=["GET", "POST"])
@login_required
def create_tutor_request():
    if not user_is_student(g.user):
        flash("Only students can create tutoring requests.", "warning")
        return redirect(url_for("dashboard"))
    db = get_db()
    if request.method == "POST":
        subject_id = request.form.get("subject_id")
        topic = request.form.get("topic", "").strip()
        description = request.form.get("description", "").strip()
        preferred_date = request.form.get("preferred_date", "").strip()
        preferred_time = request.form.get("preferred_time", "").strip()
        preferred_mode = request.form.get("preferred_mode", "Online").strip() or "Online"
        budget = request.form.get("budget", "0").strip()
        if not subject_id or not topic or not description:
            flash("Subject, topic, and description are required.", "danger")
            return redirect(url_for("create_tutor_request"))
        try:
            budget_value = float(budget or 0)
        except ValueError:
            budget_value = 0
        db.execute(
            "INSERT INTO tutor_requests(student_id, subject_id, topic, description, preferred_date, preferred_time, preferred_mode, budget, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (g.user["id"], int(subject_id), topic, description, preferred_date, preferred_time, preferred_mode, budget_value, "open", now(), now()),
        )
        db.commit()
        flash("Tutoring request created successfully.", "success")
        return redirect(url_for("dashboard"))
    subjects = db.execute("SELECT * FROM subjects ORDER BY name").fetchall()
    return render_template("create_tutor_request.html", subjects=subjects)


@app.route("/tutor/<int:tutor_id>")
@login_required
def tutor_detail(tutor_id):
    db = get_db()
    tutor = db.execute("""
        SELECT tp.*, u.name, u.email, COALESCE(ROUND(AVG(f.rating),1),0) rating,
               COUNT(f.id) rating_count
        FROM tutor_profiles tp JOIN users u ON u.id=tp.user_id
        LEFT JOIN feedback f ON f.tutor_id=tp.id
        WHERE tp.id=? AND tp.verified=1 GROUP BY tp.id
    """, (tutor_id,)).fetchone()
    if not tutor:
        abort(404)

    subjects = db.execute("""
        SELECT s.* FROM subjects s JOIN tutor_subjects ts ON ts.subject_id=s.id
        WHERE ts.tutor_id=? ORDER BY s.name
    """, (tutor_id,)).fetchall()

    availability_rows = db.execute(
        "SELECT * FROM availability WHERE tutor_id=? ORDER BY id", (tutor_id,)
    ).fetchall()

    feedback = db.execute("""
        SELECT f.*, u.name AS student_name FROM feedback f JOIN users u ON u.id=f.student_id
        WHERE f.tutor_id=? ORDER BY f.created_at DESC LIMIT 10
    """, (tutor_id,)).fetchall()

    availability_by_day = {}
    for row in availability_rows:
        availability_by_day.setdefault(row["day"], []).append({
            "start": row["start_time"],
            "end": row["end_time"],
        })

    return render_template(
        "tutor_detail.html",
        tutor=tutor,
        subjects=subjects,
        availability=availability_rows,
        availability_by_day=availability_by_day,
        feedback=feedback,
    )


@app.route("/tutor/profile", methods=["GET","POST"])
@login_required
def tutor_profile():
    db = get_db()
    if not user_is_tutor(g.user):
        ensure_tutor_profile(g.user["id"])
    profile = db.execute("SELECT * FROM tutor_profiles WHERE user_id=?", (g.user["id"],)).fetchone()
    if request.method == "POST":
        bio = request.form.get("bio", "").strip()
        qualifications = request.form.get("qualifications", "").strip()
        experience = request.form.get("experience", "").strip()
        try:
            rate = float(request.form.get("hourly_rate", 0) or 0)
        except ValueError:
            rate = 0

        selected_subjects = request.form.getlist("subjects")
        if not selected_subjects:
            flash("Please select at least one subject before saving your tutor profile.", "warning")
            return redirect(url_for("tutor_profile"))

        db.execute(
            "UPDATE tutor_profiles SET bio=?, qualifications=?, experience=?, hourly_rate=? WHERE id=?",
            (bio, qualifications, experience, rate, profile["id"]),
        )
        db.execute("DELETE FROM tutor_subjects WHERE tutor_id=?", (profile["id"],))
        for sid in selected_subjects:
            db.execute(
                "INSERT INTO tutor_subjects(tutor_id,subject_id) VALUES (?,?)",
                (profile["id"], int(sid)),
            )

        db.execute("DELETE FROM availability WHERE tutor_id=?", (profile["id"],))
        days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        for day in days:
            start = request.form.get(f"start_{day}")
            end = request.form.get(f"end_{day}")
            if start and end:
                db.execute(
                    "INSERT INTO availability(tutor_id,day,start_time,end_time) VALUES (?,?,?,?)",
                    (profile["id"], day, start, end),
                )
        db.commit()
        flash("Tutor profile updated. An administrator must verify new tutor accounts.", "success")
        return redirect(url_for("tutor_profile"))

    selected = {r["subject_id"] for r in db.execute(
        "SELECT subject_id FROM tutor_subjects WHERE tutor_id=?", (profile["id"],)
    ).fetchall()}
    subjects = db.execute("SELECT * FROM subjects ORDER BY name").fetchall()
    availability_rows = db.execute("SELECT * FROM availability WHERE tutor_id=?", (profile["id"],)).fetchall()
    availability_map = {r["day"]: r for r in availability_rows}
    return render_template("tutor_profile.html", profile=profile, subjects=subjects,
                           selected=selected, availability=availability_map)


@app.route("/book/<int:tutor_id>", methods=["GET","POST"])
@role_required("student")
def book(tutor_id):
    db = get_db()
    tutor = db.execute("""
        SELECT tp.*, u.name, u.id AS user_id
        FROM tutor_profiles tp
        JOIN users u ON u.id=tp.user_id
        WHERE tp.id=? AND tp.verified=1
    """, (tutor_id,)).fetchone()
    if not tutor:
        abort(404)

    subjects = db.execute("""
        SELECT s.* FROM subjects s JOIN tutor_subjects ts ON ts.subject_id=s.id
        WHERE ts.tutor_id=? ORDER BY s.name
    """, (tutor_id,)).fetchall()

    availability = db.execute("SELECT * FROM availability WHERE tutor_id=? ORDER BY day, start_time", (tutor_id,)).fetchall()
    availability_by_day = {}
    for item in availability:
        availability_by_day.setdefault(item["day"], []).append({
            "start": item["start_time"],
            "end": item["end_time"],
        })

    bookings_by_date = {}
    booking_rows = db.execute(
        "SELECT session_date, start_time, end_time FROM bookings WHERE tutor_id=? AND status IN ('pending','confirmed') ORDER BY session_date, start_time",
        (tutor_id,),
    ).fetchall()
    for row in booking_rows:
        bookings_by_date.setdefault(row["session_date"], []).append({
            "start": row["start_time"],
            "end": row["end_time"],
        })

    if g.user["id"] == tutor["user_id"]:
        flash("You cannot book yourself as your own tutor.", "danger")
        return redirect(url_for("tutors"))

    if request.method == "POST":
        subject_id = int(request.form["subject_id"])
        date = request.form["session_date"]
        start = request.form["start_time"]
        end = request.form["end_time"]
        note = request.form.get("request_note", "").strip()

        if not date or not start or not end:
            flash("Please select a valid date and time for the session.", "danger")
            return redirect(url_for("book", tutor_id=tutor_id))

        try:
            session_date = datetime.strptime(date, "%Y-%m-%d").date()
            if session_date < datetime.now().date():
                flash("Bookings cannot be scheduled in the past.", "danger")
                return redirect(url_for("book", tutor_id=tutor_id))
        except ValueError:
            flash("Please enter a valid booking date.", "danger")
            return redirect(url_for("book", tutor_id=tutor_id))

        try:
            start_minutes = time_to_minutes(start)
            end_minutes = time_to_minutes(end)
        except TypeError:
            start_minutes = None
            end_minutes = None

        if start_minutes is None or end_minutes is None:
            flash("Please enter a valid start and end time.", "danger")
            return redirect(url_for("book", tutor_id=tutor_id))

        if end_minutes <= start_minutes:
            flash("End time must be later than the start time.", "danger")
            return redirect(url_for("book", tutor_id=tutor_id))

        day_name = datetime.strptime(date, "%Y-%m-%d").strftime("%A")
        day_ranges = [item for item in availability if item["day"] == day_name]
        if not day_ranges:
            flash("This tutor is not available on the selected weekday.", "danger")
            return redirect(url_for("book", tutor_id=tutor_id))

        if not any(
            start_minutes >= time_to_minutes(item["start_time"]) and end_minutes <= time_to_minutes(item["end_time"])
            for item in day_ranges
        ):
            flash("The selected time must fall within the tutor's availability for that day.", "danger")
            return redirect(url_for("book", tutor_id=tutor_id))

        conflicts = db.execute("""
            SELECT id, start_time, end_time FROM bookings
            WHERE tutor_id=? AND session_date=? AND status IN ('pending','confirmed')
        """, (tutor_id, date)).fetchall()
        if any(time_ranges_overlap(start, end, row["start_time"], row["end_time"]) for row in conflicts):
            flash("That tutor already has another booking during the selected time.", "danger")
            return redirect(url_for("book", tutor_id=tutor_id))

        duration_minutes = end_minutes - start_minutes
        expected_fee = 0.0
        if tutor["hourly_rate"] and tutor["hourly_rate"] > 0:
            expected_fee = float(tutor["hourly_rate"]) * (duration_minutes / 60.0)

        db.execute(
            """INSERT INTO bookings
            (student_id,tutor_id,subject_id,session_date,start_time,end_time,request_note,status,payment_status,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (g.user["id"], tutor_id, subject_id, date, start, end, note, "pending",
             "not_applicable" if tutor["hourly_rate"] <= 0 else "unpaid", now())
        )
        db.commit()
        add_notification(tutor["user_id"], "booking_request", "New booking request",
                         f"{g.user['name']} requested a session on {date} at {start}.", "/dashboard")
        flash(f"Booking request submitted successfully. Estimated session fee: ₱{expected_fee:,.2f}", "success")
        return redirect(url_for("dashboard"))

    return render_template(
        "book.html",
        tutor=tutor,
        subjects=subjects,
        availability_by_day=availability_by_day,
        bookings_by_date=bookings_by_date,
    )


@app.route("/booking/<int:booking_id>/status", methods=["POST"])
@role_required("tutor", "admin")
def booking_status(booking_id):
    db = get_db()
    status = request.form["status"]
    if status not in ("confirmed", "completed", "cancelled", "rejected"):
        abort(400)

    booking = db.execute("SELECT * FROM bookings WHERE id=?", (booking_id,)).fetchone()
    if not booking:
        abort(404)

    if g.user["role"] == "tutor":
        profile = db.execute("SELECT id FROM tutor_profiles WHERE user_id=?", (g.user["id"],)).fetchone()
        if booking["tutor_id"] != profile["id"]:
            abort(403)

    db.execute("UPDATE bookings SET status=? WHERE id=?", (status, booking_id))
    db.commit()

    student = db.execute("SELECT name FROM users WHERE id=?", (booking["student_id"],)).fetchone()
    if student:
        add_notification(
            booking["student_id"],
            "booking_update",
            "Booking update",
            f"Your tutoring request for {booking['session_date']} was marked as {status}.",
            "/dashboard",
        )

    flash(f"Booking marked {status}.", "success")
    return redirect(url_for("dashboard"))


@app.route("/booking/<int:booking_id>/feedback", methods=["POST"])
@role_required("student")
def feedback_submit(booking_id):
    db = get_db()
    booking = db.execute("SELECT * FROM bookings WHERE id=? AND student_id=?", (booking_id, g.user["id"])).fetchone()
    if not booking or booking["status"] != "completed":
        abort(400)

    rating = int(request.form["rating"])
    comment = request.form.get("comment", "").strip()
    try:
        db.execute(
            """INSERT INTO feedback(booking_id,student_id,tutor_id,rating,comment,created_at)
            VALUES (?,?,?,?,?,?)""",
            (booking_id, g.user["id"], booking["tutor_id"], rating, comment, now()),
        )
        db.commit()
        add_notification(
            booking["tutor_id"],
            "feedback",
            "New review",
            f"{g.user['name']} left a {rating}-star review for your session.",
            "/dashboard",
        )
        flash("Feedback submitted. Thank you.", "success")
    except sqlite3.IntegrityError:
        flash("Feedback has already been submitted for this session.", "warning")
    return redirect(url_for("dashboard"))


@app.route("/booking/<int:booking_id>/notes", methods=["POST"])
@role_required("tutor", "admin")
def session_notes(booking_id):
    db = get_db()
    booking = db.execute("SELECT * FROM bookings WHERE id=?", (booking_id,)).fetchone()
    if not booking:
        abort(404)
    if g.user["role"] == "tutor":
        profile = db.execute("SELECT id FROM tutor_profiles WHERE user_id=?", (g.user["id"],)).fetchone()
        if booking["tutor_id"] != profile["id"]:
            abort(403)

    notes = request.form.get("notes", "").strip()
    db.execute(
        """INSERT INTO session_notes(booking_id,notes,updated_at) VALUES (?,?,?)
        ON CONFLICT(booking_id) DO UPDATE SET notes=excluded.notes, updated_at=excluded.updated_at""",
        (booking_id, notes, now()),
    )
    db.commit()
    flash("Session notes saved.", "success")
    return redirect(url_for("dashboard"))


@app.route("/admin")
@role_required("admin")
def admin():
    db = get_db()
    pending = db.execute("""
        SELECT tp.*, u.name, u.email FROM tutor_profiles tp JOIN users u ON u.id=tp.user_id
        WHERE tp.verified=0 ORDER BY tp.id
    """).fetchall()
    users = db.execute("SELECT id,name,email,role,created_at FROM users ORDER BY created_at DESC LIMIT 50").fetchall()
    bookings = db.execute("""
        SELECT b.*, su.name student_name, tu.name tutor_name, s.name subject_name
        FROM bookings b
        JOIN users su ON su.id=b.student_id
        JOIN tutor_profiles tp ON tp.id=b.tutor_id
        JOIN users tu ON tu.id=tp.user_id
        JOIN subjects s ON s.id=b.subject_id
        ORDER BY b.created_at DESC LIMIT 50
    """).fetchall()
    return render_template("admin.html", pending=pending, users=users, bookings=bookings)


@app.route("/admin/tutor/<int:tutor_id>/verify", methods=["POST"])
@role_required("admin")
def verify_tutor(tutor_id):
    db = get_db()
    action = request.form.get("action")
    if action == "verify":
        db.execute("UPDATE tutor_profiles SET verified=1 WHERE id=?", (tutor_id,))
        tutor = db.execute("SELECT u.id, u.name FROM tutor_profiles tp JOIN users u ON u.id=tp.user_id WHERE tp.id=?", (tutor_id,)).fetchone()
        if tutor:
            add_notification(tutor["id"], "verification", "Tutor verification approved",
                             "Your tutor profile has been verified. Students can now book your sessions.", "/dashboard")
    elif action == "unverify":
        db.execute("UPDATE tutor_profiles SET verified=0 WHERE id=?", (tutor_id,))
    else:
        abort(400)
    db.commit()
    flash("Tutor verification updated.", "success")
    return redirect(url_for("admin"))


@app.route("/notifications")
@login_required
def notifications():
    db = get_db()
    rows = db.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC", (g.user["id"],)).fetchall()
    db.execute("UPDATE notifications SET is_read=1 WHERE user_id=? AND is_read=0", (g.user["id"],))
    db.commit()
    return render_template("notifications.html", notifications=rows)


@app.route("/messages", methods=["GET", "POST"])
@login_required
def messages():
    db = get_db()
    if request.method == "POST":
        receiver_id = int(request.form["receiver_id"])
        body = request.form.get("body", "").strip()
        if not body:
            flash("Message cannot be empty.", "danger")
            return redirect(url_for("messages"))

        db.execute(
            "INSERT INTO messages(sender_id,receiver_id,body,created_at,is_read) VALUES (?,?,?,?,?)",
            (g.user["id"], receiver_id, body, now(), 0),
        )
        db.commit()
        flash("Message sent.", "success")
        return redirect(url_for("message_thread", other_id=receiver_id))

    conversations = build_conversation_list(g.user["id"])
    return render_template("messages.html", conversations=conversations, messages=[], thread_user=None)


@app.route("/messages/<int:other_id>")
@login_required
def message_thread(other_id):
    db = get_db()
    other = db.execute("SELECT id,name,role FROM users WHERE id=?", (other_id,)).fetchone()
    if not other:
        abort(404)

    rows = db.execute("""
        SELECT m.*, u.name AS sender_name
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        WHERE (m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?)
        ORDER BY m.created_at ASC
    """, (g.user["id"], other_id, other_id, g.user["id"])).fetchall()

    db.execute("UPDATE messages SET is_read=1 WHERE receiver_id=? AND sender_id=?", (g.user["id"], other_id))
    db.commit()

    conversations = build_conversation_list(g.user["id"])
    return render_template("messages.html", conversations=conversations, messages=rows, thread_user=other)


@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="The requested page was not found."), 404


with app.app_context():
    init_db()


if __name__ == "__main__":
  app.run(host="0.0.0.0", port=5000, debug=True)
