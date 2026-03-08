from __future__ import annotations

import io
import json
import os
import zipfile
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
CREDENTIALS_PATH = DATA_DIR / "credentials.json"
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "1234"


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024  # 1GB

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    _ensure_credentials()

    @app.context_processor
    def inject_now() -> dict[str, Any]:
        return {"current_year": datetime.utcnow().year}

    @app.route("/")
    def index():
        if session.get("authenticated"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        creds = _read_credentials()
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if username == creds["username"] and check_password_hash(creds["password_hash"], password):
                session["authenticated"] = True
                session["username"] = username
                flash("Logged in successfully.", "success")
                return redirect(url_for("dashboard"))

            flash("Invalid username or password.", "error")

        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout():
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard", methods=["GET", "POST"])
    @login_required
    def dashboard():
        if request.method == "POST":
            uploaded_files = request.files.getlist("files") + request.files.getlist("folder_files")
            saved_count = 0
            for uploaded in uploaded_files:
                if not uploaded or not uploaded.filename:
                    continue
                try:
                    destination = _safe_upload_destination(uploaded.filename)
                except ValueError:
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                uploaded.save(destination)
                saved_count += 1

            if saved_count:
                flash(f"Uploaded {saved_count} item(s) successfully.", "success")
            else:
                flash("No files were selected.", "error")

            return redirect(url_for("dashboard"))

        rows = _build_file_rows()
        creds = _read_credentials()
        return render_template(
            "dashboard.html",
            rows=rows,
            password_changed=creds.get("password_changed", False),
            username=session.get("username"),
        )

    @app.route("/download/file/<path:relative_path>")
    @login_required
    def download_file(relative_path: str):
        try:
            file_path = _resolve_upload_path(relative_path)
        except ValueError:
            flash("Invalid file path requested.", "error")
            return redirect(url_for("dashboard"))
        if not file_path.is_file():
            flash("Requested file does not exist.", "error")
            return redirect(url_for("dashboard"))

        return send_from_directory(UPLOAD_DIR, str(file_path.relative_to(UPLOAD_DIR)), as_attachment=True)

    @app.route("/download/folder/<path:relative_path>")
    @login_required
    def download_folder(relative_path: str):
        try:
            folder_path = _resolve_upload_path(relative_path)
        except ValueError:
            flash("Invalid folder path requested.", "error")
            return redirect(url_for("dashboard"))
        if not folder_path.is_dir():
            flash("Requested folder does not exist.", "error")
            return redirect(url_for("dashboard"))

        zip_stream = io.BytesIO()
        with zipfile.ZipFile(zip_stream, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(folder_path):
                root_path = Path(root)
                for file_name in files:
                    full_path = root_path / file_name
                    zf.write(full_path, full_path.relative_to(folder_path.parent))

        zip_stream.seek(0)
        return send_file(zip_stream, as_attachment=True, download_name=f"{folder_path.name}.zip", mimetype="application/zip")

    @app.route("/change-password", methods=["GET", "POST"])
    @login_required
    def change_password():
        creds = _read_credentials()
        if request.method == "POST":
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not check_password_hash(creds["password_hash"], current_password):
                flash("Current password is incorrect.", "error")
                return redirect(url_for("change_password"))

            if len(new_password) < 4:
                flash("New password must be at least 4 characters.", "error")
                return redirect(url_for("change_password"))

            if new_password != confirm_password:
                flash("New password and confirmation do not match.", "error")
                return redirect(url_for("change_password"))

            creds["password_hash"] = generate_password_hash(new_password)
            creds["password_changed"] = True
            _write_credentials(creds)
            flash("Password updated successfully.", "success")
            return redirect(url_for("dashboard"))

        return render_template("change_password.html")

    return app


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)

    return wrapped


def _ensure_credentials() -> None:
    if CREDENTIALS_PATH.exists():
        return

    credentials = {
        "username": DEFAULT_USERNAME,
        "password_hash": generate_password_hash(DEFAULT_PASSWORD),
        "password_changed": False,
    }
    _write_credentials(credentials)


def _read_credentials() -> dict[str, Any]:
    with CREDENTIALS_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def _write_credentials(credentials: dict[str, Any]) -> None:
    with CREDENTIALS_PATH.open("w", encoding="utf-8") as file:
        json.dump(credentials, file, indent=2)


def _safe_upload_destination(raw_name: str) -> Path:
    parts = [secure_filename(part) for part in Path(raw_name).parts if part not in ("", ".", "..")]
    if not parts:
        raise ValueError("Invalid upload name")
    candidate = UPLOAD_DIR.joinpath(*parts).resolve()
    if UPLOAD_DIR.resolve() not in candidate.parents and candidate != UPLOAD_DIR.resolve():
        raise ValueError("Invalid upload path")
    return candidate


def _resolve_upload_path(relative_path: str) -> Path:
    candidate = (UPLOAD_DIR / relative_path).resolve()
    if UPLOAD_DIR.resolve() not in candidate.parents and candidate != UPLOAD_DIR.resolve():
        raise ValueError("Invalid path")
    return candidate


def _format_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    current = float(size)
    for unit in units:
        if current < 1024 or unit == units[-1]:
            return f"{current:.1f} {unit}" if unit != "B" else f"{int(current)} B"
        current /= 1024
    return f"{size} B"


def _directory_size(directory: Path) -> int:
    total = 0
    for root, _, files in os.walk(directory):
        for file_name in files:
            total += (Path(root) / file_name).stat().st_size
    return total


def _build_file_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(UPLOAD_DIR.rglob("*")):
        if path == UPLOAD_DIR:
            continue
        rel = path.relative_to(UPLOAD_DIR).as_posix()
        stat = path.stat()
        if path.is_dir():
            size = _directory_size(path)
            file_type = "Folder"
            download_kind = "folder"
        else:
            size = stat.st_size
            extension = path.suffix[1:].upper() if path.suffix else "FILE"
            file_type = extension
            download_kind = "file"

        rows.append(
            {
                "name": rel,
                "file_type": file_type,
                "size": _format_size(size),
                "uploaded_at": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "download_kind": download_kind,
            }
        )

    return rows


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
