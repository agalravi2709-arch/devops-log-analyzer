import os
import re
import sqlite3
from datetime import datetime
from flask import (
    Flask, render_template, request,
    redirect, url_for, flash
)
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "logs.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"log", "txt"}
MAX_FILE_SIZE = 5 * 1024 * 1024

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                total_lines INTEGER NOT NULL,
                errors INTEGER NOT NULL,
                warnings INTEGER NOT NULL,
                critical INTEGER NOT NULL,
                infos INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS log_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                FOREIGN KEY(report_id) REFERENCES reports(id)
            )
        """)


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def detect_severity(line):
    match = re.search(
        r"\b(CRITICAL|FATAL|ERROR|WARN(?:ING)?|INFO|DEBUG)\b",
        line,
        re.IGNORECASE
    )

    if not match:
        return "OTHER"

    level = match.group(1).upper()

    if level in ("FATAL", "CRITICAL"):
        return "CRITICAL"
    if level == "ERROR":
        return "ERROR"
    if level in ("WARN", "WARNING"):
        return "WARNING"
    if level == "INFO":
        return "INFO"
    return "DEBUG"


def analyze_log(file_path):
    results = {
        "total": 0,
        "ERROR": 0,
        "WARNING": 0,
        "CRITICAL": 0,
        "INFO": 0,
        "DEBUG": 0,
        "OTHER": 0,
        "entries": []
    }

    with open(file_path, "r", encoding="utf-8", errors="replace") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            severity = detect_severity(line)
            results["total"] += 1
            results[severity] += 1

            results["entries"].append({
                "severity": severity,
                "message": line[:2000]
            })

    return results


def save_report(filename, results):
    with get_db() as conn:
        cursor = conn.execute("""
            INSERT INTO reports
            (filename, total_lines, errors, warnings, critical, infos, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            filename,
            results["total"],
            results["ERROR"],
            results["WARNING"],
            results["CRITICAL"],
            results["INFO"],
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        report_id = cursor.lastrowid

        conn.executemany("""
            INSERT INTO log_entries (report_id, severity, message)
            VALUES (?, ?, ?)
        """, [
            (report_id, entry["severity"], entry["message"])
            for entry in results["entries"]
        ])

        return report_id


@app.route("/")
def index():
    search = request.args.get("search", "").strip()
    severity = request.args.get("severity", "").upper()

    with get_db() as conn:
        reports = conn.execute(
            "SELECT * FROM reports ORDER BY id DESC"
        ).fetchall()

        query = """
            SELECT log_entries.*, reports.filename
            FROM log_entries
            JOIN reports ON reports.id = log_entries.report_id
            WHERE 1=1
        """
        params = []

        if search:
            query += " AND log_entries.message LIKE ?"
            params.append(f"%{search}%")

        if severity in {
            "ERROR", "WARNING", "CRITICAL", "INFO", "DEBUG", "OTHER"
        }:
            query += " AND log_entries.severity = ?"
            params.append(severity)

        query += " ORDER BY log_entries.id DESC LIMIT 200"
        entries = conn.execute(query, params).fetchall()

        stats = conn.execute("""
            SELECT
                COUNT(*) AS total_reports,
                COALESCE(SUM(total_lines), 0) AS total_lines,
                COALESCE(SUM(errors), 0) AS errors,
                COALESCE(SUM(warnings), 0) AS warnings,
                COALESCE(SUM(critical), 0) AS critical
            FROM reports
        """).fetchone()

    return render_template(
        "index.html",
        reports=reports,
        entries=entries,
        stats=stats,
        search=search,
        severity=severity
    )


@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        flash("Please select a log file.")
        return redirect(url_for("index"))

    file = request.files["file"]

    if not file.filename:
        flash("No file selected.")
        return redirect(url_for("index"))

    if not allowed_file(file.filename):
        flash("Only .log and .txt files are supported.")
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)
    safe_name = f"{datetime.now().strftime('%Y%m%d%H%M%S%f')}_{filename}"
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)

    try:
        file.save(file_path)
        results = analyze_log(file_path)
        report_id = save_report(filename, results)
        flash(f"Log file analyzed successfully. Report #{report_id} created.")
    except (OSError, UnicodeError, sqlite3.Error) as error:
        flash(f"Unable to analyze file: {error}")
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

    return redirect(url_for("index"))


@app.route("/report/<int:report_id>")
def report(report_id):
    with get_db() as conn:
        report_data = conn.execute(
            "SELECT * FROM reports WHERE id = ?", (report_id,)
        ).fetchone()
        entries = conn.execute(
            "SELECT * FROM log_entries WHERE report_id = ? ORDER BY id",
            (report_id,)
        ).fetchall()

    if report_data is None:
        flash("Report not found.")
        return redirect(url_for("index"))

    return render_template(
        "index.html",
        reports=[report_data],
        entries=entries,
        stats={
            "total_reports": 1,
            "total_lines": report_data["total_lines"],
            "errors": report_data["errors"],
            "warnings": report_data["warnings"],
            "critical": report_data["critical"]
        },
        search="",
        severity="",
        selected_report=report_data
    )


@app.route("/delete/<int:report_id>", methods=["POST"])
def delete_report(report_id):
    with get_db() as conn:
        conn.execute(
            "DELETE FROM log_entries WHERE report_id = ?", (report_id,)
        )
        conn.execute(
            "DELETE FROM reports WHERE id = ?", (report_id,)
        )

    flash("Report deleted.")
    return redirect(url_for("index"))


@app.route("/health")
def health():
    try:
        with get_db() as conn:
            conn.execute("SELECT 1")
        return {"status": "healthy"}, 200
    except sqlite3.Error:
        return {"status": "unhealthy"}, 500


initialize_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)