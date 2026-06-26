import sqlite3
from pathlib import Path

from flask import Flask, abort, render_template, request


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATABASE_FILE = PROJECT_ROOT / "backend-python" / "storage" / "siem_lite.db"

app = Flask(__name__)


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}


def database_exists():
    """Check whether the SIEM SQLite database exists."""
    return DATABASE_FILE.exists()


def get_db_connection():
    """Open a SQLite database connection."""
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def count_query(connection, sql, params=()):
    """Run a COUNT query and return the number."""
    row = connection.execute(sql, params).fetchone()
    return row[0] if row else 0


def get_dashboard_stats(connection):
    """Collect high-level dashboard statistics."""
    total_process_events = count_query(
        connection,
        "SELECT COUNT(*) FROM process_events"
    )

    total_alerts = count_query(
        connection,
        "SELECT COUNT(*) FROM alerts"
    )

    medium_plus_alerts = count_query(
        connection,
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE severity IN ('medium', 'high', 'critical')
        """
    )

    high_plus_alerts = count_query(
        connection,
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE severity IN ('high', 'critical')
        """
    )

    latest_run = connection.execute(
        """
        SELECT *
        FROM ingestion_runs
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()

    return {
        "total_process_events": total_process_events,
        "total_alerts": total_alerts,
        "medium_plus_alerts": medium_plus_alerts,
        "high_plus_alerts": high_plus_alerts,
        "latest_run": latest_run
    }


def get_severity_summary(connection):
    """Return alert counts grouped by severity."""
    rows = connection.execute(
        """
        SELECT severity, COUNT(*) AS count
        FROM alerts
        GROUP BY severity
        """
    ).fetchall()

    summary = {
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0
    }

    for row in rows:
        summary[row["severity"]] = row["count"]

    return summary


def get_rule_summary(connection):
    """Return alert counts grouped by rule."""
    return connection.execute(
        """
        SELECT rule, severity, COUNT(*) AS count
        FROM alerts
        GROUP BY rule, severity
        ORDER BY count DESC, rule ASC
        """
    ).fetchall()


def get_latest_alerts(connection, limit=10):
    """Return latest alerts for the dashboard overview."""
    return connection.execute(
        """
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()


def get_latest_process_events(connection, limit=10):
    """Return latest process events for the dashboard overview."""
    return connection.execute(
        """
        SELECT *
        FROM process_events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()


@app.route("/")
def index():
    """Dashboard overview page."""
    if not database_exists():
        return render_template(
            "db_missing.html",
            db_path=str(DATABASE_FILE)
        )

    connection = get_db_connection()

    stats = get_dashboard_stats(connection)
    severity_summary = get_severity_summary(connection)
    rule_summary = get_rule_summary(connection)
    latest_alerts = get_latest_alerts(connection, limit=10)
    latest_process_events = get_latest_process_events(connection, limit=10)

    connection.close()

    severity_chart = {
        "labels": list(severity_summary.keys()),
        "counts": list(severity_summary.values())
    }

    rule_chart = {
        "labels": [row["rule"] for row in rule_summary],
        "counts": [row["count"] for row in rule_summary]
    }

    return render_template(
        "index.html",
        stats=stats,
        severity_summary=severity_summary,
        rule_summary=rule_summary,
        latest_alerts=latest_alerts,
        latest_process_events=latest_process_events,
        severity_chart=severity_chart,
        rule_chart=rule_chart
    )


@app.route("/alerts")
def alerts():
    """Alerts table with basic search and filters."""
    if not database_exists():
        return render_template(
            "db_missing.html",
            db_path=str(DATABASE_FILE)
        )

    severity = request.args.get("severity", "").strip().lower()
    rule = request.args.get("rule", "").strip()
    search = request.args.get("search", "").strip()

    try:
        limit = int(request.args.get("limit", "100"))
    except ValueError:
        limit = 100

    limit = max(1, min(limit, 500))

    where_clauses = []
    params = []

    if severity:
        where_clauses.append("severity = ?")
        params.append(severity)

    if rule:
        where_clauses.append("rule = ?")
        params.append(rule)

    if search:
        where_clauses.append(
            """
            (
                name LIKE ?
                OR command_line LIKE ?
                OR exe_path LIKE ?
                OR reason LIKE ?
            )
            """
        )
        search_value = f"%{search}%"
        params.extend([search_value, search_value, search_value, search_value])

    where_sql = ""

    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    sql = f"""
        SELECT *
        FROM alerts
        {where_sql}
        ORDER BY id DESC
        LIMIT ?
    """

    params.append(limit)

    connection = get_db_connection()

    alert_rows = connection.execute(sql, params).fetchall()

    rule_options = connection.execute(
        """
        SELECT DISTINCT rule
        FROM alerts
        ORDER BY rule ASC
        """
    ).fetchall()

    connection.close()

    filters = {
        "severity": severity,
        "rule": rule,
        "search": search,
        "limit": limit
    }

    return render_template(
        "alerts.html",
        alerts=alert_rows,
        rule_options=rule_options,
        filters=filters
    )


@app.route("/alerts/<int:alert_id>")
def alert_detail(alert_id):
    """Single alert detail page."""
    if not database_exists():
        return render_template(
            "db_missing.html",
            db_path=str(DATABASE_FILE)
        )

    connection = get_db_connection()

    alert = connection.execute(
        """
        SELECT *
        FROM alerts
        WHERE id = ?
        """,
        (alert_id,)
    ).fetchone()

    connection.close()

    if alert is None:
        abort(404)

    return render_template(
        "alert_detail.html",
        alert=alert
    )


@app.route("/processes")
def processes():
    """Process events table with basic search and filters."""
    if not database_exists():
        return render_template(
            "db_missing.html",
            db_path=str(DATABASE_FILE)
        )

    search = request.args.get("search", "").strip()
    uid = request.args.get("uid", "").strip()

    try:
        limit = int(request.args.get("limit", "100"))
    except ValueError:
        limit = 100

    limit = max(1, min(limit, 500))

    where_clauses = []
    params = []

    if uid:
        where_clauses.append("uid = ?")
        params.append(uid)

    if search:
        where_clauses.append(
            """
            (
                name LIKE ?
                OR command_line LIKE ?
                OR exe_path LIKE ?
            )
            """
        )
        search_value = f"%{search}%"
        params.extend([search_value, search_value, search_value])

    where_sql = ""

    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    sql = f"""
        SELECT *
        FROM process_events
        {where_sql}
        ORDER BY id DESC
        LIMIT ?
    """

    params.append(limit)

    connection = get_db_connection()
    process_rows = connection.execute(sql, params).fetchall()
    connection.close()

    filters = {
        "search": search,
        "uid": uid,
        "limit": limit
    }

    return render_template(
        "processes.html",
        processes=process_rows,
        filters=filters
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )