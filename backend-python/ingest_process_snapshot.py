import json
import os
import re
import sqlite3
from datetime import datetime, timezone


# Input from the C++ agent
INPUT_FILE = "agent-cpp/output/process_snapshot.jsonl"

# JSONL output for latest generated alerts
ALERTS_OUTPUT_FILE = "backend-python/output/alerts.jsonl"

# SQLite database output
DATABASE_FILE = "backend-python/storage/siem_lite.db"


# Severity ranking used for filtering terminal output
SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4
}


# Command-line detection rules.
# This is your SIEM-style rule engine.
COMMAND_LINE_RULES = [
    {
        "rule": "REVERSE_SHELL_PATTERN",
        "severity": "high",
        "patterns": [
            ("bash -i", r"\bbash\s+-i\b"),
            ("/dev/tcp", r"/dev/tcp"),
            ("nc -e", r"(^|\s)nc\s+.*-e(\s|$)"),
            ("ncat -e", r"(^|\s)ncat\s+.*-e(\s|$)"),
            ("netcat -e", r"(^|\s)netcat\s+.*-e(\s|$)")
        ],
        "reason_template": "Command line matches reverse shell pattern: {pattern_name}"
    },
    {
        "rule": "SCRIPT_EXECUTION",
        "severity": "medium",
        "patterns": [
            ("python -c", r"\bpython\s+-c\b"),
            ("python3 -c", r"\bpython3\s+-c\b"),
            ("perl -e", r"\bperl\s+-e\b"),
            ("ruby -e", r"\bruby\s+-e\b")
        ],
        "reason_template": "Command line matches script execution pattern: {pattern_name}"
    },
    {
        "rule": "DOWNLOAD_TOOL_USAGE",
        "severity": "medium",
        "patterns": [
            ("curl", r"(^|\s)curl(\s|$)"),
            ("wget", r"(^|\s)wget(\s|$)")
        ],
        "reason_template": "Command line uses download tool: {pattern_name}"
    },
    {
        "rule": "MAKE_FILE_EXECUTABLE",
        "severity": "medium",
        "patterns": [
            ("chmod +x", r"\bchmod\s+\+x\b")
        ],
        "reason_template": "Command line makes a file executable: {pattern_name}"
    },
    {
        "rule": "NETCAT_USAGE",
        "severity": "medium",
        "patterns": [
            ("nc", r"(^|\s)nc(\s|$)"),
            ("ncat", r"(^|\s)ncat(\s|$)"),
            ("netcat", r"(^|\s)netcat(\s|$)")
        ],
        "reason_template": "Command line uses netcat-style tool: {pattern_name}"
    }
]


def utc_now():
    """Return the current UTC time as an ISO formatted string."""
    return datetime.now(timezone.utc).isoformat()


def load_process_events(file_path):
    """Load JSONL process events from the C++ agent output file."""
    events = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            try:
                event = json.loads(line)
                events.append(event)
            except json.JSONDecodeError:
                print(f"Warning: invalid JSON on line {line_number}")

    return events


def create_alert(rule, severity, event, reason, run_id):
    """
    Create one alert dictionary in a consistent format.

    This prevents each detection rule from needing to manually build
    a different alert structure.
    """
    return {
        "run_id": run_id,
        "rule": rule,
        "severity": severity,
        "pid": event.get("pid"),
        "ppid": event.get("ppid"),
        "uid": event.get("uid"),
        "name": event.get("name"),
        "command_line": event.get("command_line"),
        "exe_path": event.get("exe_path"),
        "reason": reason,
        "detected_at": utc_now()
    }


def detect_root_processes(events, run_id):
    """
    Detect processes running as root/UID 0.

    This stays info severity because many normal Linux processes run as root.
    It is useful visibility, but not automatically dangerous.
    """
    alerts = []

    for event in events:
        if event.get("uid") == 0:
            alert = create_alert(
                rule="ROOT_PROCESS",
                severity="info",
                event=event,
                reason="Process is running as UID 0/root",
                run_id=run_id
            )

            alerts.append(alert)

    return alerts


def detect_command_line_rules(events, run_id):
    """
    Run command-line detection rules against process events.

    This is the generic rule engine:
    process events -> rule list -> regex patterns -> alerts
    """
    alerts = []

    for event in events:
        command_line = event.get("command_line", "")

        # Skip empty or unavailable command lines
        if not command_line or command_line == "unavailable":
            continue

        command_line_lower = command_line.lower()

        for rule in COMMAND_LINE_RULES:
            for pattern_name, pattern_regex in rule["patterns"]:
                if re.search(pattern_regex, command_line_lower):
                    reason = rule["reason_template"].format(
                        pattern_name=pattern_name
                    )

                    alert = create_alert(
                        rule=rule["rule"],
                        severity=rule["severity"],
                        event=event,
                        reason=reason,
                        run_id=run_id
                    )

                    alerts.append(alert)

                    # Stop after the first matching pattern inside this rule.
                    # Example: one SCRIPT_EXECUTION alert is enough.
                    break

    return alerts


def detect_root_suspicious_commands(events, run_id):
    """
    Detect suspicious command lines running as root.

    Root processes are common on Linux.
    Suspicious command lines are sometimes legitimate.
    But root + suspicious command line together is much more important.
    """
    alerts = []

    for event in events:
        # Only check root-owned processes
        if event.get("uid") != 0:
            continue

        command_line = event.get("command_line", "")

        # Skip empty or unavailable command lines
        if not command_line or command_line == "unavailable":
            continue

        command_line_lower = command_line.lower()
        matched = False

        for rule in COMMAND_LINE_RULES:
            if matched:
                break

            for pattern_name, pattern_regex in rule["patterns"]:
                if re.search(pattern_regex, command_line_lower):
                    alert = create_alert(
                        rule="ROOT_SUSPICIOUS_COMMAND",
                        severity="high",
                        event=event,
                        reason=f"Root process matched suspicious pattern: {pattern_name}",
                        run_id=run_id
                    )

                    alerts.append(alert)

                    # One high-severity root suspicious alert per process is enough
                    matched = True
                    break

    return alerts


def run_detections(events, run_id):
    """Run all detection rules and return generated alerts."""
    alerts = []

    alerts.extend(detect_root_processes(events, run_id))
    alerts.extend(detect_command_line_rules(events, run_id))
    alerts.extend(detect_root_suspicious_commands(events, run_id))

    return alerts


def save_alerts_to_jsonl(alerts, output_path):
    """Save generated alerts to a JSON Lines file."""

    output_dir = os.path.dirname(output_path)

    # Create output folder if it does not exist
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    # Save one alert as one JSON object per line
    with open(output_path, "w", encoding="utf-8") as file:
        for alert in alerts:
            file.write(json.dumps(alert) + "\n")


def initialise_database(database_path):
    """Create the SQLite database and tables if they do not exist."""

    database_dir = os.path.dirname(database_path)

    if database_dir:
        os.makedirs(database_dir, exist_ok=True)

    connection = sqlite3.connect(database_path)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ingestion_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            source_file TEXT NOT NULL,
            process_event_count INTEGER NOT NULL,
            alert_count INTEGER NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS process_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            pid INTEGER,
            ppid INTEGER,
            uid INTEGER,
            name TEXT,
            command_line TEXT,
            exe_path TEXT,
            ingested_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            rule TEXT NOT NULL,
            severity TEXT NOT NULL,
            pid INTEGER,
            ppid INTEGER,
            uid INTEGER,
            name TEXT,
            command_line TEXT,
            exe_path TEXT,
            reason TEXT,
            detected_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_process_events_run_id
        ON process_events(run_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_run_id
        ON alerts(run_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_rule
        ON alerts(rule)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_severity
        ON alerts(severity)
    """)

    connection.commit()
    connection.close()


def save_ingestion_run_to_database(database_path, run_id, source_file, events, alerts):
    """Save one ingestion run summary to SQLite."""

    connection = sqlite3.connect(database_path)
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO ingestion_runs (
            run_id,
            source_file,
            process_event_count,
            alert_count,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            run_id,
            source_file,
            len(events),
            len(alerts),
            utc_now()
        )
    )

    connection.commit()
    connection.close()


def save_process_events_to_database(database_path, events, run_id):
    """Save process telemetry events to SQLite."""

    connection = sqlite3.connect(database_path)
    cursor = connection.cursor()

    for event in events:
        cursor.execute(
            """
            INSERT INTO process_events (
                run_id,
                pid,
                ppid,
                uid,
                name,
                command_line,
                exe_path,
                ingested_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                event.get("pid"),
                event.get("ppid"),
                event.get("uid"),
                event.get("name"),
                event.get("command_line"),
                event.get("exe_path"),
                utc_now()
            )
        )

    connection.commit()
    connection.close()


def save_alerts_to_database(database_path, alerts):
    """Save generated alerts to SQLite."""

    connection = sqlite3.connect(database_path)
    cursor = connection.cursor()

    for alert in alerts:
        cursor.execute(
            """
            INSERT INTO alerts (
                run_id,
                rule,
                severity,
                pid,
                ppid,
                uid,
                name,
                command_line,
                exe_path,
                reason,
                detected_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.get("run_id"),
                alert.get("rule"),
                alert.get("severity"),
                alert.get("pid"),
                alert.get("ppid"),
                alert.get("uid"),
                alert.get("name"),
                alert.get("command_line"),
                alert.get("exe_path"),
                alert.get("reason"),
                alert.get("detected_at")
            )
        )

    connection.commit()
    connection.close()


def print_alerts(alerts, min_severity="medium"):
    """Print only alerts at or above the chosen severity."""
    min_rank = SEVERITY_RANK.get(min_severity, 0)

    visible_alerts = [
        alert for alert in alerts
        if SEVERITY_RANK.get(alert.get("severity", "info"), 0) >= min_rank
    ]

    print(f"Showing {len(visible_alerts)} alerts with severity >= {min_severity}")

    for alert in visible_alerts[:20]:
        print("----------------------------------------")
        print(f"Rule: {alert.get('rule')}")
        print(f"Severity: {alert.get('severity')}")
        print(f"PID: {alert.get('pid')}")
        print(f"PPID: {alert.get('ppid')}")
        print(f"UID: {alert.get('uid')}")
        print(f"Name: {alert.get('name')}")
        print(f"Command Line: {alert.get('command_line')}")
        print(f"Executable Path: {alert.get('exe_path')}")
        print(f"Reason: {alert.get('reason')}")
        print(f"Detected At: {alert.get('detected_at')}")


def main():
    # A unique ID for this backend run.
    # This lets the database group process events and alerts from the same snapshot.
    run_id = utc_now()

    # 1. Load process telemetry from the C++ agent
    events = load_process_events(INPUT_FILE)

    # 2. Run all detection rules
    alerts = run_detections(events, run_id)

    # 3. Save latest alerts to JSONL
    save_alerts_to_jsonl(alerts, ALERTS_OUTPUT_FILE)

    # 4. Save events and alerts to SQLite
    initialise_database(DATABASE_FILE)
    save_ingestion_run_to_database(DATABASE_FILE, run_id, INPUT_FILE, events, alerts)
    save_process_events_to_database(DATABASE_FILE, events, run_id)
    save_alerts_to_database(DATABASE_FILE, alerts)

    # 5. Print summary
    print(f"Loaded {len(events)} process events")
    print(f"Generated {len(alerts)} alerts")
    print(f"Saved alerts JSONL to {ALERTS_OUTPUT_FILE}")
    print(f"Saved SQLite database to {DATABASE_FILE}")

    # 6. Print only medium or higher alerts to terminal
    print_alerts(alerts, min_severity="medium")


if __name__ == "__main__":
    main()