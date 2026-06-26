import json
import re


def load_process_events(file_path):
    """Load JSONL process events from the C++ agent output file."""
    events = []

    with open(file_path, "r") as file:
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


def detect_root_processes(events):
    """Detect processes running as root/UID 0."""
    alerts = []

    for event in events:
        if event.get("uid") == 0:
            alert = {
                "rule": "ROOT_PROCESS",
                "severity": "info",
                "pid": event.get("pid"),
                "ppid": event.get("ppid"),
                "name": event.get("name"),
                "command_line": event.get("command_line"),
                "exe_path": event.get("exe_path"),
                "reason": "Process is running as UID 0/root"
            }

            alerts.append(alert)

    return alerts


def detect_suspicious_command_lines(events):
    """Detect suspicious command-line patterns often seen in attacks."""
    alerts = []

    suspicious_patterns = [
        ("bash -i", r"\bbash\s+-i\b"),
        ("/dev/tcp", r"/dev/tcp"),
        ("nc", r"(^|\s)nc(\s|$)"),
        ("ncat", r"(^|\s)ncat(\s|$)"),
        ("netcat", r"(^|\s)netcat(\s|$)"),
        ("python -c", r"\bpython\s+-c\b"),
        ("python3 -c", r"\bpython3\s+-c\b"),
        ("chmod +x", r"\bchmod\s+\+x\b"),
        ("curl", r"(^|\s)curl(\s|$)"),
        ("wget", r"(^|\s)wget(\s|$)")
    ]

    for event in events:
        command_line = event.get("command_line", "")
        command_line_lower = command_line.lower()

        for pattern_name, pattern_regex in suspicious_patterns:
            if re.search(pattern_regex, command_line_lower):
                alert = {
                    "rule": "SUSPICIOUS_COMMAND_LINE",
                    "severity": "medium",
                    "pid": event.get("pid"),
                    "ppid": event.get("ppid"),
                    "name": event.get("name"),
                    "command_line": command_line,
                    "exe_path": event.get("exe_path"),
                    "reason": f"Command line matches suspicious pattern: {pattern_name}"
                }

                alerts.append(alert)

    return alerts

def print_alerts(alerts, min_severity="medium"):
    """Print only alerts at or above the chosen severity."""
    severity_rank = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }

    min_rank = severity_rank.get(min_severity, 0)

    visible_alerts = [
        alert for alert in alerts
        if severity_rank.get(alert.get("severity", "info"), 0) >= min_rank
    ]

    print(f"Showing {len(visible_alerts)} alerts with severity >= {min_severity}")

    for alert in visible_alerts[:20]:
        print("----------------------------------------")
        print(f"Rule: {alert.get('rule')}")
        print(f"Severity: {alert.get('severity')}")
        print(f"PID: {alert.get('pid')}")
        print(f"PPID: {alert.get('ppid')}")
        print(f"Name: {alert.get('name')}")
        print(f"Command Line: {alert.get('command_line')}")
        print(f"Executable Path: {alert.get('exe_path')}")
        print(f"Reason: {alert.get('reason')}")

def main():
    file_path = "agent-cpp/output/process_snapshot.jsonl"

    # 1. Load process telemetry from the C++ agent
    events = load_process_events(file_path)
    print(f"Loaded {len(events)} process events")

    # 2. Run detection rules
    alerts = []
    alerts.extend(detect_root_processes(events))
    alerts.extend(detect_suspicious_command_lines(events))

    # 3. Print results
    print(f"Generated {len(alerts)} alerts")
    print_alerts(alerts)


if __name__ == "__main__":
    main()