# Mini EDR + SIEM-Lite MVP Scope

## Goal

Build a Linux-focused mini EDR and SIEM-lite platform that collects process telemetry from an endpoint, stores events, applies detection rules and shows alerts for investigation.

## Version 1 Architecture

Linux endpoint → C++ agent → JSON telemetry → Python backend → SQLite database → YAML detection rules → CLI alerts

## Version 1 Telemetry

The C++ agent will collect basic process telemetry from a Linux endpoint:

- PID
- PPID
- process name
- command line
- UID
- executable path
- hostname
- timestamp

## Version 1 Backend

The Python backend will:

- receive telemetry events
- validate event data
- store events in SQLite
- load detection rules from YAML
- generate alerts when suspicious behaviour is detected

## Version 1 Detections

The first detection rules will focus on suspicious Linux command-line behaviour:

- access to `/etc/shadow`
- `curl` piped into `bash`
- reverse shell-looking commands
- cron modification
- new user creation

## Version 1 Interface

Version 1 will use a CLI interface first.

The CLI should allow an analyst to:

- list alerts
- filter alerts by severity
- search events by process name
- search alerts by MITRE technique
- investigate a specific alert

## Out of Scope for Version 1

The first version will not include:

- kernel drivers
- eBPF
- machine learning
- real malware execution
- cloud deployment
- advanced frontend dashboard

## Future Enhancements

Possible future upgrades:

- simple web dashboard
- file integrity monitoring
- network telemetry
- auditd or eBPF integration
- PostgreSQL database
- alert timeline view
- host isolation simulation
