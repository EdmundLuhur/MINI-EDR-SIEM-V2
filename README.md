CyberGuard: Mini EDR + SIEM-Lite Detection Platform
Overview
CyberGuard is a Linux-focused mini endpoint detection and SIEM-lite platform built to collect endpoint telemetry, apply detection rules, generate security alerts, and support basic investigation workflows.
The project uses a C++ endpoint agent, Bash automation scripts, and a Python backend to simulate how endpoint detection and log analysis platforms work at a simplified but practical level.
Project Goals
Rebuild practical programming skills in C++, Python and Bash.
Understand how endpoint telemetry is collected from Linux systems.
Build detection logic for suspicious process, file and command activity.
Map selected alerts to MITRE ATT&CK techniques.
Create a recruiter-ready cybersecurity engineering portfolio project.
Core Features
C++ Linux endpoint agent for collecting process and system telemetry.
Python backend for receiving, storing and analysing events.
YAML-based detection rules.
SQLite database for local event and alert storage.
Bash scripts for setup, testing and simulated suspicious behaviour.
SIEM-lite interface for viewing and filtering alerts.
Documentation, screenshots and demo evidence.
Technology Stack
Component
Technology
Endpoint Agent
C++
Backend
Python
Automation
Bash
Storage
SQLite
Rules
YAML
Interface
CLI first, dashboard optional
Platform
Linux VM

Architecture
Linux Host
   |
   | C++ Agent collects telemetry
   v
Python Backend API
   |
   | Stores raw events
   v
SQLite Database
   |
   | Detection engine applies YAML rules
   v
Alerts / SIEM-lite Interface

Example Detection Ideas
Access to sensitive files such as /etc/shadow.
Suspicious shell execution.
Reverse shell command patterns.
New user creation.
Suspicious cron modification.
Use of curl | bash.
Privilege escalation indicators.
MITRE ATT&CK Mapping
Selected alerts are mapped to MITRE ATT&CK techniques to make the detections easier to explain in a professional security context.
Example:
Detection
MITRE Technique
Severity
Access to /etc/shadow
Credential Access
High
Suspicious cron modification
Persistence
Medium
Reverse shell pattern
Command and Control
High

How to Run
# Start backend
cd server-python
python3 app.py

# Run agent
cd ../agent-cpp
./cyberguard-agent

# Generate test events
cd ../scripts
bash generate_test_events.sh

Demo Evidence
Screenshots and sample outputs are stored in the screenshots/ folder.
Limitations
This is a learning and portfolio project, not a production-ready EDR. It does not use kernel-level telemetry, eBPF, signed drivers, cloud-scale ingestion or advanced behavioural analytics.
Future Improvements
Add dashboard visualisation.
Add host-based timeline view.
Add log ingestion from /var/log/auth.log.
Add rule severity scoring.
Add Docker deployment.
Add support for multiple agents.

