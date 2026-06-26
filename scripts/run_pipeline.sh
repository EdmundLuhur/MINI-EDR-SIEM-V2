#!/usr/bin/env bash

set -euo pipefail

echo "[1/4] Compiling C++ process collector..."
g++ -std=c++17 agent-cpp/src/main.cpp -o agent-cpp/process_collector

echo "[2/4] Creating output folders..."
mkdir -p agent-cpp/output
mkdir -p backend-python/output
mkdir -p backend-python/storage

echo "[3/4] Collecting process snapshot..."
./agent-cpp/process_collector > agent-cpp/output/process_snapshot.jsonl

echo "[4/4] Running SIEM-lite ingestion and detections..."
python3 backend-python/ingest_process_snapshot.py

echo
echo "Pipeline complete."
echo "Process snapshot: agent-cpp/output/process_snapshot.jsonl"
echo "Alerts JSONL:     backend-python/output/alerts.jsonl"
echo "SQLite database:  backend-python/storage/siem_lite.db"