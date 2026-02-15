#!/bin/bash
# Запуск Entry на двух портах: TCP :8443 и QUIC :8444.
# Использование: из systemd или вручную из каталога репозитория.
# Переменные ENTRY_* (кроме ENTRY_TRANSPORT и ENTRY_ADDR для второго процесса) берутся из окружения.

set -e
cd "$(dirname "$0")/.."
ENTRY_ADDR="${ENTRY_ADDR:-:8443}"

PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait "${PIDS[@]}" 2>/dev/null || true
  exit 0
}
trap cleanup SIGTERM SIGINT

# TCP (по умолчанию :8443)
./astra-entry &
PIDS+=($!)

# QUIC на :8444 (тот же бинарник, другие ENTRY_*)
ENTRY_TRANSPORT=quic ENTRY_ADDR="${ENTRY_QUIC_ADDR:-:8444}" ./astra-entry &
PIDS+=($!)

wait
