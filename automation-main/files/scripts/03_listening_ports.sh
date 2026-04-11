#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

timestamp="$(date '+%Y-%m-%d %H:%M:%S %z')"

echo "===== LISTENING_PORTS_BEGIN ====="
echo "timestamp=${timestamp}"

# Prefer ss (modern), fallback to netstat
if command -v ss >/dev/null 2>&1; then
  echo "tool=ss"
  ss -tuln 2>/dev/null | tail -n +2 | while read -r line; do
    proto="$(echo "$line" | awk '{print $1}')"
    local_addr="$(echo "$line" | awk '{print $5}')"

    ip="$(echo "$local_addr" | sed -E 's/:(.*)$//')"
    port="$(echo "$local_addr" | sed -E 's/^.*://')"

    echo "proto=${proto} ip=${ip} port=${port}"
  done

elif command -v netstat >/dev/null 2>&1; then
  echo "tool=netstat"
  netstat -tuln 2>/dev/null | tail -n +3 | while read -r line; do
    proto="$(echo "$line" | awk '{print $1}')"
    local_addr="$(echo "$line" | awk '{print $4}')"

    ip="$(echo "$local_addr" | sed -E 's/:(.*)$//')"
    port="$(echo "$local_addr" | sed -E 's/^.*://')"

    echo "proto=${proto} ip=${ip} port=${port}"
  done

else
  echo "error=no_ss_or_netstat_available"
fi

echo "===== LISTENING_PORTS_END ====="