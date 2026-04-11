#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

timestamp="$(date '+%Y-%m-%d %H:%M:%S %z')"

load_1=""
load_5=""
load_15=""
cpu_count=""
mem_total_kb=""
mem_available_kb=""
mem_usage_percent=""
disk_root_usage=""
zombie_processes="0"

# Load average
if [[ -r /proc/loadavg ]]; then
  read -r load_1 load_5 load_15 _ < /proc/loadavg
fi

# CPU count
if command -v nproc >/dev/null 2>&1; then
  cpu_count="$(nproc)"
elif [[ -r /proc/cpuinfo ]]; then
  cpu_count="$(grep -c '^processor' /proc/cpuinfo)"
fi

# Memory
if [[ -r /proc/meminfo ]]; then
  mem_total_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
  mem_available_kb="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"

  if [[ -n "${mem_total_kb}" && -n "${mem_available_kb}" ]]; then
    mem_used_kb=$((mem_total_kb - mem_available_kb))
    mem_usage_percent=$((mem_used_kb * 100 / mem_total_kb))
  fi
fi

# Disk usage (root)
if command -v df >/dev/null 2>&1; then
  disk_root_usage="$(df -h / 2>/dev/null | awk 'NR==2 {print $5}')"
fi

# Zombie process count
if command -v ps >/dev/null 2>&1; then
  zombie_processes="$(ps -eo stat= 2>/dev/null | grep -c Z || true)"
fi

echo "===== HEALTH_CHECK_BEGIN ====="
echo "timestamp=${timestamp}"
echo "load_1=${load_1}"
echo "load_5=${load_5}"
echo "load_15=${load_15}"
echo "cpu_count=${cpu_count}"
echo "mem_total_kb=${mem_total_kb}"
echo "mem_available_kb=${mem_available_kb}"
echo "mem_usage_percent=${mem_usage_percent}"
echo "disk_root_usage=${disk_root_usage}"
echo "zombie_processes=${zombie_processes}"

# Simple health flags
if [[ -n "${mem_usage_percent}" && "${mem_usage_percent}" -gt 90 ]]; then
  echo "alert_memory=HIGH"
else
  echo "alert_memory=OK"
fi

if [[ -n "${load_1}" && -n "${cpu_count}" ]]; then
  load_int="${load_1%.*}"
  if [[ "${load_int}" -gt "${cpu_count}" ]]; then
    echo "alert_load=HIGH"
  else
    echo "alert_load=OK"
  fi
fi

echo "===== HEALTH_CHECK_END ====="