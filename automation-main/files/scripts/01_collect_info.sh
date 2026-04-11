#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

timestamp="$(date '+%Y-%m-%d %H:%M:%S %z')"
hostname_short="$(hostname 2>/dev/null || true)"
hostname_fqdn="$(hostname -f 2>/dev/null || true)"
kernel="$(uname -r 2>/dev/null || true)"
arch="$(uname -m 2>/dev/null || true)"
os_pretty_name=""
uptime_human=""
primary_ip=""
python_path=""
python_version=""
current_user="$(id -un 2>/dev/null || true)"
current_uid="$(id -u 2>/dev/null || true)"

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  os_pretty_name="${PRETTY_NAME:-}"
fi

if command -v uptime >/dev/null 2>&1; then
  uptime_human="$(uptime -p 2>/dev/null || true)"
fi

if command -v hostname >/dev/null 2>&1; then
  primary_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
fi

if command -v python3 >/dev/null 2>&1; then
  python_path="$(command -v python3)"
  python_version="$(python3 --version 2>/dev/null || true)"
elif command -v python >/dev/null 2>&1; then
  python_path="$(command -v python)"
  python_version="$(python --version 2>/dev/null || true)"
fi

echo "===== COLLECT_INFO_BEGIN ====="
echo "timestamp=${timestamp}"
echo "hostname_short=${hostname_short}"
echo "hostname_fqdn=${hostname_fqdn}"
echo "os_pretty_name=${os_pretty_name}"
echo "kernel=${kernel}"
echo "architecture=${arch}"
echo "uptime=${uptime_human}"
echo "primary_ip=${primary_ip}"
echo "current_user=${current_user}"
echo "current_uid=${current_uid}"
echo "python_path=${python_path}"
echo "python_version=${python_version}"

if command -v systemctl >/dev/null 2>&1; then
  echo "init_system=systemd"
else
  echo "init_system=non-systemd"
fi

if [[ -r /proc/meminfo ]]; then
  mem_total_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
  echo "mem_total_kb=${mem_total_kb}"
fi

if command -v df >/dev/null 2>&1; then
  root_usage="$(df -h / 2>/dev/null | awk 'NR==2 {print $5}')"
  echo "root_fs_usage=${root_usage}"
fi

echo "===== COLLECT_INFO_END ====="
