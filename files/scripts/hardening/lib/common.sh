#!/usr/bin/env bash
# lib/common.sh — Shared library for multi-OS hardening framework
# Sourced by all orchestrator and adapter scripts.
#
# Provides: OS detection, logging, counters, privilege checks,
#           backup utilities, adapter loading, global constants.
#
# Compatibility: bash 3.2+ (macOS), bash 4.0+ (Linux/FreeBSD), zsh 5.0+

###############################################################################
# Guard against double-sourcing
###############################################################################
[[ -n "${_COMMON_SH_LOADED:-}" ]] && return 0
_COMMON_SH_LOADED=1

###############################################################################
# Global constants
###############################################################################
readonly HARDENING_VERSION="4.0.0"

# SCRIPT_DIR: directory of the *calling* script (the one that sourced us).
# Falls back to pwd if BASH_SOURCE is unavailable (zsh compat).
if [[ -n "${BASH_SOURCE[1]:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
elif [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
else
    SCRIPT_DIR="$(pwd)"
fi
readonly SCRIPT_DIR

readonly LIB_DIR="${SCRIPT_DIR}/lib"
readonly SCRIPT_NAME="$(basename "$0")"
readonly HOSTNAME_ORIG="$(hostname)"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

###############################################################################
# Log directory and LOGFILE
###############################################################################
_LOG_DIR="/var/log/hardening"
if mkdir -p "$_LOG_DIR" 2>/dev/null && [[ -w "$_LOG_DIR" ]]; then
    readonly LOG_DIR="$_LOG_DIR"
else
    readonly LOG_DIR="/tmp"
fi
unset _LOG_DIR

# LOGFILE is set by the calling script (it appends its own suffix).
# We export LOG_DIR so callers can build their own LOGFILE path.

###############################################################################
# Logging functions
#
# All emit:  [YYYY-MM-DD HH:MM:SS] [LEVEL]   message
# Counters are incremented by drift/restore/fail variants.
###############################################################################
DRIFT_COUNT=0
RESTORE_COUNT=0
FAIL_COUNT=0

log_info()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]    $*"; }
log_ok()      { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [OK]      $*"; }
log_skip()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SKIP]    $*"; }
log_warn()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]    $*"; }
log_error()   { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR]   $*" >&2; }
log_drift()   { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [DRIFT]   $*"; DRIFT_COUNT=$((DRIFT_COUNT + 1)); }
log_restore() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [RESTORE] $*"; RESTORE_COUNT=$((RESTORE_COUNT + 1)); }
log_fail()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [FAIL]    $*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

###############################################################################
# OS Detection
#
# Sets:
#   OS_FAMILY  — debian | rhel | freebsd | macos
#   OS_ID      — ubuntu, debian, rocky, almalinux, rhel, centos, freebsd, macos
#   OS_VERSION — e.g. "22.04", "9.3", "14.0", "15.4"
###############################################################################
detect_os() {
    OS_FAMILY=""
    OS_ID=""
    OS_VERSION=""

    case "$(uname -s)" in
        Darwin)
            OS_FAMILY="macos"
            OS_ID="macos"
            # sw_vers -productVersion returns e.g. "15.4"
            OS_VERSION="$(sw_vers -productVersion 2>/dev/null || echo "unknown")"
            ;;
        FreeBSD)
            OS_FAMILY="freebsd"
            OS_ID="freebsd"
            # freebsd-version returns e.g. "14.0-RELEASE"; strip suffix
            OS_VERSION="$(freebsd-version -u 2>/dev/null | sed 's/-.*//' || echo "unknown")"
            ;;
        Linux)
            if [[ -f /etc/os-release ]]; then
                # shellcheck disable=SC1091
                . /etc/os-release
                OS_ID="${ID:-unknown}"
                OS_VERSION="${VERSION_ID:-unknown}"
            elif [[ -f /etc/redhat-release ]]; then
                OS_ID="rhel"
                OS_VERSION="$(sed 's/.*release \([0-9.]*\).*/\1/' /etc/redhat-release)"
            else
                OS_ID="unknown"
                OS_VERSION="unknown"
            fi

            case "$OS_ID" in
                ubuntu|debian|linuxmint|pop|kali)
                    OS_FAMILY="debian"
                    ;;
                rhel|centos|rocky|almalinux|ol|fedora|amzn)
                    OS_FAMILY="rhel"
                    ;;
                *)
                    # Best-effort: check for apt vs yum/dnf
                    if command -v apt-get >/dev/null 2>&1; then
                        OS_FAMILY="debian"
                    elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
                        OS_FAMILY="rhel"
                    else
                        OS_FAMILY="unknown"
                    fi
                    ;;
            esac
            ;;
        *)
            OS_FAMILY="unknown"
            OS_ID="unknown"
            OS_VERSION="unknown"
            ;;
    esac

    readonly OS_FAMILY OS_ID OS_VERSION
    log_info "OS detected: family=${OS_FAMILY} id=${OS_ID} version=${OS_VERSION}"
}

###############################################################################
# Privilege checks
###############################################################################

# require_root — exit if not running as root (EUID 0)
require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        log_error "This script must be run as root. Usage: sudo $SCRIPT_NAME"
        exit 1
    fi
}

# require_privileged — like require_root, but on macOS also accepts
# members of the 'admin' group (who can use sudo).
require_privileged() {
    local euid="${EUID:-$(id -u)}"
    if [[ "$euid" -eq 0 ]]; then
        return 0
    fi

    if [[ "${OS_FAMILY:-}" == "macos" ]]; then
        if id -Gn 2>/dev/null | tr ' ' '\n' | grep -qx 'admin'; then
            log_warn "Running as admin-group member (not root). Some operations may require sudo."
            return 0
        fi
    fi

    log_error "This script requires root privileges. Usage: sudo $SCRIPT_NAME"
    exit 1
}

###############################################################################
# Backup utilities
#
# BACKUP_DIR          — per-run backup (timestamped)
# BASELINE_SNAPSHOT_DIR — persistent baseline for drift detection
#
# macOS uses /Library/Caches/hardening instead of /var/backups/hardening
###############################################################################
_backup_base_dir() {
    case "${OS_FAMILY:-}" in
        macos) echo "/Library/Caches/hardening" ;;
        *)     echo "/var/backups/hardening"     ;;
    esac
}

BACKUP_DIR=""
BASELINE_SNAPSHOT_DIR=""

# create_backup_dir — initialize BACKUP_DIR and BASELINE_SNAPSHOT_DIR.
# Called once at the start of each orchestrator.
create_backup_dir() {
    local base
    base="$(_backup_base_dir)"

    BACKUP_DIR="${base}/backup_${TIMESTAMP}"
    BASELINE_SNAPSHOT_DIR="${base}/baseline"

    if [[ ! -d "$BACKUP_DIR" ]]; then
        mkdir -p "$BACKUP_DIR"
        log_info "Backup directory created: $BACKUP_DIR"
    fi
    if [[ ! -d "$BASELINE_SNAPSHOT_DIR" ]]; then
        mkdir -p "$BASELINE_SNAPSHOT_DIR"
        log_info "Baseline snapshot directory created: $BASELINE_SNAPSHOT_DIR"
    fi
}

# backup_file <path> — copy a file into BACKUP_DIR before modifying it.
# Uses cp -pR for BSD compatibility (no -a on some BSDs).
backup_file() {
    local src="$1"
    [[ -e "$src" ]] || return 0

    if [[ -z "$BACKUP_DIR" ]]; then
        log_warn "backup_file called before create_backup_dir; creating now"
        create_backup_dir
    fi

    local dest="${BACKUP_DIR}/$(echo "$src" | tr '/' '_')"

    # cp -a is GNU-only; cp -pR works on BSD and GNU
    if cp -pR "$src" "$dest" 2>/dev/null; then
        log_info "Backup: $src -> $dest"
    else
        log_warn "Backup failed for $src"
    fi
}

###############################################################################
# OS adapter loading
#
# Sources lib/os_${OS_FAMILY}.sh which must define the adapter functions
# expected by the orchestrator scripts.
###############################################################################
load_os_adapter() {
    if [[ -z "${OS_FAMILY:-}" ]]; then
        log_error "load_os_adapter called before detect_os"
        exit 1
    fi

    if [[ "$OS_FAMILY" == "unknown" ]]; then
        log_error "Unsupported OS family: cannot load adapter"
        exit 1
    fi

    local adapter="${LIB_DIR}/os_${OS_FAMILY}.sh"
    if [[ ! -f "$adapter" ]]; then
        log_error "OS adapter not found: $adapter"
        exit 1
    fi

    log_info "Loading OS adapter: os_${OS_FAMILY}.sh"
    # shellcheck disable=SC1090
    . "$adapter"
}

###############################################################################
# Protected Account Check
###############################################################################

# is_protected_account <username>
#   Return 0 if the account is in PROTECTED_ACCOUNTS or ACCOUNT_ALLOWLIST.
#   Every account manipulation function in adapters must call this first.
is_protected_account() {
    local account="${1:-}"
    [[ -z "$account" ]] && return 1

    # Check PROTECTED_ACCOUNTS (공통 보호 — config.sh 기본값 또는 환경변수)
    local _acct
    for _acct in ${PROTECTED_ACCOUNTS:-}; do
        if [[ "$account" == "$_acct" ]]; then
            log_warn "[GUARD] ${account} — protected account, skipping"
            return 0
        fi
    done

    # Check ACCOUNT_ALLOWLIST (서버별 보호 — 아티팩트에서 전달)
    for _acct in ${ACCOUNT_ALLOWLIST:-}; do
        if [[ "$account" == "$_acct" ]]; then
            log_warn "[GUARD] ${account} — allowlisted account, skipping"
            return 0
        fi
    done

    return 1
}
