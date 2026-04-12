#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# 01_baseline_hardening.sh — Orchestrator for initial system hardening (v4)
#
# Thin wrapper that sources the common library, detects the OS, loads the
# appropriate adapter, and delegates all real work to adapter functions.
#
# Usage:
#   sudo ./01_baseline_hardening.sh [--check] [--profile=<name>]
#
# Options:
#   --check          Run tunnel status check only (adapter check_tunnel_status)
#   --profile=X      Set UFW_PROFILE env var (default: "base")
#
# Compatibility: bash 3.2+ (macOS), bash 4.0+ (Linux/FreeBSD)
###############################################################################

# Resolve the directory this script lives in
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# ---------------------------------------------------------------------------
# 1. Source common library
# ---------------------------------------------------------------------------
# shellcheck source=lib/common.sh
. "${SELF_DIR}/lib/common.sh"

# ---------------------------------------------------------------------------
# 2. Detect OS
# ---------------------------------------------------------------------------
detect_os

# ---------------------------------------------------------------------------
# 2a. Source config
# ---------------------------------------------------------------------------
# shellcheck source=config.sh
source "${SELF_DIR}/config.sh"

# ---------------------------------------------------------------------------
# 3. Load OS adapter
# ---------------------------------------------------------------------------
load_os_adapter

# ---------------------------------------------------------------------------
# 4. Parse command-line arguments
# ---------------------------------------------------------------------------
CHECK_ONLY=0
UFW_PROFILE="${UFW_PROFILE:-base}"
export UFW_PROFILE

for arg in "$@"; do
    case "$arg" in
        --check)
            CHECK_ONLY=1
            ;;
        --profile=*)
            UFW_PROFILE="${arg#--profile=}"
            export UFW_PROFILE
            ;;
        *)
            log_warn "Unknown argument: $arg"
            ;;
    esac
done

# If --check mode, run tunnel status check and exit
if [[ "$CHECK_ONLY" -eq 1 ]]; then
    if type check_tunnel_status >/dev/null 2>&1; then
        check_tunnel_status
    else
        log_warn "check_tunnel_status not implemented for OS_FAMILY=${OS_FAMILY}"
    fi
    exit 0
fi

# ---------------------------------------------------------------------------
# 5. auditd snapshot function (inline — no safety_guards.sh dependency)
# ---------------------------------------------------------------------------
snapshot_auditd() {
    log_info "Snapshotting auditd configuration (read-only)"

    if [[ -z "${BASELINE_SNAPSHOT_DIR:-}" ]]; then
        log_warn "BASELINE_SNAPSHOT_DIR is not set — skipping auditd snapshot"
        return 0
    fi

    local snap_dir="${BASELINE_SNAPSHOT_DIR}/auditd"
    mkdir -p "$snap_dir" 2>/dev/null || true

    # auditd.conf
    local auditd_conf=""
    if [[ -f /etc/audit/auditd.conf ]]; then
        auditd_conf="/etc/audit/auditd.conf"
    elif [[ -f /etc/auditd.conf ]]; then
        auditd_conf="/etc/auditd.conf"
    fi

    if [[ -n "$auditd_conf" ]]; then
        cp -pR "$auditd_conf" "${snap_dir}/auditd.conf" 2>/dev/null && \
            log_ok "Snapshotted ${auditd_conf}" || \
            log_warn "Failed to snapshot ${auditd_conf}"
    else
        log_skip "No auditd.conf found — nothing to snapshot"
    fi

    # Current loaded rules
    if command -v auditctl >/dev/null 2>&1; then
        auditctl -l > "${snap_dir}/audit_rules_loaded.txt" 2>/dev/null && \
            log_ok "Snapshotted loaded audit rules (auditctl -l)" || \
            log_warn "Failed to snapshot loaded audit rules"
    else
        log_skip "auditctl not available — skipping rules snapshot"
    fi

    # rules.d directory
    if [[ -d /etc/audit/rules.d ]]; then
        mkdir -p "${snap_dir}/rules.d" 2>/dev/null || true
        cp -pR /etc/audit/rules.d/* "${snap_dir}/rules.d/" 2>/dev/null && \
            log_ok "Snapshotted /etc/audit/rules.d/" || \
            log_warn "Failed to snapshot /etc/audit/rules.d/ (may be empty)"
    else
        log_skip "No /etc/audit/rules.d directory — skipping"
    fi

    log_info "auditd snapshot complete at ${snap_dir}"
}

# ---------------------------------------------------------------------------
# 6. Main flow (piped through tee)
# ---------------------------------------------------------------------------
main() {
    # a. Log start banner
    log_info "============================================================"
    log_info "  Baseline Hardening v${HARDENING_VERSION} — START"
    log_info "  Hostname : ${HOSTNAME_ORIG}"
    log_info "  OS       : ${OS_FAMILY} / ${OS_ID} ${OS_VERSION}"
    log_info "  Profile  : ${UFW_PROFILE}"
    log_info "  Timestamp: ${TIMESTAMP}"
    log_info "  Protected: ${PROTECTED_ACCOUNTS:-none}"
    log_info "============================================================"

    # b. Require privileged access
    require_privileged

    # c. Create backup directory
    create_backup_dir

    # d. auditd snapshot (read-only)
    snapshot_auditd

    # e. Run hardening (adapter function)
    log_info "--- Running OS hardening (${OS_FAMILY}) ---"
    run_hardening

    # f. Create baseline snapshot (adapter function)
    log_info "--- Creating baseline snapshot ---"
    create_baseline_snapshot

    # g. Log completion banner
    log_info "============================================================"
    log_info "  Baseline Hardening v${HARDENING_VERSION} — COMPLETE"
    log_info "  Failures        : ${FAIL_COUNT}"
    log_info "============================================================"

    # h. Kill other SSH sessions (skip on macOS, skip if disabled)
    if [[ "$OS_FAMILY" != "macos" ]] && [[ "${KILL_OTHER_SESSIONS:-true}" == "true" ]]; then
        if type -t kill_other_ssh_sessions &>/dev/null; then
            log_info "--- Terminating other SSH sessions ---"
            kill_other_ssh_sessions
        fi
    else
        log_info "SSH session kill skipped (KILL_OTHER_SESSIONS=${KILL_OTHER_SESSIONS:-true})"
    fi
}

# ---------------------------------------------------------------------------
# 7. Set LOGFILE and pipe through tee
# ---------------------------------------------------------------------------
LOGFILE="${LOG_DIR}/${TIMESTAMP}_${HOSTNAME_ORIG}_baseline_hardening.log"
export LOGFILE

main 2>&1 | tee -a "$LOGFILE"

exit "${PIPESTATUS[0]:-0}"
