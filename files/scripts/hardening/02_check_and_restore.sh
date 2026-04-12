#!/usr/bin/env bash
set -euo pipefail
###############################################################################
# 02_check_and_restore.sh — Orchestrator for drift detection & restore (v4)
#
# Usage:  sudo ./02_check_and_restore.sh [--auto-restore]
#
# Environment: WHITELISTED_PORTS, ACCOUNT_ALLOWLIST, CRONTAB_ALLOWLIST,
#              SERVICE_ALLOWLIST, HARDENING_WEBHOOK_URL
#
# Compatibility: bash 3.2+ (macOS), bash 4.0+ (Linux/FreeBSD)
###############################################################################

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# shellcheck source=lib/common.sh
. "${SELF_DIR}/lib/common.sh"
detect_os
# shellcheck source=config.sh
source "${SELF_DIR}/config.sh"
load_os_adapter

# --- Parse arguments ---
MODE="check-only"
for arg in "$@"; do
    case "$arg" in
        --auto-restore) MODE="auto-restore" ;;
        --check-only)   MODE="check-only"   ;;
        *)              log_warn "Unknown argument: $arg" ;;
    esac
done

export MODE
export WHITELISTED_PORTS="${WHITELISTED_PORTS:-}"
export ACCOUNT_ALLOWLIST="${ACCOUNT_ALLOWLIST:-}"
export CRONTAB_ALLOWLIST="${CRONTAB_ALLOWLIST:-}"
export SERVICE_ALLOWLIST="${SERVICE_ALLOWLIST:-}"

###############################################################################
# Helper functions (orchestrator-level)
###############################################################################

# backup_before_restore <file> — snapshot a file before restoring it
backup_before_restore() {
    local src="${1:-}"
    [[ -z "$src" || ! -e "$src" ]] && return 0
    local restore_dir
    restore_dir="$(_backup_base_dir)/hardening_restore_${TIMESTAMP}"
    [[ -d "$restore_dir" ]] || mkdir -p "$restore_dir"
    local dest="${restore_dir}/$(echo "$src" | tr '/' '_')"
    if cp -pR "$src" "$dest" 2>/dev/null; then
        log_info "Pre-restore backup: $src -> $dest"
    else
        log_warn "Pre-restore backup failed for $src"
    fi
}
export -f backup_before_restore

# cleanup_old_backups — remove hardening_restore_* dirs older than 30 days
cleanup_old_backups() {
    log_info "Cleaning up old restore backups (>30 days)"
    local base_dir
    base_dir="$(_backup_base_dir)"
    [[ -d "$base_dir" ]] || return 0
    find "$base_dir" -maxdepth 1 -type d -name 'hardening_restore_*' -mtime +30 \
        -exec rm -rf {} + 2>/dev/null || true
    log_ok "Old restore backup cleanup complete"
}

# send_alert <message> — syslog + optional webhook
send_alert() {
    local message="${1:-}"
    [[ -z "$message" ]] && return 0
    if command -v logger >/dev/null 2>&1; then
        logger -t "hardening-check" "$message" 2>/dev/null || true
    fi
    if [[ -n "${HARDENING_WEBHOOK_URL:-}" ]] && command -v curl >/dev/null 2>&1; then
        local payload
        payload="{\"hostname\":\"${HOSTNAME_ORIG}\",\"timestamp\":\"${TIMESTAMP}\",\"message\":\"${message}\"}"
        curl -sS -m 10 -X POST -H "Content-Type: application/json" \
            -d "$payload" "$HARDENING_WEBHOOK_URL" >/dev/null 2>&1 || \
            log_warn "Webhook delivery failed"
    fi
}

# print_summary — final report of counters
print_summary() {
    echo ""
    log_info "============================================================"
    log_info "  Check & Restore Summary"
    log_info "  Mode: ${MODE}  Host: ${HOSTNAME_ORIG}  OS: ${OS_FAMILY}/${OS_ID} ${OS_VERSION}"
    log_info "  Drifts: ${DRIFT_COUNT}  Restores: ${RESTORE_COUNT}  Failures: ${FAIL_COUNT}"
    log_info "============================================================"
    if [[ "$DRIFT_COUNT" -eq 0 && "$FAIL_COUNT" -eq 0 ]]; then
        log_ok "System is in compliance with baseline."
    elif [[ "$FAIL_COUNT" -gt 0 ]]; then
        log_error "Completed with ${FAIL_COUNT} failure(s) — review log."
    elif [[ "$MODE" == "auto-restore" ]]; then
        log_info "Drifts detected and restored: ${RESTORE_COUNT}"
    else
        log_warn "Drifts detected: ${DRIFT_COUNT} — re-run with --auto-restore to fix"
    fi
    echo ""
}

###############################################################################
# Main flow
###############################################################################
main() {
    log_info "============================================================"
    log_info "  Check & Restore v${HARDENING_VERSION} — START"
    log_info "  Host: ${HOSTNAME_ORIG}  OS: ${OS_FAMILY}/${OS_ID} ${OS_VERSION}"
    log_info "  Mode: ${MODE}  Timestamp: ${TIMESTAMP}"
    log_info "  Protected: ${PROTECTED_ACCOUNTS:-none}"
    log_info "============================================================"

    require_privileged
    create_backup_dir

    # Verify baseline snapshot exists
    if [[ ! -d "$BASELINE_SNAPSHOT_DIR" ]]; then
        log_error "Baseline snapshot not found: ${BASELINE_SNAPSHOT_DIR}"
        log_error "Run 01_baseline_hardening.sh first."
        exit 1
    fi

    # Verify integrity file if present
    local integrity_file="${BASELINE_SNAPSHOT_DIR}/INTEGRITY.sha256"
    if [[ -f "$integrity_file" ]]; then
        log_info "Verifying baseline integrity (INTEGRITY.sha256)"
        local verified=0
        if command -v sha256sum >/dev/null 2>&1; then
            (cd "$BASELINE_SNAPSHOT_DIR" && sha256sum -c INTEGRITY.sha256 >/dev/null 2>&1) && verified=1
        elif command -v shasum >/dev/null 2>&1; then
            (cd "$BASELINE_SNAPSHOT_DIR" && shasum -a 256 -c INTEGRITY.sha256 >/dev/null 2>&1) && verified=1
        else
            log_skip "No sha256sum/shasum available — skipping integrity check"
            verified=2
        fi
        if [[ "$verified" -eq 1 ]]; then
            log_ok "Baseline integrity verified"
        elif [[ "$verified" -eq 0 ]]; then
            log_warn "Baseline integrity check failed — some files may have been modified"
        fi
    fi

    # Run checks (adapter function — reads global $MODE)
    log_info "--- Running drift checks (${OS_FAMILY}) ---"
    run_checks

    # auditd diff/restore (adapter function)
    if type check_auditd >/dev/null 2>&1; then
        log_info "--- Checking auditd configuration ---"
        check_auditd
    fi

    # Cleanup old backups
    cleanup_old_backups

    # Send alert
    send_alert "hardening-check: host=${HOSTNAME_ORIG} mode=${MODE} drifts=${DRIFT_COUNT} restores=${RESTORE_COUNT} failures=${FAIL_COUNT}"

    # Print summary
    print_summary
}

# --- Pipe through tee ---
LOGFILE="${LOG_DIR}/${TIMESTAMP}_${HOSTNAME_ORIG}_check_result.log"
export LOGFILE
main 2>&1 | tee -a "$LOGFILE"
exit "${PIPESTATUS[0]:-0}"
