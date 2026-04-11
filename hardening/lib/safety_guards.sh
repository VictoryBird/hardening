#!/usr/bin/env bash
# lib/safety_guards.sh — Safety guards for protected accounts, network,
# and green team agent.
#
# Sourced after lib/common.sh. Provides hard guards that ALL OS adapters
# must respect.  These prevent hardening from breaking critical training
# infrastructure (scoring agent, required accounts, network connectivity).
#
# Requires: log_*, OS_FAMILY, HOSTNAME_ORIG, BASELINE_SNAPSHOT_DIR,
#           backup_file  — all provided by lib/common.sh
#
# Compatibility: bash 3.2+ (macOS) — no associative arrays or bash 4+ features.

###############################################################################
# Guard against double-sourcing
###############################################################################
[[ -n "${_SAFETY_GUARDS_SH_LOADED:-}" ]] && return 0
_SAFETY_GUARDS_SH_LOADED=1

###############################################################################
# Constants
###############################################################################
readonly PROTECTED_ACCOUNT_GT="gt"
readonly PROTECTED_ACCOUNT_USR="usr"

# Ports that must remain open outbound (TCP)
readonly GUARD_REQUIRED_TCP_PORTS="22 80 443 8080 110 995 143 993 21"

###############################################################################
# Account Protection
###############################################################################

# is_protected_account <username>
#   Return 0 if the account is gt or usr (protected).
#   Every account manipulation function in adapters must call this first.
is_protected_account() {
    local account="${1:-}"
    [[ -z "$account" ]] && return 1

    # Hardcoded protected accounts (green team)
    case "$account" in
        "$PROTECTED_ACCOUNT_GT"|"$PROTECTED_ACCOUNT_USR")
            log_warn "[GUARD] ${account} — protected account, skipping"
            return 0
            ;;
    esac

    # Ansible/automation account
    if [[ -n "${ANSIBLE_ACCOUNT:-}" ]] && [[ "$account" == "$ANSIBLE_ACCOUNT" ]]; then
        log_warn "[GUARD] ${account} — automation account, skipping"
        return 0
    fi

    # Account allowlist from config.sh
    local _acct
    for _acct in ${ACCOUNT_ALLOWLIST:-}; do
        if [[ "$account" == "$_acct" ]]; then
            log_warn "[GUARD] ${account} — allowlisted account, skipping"
            return 0
        fi
    done

    return 1
}

# guard_account_gt
#   Verify gt account exists, is in the appropriate admin group with NOPASSWD.
#   Creates the sudoers drop-in if missing; validates with visudo -c.
guard_account_gt() {
    log_info "Guard: verifying protected account '${PROTECTED_ACCOUNT_GT}'"

    # --- Check account exists ---
    if ! id "$PROTECTED_ACCOUNT_GT" >/dev/null 2>&1; then
        log_fail "Protected account '${PROTECTED_ACCOUNT_GT}' does not exist — cannot continue safely"
        return 1
    fi
    log_ok "Account '${PROTECTED_ACCOUNT_GT}' exists"

    # --- Determine group and sudoers path per OS ---
    local required_group=""
    local sudoers_dir=""
    case "${OS_FAMILY}" in
        debian)
            required_group="sudo"
            sudoers_dir="/etc/sudoers.d"
            ;;
        rhel)
            required_group="wheel"
            sudoers_dir="/etc/sudoers.d"
            ;;
        freebsd)
            required_group="wheel"
            sudoers_dir="/usr/local/etc/sudoers.d"
            ;;
        macos)
            required_group="admin"
            sudoers_dir="/etc/sudoers.d"
            ;;
        *)
            log_warn "Unknown OS_FAMILY '${OS_FAMILY}' — skipping group/sudoers check for gt"
            return 1
            ;;
    esac

    # --- Verify group membership ---
    if id -Gn "$PROTECTED_ACCOUNT_GT" 2>/dev/null | tr ' ' '\n' | grep -qx "$required_group"; then
        log_ok "Account '${PROTECTED_ACCOUNT_GT}' is in group '${required_group}'"
    else
        log_drift "Account '${PROTECTED_ACCOUNT_GT}' is NOT in group '${required_group}' — restoring"
        if [[ "$OS_FAMILY" == "freebsd" ]]; then
            pw groupmod "$required_group" -m "$PROTECTED_ACCOUNT_GT" 2>/dev/null || true
        elif [[ "$OS_FAMILY" == "macos" ]]; then
            dseditgroup -o edit -a "$PROTECTED_ACCOUNT_GT" -t user "$required_group" 2>/dev/null || true
        else
            usermod -aG "$required_group" "$PROTECTED_ACCOUNT_GT" 2>/dev/null || true
        fi
        log_restore "Added '${PROTECTED_ACCOUNT_GT}' to group '${required_group}'"
    fi

    # --- Verify sudoers drop-in ---
    local sudoers_file="${sudoers_dir}/00-gt-nopasswd"
    local expected_content="gt ALL=(ALL) NOPASSWD: ALL"

    mkdir -p "$sudoers_dir" 2>/dev/null || true

    local needs_write=0
    if [[ ! -f "$sudoers_file" ]]; then
        needs_write=1
    else
        # Check content matches
        local current_content
        current_content="$(cat "$sudoers_file" 2>/dev/null)"
        if [[ "$current_content" != "$expected_content" ]]; then
            needs_write=1
        fi
    fi

    # Check permissions even if content is fine
    if [[ -f "$sudoers_file" ]]; then
        local current_perms
        if [[ "$OS_FAMILY" == "macos" || "$OS_FAMILY" == "freebsd" ]]; then
            current_perms="$(stat -f '%Lp' "$sudoers_file" 2>/dev/null)"
        else
            current_perms="$(stat -c '%a' "$sudoers_file" 2>/dev/null)"
        fi
        if [[ "$current_perms" != "440" ]]; then
            needs_write=1
        fi
    fi

    if [[ "$needs_write" -eq 1 ]]; then
        if [[ -f "$sudoers_file" ]]; then
            log_drift "Sudoers drop-in '${sudoers_file}' needs repair"
            backup_file "$sudoers_file"
        else
            log_drift "Sudoers drop-in '${sudoers_file}' missing — creating"
        fi

        printf '%s\n' "$expected_content" > "$sudoers_file"
        chmod 0440 "$sudoers_file"
        chown root:${required_group} "$sudoers_file" 2>/dev/null || \
            chown root:root "$sudoers_file" 2>/dev/null || true

        # Validate with visudo -c
        if visudo -c -f "$sudoers_file" >/dev/null 2>&1; then
            log_restore "Sudoers drop-in '${sudoers_file}' written and validated"
        else
            log_fail "visudo -c failed for '${sudoers_file}' — removing broken file"
            rm -f "$sudoers_file"
            return 1
        fi
    else
        log_ok "Sudoers drop-in '${sudoers_file}' is correct"
    fi

    return 0
}

# guard_account_usr
#   Verify usr account exists, log that it must not be deleted.
guard_account_usr() {
    log_info "Guard: verifying protected account '${PROTECTED_ACCOUNT_USR}'"

    if ! id "$PROTECTED_ACCOUNT_USR" >/dev/null 2>&1; then
        log_fail "Protected account '${PROTECTED_ACCOUNT_USR}' does not exist — it must not be deleted"
        return 1
    fi

    log_ok "Account '${PROTECTED_ACCOUNT_USR}' exists — this account must not be deleted"
    return 0
}

# change_usr_password <new_password>
#   The ONLY allowed way to change usr's password.
#   Prints the new password in a visible box to stdout.
change_usr_password() {
    local new_password="${1:-}"

    if [[ -z "$new_password" ]]; then
        log_error "change_usr_password: password argument is empty"
        return 1
    fi

    if ! id "$PROTECTED_ACCOUNT_USR" >/dev/null 2>&1; then
        log_error "change_usr_password: account '${PROTECTED_ACCOUNT_USR}' does not exist"
        return 1
    fi

    local rc=0
    case "${OS_FAMILY}" in
        debian|rhel)
            printf '%s:%s\n' "$PROTECTED_ACCOUNT_USR" "$new_password" | chpasswd || rc=$?
            ;;
        freebsd)
            echo "$new_password" | pw mod user "$PROTECTED_ACCOUNT_USR" -h 0 || rc=$?
            ;;
        macos)
            dscl . -passwd "/Users/${PROTECTED_ACCOUNT_USR}" "$new_password" || rc=$?
            ;;
        *)
            log_error "change_usr_password: unsupported OS_FAMILY '${OS_FAMILY}'"
            return 1
            ;;
    esac

    if [[ "$rc" -ne 0 ]]; then
        log_fail "Failed to change password for '${PROTECTED_ACCOUNT_USR}'"
        return 1
    fi

    # Print password in a visible box
    echo ""
    echo "##############################################################"
    echo "#                                                            #"
    echo "#  PASSWORD CHANGED for account: ${PROTECTED_ACCOUNT_USR}"
    echo "#  New password: ${new_password}"
    echo "#                                                            #"
    echo "##############################################################"
    echo ""

    log_ok "Password for '${PROTECTED_ACCOUNT_USR}' changed successfully"
    return 0
}

###############################################################################
# Network Protection
###############################################################################

# guard_network_outbound
#   Verify required outbound TCP ports are not blocked by the host firewall.
#   Also checks ICMP (ping).
#   Returns 1 if any required port is blocked.
guard_network_outbound() {
    log_info "Guard: verifying outbound network ports are not blocked"

    local blocked=0

    case "${OS_FAMILY}" in
        debian)
            _guard_network_ufw || blocked=1
            ;;
        rhel)
            _guard_network_firewalld || blocked=1
            ;;
        freebsd)
            _guard_network_pf_freebsd || blocked=1
            ;;
        macos)
            _guard_network_pf_macos || blocked=1
            ;;
        *)
            log_warn "guard_network_outbound: unknown OS_FAMILY '${OS_FAMILY}' — skipping"
            ;;
    esac

    if [[ "$blocked" -eq 1 ]]; then
        log_fail "One or more required outbound ports are blocked"
        return 1
    fi

    log_ok "All required outbound ports appear unblocked"
    return 0
}

# --- Internal: UFW (Debian) ---
_guard_network_ufw() {
    if ! command -v ufw >/dev/null 2>&1; then
        log_info "ufw not installed — assuming no outbound blocks"
        return 0
    fi

    local ufw_status
    ufw_status="$(ufw status 2>/dev/null)" || true

    # If ufw is inactive, no rules to block
    if echo "$ufw_status" | grep -qi "inactive"; then
        log_info "ufw is inactive — no outbound blocks"
        return 0
    fi

    local port blocked=0
    for port in $GUARD_REQUIRED_TCP_PORTS; do
        # Check for explicit deny/reject on outbound
        if ufw status verbose 2>/dev/null | grep -Ei "^${port}/tcp.*DENY OUT|REJECT OUT" >/dev/null 2>&1; then
            log_drift "UFW is blocking outbound TCP port ${port} — removing rule"
            ufw delete deny out "$port"/tcp 2>/dev/null || true
            ufw delete reject out "$port"/tcp 2>/dev/null || true
            log_restore "Removed UFW outbound block on TCP port ${port}"
        fi
    done

    # Check ICMP — look for ufw before.rules or after.rules blocking icmp
    if grep -q 'icmp.*DROP\|icmp.*REJECT' /etc/ufw/before.rules 2>/dev/null; then
        log_warn "Possible ICMP block in /etc/ufw/before.rules — review manually"
    fi

    return $blocked
}

# --- Internal: firewalld (RHEL) ---
_guard_network_firewalld() {
    if ! command -v firewall-cmd >/dev/null 2>&1; then
        log_info "firewalld not installed — assuming no outbound blocks"
        return 0
    fi

    if ! firewall-cmd --state >/dev/null 2>&1; then
        log_info "firewalld is not running — no outbound blocks"
        return 0
    fi

    # firewalld by default does not block outbound.
    # Check for direct rules that could block our ports.
    local port blocked=0
    local direct_rules
    direct_rules="$(firewall-cmd --direct --get-all-rules 2>/dev/null)" || true

    for port in $GUARD_REQUIRED_TCP_PORTS; do
        if echo "$direct_rules" | grep -E "DROP.*dport ${port}\b|REJECT.*dport ${port}\b" >/dev/null 2>&1; then
            log_drift "firewalld direct rule blocking outbound TCP port ${port}"
            # Attempt removal of common blocking patterns
            firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 0 -p tcp --dport "$port" -j DROP 2>/dev/null || true
            firewall-cmd --direct --remove-rule ipv4 filter OUTPUT 0 -p tcp --dport "$port" -j REJECT 2>/dev/null || true
            log_restore "Removed firewalld outbound block on TCP port ${port}"
        fi
    done

    # Check ICMP
    if echo "$direct_rules" | grep -E "icmp.*DROP|icmp.*REJECT" >/dev/null 2>&1; then
        log_warn "Possible ICMP block in firewalld direct rules — review manually"
    fi

    return $blocked
}

# --- Internal: pf (FreeBSD) ---
_guard_network_pf_freebsd() {
    if ! command -v pfctl >/dev/null 2>&1; then
        log_info "pf not available — assuming no outbound blocks"
        return 0
    fi

    # Check if pf is enabled
    if ! pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
        log_info "pf is not enabled — no outbound blocks"
        return 0
    fi

    local pf_rules blocked=0
    pf_rules="$(pfctl -s rules 2>/dev/null)" || true

    local port
    for port in $GUARD_REQUIRED_TCP_PORTS; do
        if echo "$pf_rules" | grep -E "block.*out.*proto tcp.*port ${port}\b" >/dev/null 2>&1; then
            log_drift "pf is blocking outbound TCP port ${port}"
            blocked=1
        fi
    done

    # Check ICMP block
    if echo "$pf_rules" | grep -E "block.*out.*proto icmp" >/dev/null 2>&1; then
        log_warn "pf may be blocking outbound ICMP"
    fi

    return $blocked
}

# --- Internal: pf (macOS) ---
_guard_network_pf_macos() {
    if ! command -v pfctl >/dev/null 2>&1; then
        log_info "pf not available — assuming no outbound blocks"
        return 0
    fi

    local pf_rules blocked=0
    pf_rules="$(pfctl -s rules 2>/dev/null)" || true

    local port
    for port in $GUARD_REQUIRED_TCP_PORTS; do
        if echo "$pf_rules" | grep -E "block.*out.*proto tcp.*port ${port}\b" >/dev/null 2>&1; then
            log_drift "pf is blocking outbound TCP port ${port}"
            blocked=1
        fi
    done

    return $blocked
}

# guard_dns_unchanged
#   Verify hostname has not changed from HOSTNAME_ORIG.  Auto-restore if changed.
guard_dns_unchanged() {
    log_info "Guard: verifying hostname unchanged"

    local current_hostname
    current_hostname="$(hostname)"

    if [[ "$current_hostname" == "$HOSTNAME_ORIG" ]]; then
        log_ok "Hostname unchanged: ${HOSTNAME_ORIG}"
        return 0
    fi

    log_drift "Hostname changed from '${HOSTNAME_ORIG}' to '${current_hostname}' — restoring"

    case "${OS_FAMILY}" in
        debian|rhel)
            hostnamectl set-hostname "$HOSTNAME_ORIG" 2>/dev/null || \
                hostname "$HOSTNAME_ORIG" 2>/dev/null || true
            # Also update /etc/hostname if it exists
            if [[ -f /etc/hostname ]]; then
                backup_file /etc/hostname
                printf '%s\n' "$HOSTNAME_ORIG" > /etc/hostname
            fi
            ;;
        freebsd)
            hostname "$HOSTNAME_ORIG" 2>/dev/null || true
            if [[ -f /etc/rc.conf ]]; then
                backup_file /etc/rc.conf
                sed -i '' "s/^hostname=.*/hostname=\"${HOSTNAME_ORIG}\"/" /etc/rc.conf 2>/dev/null || \
                    sed -i "s/^hostname=.*/hostname=\"${HOSTNAME_ORIG}\"/" /etc/rc.conf 2>/dev/null || true
            fi
            ;;
        macos)
            scutil --set HostName "$HOSTNAME_ORIG" 2>/dev/null || true
            scutil --set LocalHostName "$HOSTNAME_ORIG" 2>/dev/null || true
            scutil --set ComputerName "$HOSTNAME_ORIG" 2>/dev/null || true
            ;;
    esac

    log_restore "Hostname restored to '${HOSTNAME_ORIG}'"
    return 0
}

# guard_ipv6_preserved
#   Verify IPv6 is not disabled (Linux only).  Auto-restore if disabled.
guard_ipv6_preserved() {
    # Only relevant on Linux
    if [[ "$OS_FAMILY" != "debian" && "$OS_FAMILY" != "rhel" ]]; then
        log_skip "guard_ipv6_preserved: not applicable on ${OS_FAMILY}"
        return 0
    fi

    log_info "Guard: verifying IPv6 is not disabled"

    local ipv6_disabled
    ipv6_disabled="$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)" || true

    if [[ "$ipv6_disabled" == "1" ]]; then
        log_drift "IPv6 is disabled (net.ipv6.conf.all.disable_ipv6=1) — restoring"
        sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
        sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1 || true

        # Also fix sysctl.conf / sysctl.d if someone persisted the disable
        local f
        for f in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
            [[ -f "$f" ]] || continue
            if grep -q 'net.ipv6.conf.*disable_ipv6.*=.*1' "$f" 2>/dev/null; then
                backup_file "$f"
                sed -i.bak 's/net\.ipv6\.conf\.\(.*\)\.disable_ipv6.*=.*1/net.ipv6.conf.\1.disable_ipv6 = 0/' "$f" 2>/dev/null || \
                    sed -i '' 's/net\.ipv6\.conf\.\(.*\)\.disable_ipv6.*=.*1/net.ipv6.conf.\1.disable_ipv6 = 0/' "$f" 2>/dev/null || true
                rm -f "${f}.bak" 2>/dev/null || true
            fi
        done

        log_restore "IPv6 re-enabled (net.ipv6.conf.all.disable_ipv6=0)"
    else
        log_ok "IPv6 is enabled"
    fi

    return 0
}

###############################################################################
# Green Team Agent Protection
###############################################################################

# is_protected_service <service_name>
#   Return 0 if service is gtmon, fscd, or net.cr14.gtmon (protected).
is_protected_service() {
    local svc="${1:-}"
    case "$svc" in
        gtmon|gtmon.service|fscd|fscd.service|net.cr14.gtmon|net.cr14.gtmon.plist)
            return 0
            ;;
    esac
    return 1
}

# is_gtmon_required_port <port>
#   Return 0 if port is 80, 443, or 22 (gtmon needs outbound access on these).
is_gtmon_required_port() {
    local port="${1:-}"
    case "$port" in
        80|443|22)
            return 0
            ;;
    esac
    return 1
}

# guard_gtmon_agent
#   Verify gtmon binary, service, and autostart.  Restore if broken.
guard_gtmon_agent() {
    log_info "Guard: verifying green team monitoring agent (gtmon)"

    case "${OS_FAMILY}" in
        debian|rhel)
            _guard_gtmon_linux
            ;;
        freebsd)
            _guard_gtmon_freebsd
            ;;
        macos)
            _guard_gtmon_macos
            ;;
        *)
            log_warn "guard_gtmon_agent: unsupported OS_FAMILY '${OS_FAMILY}'"
            return 1
            ;;
    esac
}

# --- Internal: gtmon on Linux (systemd) ---
_guard_gtmon_linux() {
    # Find binary
    local gtmon_bin=""
    if [[ -f /opt/gtmon ]]; then
        gtmon_bin="/opt/gtmon"
    elif [[ -f /usr/bin/gtmon ]]; then
        gtmon_bin="/usr/bin/gtmon"
    fi

    if [[ -z "$gtmon_bin" ]]; then
        log_warn "gtmon binary not found at /opt/gtmon or /usr/bin/gtmon"
    else
        # Restore executable permissions if removed
        if [[ ! -x "$gtmon_bin" ]]; then
            log_drift "gtmon binary '${gtmon_bin}' is not executable — restoring"
            chmod +x "$gtmon_bin"
            log_restore "Restored execute permission on '${gtmon_bin}'"
        else
            log_ok "gtmon binary '${gtmon_bin}' is executable"
        fi
    fi

    # Check systemd service
    if ! command -v systemctl >/dev/null 2>&1; then
        log_warn "systemctl not available — cannot verify gtmon.service"
        return 0
    fi

    # Enable if disabled
    if ! systemctl is-enabled gtmon.service >/dev/null 2>&1; then
        log_drift "gtmon.service is not enabled — enabling"
        systemctl enable gtmon.service 2>/dev/null || true
        log_restore "Enabled gtmon.service"
    else
        log_ok "gtmon.service is enabled"
    fi

    # Start if stopped
    if ! systemctl is-active gtmon.service >/dev/null 2>&1; then
        log_drift "gtmon.service is not running — starting"
        systemctl start gtmon.service 2>/dev/null || true
        log_restore "Started gtmon.service"
    else
        log_ok "gtmon.service is running"
    fi
}

# --- Internal: gtmon on FreeBSD (rc + fscd) ---
_guard_gtmon_freebsd() {
    # Find binary
    local gtmon_bin=""
    if [[ -f /opt/gtmon ]]; then
        gtmon_bin="/opt/gtmon"
    elif [[ -f /usr/bin/gtmon ]]; then
        gtmon_bin="/usr/bin/gtmon"
    fi

    if [[ -z "$gtmon_bin" ]]; then
        log_warn "gtmon binary not found at /opt/gtmon or /usr/bin/gtmon"
    else
        if [[ ! -x "$gtmon_bin" ]]; then
            log_drift "gtmon binary '${gtmon_bin}' is not executable — restoring"
            chmod +x "$gtmon_bin"
            log_restore "Restored execute permission on '${gtmon_bin}'"
        else
            log_ok "gtmon binary '${gtmon_bin}' is executable"
        fi
    fi

    # Check rc service: gtmon
    if command -v service >/dev/null 2>&1; then
        # Enable in rc.conf if needed
        if ! grep -q '^gtmon_enable="YES"' /etc/rc.conf 2>/dev/null; then
            log_drift "gtmon not enabled in /etc/rc.conf — enabling"
            if [[ -f /etc/rc.conf ]]; then
                backup_file /etc/rc.conf
            fi
            sysrc gtmon_enable="YES" 2>/dev/null || \
                echo 'gtmon_enable="YES"' >> /etc/rc.conf
            log_restore "Enabled gtmon in rc.conf"
        else
            log_ok "gtmon is enabled in rc.conf"
        fi

        # Start if not running
        if ! service gtmon status >/dev/null 2>&1; then
            log_drift "gtmon service is not running — starting"
            service gtmon start 2>/dev/null || true
            log_restore "Started gtmon service"
        else
            log_ok "gtmon service is running"
        fi
    fi

    # Check fscd service helper
    if command -v service >/dev/null 2>&1; then
        if ! grep -q '^fscd_enable="YES"' /etc/rc.conf 2>/dev/null; then
            log_drift "fscd not enabled in /etc/rc.conf — enabling"
            if [[ -f /etc/rc.conf ]]; then
                backup_file /etc/rc.conf
            fi
            sysrc fscd_enable="YES" 2>/dev/null || \
                echo 'fscd_enable="YES"' >> /etc/rc.conf
            log_restore "Enabled fscd in rc.conf"
        else
            log_ok "fscd is enabled in rc.conf"
        fi

        if ! service fscd status >/dev/null 2>&1; then
            log_drift "fscd service is not running — starting"
            service fscd start 2>/dev/null || true
            log_restore "Started fscd service"
        else
            log_ok "fscd service is running"
        fi
    fi
}

# --- Internal: gtmon on macOS (launchd) ---
_guard_gtmon_macos() {
    local scoringbot="/Users/gt/scoringbot/scoringbot"
    local plist_label="net.cr14.gtmon"
    local plist_path="/Library/LaunchDaemons/${plist_label}.plist"

    # Check binary
    if [[ -f "$scoringbot" ]]; then
        if [[ ! -x "$scoringbot" ]]; then
            log_drift "scoringbot binary is not executable — restoring"
            chmod +x "$scoringbot"
            log_restore "Restored execute permission on '${scoringbot}'"
        else
            log_ok "scoringbot binary '${scoringbot}' is executable"
        fi
    else
        log_warn "scoringbot binary not found at '${scoringbot}'"
    fi

    # Check launchd plist exists
    if [[ ! -f "$plist_path" ]]; then
        log_warn "LaunchDaemon plist not found at '${plist_path}'"
        return 0
    fi

    # Check if loaded / running
    if ! launchctl list 2>/dev/null | grep -q "$plist_label"; then
        log_drift "LaunchDaemon '${plist_label}' is not loaded — loading"
        launchctl load -w "$plist_path" 2>/dev/null || true
        log_restore "Loaded LaunchDaemon '${plist_label}'"
    else
        log_ok "LaunchDaemon '${plist_label}' is loaded"
    fi
}

###############################################################################
# auditd Protection
###############################################################################

# guard_auditd_snapshot_only
#   Save current auditd config as a baseline snapshot WITHOUT modifying
#   anything.  Script 01 must only snapshot; script 02 does diff/restore.
guard_auditd_snapshot_only() {
    log_info "Guard: snapshotting auditd configuration (read-only)"

    if [[ -z "${BASELINE_SNAPSHOT_DIR:-}" ]]; then
        log_error "BASELINE_SNAPSHOT_DIR is not set — cannot snapshot auditd"
        return 1
    fi

    local snap_dir="${BASELINE_SNAPSHOT_DIR}/auditd"
    mkdir -p "$snap_dir" 2>/dev/null || true

    # --- auditd.conf ---
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

    # --- Current loaded rules (auditctl -l) ---
    if command -v auditctl >/dev/null 2>&1; then
        auditctl -l > "${snap_dir}/audit_rules_loaded.txt" 2>/dev/null && \
            log_ok "Snapshotted loaded audit rules (auditctl -l)" || \
            log_warn "Failed to snapshot loaded audit rules"
    else
        log_skip "auditctl not available — skipping rules snapshot"
    fi

    # --- rules.d directory ---
    local rules_d=""
    if [[ -d /etc/audit/rules.d ]]; then
        rules_d="/etc/audit/rules.d"
    fi

    if [[ -n "$rules_d" ]]; then
        mkdir -p "${snap_dir}/rules.d" 2>/dev/null || true
        cp -pR "${rules_d}/"* "${snap_dir}/rules.d/" 2>/dev/null && \
            log_ok "Snapshotted ${rules_d}/" || \
            log_warn "Failed to snapshot ${rules_d}/ (may be empty)"
    else
        log_skip "No /etc/audit/rules.d directory — skipping"
    fi

    log_info "auditd snapshot complete at ${snap_dir}"
    return 0
}

###############################################################################
# Orchestration
###############################################################################

# run_all_guards
#   Run all guards in sequence.  Returns 1 if any critical guard failed.
run_all_guards() {
    log_info "=== Running all safety guards ==="

    local failures=0

    guard_account_gt    || failures=$((failures + 1))
    guard_account_usr   || failures=$((failures + 1))
    guard_network_outbound || true   # non-fatal: log only
    guard_dns_unchanged || true       # auto-restores
    guard_ipv6_preserved || true      # auto-restores
    guard_gtmon_agent   || true       # best-effort
    guard_auditd_snapshot_only || true  # best-effort

    if [[ "$failures" -gt 0 ]]; then
        log_error "=== Safety guards completed with ${failures} critical failure(s) ==="
        return 1
    fi

    log_ok "=== All safety guards passed ==="
    return 0
}
