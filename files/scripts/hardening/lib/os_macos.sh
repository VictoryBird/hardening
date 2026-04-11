#!/usr/bin/env bash
# lib/os_macos.sh — macOS hardening adapter
#
# Implements the hardening functions called by the orchestrator scripts
# (01_baseline_hardening.sh and 02_check_and_restore.sh).
#
# Requires: lib/common.sh (log_*, OS_FAMILY, HOSTNAME_ORIG, BACKUP_DIR,
#           BASELINE_SNAPSHOT_DIR, backup_file, create_backup_dir)
#           lib/safety_guards.sh (is_protected_account, is_protected_service,
#           guard_account_gt, guard_network_outbound,
#           is_gtmon_required_port)
#
# Exports: run_hardening(), run_checks(), create_baseline_snapshot(),
#          kill_other_ssh_sessions(), check_auditd()
#
# Compatibility: bash 3.2+ (macOS ships with bash 3.2)
#   - NO associative arrays (bash 4+ only)
#   - NO declare -g
#   - NO ${var,,} lowercase syntax
#   - BSD sed uses -i ''
#   - BSD stat uses -f '%Lp'

###############################################################################
# Guard against double-sourcing
###############################################################################
# shellcheck disable=SC2154
[[ -n "${_OS_MACOS_SH_LOADED:-}" ]] && return 0
_OS_MACOS_SH_LOADED=1

###############################################################################
# Configuration Constants
###############################################################################

# --- SSH hardening settings (from config.sh, macOS overrides PermitRootLogin to "no") ---
MAC_SSH_PERMIT_ROOT_LOGIN="no"
MAC_SSH_PASSWORD_AUTH="${SSH_PASSWORD_AUTH}"
MAC_SSH_MAX_AUTH_TRIES="${SSH_MAX_AUTH_TRIES}"
MAC_SSH_CLIENT_ALIVE_INTERVAL="${SSH_CLIENT_ALIVE_INTERVAL}"
MAC_SSH_CLIENT_ALIVE_COUNT_MAX="${SSH_CLIENT_ALIVE_COUNT_MAX}"
MAC_SSH_LOGIN_GRACE_TIME="${SSH_LOGIN_GRACE_TIME}"

# --- Sensitive file permissions (octal, BSD stat -f '%Lp') ---
# Files that should be 644
readonly MAC_FILES_644="/etc/passwd /etc/group"

# Files that should be 600
readonly MAC_FILES_600="/etc/master.passwd /etc/sudoers"

# Files to remove other-rw
readonly MAC_FILES_O_NORW="/etc/ssh/sshd_config /etc/sysctl.conf /etc/pf.conf"

# --- sysctl settings (very limited on macOS) ---
# Using plain lists instead of associative arrays for bash 3.2 compat
readonly MAC_SYSCTL_KEYS="net.inet.ip.forwarding net.inet.ip.redirect net.inet6.ip6.forwarding"
readonly MAC_SYSCTL_VALS="0 0 0"

# --- Custom allowed ports (from config.sh) ---
MAC_CUSTOM_ALLOWED_PORTS="${CUSTOM_ALLOWED_PORTS}"

# --- Allowlists (from config.sh) ---
MAC_WHITELISTED_PORTS="${WHITELISTED_PORTS}"
MAC_ACCOUNT_ALLOWLIST="${ACCOUNT_ALLOWLIST}"

# --- Restore backup directory (for 02 script) ---
MAC_RESTORE_BACKUP_DIR=""

# --- Scoring bot constants ---
readonly MAC_GTMON_BINARY="/Users/gt/scoringbot/scoringbot"
readonly MAC_GTMON_PLIST="net.cr14.gtmon"

###############################################################################
# Package/Service Management Functions
###############################################################################

pkg_install() {
    log_warn "pkg_install: no package manager assumed on macOS — cannot install: $*"
    return 1
}

pkg_remove() {
    log_warn "pkg_remove: no package manager assumed on macOS — cannot remove: $*"
    return 1
}

pkg_is_installed() {
    # Always return false — no package manager assumed
    return 1
}

svc_enable() {
    local svc="$1"
    if is_protected_service "$svc"; then
        log_skip "svc_enable: refusing to modify protected service '$svc'"
        return 0
    fi
    local plist
    plist="$(_find_plist "$svc")"
    if [[ -n "$plist" ]]; then
        launchctl load -w "$plist" 2>/dev/null
    else
        log_warn "svc_enable: plist not found for '$svc'"
        return 1
    fi
}

svc_disable() {
    local svc="$1"
    if is_protected_service "$svc"; then
        log_skip "svc_disable: refusing to modify protected service '$svc'"
        return 0
    fi
    local plist
    plist="$(_find_plist "$svc")"
    if [[ -n "$plist" ]]; then
        launchctl unload -w "$plist" 2>/dev/null
    else
        log_warn "svc_disable: plist not found for '$svc'"
        return 1
    fi
}

svc_start() {
    local svc="$1"
    local plist
    plist="$(_find_plist "$svc")"
    if [[ -n "$plist" ]]; then
        launchctl load "$plist" 2>/dev/null
    else
        log_warn "svc_start: plist not found for '$svc'"
        return 1
    fi
}

svc_restart() {
    local svc="$1"
    local plist
    plist="$(_find_plist "$svc")"
    if [[ -n "$plist" ]]; then
        launchctl unload "$plist" 2>/dev/null || true
        launchctl load "$plist" 2>/dev/null
    else
        log_warn "svc_restart: plist not found for '$svc'"
        return 1
    fi
}

svc_is_active() {
    local svc="$1"
    launchctl list 2>/dev/null | grep -q "$svc"
}

svc_is_enabled() {
    # On macOS, enabled ~= loaded in launchd
    svc_is_active "$1"
}

###############################################################################
# Internal Helpers
###############################################################################

# _find_plist <service_label_or_name>
#   Search LaunchDaemons and LaunchAgents for a plist matching the service.
#   Returns the full path to the plist, or empty string if not found.
_find_plist() {
    local svc="$1"
    local search_dirs="/Library/LaunchDaemons /Library/LaunchAgents /System/Library/LaunchDaemons /System/Library/LaunchAgents"
    local dir plist_file

    for dir in $search_dirs; do
        [[ -d "$dir" ]] || continue

        # Try exact match: <svc>.plist
        plist_file="${dir}/${svc}.plist"
        if [[ -f "$plist_file" ]]; then
            echo "$plist_file"
            return 0
        fi

        # Try grep in the directory for label match
        for plist_file in "${dir}"/*.plist; do
            [[ -f "$plist_file" ]] || continue
            if grep -q "<string>${svc}</string>" "$plist_file" 2>/dev/null; then
                echo "$plist_file"
                return 0
            fi
        done
    done

    return 1
}

# _mac_backup_before_restore <path> — backup before restore (02 script)
_mac_backup_before_restore() {
    local target="$1"
    [[ -e "$target" ]] || return 0
    if [[ -z "$MAC_RESTORE_BACKUP_DIR" ]]; then
        MAC_RESTORE_BACKUP_DIR="/Library/Caches/hardening/hardening_restore_${TIMESTAMP}"
    fi
    if [[ ! -d "$MAC_RESTORE_BACKUP_DIR" ]]; then
        mkdir -p "$MAC_RESTORE_BACKUP_DIR"
    fi
    local dest="${MAC_RESTORE_BACKUP_DIR}/$(echo "$target" | tr '/' '_')"
    cp -pR "$target" "$dest" 2>/dev/null && \
        log_info "Pre-restore backup: $target -> $dest" || true
}

# _mac_sysctl_get_key <index> — get key from space-separated list
_mac_sysctl_get_key() {
    local idx="$1"
    local i=0
    local key
    for key in $MAC_SYSCTL_KEYS; do
        if [[ "$i" -eq "$idx" ]]; then
            echo "$key"
            return 0
        fi
        i=$((i + 1))
    done
    return 1
}

# _mac_sysctl_get_val <index> — get val from space-separated list
_mac_sysctl_get_val() {
    local idx="$1"
    local i=0
    local val
    for val in $MAC_SYSCTL_VALS; do
        if [[ "$i" -eq "$idx" ]]; then
            echo "$val"
            return 0
        fi
        i=$((i + 1))
    done
    return 1
}

# _mac_sysctl_count — count entries
_mac_sysctl_count() {
    local count=0
    local key
    for key in $MAC_SYSCTL_KEYS; do
        count=$((count + 1))
    done
    echo "$count"
}

# _mac_sed_set <file> <key> <value>
#   Set a key-value pair in a config file using BSD sed.
#   If key exists (commented or not), replace the line. Otherwise append.
_mac_sed_set() {
    local file="$1" key="$2" value="$3"
    if grep -qE "^[#[:space:]]*${key}[[:space:]]" "$file" 2>/dev/null; then
        sed -i '' "s|^[#[:space:]]*${key}[[:space:]].*|${key} ${value}|" "$file"
    else
        echo "${key} ${value}" >> "$file"
    fi
}

###############################################################################
# Hardening Setup Functions
###############################################################################

# [1] Firewall — pf + Application Firewall (socketfilterfw)
setup_firewall() {
    log_info "===== [1] macOS firewall (pf + Application Firewall) ====="

    # --- Application Firewall (socketfilterfw) ---
    if command -v /usr/libexec/ApplicationFirewall/socketfilterfw >/dev/null 2>&1; then
        local sfw="/usr/libexec/ApplicationFirewall/socketfilterfw"

        "$sfw" --setglobalstate on 2>/dev/null && \
            log_ok "Application Firewall: enabled" || \
            log_warn "Application Firewall: failed to enable"

        "$sfw" --setstealthmode on 2>/dev/null && \
            log_ok "Application Firewall: stealth mode enabled" || \
            log_warn "Application Firewall: stealth mode enable failed"

        "$sfw" --setallowsigned on 2>/dev/null && \
            log_ok "Application Firewall: allow signed apps enabled" || \
            log_warn "Application Firewall: allow signed apps setting failed"
    else
        log_warn "socketfilterfw not found — Application Firewall not available"
    fi

    # --- pf (packet filter) ---
    local pf_conf="/etc/pf.conf"
    local pf_anchor_marker="# HARDENING_PF_RULES_BEGIN"

    if [[ ! -f "$pf_conf" ]]; then
        log_warn "pf.conf not found at $pf_conf — skipping pf setup"
        return
    fi

    # Check if our rules are already present
    if grep -q "$pf_anchor_marker" "$pf_conf" 2>/dev/null; then
        log_skip "pf hardening rules already present in $pf_conf"
    else
        backup_file "$pf_conf"

        # -- Build allowed port rules --
        local pf_port_rules=""
        if [[ -n "${MAC_CUSTOM_ALLOWED_PORTS}" ]]; then
            # CUSTOM_ALLOWED_PORTS가 설정됨 — 해당 포트 사용
            local port_nums=""
            port_nums=$(echo "${MAC_CUSTOM_ALLOWED_PORTS}" | tr ' ' '\n' | sed 's|/tcp||; s|/udp||' | sort -un | tr '\n' ' ' | sed 's/ *$//')
            # SSH 포트(22) 포함 확인
            if ! echo " $port_nums " | grep -q " 22 "; then
                port_nums="22 ${port_nums}"
            fi
            local port_list
            port_list=$(echo "$port_nums" | tr ' ' ',')
            pf_port_rules="pass in quick proto tcp from any to any port { ${port_list} } flags S/SA keep state"
            log_info "pf: CUSTOM_ALLOWED_PORTS 사용 (ports: ${port_nums})"
        else
            # 폴백: SSH만 허용
            pf_port_rules="pass in quick proto tcp from any to any port 22 flags S/SA keep state"
        fi

        # -- Build outbound rules based on OUTBOUND_POLICY --
        local pf_outbound_rules=""
        if [[ "${OUTBOUND_POLICY}" == "restrict" ]]; then
            # Build outbound port list for pf macro
            local _out_ports=""
            for port_proto in ${OUTBOUND_ALLOWED_PORTS}; do
                local _port="${port_proto%%/*}"
                _out_ports="${_out_ports} ${_port}"
            done
            _out_ports=$(echo "$_out_ports" | xargs)  # trim

            pf_outbound_rules="# Outbound policy: restrict
allowed_tcp_out = \"{ $(echo "$_out_ports" | tr ' ' ', ') }\"
block out all
pass out quick on lo0 all
pass out quick proto tcp to port \$allowed_tcp_out keep state
pass out quick proto udp to port 53 keep state
pass out quick proto udp to port 123 keep state"
            if [[ "${OUTBOUND_ALLOW_ICMP}" == "true" ]]; then
                pf_outbound_rules="${pf_outbound_rules}
pass out quick proto icmp all keep state
pass out quick proto icmp6 all keep state"
            fi
            log_ok "pf outbound restrict policy prepared"
        else
            pf_outbound_rules="# Outbound policy: allow (unrestricted)
pass out quick all keep state"
            log_ok "pf outbound policy: allow (unrestricted)"
        fi

        # APPEND rules — do NOT overwrite Apple anchors
        cat >> "$pf_conf" <<PF_EOF

# HARDENING_PF_RULES_BEGIN
# Auto-generated hardening rules — do not edit manually

# Block all incoming by default, allow established and related
block in log all
pass in quick on lo0 all

# Outbound rules
${pf_outbound_rules}

# Allow inbound on specified ports
${pf_port_rules}

# Allow established connections
pass in quick proto tcp from any to any flags A/A keep state
pass in quick proto udp keep state

# HARDENING_PF_RULES_END
PF_EOF
        log_ok "pf hardening rules appended to $pf_conf"
    fi

    # Enable and reload pf
    pfctl -e 2>/dev/null || true
    if pfctl -f "$pf_conf" 2>/dev/null; then
        log_ok "pf rules loaded successfully"
    else
        log_warn "pf rules load failed — check $pf_conf syntax"
    fi

    # --- Safety: verify outbound ports are not blocked ---
    guard_network_outbound || log_warn "Outbound port check flagged issues after firewall setup"
}

# [2] macOS system hardening
setup_macos_system() {
    log_info "===== [2] macOS system hardening ====="

    # Disable auto-login
    defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null && \
        log_ok "Auto-login disabled" || \
        log_skip "Auto-login was not configured (or already disabled)"

    # Screen saver password
    defaults write com.apple.screensaver askForPassword -int 1 2>/dev/null && \
        log_ok "Screen saver password: enabled" || \
        log_warn "Screen saver password: failed to set"

    defaults write com.apple.screensaver askForPasswordDelay -int 0 2>/dev/null && \
        log_ok "Screen saver password delay: 0 (immediate)" || \
        log_warn "Screen saver password delay: failed to set"

    # Disable remote Apple Events
    systemsetup -setremoteappleevents off 2>/dev/null && \
        log_ok "Remote Apple Events: disabled" || \
        log_warn "Remote Apple Events: failed to disable"

    # Disable Guest account
    defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false 2>/dev/null && \
        log_ok "Guest account: disabled" || \
        log_warn "Guest account: failed to disable"

    # Disable Bluetooth sharing
    defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false 2>/dev/null && \
        log_ok "Bluetooth sharing: disabled" || \
        log_warn "Bluetooth sharing: failed to disable"

    # Disable AirDrop
    defaults write com.apple.NetworkBrowser DisableAirDrop -bool true 2>/dev/null && \
        log_ok "AirDrop: disabled" || \
        log_warn "AirDrop: failed to disable"

    # Enable Gatekeeper
    if command -v spctl >/dev/null 2>&1; then
        spctl --master-enable 2>/dev/null && \
            log_ok "Gatekeeper: enabled" || \
            log_warn "Gatekeeper: failed to enable"
    else
        log_warn "spctl not found — cannot enable Gatekeeper"
    fi

    # Check SIP status (warn if disabled, do NOT attempt to modify)
    if command -v csrutil >/dev/null 2>&1; then
        local sip_status
        sip_status="$(csrutil status 2>/dev/null)" || true
        if echo "$sip_status" | grep -qi "enabled"; then
            log_ok "SIP (System Integrity Protection): enabled"
        else
            log_warn "SIP (System Integrity Protection): NOT enabled — this is a significant security risk"
        fi
    else
        log_skip "csrutil not found — cannot check SIP status"
    fi

    # Check FileVault status (warn if disabled, do NOT modify)
    if command -v fdesetup >/dev/null 2>&1; then
        local fv_status
        fv_status="$(fdesetup status 2>/dev/null)" || true
        if echo "$fv_status" | grep -qi "on"; then
            log_ok "FileVault: enabled"
        else
            log_warn "FileVault: NOT enabled — disk encryption is recommended"
        fi
    else
        log_skip "fdesetup not found — cannot check FileVault status"
    fi

    # Disable remote login (screen sharing)
    systemsetup -setremotelogin off 2>/dev/null || true
    # Note: we do NOT log this to avoid noise if SSH is actually needed

    # Show all filename extensions in Finder
    defaults write NSGlobalDomain AppleShowAllExtensions -bool true 2>/dev/null && \
        log_ok "Finder: show all filename extensions" || \
        log_warn "Finder: failed to set show all extensions"

    log_ok "macOS system hardening complete"
}

# [3] SSH hardening
setup_ssh_hardening() {
    log_info "===== [3] SSH hardening ====="
    local sshd_config="/etc/ssh/sshd_config"

    if [[ ! -f "$sshd_config" ]]; then
        log_skip "sshd_config not found — skipping SSH hardening"
        return
    fi

    backup_file "$sshd_config"

    # Determine effective PasswordAuthentication
    local effective_pw_auth="${MAC_SSH_PASSWORD_AUTH}"
    if [[ "${MAC_SSH_PASSWORD_AUTH}" == "no" ]]; then
        local has_ssh_key=false
        local _home
        # Check for SSH keys for login-capable users
        while IFS=: read -r _user _ _ _ _ _home _shell; do
            case "$_shell" in
                */nologin|*/false) continue ;;
            esac
            if [[ -f "${_home}/.ssh/authorized_keys" ]] && [[ -s "${_home}/.ssh/authorized_keys" ]]; then
                has_ssh_key=true
                break
            fi
        done < /etc/passwd
        if [[ "$has_ssh_key" == "false" ]]; then
            log_warn "No SSH keys found — keeping PasswordAuthentication=yes to avoid lockout"
            effective_pw_auth="yes"
        fi
    fi
    # Protect automation account from password auth lockout
    if [[ -n "${ANSIBLE_ACCOUNT:-}" ]] && [[ "${effective_pw_auth}" == "no" ]]; then
        local ansible_home
        ansible_home=$(dscl . -read "/Users/${ANSIBLE_ACCOUNT}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
        if [[ -n "$ansible_home" ]] && [[ ! -s "${ansible_home}/.ssh/authorized_keys" ]]; then
            log_warn "Automation account '${ANSIBLE_ACCOUNT}' has no SSH key — forcing PasswordAuthentication=yes"
            effective_pw_auth="yes"
        fi
    fi

    # Apply SSH settings directly to sshd_config using BSD sed
    _mac_sed_set "$sshd_config" "PermitRootLogin" "${MAC_SSH_PERMIT_ROOT_LOGIN}"
    _mac_sed_set "$sshd_config" "PasswordAuthentication" "${effective_pw_auth}"
    _mac_sed_set "$sshd_config" "MaxAuthTries" "${MAC_SSH_MAX_AUTH_TRIES}"
    _mac_sed_set "$sshd_config" "PermitEmptyPasswords" "no"
    _mac_sed_set "$sshd_config" "X11Forwarding" "no"
    _mac_sed_set "$sshd_config" "AllowTcpForwarding" "no"
    _mac_sed_set "$sshd_config" "AllowAgentForwarding" "no"
    _mac_sed_set "$sshd_config" "PermitTunnel" "no"
    _mac_sed_set "$sshd_config" "GatewayPorts" "no"
    _mac_sed_set "$sshd_config" "ClientAliveInterval" "${MAC_SSH_CLIENT_ALIVE_INTERVAL}"
    _mac_sed_set "$sshd_config" "ClientAliveCountMax" "${MAC_SSH_CLIENT_ALIVE_COUNT_MAX}"
    _mac_sed_set "$sshd_config" "LoginGraceTime" "${MAC_SSH_LOGIN_GRACE_TIME}"
    _mac_sed_set "$sshd_config" "HostbasedAuthentication" "no"
    _mac_sed_set "$sshd_config" "IgnoreRhosts" "yes"
    _mac_sed_set "$sshd_config" "MaxSessions" "4"
    _mac_sed_set "$sshd_config" "MaxStartups" "10:30:60"
    _mac_sed_set "$sshd_config" "Banner" "/etc/motd"

    # Validate config before restarting
    if sshd -t 2>/dev/null; then
        # Restart SSH via launchctl
        local ssh_plist
        ssh_plist="$(_find_plist "com.openssh.sshd")"
        if [[ -z "$ssh_plist" ]]; then
            ssh_plist="/System/Library/LaunchDaemons/ssh.plist"
        fi
        if [[ -f "$ssh_plist" ]]; then
            launchctl unload "$ssh_plist" 2>/dev/null || true
            launchctl load "$ssh_plist" 2>/dev/null || true
            sleep 1  # Allow sshd to complete reload before continuing
            log_ok "SSH hardening applied and service restarted"
        else
            log_warn "SSH plist not found — cannot restart sshd (changes apply on next restart)"
        fi
    else
        log_error "sshd config syntax error — rolling back from backup"
        # Restore from backup
        local backup_path="${BACKUP_DIR}/$(echo "$sshd_config" | tr '/' '_')"
        if [[ -f "$backup_path" ]]; then
            cp -pR "$backup_path" "$sshd_config" 2>/dev/null
            log_warn "sshd_config restored from backup"
        fi
    fi
}

# [4] nologin accounts — macOS system accounts are already locked.
#     We verify and log login-capable users.
setup_nologin_accounts() {
    log_info "===== [4] Verify system account shells (macOS) ====="

    local login_capable_count=0
    while IFS=: read -r username _ uid _ _ home shell; do
        # Skip accounts with nologin or false shells
        case "$shell" in
            */nologin|*/false|"") continue ;;
        esac

        # System accounts on macOS typically have UID < 500
        if [[ "$uid" -lt 500 ]] && [[ "$username" != "root" ]]; then
            # SAFETY: check protected accounts
            if is_protected_account "$username"; then
                log_skip "Protected system account: $username (uid=$uid, shell=$shell)"
                continue
            fi
            log_info "System account with login shell: $username (uid=$uid, shell=$shell)"
        fi

        if [[ "$uid" -ge 500 ]]; then
            login_capable_count=$((login_capable_count + 1))
            log_info "Login-capable user: $username (uid=$uid, shell=$shell)"
        fi
    done < /etc/passwd

    log_ok "Login-capable user accounts: $login_capable_count"
}

# [5] Sudoers — gt NOPASSWD preservation
setup_sudoers() {
    log_info "===== [5] sudoers NOPASSWD cleanup ====="

    # Ensure gt sudoers drop-in exists (safety_guards.sh handles this)
    # Here we clean up other NOPASSWD entries

    if [[ -f /etc/sudoers ]]; then
        backup_file /etc/sudoers

        # Remove NOPASSWD from non-gt lines in main sudoers
        # Using BSD sed -i ''
        if grep -v '^[[:space:]]*gt[[:space:]]' /etc/sudoers | grep -q 'NOPASSWD' 2>/dev/null; then
            sed -i '' '/^[[:space:]]*gt[[:space:]]/!{s/\(ALL=(ALL)\)[[:space:]]*NOPASSWD:[[:space:]]*ALL/\1 ALL/;}' /etc/sudoers
            sed -i '' '/^[[:space:]]*gt[[:space:]]/!{s/\(ALL=(ALL:ALL)\)[[:space:]]*NOPASSWD:[[:space:]]*ALL/\1 ALL/;}' /etc/sudoers

            if visudo -c 2>/dev/null; then
                log_ok "sudoers NOPASSWD removed (gt preserved)"
            else
                log_fail "sudoers syntax error after edit — manual review needed"
            fi
        else
            log_ok "sudoers: no unauthorized NOPASSWD entries"
        fi
    fi

    # Check sudoers.d for unauthorized NOPASSWD files
    if [[ -d /etc/sudoers.d ]]; then
        local f fname
        for f in /etc/sudoers.d/*; do
            [[ -f "$f" ]] || continue
            fname="$(basename "$f")"

            # SAFETY: skip gt's sudoers drop-in
            if [[ "$fname" == "00-gt-nopasswd" ]]; then
                continue
            fi

            if grep -q 'NOPASSWD' "$f" 2>/dev/null; then
                log_drift "sudoers.d NOPASSWD file: $f"
                backup_file "$f"
                sed -i '' 's/NOPASSWD:[[:space:]]*//' "$f" 2>/dev/null || true
                log_ok "Removed NOPASSWD from $f"
            fi
        done
    fi
}

# [6] Banner — /etc/motd and login window text
setup_banner() {
    log_info "===== [6] Legal warning banner ====="
    local banner_text
    banner_text="
====================================================================
                    AUTHORIZED ACCESS ONLY
====================================================================
This system is for authorized use only. All activities are monitored
and logged. Unauthorized access is prohibited and will be prosecuted
to the fullest extent of the law.
===================================================================="

    # /etc/motd for SSH banner
    backup_file /etc/motd
    echo "$banner_text" > /etc/motd
    log_ok "Banner set: /etc/motd"

    # Login window text (GUI)
    defaults write /Library/Preferences/com.apple.loginwindow LoginwindowText \
        "AUTHORIZED ACCESS ONLY. All activities are monitored and logged." 2>/dev/null && \
        log_ok "Login window text set" || \
        log_warn "Login window text: failed to set"
}

# [7] sysctl — very limited on macOS
setup_sysctl() {
    log_info "===== [7] sysctl settings (macOS — limited) ====="
    local sysctl_conf="/etc/sysctl.conf"

    # Create sysctl.conf if it doesn't exist
    if [[ ! -f "$sysctl_conf" ]]; then
        touch "$sysctl_conf"
        log_info "Created $sysctl_conf"
    else
        backup_file "$sysctl_conf"
    fi

    local count
    count="$(_mac_sysctl_count)"
    local i=0
    while [[ "$i" -lt "$count" ]]; do
        local key val
        key="$(_mac_sysctl_get_key "$i")"
        val="$(_mac_sysctl_get_val "$i")"

        # Apply immediately
        if sysctl -w "${key}=${val}" >/dev/null 2>&1; then
            log_ok "sysctl ${key}=${val}"
        else
            log_warn "sysctl ${key}=${val} — failed to apply (may not be supported)"
        fi

        # Persist in sysctl.conf
        if grep -qE "^${key}=" "$sysctl_conf" 2>/dev/null; then
            sed -i '' "s|^${key}=.*|${key}=${val}|" "$sysctl_conf"
        else
            echo "${key}=${val}" >> "$sysctl_conf"
        fi

        i=$((i + 1))
    done
}

# [8] Sensitive file permissions
setup_sensitive_file_permissions() {
    log_info "===== [8] Sensitive file permissions ====="

    local f
    for f in $MAC_FILES_644; do
        if [[ -f "$f" ]]; then
            chmod 644 "$f" 2>/dev/null && log_ok "chmod 644 $f" || log_warn "chmod 644 $f failed"
            chown root:wheel "$f" 2>/dev/null || true
        fi
    done

    for f in $MAC_FILES_600; do
        if [[ -f "$f" ]]; then
            chmod 600 "$f" 2>/dev/null && log_ok "chmod 600 $f" || log_warn "chmod 600 $f failed"
            chown root:wheel "$f" 2>/dev/null || true
        fi
    done

    for f in $MAC_FILES_O_NORW; do
        if [[ -e "$f" ]]; then
            chmod o-rwx "$f" 2>/dev/null && log_ok "chmod o-rwx $f" || log_warn "chmod o-rwx $f failed"
        fi
    done

    # SSH directory
    if [[ -d /etc/ssh ]]; then
        chmod 755 /etc/ssh 2>/dev/null || true
        for f in /etc/ssh/ssh_host_*_key; do
            [[ -f "$f" ]] || continue
            chmod 600 "$f" 2>/dev/null && log_ok "chmod 600 $f" || log_warn "chmod 600 $f failed"
        done
    fi

    log_ok "Sensitive file permissions configured"
}

###############################################################################
# run_hardening() — Called by 01 orchestrator
###############################################################################

run_hardening() {
    log_info "===== macOS hardening adapter: run_hardening() ====="

    [[ "${HARDEN_FIREWALL}" == "true" ]] && setup_firewall || log_skip "[TOGGLE] Firewall disabled"
    [[ "${HARDEN_SYSCTL}" == "true" ]] && setup_macos_system || log_skip "[TOGGLE] macOS system settings disabled"
    [[ "${HARDEN_SSH}" == "true" ]] && setup_ssh_hardening || log_skip "[TOGGLE] SSH disabled"
    [[ "${HARDEN_ACCOUNTS}" == "true" ]] && setup_nologin_accounts || log_skip "[TOGGLE] Account nologin disabled"
    [[ "${HARDEN_SUDOERS}" == "true" ]] && setup_sudoers || log_skip "[TOGGLE] Sudoers disabled"
    [[ "${HARDEN_BANNER}" == "true" ]] && setup_banner || log_skip "[TOGGLE] Banner disabled"
    [[ "${HARDEN_SYSCTL}" == "true" ]] && setup_sysctl || log_skip "[TOGGLE] Sysctl disabled"
    [[ "${HARDEN_FILE_PERMISSIONS}" == "true" ]] && setup_sensitive_file_permissions || log_skip "[TOGGLE] File permissions disabled"

    log_ok "===== macOS hardening complete ====="
}

###############################################################################
# create_baseline_snapshot() — Called by 01 after hardening
###############################################################################

create_baseline_snapshot() {
    log_info "===== Creating baseline snapshot (macOS) ====="
    mkdir -p "${BASELINE_SNAPSHOT_DIR}"

    # Service state
    { echo "# LaunchDaemons/Agents snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      launchctl list 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/services_baseline.txt" || true

    # Listening ports
    { echo "# Listening ports snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      lsof -iTCP -sTCP:LISTEN -n -P 2>/dev/null || netstat -an -p tcp 2>/dev/null | grep LISTEN || true
    } > "${BASELINE_SNAPSHOT_DIR}/ports_baseline.txt" || true

    # pf rules
    { echo "# pf rules snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      pfctl -s rules 2>/dev/null || echo "(pf not active)"
    } > "${BASELINE_SNAPSHOT_DIR}/pf_rules_baseline.txt" || true

    # Application Firewall state
    { echo "# Application Firewall snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      if command -v /usr/libexec/ApplicationFirewall/socketfilterfw >/dev/null 2>&1; then
          /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || true
          /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || true
      else
          echo "(socketfilterfw not available)"
      fi
    } > "${BASELINE_SNAPSHOT_DIR}/appfirewall_baseline.txt" || true

    # sysctl settings
    { sysctl -a 2>/dev/null | sed 's/: /=/' | grep -v '^#' | sort
    } > "${BASELINE_SNAPSHOT_DIR}/sysctl_baseline.conf" || true

    # User accounts
    { echo "# User accounts snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      cat /etc/passwd 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/passwd_baseline.txt" || true

    # SSH config
    { echo "# SSH config snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      sshd -T 2>/dev/null || cat /etc/ssh/sshd_config 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/sshd_baseline.txt" || true

    # SSH effective config
    sshd -T 2>/dev/null | sort \
        > "${BASELINE_SNAPSHOT_DIR}/sshd_effective_baseline.txt" 2>/dev/null || true

    # Login-capable accounts
    awk -F: '$7 !~ /(nologin|false)/ && $7 != "" {print $1":"$7}' /etc/passwd 2>/dev/null | sort \
        > "${BASELINE_SNAPSHOT_DIR}/login_accounts_baseline.txt" || true

    # File permissions
    { local _perm_targets
      _perm_targets="$MAC_FILES_644 $MAC_FILES_600 $MAC_FILES_O_NORW /etc/ssh/sshd_config /etc/sysctl.conf /etc/pf.conf /etc/motd"
      for f in $_perm_targets; do
          [[ -e "$f" ]] || continue
          local perms owner
          perms="$(stat -f '%Lp' "$f" 2>/dev/null)"
          owner="$(stat -f '%Su:%Sg' "$f" 2>/dev/null)"
          echo "${perms} ${owner} ${f}"
      done
    } > "${BASELINE_SNAPSHOT_DIR}/file_permissions_baseline.txt" || true

    # Listening ports (lsof format for comparison)
    lsof -iTCP -sTCP:LISTEN -n -P 2>/dev/null \
        > "${BASELINE_SNAPSHOT_DIR}/listening_ports_baseline.txt" || true

    # macOS system settings
    { echo "# macOS system settings snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      echo "GuestEnabled=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null || echo 'N/A')"
      echo "autoLoginUser=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || echo 'N/A')"
      echo "RemoteAppleEvents=$(systemsetup -getremoteappleevents 2>/dev/null || echo 'N/A')"
      if command -v /usr/libexec/ApplicationFirewall/socketfilterfw >/dev/null 2>&1; then
          echo "AppFirewall=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo 'N/A')"
      fi
      if command -v csrutil >/dev/null 2>&1; then
          echo "SIP=$(csrutil status 2>/dev/null || echo 'N/A')"
      fi
      if command -v fdesetup >/dev/null 2>&1; then
          echo "FileVault=$(fdesetup status 2>/dev/null || echo 'N/A')"
      fi
      if command -v spctl >/dev/null 2>&1; then
          echo "Gatekeeper=$(spctl --status 2>/dev/null || echo 'N/A')"
      fi
    } > "${BASELINE_SNAPSHOT_DIR}/macos_settings_baseline.txt" || true

    # Sudoers snapshot
    { echo "# Sudoers snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      cat /etc/sudoers 2>/dev/null || true
      echo "---"
      for f in /etc/sudoers.d/*; do
          [[ -f "$f" ]] || continue
          echo "=== $(basename "$f") ==="
          cat "$f" 2>/dev/null || true
      done
    } > "${BASELINE_SNAPSHOT_DIR}/sudoers_baseline.txt" || true

    # auditd snapshot (OpenBSM) — saved for drift detection only, not auto-restored
    mkdir -p "${BASELINE_SNAPSHOT_DIR}/auditd"
    cp -pR /etc/security/audit_control "${BASELINE_SNAPSHOT_DIR}/auditd/" 2>/dev/null || true
    # Also save audit_class and audit_event if they exist
    cp -pR /etc/security/audit_class "${BASELINE_SNAPSHOT_DIR}/auditd/" 2>/dev/null || true
    cp -pR /etc/security/audit_event "${BASELINE_SNAPSHOT_DIR}/auditd/" 2>/dev/null || true

    # Scoringbot binary state snapshot
    { echo "# Scoringbot binary snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      echo "BINARY=${MAC_GTMON_BINARY}"
      if [[ -f "${MAC_GTMON_BINARY}" ]]; then
          ls -la "${MAC_GTMON_BINARY}" 2>/dev/null || true
          shasum -a 256 "${MAC_GTMON_BINARY}" 2>/dev/null || md5 "${MAC_GTMON_BINARY}" 2>/dev/null || true
      else
          echo "(not present at snapshot time)"
      fi
    } > "${BASELINE_SNAPSHOT_DIR}/scoringbot_baseline.txt" || true

    log_ok "Baseline snapshot saved: ${BASELINE_SNAPSHOT_DIR}"
}

###############################################################################
# Check Functions (check_*) — for run_checks()
###############################################################################

# [C1] Firewall check — verify pf + Application Firewall state
check_firewall() {
    log_info "===== [C1] Firewall check (pf + Application Firewall) ====="

    # Check Application Firewall
    if command -v /usr/libexec/ApplicationFirewall/socketfilterfw >/dev/null 2>&1; then
        local sfw="/usr/libexec/ApplicationFirewall/socketfilterfw"
        local fw_state
        fw_state="$("$sfw" --getglobalstate 2>/dev/null)" || true

        if echo "$fw_state" | grep -qi "enabled"; then
            log_ok "Application Firewall: enabled"
        else
            log_drift "Application Firewall: disabled"
            if [[ "$MODE" == "auto-restore" ]]; then
                "$sfw" --setglobalstate on 2>/dev/null && \
                    log_restore "Application Firewall re-enabled" || \
                    log_fail "Application Firewall re-enable failed"
            fi
        fi

        local stealth_state
        stealth_state="$("$sfw" --getstealthmode 2>/dev/null)" || true
        if echo "$stealth_state" | grep -qi "enabled"; then
            log_ok "Stealth mode: enabled"
        else
            log_drift "Stealth mode: disabled"
            if [[ "$MODE" == "auto-restore" ]]; then
                "$sfw" --setstealthmode on 2>/dev/null && \
                    log_restore "Stealth mode re-enabled" || \
                    log_fail "Stealth mode re-enable failed"
            fi
        fi
    fi

    # Check pf
    local pf_info
    pf_info="$(pfctl -s info 2>/dev/null)" || true
    if echo "$pf_info" | grep -q "Status: Enabled"; then
        log_ok "pf: enabled"
    else
        log_drift "pf: not enabled"
        if [[ "$MODE" == "auto-restore" ]]; then
            pfctl -e 2>/dev/null && \
                log_restore "pf re-enabled" || \
                log_fail "pf re-enable failed"
            pfctl -f /etc/pf.conf 2>/dev/null || true
        fi
    fi

    # Verify our hardening rules are still present
    if grep -q "HARDENING_PF_RULES_BEGIN" /etc/pf.conf 2>/dev/null; then
        log_ok "pf hardening rules present in /etc/pf.conf"
    else
        log_drift "pf hardening rules missing from /etc/pf.conf"
    fi
}

# [C2] macOS system settings check
check_macos_system() {
    log_info "===== [C2] macOS system settings check ====="

    # Guest account
    local guest_enabled
    guest_enabled="$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)" || true
    if [[ "$guest_enabled" == "0" ]] || [[ "$guest_enabled" == "false" ]]; then
        log_ok "Guest account: disabled"
    else
        log_drift "Guest account: enabled (should be disabled)"
        if [[ "$MODE" == "auto-restore" ]]; then
            defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false 2>/dev/null && \
                log_restore "Guest account disabled" || \
                log_fail "Guest account disable failed"
        fi
    fi

    # Auto-login
    local auto_login
    auto_login="$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)" || true
    if [[ -z "$auto_login" ]] || [[ "$auto_login" == *"does not exist"* ]]; then
        log_ok "Auto-login: disabled"
    else
        log_drift "Auto-login enabled for user: $auto_login"
        if [[ "$MODE" == "auto-restore" ]]; then
            defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null && \
                log_restore "Auto-login disabled" || \
                log_fail "Auto-login disable failed"
        fi
    fi

    # Gatekeeper
    if command -v spctl >/dev/null 2>&1; then
        local gk_status
        gk_status="$(spctl --status 2>/dev/null)" || true
        if echo "$gk_status" | grep -qi "enabled"; then
            log_ok "Gatekeeper: enabled"
        else
            log_drift "Gatekeeper: disabled"
            if [[ "$MODE" == "auto-restore" ]]; then
                spctl --master-enable 2>/dev/null && \
                    log_restore "Gatekeeper re-enabled" || \
                    log_fail "Gatekeeper re-enable failed"
            fi
        fi
    fi

    # SIP (read-only check — cannot modify)
    if command -v csrutil >/dev/null 2>&1; then
        local sip_status
        sip_status="$(csrutil status 2>/dev/null)" || true
        if echo "$sip_status" | grep -qi "enabled"; then
            log_ok "SIP: enabled"
        else
            log_warn "SIP: NOT enabled (cannot be re-enabled without Recovery Mode)"
        fi
    fi

    # FileVault (read-only check — cannot modify)
    if command -v fdesetup >/dev/null 2>&1; then
        local fv_status
        fv_status="$(fdesetup status 2>/dev/null)" || true
        if echo "$fv_status" | grep -qi "on"; then
            log_ok "FileVault: enabled"
        else
            log_warn "FileVault: NOT enabled"
        fi
    fi
}

# [C3] SSH config check
check_ssh_config() {
    log_info "===== [C3] SSH config check ====="

    local sshd_config="/etc/ssh/sshd_config"
    if [[ ! -f "$sshd_config" ]]; then
        log_skip "sshd_config not found — skipping"
        return
    fi

    # Check key settings
    local key val expected
    local settings_to_check="PermitRootLogin:${MAC_SSH_PERMIT_ROOT_LOGIN} PermitEmptyPasswords:no X11Forwarding:no AllowTcpForwarding:no PermitTunnel:no"

    for entry in $settings_to_check; do
        key="${entry%%:*}"
        expected="${entry#*:}"

        # Get current effective value
        val="$(sshd -T 2>/dev/null | grep -i "^$(echo "$key" | tr '[:upper:]' '[:lower:]') " | awk '{print $2}')" || true
        if [[ -z "$val" ]]; then
            val="$(grep -i "^${key}" "$sshd_config" 2>/dev/null | tail -1 | awk '{print $2}')" || true
        fi

        local expected_lower val_lower
        expected_lower="$(echo "$expected" | tr '[:upper:]' '[:lower:]')"
        val_lower="$(echo "$val" | tr '[:upper:]' '[:lower:]')"

        if [[ "$val_lower" == "$expected_lower" ]]; then
            log_ok "SSH ${key}=${val}"
        else
            log_drift "SSH ${key}: expected=${expected}, current=${val}"
            if [[ "$MODE" == "auto-restore" ]]; then
                _mac_backup_before_restore "$sshd_config"
                _mac_sed_set "$sshd_config" "$key" "$expected"
                log_restore "SSH ${key}=${expected} restored"
            fi
        fi
    done

    # Reload SSH if we made changes
    if [[ "$MODE" == "auto-restore" ]]; then
        if sshd -t 2>/dev/null; then
            local ssh_plist
            ssh_plist="$(_find_plist "com.openssh.sshd")"
            if [[ -z "$ssh_plist" ]]; then
                ssh_plist="/System/Library/LaunchDaemons/ssh.plist"
            fi
            if [[ -f "$ssh_plist" ]]; then
                launchctl unload "$ssh_plist" 2>/dev/null || true
                launchctl load "$ssh_plist" 2>/dev/null || true
            fi
        fi
    fi
}

# [C4] Login accounts check
check_login_accounts() {
    log_info "===== [C4] Login accounts check ====="

    local baseline_file="${BASELINE_SNAPSHOT_DIR}/login_accounts_baseline.txt"
    if [[ ! -f "$baseline_file" ]]; then
        log_warn "Login accounts baseline not found — skipping diff"
        return
    fi

    local current_accounts
    current_accounts="$(awk -F: '$7 !~ /(nologin|false)/ && $7 != "" {print $1":"$7}' /etc/passwd 2>/dev/null | sort)"

    local new_accounts
    new_accounts="$(comm -13 "$baseline_file" <(echo "$current_accounts") 2>/dev/null)" || true

    if [[ -n "$new_accounts" ]]; then
        while IFS= read -r acct; do
            [[ -z "$acct" ]] && continue
            local username
            username="${acct%%:*}"
            # SAFETY: check protected accounts
            if is_protected_account "$username"; then
                log_ok "Protected account OK: $username"
                continue
            fi
            log_drift "New login-capable account since baseline: $acct"
        done <<< "$new_accounts"
    else
        log_ok "No new login-capable accounts vs baseline"
    fi

    # Check for UID 0 backdoor accounts
    local uid0_users
    uid0_users="$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null)" || true
    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        if [[ "$user" != "root" ]]; then
            log_drift "Non-root UID 0 account: ${user} (possible backdoor!)"
        fi
    done <<< "$uid0_users"
}

# [C5] Sudoers check
check_sudoers() {
    log_info "===== [C5] sudoers NOPASSWD check ====="

    if [[ -f /etc/sudoers ]]; then
        # Check for NOPASSWD excluding gt lines
        if grep -v '^[[:space:]]*gt[[:space:]]' /etc/sudoers | grep -q 'NOPASSWD' 2>/dev/null; then
            log_drift "sudoers has NOPASSWD (non-gt lines)!"
            if [[ "$MODE" == "auto-restore" ]]; then
                _mac_backup_before_restore /etc/sudoers
                sed -i '' '/^[[:space:]]*gt[[:space:]]/!{s/\(ALL=(ALL)\)[[:space:]]*NOPASSWD:[[:space:]]*ALL/\1 ALL/;}' /etc/sudoers
                sed -i '' '/^[[:space:]]*gt[[:space:]]/!{s/\(ALL=(ALL:ALL)\)[[:space:]]*NOPASSWD:[[:space:]]*ALL/\1 ALL/;}' /etc/sudoers
                if visudo -c 2>/dev/null; then
                    log_restore "sudoers NOPASSWD removed (gt preserved)"
                else
                    log_fail "sudoers syntax error — manual check required"
                fi
            fi
        else
            log_ok "sudoers: no NOPASSWD (gt excluded from check)"
        fi
    fi

    if [[ -d /etc/sudoers.d ]]; then
        local nopasswd_files
        nopasswd_files="$(grep -rl 'NOPASSWD' /etc/sudoers.d/ 2>/dev/null)" || true
        if [[ -n "$nopasswd_files" ]]; then
            while IFS= read -r f; do
                local fname
                fname="$(basename "$f")"
                # SAFETY: skip gt's sudoers drop-in
                if [[ "$fname" == "00-gt-nopasswd" ]]; then
                    log_ok "gt NOPASSWD preserved: $f"
                    continue
                fi
                log_drift "sudoers.d NOPASSWD file: $f"
            done <<< "$nopasswd_files"
        else
            log_ok "sudoers.d: no NOPASSWD (gt excluded)"
        fi
    fi
}

# [C6] Suspicious files detection
check_suspicious_files() {
    log_info "===== [C6] Suspicious files detection ====="

    # Check for hidden executables in system dirs
    local suspicious_dirs="/bin /sbin /usr/bin /usr/sbin /usr/local/bin"
    local dir
    for dir in $suspicious_dirs; do
        if [[ -d "$dir" ]]; then
            local hidden_files
            hidden_files="$(find "$dir" -maxdepth 2 -name '.*' -type f -perm +0111 2>/dev/null)" || true
            if [[ -n "$hidden_files" ]]; then
                while IFS= read -r f; do
                    log_drift "Hidden executable: $f"
                done <<< "$hidden_files"
            fi
        fi
    done

    # Check temp directories for executables
    local temp_dir
    for temp_dir in /tmp /private/tmp /var/tmp; do
        if [[ -d "$temp_dir" ]]; then
            local exec_files
            exec_files="$(find "$temp_dir" -type f -perm +0111 2>/dev/null | head -20)" || true
            if [[ -n "$exec_files" ]]; then
                while IFS= read -r f; do
                    log_drift "Executable in temp dir: $f"
                done <<< "$exec_files"
            fi
        fi
    done

    # Check for unusual authorized_keys locations
    local unusual_authkeys
    unusual_authkeys="$(find /usr/sbin /sbin /bin -name 'authorized_keys' -type f 2>/dev/null)" || true
    if [[ -n "$unusual_authkeys" ]]; then
        while IFS= read -r f; do
            log_drift "Unusual authorized_keys location: $f"
        done <<< "$unusual_authkeys"
    fi

    log_ok "Suspicious files scan complete"
}

# [C7] Suspicious processes check
check_suspicious_processes() {
    log_info "===== [C7] Suspicious processes check ====="

    # Check for suspicious process patterns
    # MAC_GTMON_BINARY is a known-good scoring process — exclude it from flagging
    local suspect_patterns='(cryptominer|xmrig|kinsing|kdevtmpfsi|kthreaddi|\.hidden|/tmp/\.)'
    local suspect_procs
    suspect_procs="$(ps auxww 2>/dev/null | grep -iE "$suspect_patterns" | grep -v grep | grep -v "${MAC_GTMON_BINARY}")" || true
    if [[ -n "$suspect_procs" ]]; then
        while IFS= read -r line; do
            log_drift "Suspicious process: $line"
        done <<< "$suspect_procs"
    else
        log_ok "No suspicious processes detected"
    fi

    # Check for processes running from temp paths
    local tmp_procs
    tmp_procs="$(ps auxww 2>/dev/null | awk '{print $11}' | grep -E '^(/tmp/|/private/tmp/|/var/tmp/)' | sort -u)" || true
    if [[ -n "$tmp_procs" ]]; then
        while IFS= read -r proc; do
            log_drift "Process running from temp path: $proc"
        done <<< "$tmp_procs"
    else
        log_ok "No temp path processes"
    fi

    # Confirm scoringbot (MAC_GTMON_BINARY) is running if present on disk
    if [[ -f "${MAC_GTMON_BINARY}" ]]; then
        local gtmon_running
        gtmon_running="$(ps auxww 2>/dev/null | grep "${MAC_GTMON_BINARY}" | grep -v grep)" || true
        if [[ -n "$gtmon_running" ]]; then
            log_ok "Scoringbot process running: ${MAC_GTMON_BINARY}"
        else
            log_info "Scoringbot binary present but not currently running: ${MAC_GTMON_BINARY}"
        fi
    fi
}

# [C8] Network listening ports check
check_network() {
    log_info "===== [C8] Network listening ports check ====="

    local baseline_file="${BASELINE_SNAPSHOT_DIR}/listening_ports_baseline.txt"
    local current_ports
    current_ports="$(lsof -iTCP -sTCP:LISTEN -n -P 2>/dev/null)" || true

    if [[ -f "$baseline_file" ]] && [[ -n "$current_ports" ]]; then
        # Extract port numbers from current and baseline
        local current_addrs baseline_addrs
        current_addrs="$(echo "$current_ports" | awk 'NR>1 {print $9}' | sort -u)"
        baseline_addrs="$(awk 'NR>1 {print $9}' "$baseline_file" 2>/dev/null | sort -u)"

        local new_ports
        new_ports="$(comm -13 <(echo "$baseline_addrs") <(echo "$current_addrs") 2>/dev/null)" || true
        if [[ -n "$new_ports" ]]; then
            while IFS= read -r addr; do
                [[ -z "$addr" ]] && continue
                local proc_info
                proc_info="$(echo "$current_ports" | grep "$addr" | awk '{print $1}' | head -1)"
                log_drift "New listening port: ${addr} (${proc_info})"
            done <<< "$new_ports"
        else
            log_ok "No new listening ports vs baseline"
        fi
    fi

    # Check for suspicious ports
    local suspect_ports="4444 5555 6666 7777 8888 9999 1234 31337 12345 54321"
    local port
    for port in $suspect_ports; do
        if echo ",${MAC_WHITELISTED_PORTS}," | grep -q ",${port},"; then
            continue
        fi
        if echo "$current_ports" | grep -q ":${port} " 2>/dev/null; then
            local proc
            proc="$(echo "$current_ports" | grep ":${port} " | awk '{print $1}' | head -1)"
            log_drift "Suspicious port listening: :${port} (${proc})"
        fi
    done

    # Show external established connections
    local ext_conns
    ext_conns="$(lsof -iTCP -sTCP:ESTABLISHED -n -P 2>/dev/null | awk 'NR>1 && $9 !~ /^(127\.|::1|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/ {print $1, $9}' | head -20)" || true
    if [[ -n "$ext_conns" ]]; then
        log_info "External ESTABLISHED connections:"
        while IFS= read -r line; do
            log_info "  $line"
        done <<< "$ext_conns"
    fi
}

# [C9] File permissions check
check_file_permissions() {
    log_info "===== [C9] File permissions check ====="

    local baseline_file="${BASELINE_SNAPSHOT_DIR}/file_permissions_baseline.txt"
    if [[ ! -f "$baseline_file" ]]; then
        log_warn "File permissions baseline not found — skipping"
        return
    fi

    while IFS=' ' read -r expected_perm expected_owner filepath; do
        [[ -z "$filepath" ]] && continue
        if [[ ! -e "$filepath" ]]; then
            log_warn "File missing (deleted?): $filepath"
            continue
        fi

        local current_perm current_owner
        current_perm="$(stat -f '%Lp' "$filepath" 2>/dev/null)"
        current_owner="$(stat -f '%Su:%Sg' "$filepath" 2>/dev/null)"
        local drifted=false

        if [[ "$current_perm" != "$expected_perm" ]]; then
            log_drift "Permission changed: $filepath (expected=${expected_perm}, current=${current_perm})"
            drifted=true
            if [[ "$MODE" == "auto-restore" ]]; then
                _mac_backup_before_restore "$filepath"
                if chmod "$expected_perm" "$filepath" 2>/dev/null; then
                    log_restore "chmod ${expected_perm} ${filepath}"
                else
                    log_fail "chmod ${expected_perm} ${filepath} failed"
                fi
            fi
        fi

        if [[ "$current_owner" != "$expected_owner" ]]; then
            log_drift "Owner changed: $filepath (expected=${expected_owner}, current=${current_owner})"
            drifted=true
            if [[ "$MODE" == "auto-restore" ]]; then
                _mac_backup_before_restore "$filepath"
                if chown "$expected_owner" "$filepath" 2>/dev/null; then
                    log_restore "chown ${expected_owner} ${filepath}"
                else
                    log_fail "chown ${expected_owner} ${filepath} failed"
                fi
            fi
        fi

        if [[ "$drifted" == "false" ]]; then
            log_ok "OK: $filepath (${current_perm} ${current_owner})"
        fi
    done < "$baseline_file"
}

# [C10] Sysctl check
check_sysctl() {
    log_info "===== [C10] sysctl settings check ====="

    local count
    count="$(_mac_sysctl_count)"
    local i=0
    while [[ "$i" -lt "$count" ]]; do
        local key expected_val current_val
        key="$(_mac_sysctl_get_key "$i")"
        expected_val="$(_mac_sysctl_get_val "$i")"
        current_val="$(sysctl -n "$key" 2>/dev/null)" || true

        if [[ "$current_val" == "$expected_val" ]]; then
            log_ok "sysctl ${key} = ${current_val}"
        else
            log_drift "sysctl ${key}: expected=${expected_val}, current=${current_val}"
            if [[ "$MODE" == "auto-restore" ]]; then
                if sysctl -w "${key}=${expected_val}" >/dev/null 2>&1; then
                    log_restore "sysctl ${key}=${expected_val} restored"
                else
                    log_fail "sysctl ${key} restore failed"
                fi
            fi
        fi

        i=$((i + 1))
    done
}

###############################################################################
# check_auditd() — OpenBSM-based audit check (macOS)
###############################################################################

check_auditd() {
    log_info "===== [C11] OpenBSM audit check (macOS) ====="

    # macOS uses OpenBSM — auditd exists but is different from Linux
    if ! command -v audit >/dev/null 2>&1 && ! command -v praudit >/dev/null 2>&1; then
        log_warn "OpenBSM audit tools not found"
        return
    fi

    # Check if audit is running
    local audit_pid
    audit_pid="$(pgrep -x auditd 2>/dev/null)" || true
    if [[ -n "$audit_pid" ]]; then
        log_ok "auditd is running (PID: $audit_pid)"
    else
        log_drift "auditd is not running"
        if [[ "$MODE" == "auto-restore" ]]; then
            # Attempt to start audit
            local audit_plist
            audit_plist="$(_find_plist "com.apple.auditd")"
            if [[ -n "$audit_plist" ]]; then
                launchctl load "$audit_plist" 2>/dev/null && \
                    log_restore "auditd started via launchd" || \
                    log_fail "auditd start failed"
            else
                audit -i 2>/dev/null && \
                    log_restore "auditd initialized" || \
                    log_fail "auditd initialization failed"
            fi
        fi
    fi

    # Check audit_control file
    local audit_control="/etc/security/audit_control"
    if [[ -f "$audit_control" ]]; then
        log_ok "audit_control exists: $audit_control"

        # Verify flags include useful audit classes
        local flags
        flags="$(grep '^flags:' "$audit_control" 2>/dev/null | head -1)" || true
        if [[ -n "$flags" ]]; then
            log_info "Audit flags: $flags"
        else
            log_warn "No audit flags configured in $audit_control"
        fi
    else
        log_warn "audit_control not found at $audit_control"
    fi

    # Check baseline snapshot if available — compare only, do NOT restore
    local snap_dir="${BASELINE_SNAPSHOT_DIR}/auditd"
    if [[ -d "$snap_dir" ]] && [[ -f "${snap_dir}/audit_control" ]]; then
        local current_conf="/etc/security/audit_control"
        if [[ -f "$current_conf" ]]; then
            if ! diff -q "$current_conf" "${snap_dir}/audit_control" >/dev/null 2>&1; then
                log_drift "audit_control differs from baseline snapshot"
                # auditd config is snapshot-only — auto-restore is not performed
                # Changes to audit policy must be reviewed and applied manually
                log_warn "auditd: manual restore needed — review diff between ${snap_dir}/audit_control and $current_conf"
            else
                log_ok "audit_control matches baseline snapshot"
            fi
        fi
    fi
}

###############################################################################
# run_checks() — Called by 02 orchestrator
###############################################################################

run_checks() {
    log_info "===== macOS adapter: run_checks() (mode=${MODE}) ====="

    [[ "${HARDEN_FIREWALL}" == "true" ]] && check_firewall || log_skip "[TOGGLE] Firewall check skipped"
    [[ "${HARDEN_SYSCTL}" == "true" ]] && check_macos_system || log_skip "[TOGGLE] macOS system check skipped"
    [[ "${HARDEN_SSH}" == "true" ]] && check_ssh_config || log_skip "[TOGGLE] SSH check skipped"
    [[ "${HARDEN_ACCOUNTS}" == "true" ]] && check_login_accounts || log_skip "[TOGGLE] Account check skipped"
    [[ "${HARDEN_SUDOERS}" == "true" ]] && check_sudoers || log_skip "[TOGGLE] Sudoers check skipped"
    check_suspicious_files      # [C6] always run (security)
    check_suspicious_processes  # [C7] always run (security)
    check_network               # [C8] always run (security)
    [[ "${HARDEN_FILE_PERMISSIONS}" == "true" ]] && check_file_permissions || log_skip "[TOGGLE] File permissions check skipped"
    [[ "${HARDEN_SYSCTL}" == "true" ]] && check_sysctl || log_skip "[TOGGLE] Sysctl check skipped"
    check_auditd                # [C11] always run

    log_ok "===== macOS drift checks complete ====="
}

###############################################################################
# kill_other_ssh_sessions() — Minimal/no-op on macOS
###############################################################################

kill_other_ssh_sessions() {
    log_info "===== Kill other SSH sessions (macOS — minimal) ====="

    # On macOS, SSH session management is simpler.
    # We attempt to identify and kill other sshd child processes,
    # but this is best-effort.

    local my_sshd_pids=""
    local check_pid=$$
    local depth=0
    while [[ $depth -lt 10 ]] && [[ $check_pid -gt 1 ]]; do
        local pname pppid
        pname="$(ps -o comm= -p "$check_pid" 2>/dev/null | tr -d ' ')" || true
        pppid="$(ps -o ppid= -p "$check_pid" 2>/dev/null | tr -d ' ')" || true

        if [[ "$pname" == "sshd" ]]; then
            if [[ "$pppid" != "1" ]] && [[ "$pppid" != "0" ]]; then
                my_sshd_pids="${my_sshd_pids} ${check_pid}"
            fi
        fi
        check_pid="$pppid"
        depth=$((depth + 1))
    done

    if [[ -z "$my_sshd_pids" ]]; then
        log_skip "Cannot find current session sshd process — skipping session kill"
        return 0
    fi
    log_info "  Current session sshd PID(s):${my_sshd_pids}"

    local killed_count=0
    local pid
    # Find all sshd processes that are not the main daemon and not ours
    while IFS= read -r pid; do
        [[ -z "$pid" ]] && continue
        pid="$(echo "$pid" | tr -d ' ')"

        # Skip if this is our session
        local is_ours=false
        local my_pid
        for my_pid in $my_sshd_pids; do
            if [[ "$pid" == "$my_pid" ]]; then
                is_ours=true
                break
            fi
        done
        [[ "$is_ours" == "true" ]] && continue

        # Check parent — skip the main sshd daemon (ppid=1)
        local ppid_of
        ppid_of="$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')" || true
        [[ "$ppid_of" == "1" || "$ppid_of" == "0" ]] && continue

        local user
        user=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')

        # Protect gt account and automation account
        if [[ "$user" == "${PROTECTED_ACCOUNT_GT:-gt}" ]]; then
            log_skip "  Skipping gt session: PID ${pid}"
            continue
        fi
        if [[ -n "${ANSIBLE_ACCOUNT:-}" ]] && [[ "$user" == "${ANSIBLE_ACCOUNT}" ]]; then
            log_skip "  Skipping automation account session: PID ${pid} (${user})"
            continue
        fi

        kill "$pid" 2>/dev/null && {
            log_info "  Killed sshd session PID=$pid"
            killed_count=$((killed_count + 1))
        }
    done <<< "$(pgrep -x sshd 2>/dev/null)"

    if [[ "$killed_count" -gt 0 ]]; then
        log_ok "Killed $killed_count other SSH session(s)"
    else
        log_ok "No other SSH sessions found to kill"
    fi
}
