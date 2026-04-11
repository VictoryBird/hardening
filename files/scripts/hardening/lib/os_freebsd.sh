#!/usr/bin/env bash
# lib/os_freebsd.sh — FreeBSD hardening adapter
#
# Implements the hardening functions called by the orchestrator scripts
# (01_baseline_hardening.sh and 02_check_and_restore.sh).
#
# Requires: lib/common.sh (log_*, OS_FAMILY, HOSTNAME_ORIG, BACKUP_DIR,
#           BASELINE_SNAPSHOT_DIR, backup_file, create_backup_dir)
#           lib/safety_guards.sh (is_protected_account, is_protected_service,
#           guard_account_gt, guard_network_outbound, change_usr_password,
#           is_gtmon_required_port)
#
# Exports: run_hardening(), run_checks(), create_baseline_snapshot(),
#          kill_other_ssh_sessions(), check_auditd()
#
# Compatibility: bash 4.0+ (FreeBSD ports typically have bash 4+)

###############################################################################
# Guard against double-sourcing
###############################################################################
[[ -n "${_OS_FREEBSD_SH_LOADED:-}" ]] && return 0
_OS_FREEBSD_SH_LOADED=1

###############################################################################
# Configuration Constants
###############################################################################

# --- sysctl security settings (NO IPv6 disable) ---
declare -A BSD_SYSCTL_SETTINGS=(
    ["security.bsd.see_other_uids"]="0"
    ["security.bsd.see_other_gids"]="0"
    ["security.bsd.unprivileged_read_msgbuf"]="0"
    ["security.bsd.unprivileged_proc_debug"]="0"
    ["net.inet.tcp.blackhole"]="2"
    ["net.inet.udp.blackhole"]="1"
    ["net.inet.icmp.drop_redirect"]="1"
    ["net.inet.tcp.drop_synfin"]="1"
    ["net.inet.ip.random_id"]="1"
    ["net.inet.ip.redirect"]="0"
    ["net.inet6.ip6.redirect"]="0"
)
# Conditionally disable IP forwarding based on config.sh
if [[ "${SYSCTL_DISABLE_IP_FORWARD}" == "true" ]]; then
    BSD_SYSCTL_SETTINGS["net.inet.ip.forwarding"]="0"
    BSD_SYSCTL_SETTINGS["net.inet6.ip6.forwarding"]="0"
fi

# --- Sensitive file permissions ---
readonly BSD_FILES_644=(/etc/passwd /etc/group)
readonly BSD_FILES_600=(/etc/master.passwd /etc/spwd.db)
readonly BSD_FILES_CHOWN=(/etc/passwd /etc/group /etc/master.passwd /etc/spwd.db)

# --- other permission removal targets ---
readonly BSD_FILES_O_NORW=(
    /etc/fstab /etc/ftpusers /etc/group /etc/hosts
    /etc/hosts.allow /etc/hosts.equiv
    /etc/inetd.conf /etc/login.access
    /etc/login.conf /etc/ssh/sshd_config /etc/sysctl.conf
    /etc/crontab /usr/bin/crontab
    /var/log /var/cron/tabs
)

# --- SUID removal targets (from config.sh) ---
IFS=' ' read -ra BSD_SUID_REMOVE_TARGETS <<< "$SUID_REMOVE_TARGETS"

# --- nologin target system accounts ---
readonly BSD_NOLOGIN_ACCOUNTS=(
    bin tty kmem games news man operator sshd
    daemon nobody _pflogd _dhcp _ntp
    auditdistd unbound hast proxy www pop
    bind cups smmsp mailnull
)

# --- Services to disable (from config.sh) ---
# FreeBSD services don't use .service suffix — use names directly
IFS=' ' read -ra BSD_DISABLE_SERVICES <<< "$DISABLE_SERVICES"

# --- SSH hardening settings (from config.sh) ---
BSD_SSH_PERMIT_ROOT_LOGIN="${SSH_PERMIT_ROOT_LOGIN}"
BSD_SSH_PASSWORD_AUTH="${SSH_PASSWORD_AUTH}"
BSD_SSH_MAX_AUTH_TRIES="${SSH_MAX_AUTH_TRIES}"
BSD_SSH_CLIENT_ALIVE_INTERVAL="${SSH_CLIENT_ALIVE_INTERVAL}"
BSD_SSH_CLIENT_ALIVE_COUNT_MAX="${SSH_CLIENT_ALIVE_COUNT_MAX}"
BSD_SSH_LOGIN_GRACE_TIME="${SSH_LOGIN_GRACE_TIME}"

# --- login.conf password policy (from config.sh) ---
BSD_PASS_MAX_DAYS="${PASS_MAX_DAYS}"
BSD_PASS_MIN_DAYS="${PASS_MIN_DAYS}"
BSD_PASS_WARN_AGE="${PASS_WARN_AGE}"
BSD_DEFAULT_UMASK="${DEFAULT_UMASK}"

# --- pf firewall profile (from config.sh) ---
BSD_PF_PROFILE="${HARDENING_PROFILE}"

declare -A BSD_PF_PROFILES=(
    [base]="22"
    [web]="22 80 443"
    [ad]="22 53 88 389 636 3268 3269"
    [log]="22 514 1514 1515 1516"
    [full]="22 53 80 88 389 443 514 636 953 1514 1515 1516 3268 3269"
)

# --- Tunnel defense settings (from config.sh) ---
BSD_TUNNEL_DEFENSE_ENABLED="${TUNNEL_DEFENSE_ENABLED}"
BSD_TUNNEL_ICMP_MAX_PAYLOAD="${TUNNEL_ICMP_MAX_PAYLOAD}"
BSD_TUNNEL_REMOVE_TOOLS="${TUNNEL_REMOVE_TOOLS}"
BSD_TUNNEL_LOCK_RESOLV="${TUNNEL_LOCK_RESOLV}"
readonly BSD_TUNNEL_TOOL_PROCS=(
    ptunnel ptunnel-ng icmptunnel icmpsh pingtunnel
    iodine iodined dns2tcp dnscat dnscat2 dnscapy dnstunnel
    chisel ligolo frpc ngrok inlets bore gost
    autossh sshuttle
)

# --- Tunnel tool packages ---
readonly BSD_TUNNEL_PKGS=(
    ptunnel ptunnel-ng
    iodine dns2tcp dnscat2
    chisel sshuttle autossh
)

# --- Tunnel tool binaries ---
readonly BSD_TUNNEL_BINS=(
    /usr/local/sbin/iodined /usr/local/bin/iodine
    /usr/local/bin/dns2tcp /usr/local/bin/dnscat
    /usr/local/bin/chisel /usr/local/bin/gost
    /usr/local/bin/ligolo /usr/local/bin/frpc
    /usr/local/bin/bore /usr/local/bin/inlets
    /usr/local/sbin/ptunnel /usr/local/sbin/ptunnel-ng
    /usr/local/bin/dnscat2
)

# --- sysctl skip pattern for checks ---
readonly BSD_SYSCTL_SKIP_PATTERN='^(kern\.boottime|kern\.cp_time|hw\.pagesize|hw\.availpages|vm\.stats\.|kern\.ipc\.shm_last|kern\.msgbuf_clear|kern\.proc\.|debug\.|hw\.acpi\.|p1003)'

# --- Custom allowed ports (from config.sh) ---
BSD_CUSTOM_ALLOWED_PORTS="${CUSTOM_ALLOWED_PORTS}"

# --- Allowlists (from config.sh) ---
BSD_WHITELISTED_PORTS="${WHITELISTED_PORTS}"
BSD_ACCOUNT_ALLOWLIST="${ACCOUNT_ALLOWLIST}"
BSD_CRONTAB_ALLOWLIST="${CRONTAB_ALLOWLIST}"
BSD_SERVICE_ALLOWLIST="${SERVICE_ALLOWLIST}"

# --- Restore backup directory (for 02 script) ---
BSD_RESTORE_BACKUP_DIR=""

###############################################################################
# Package/Service Management Functions
###############################################################################

pkg_install() {
    pkg install -y "$@"
}

pkg_remove() {
    pkg delete -y "$@" 2>/dev/null || true
    pkg autoremove -y 2>/dev/null || true
}

pkg_is_installed() {
    pkg info "$1" >/dev/null 2>&1
}

svc_enable() {
    local svc="$1"
    if is_protected_service "$svc"; then
        log_skip "svc_enable: refusing to modify protected service '$svc'"
        return 0
    fi
    sysrc "${svc}_enable=YES" 2>/dev/null
}

svc_disable() {
    local svc="$1"
    if is_protected_service "$svc"; then
        log_skip "svc_disable: refusing to modify protected service '$svc'"
        return 0
    fi
    sysrc "${svc}_enable=NO" 2>/dev/null || true
    service "$svc" stop 2>/dev/null || true
}

svc_start() {
    service "$1" start 2>/dev/null
}

svc_restart() {
    service "$1" restart 2>/dev/null
}

svc_is_active() {
    service "$1" status >/dev/null 2>&1
}

svc_is_enabled() {
    local val
    val=$(sysrc -n "${1}_enable" 2>/dev/null || echo "NO")
    [[ "$val" == "YES" ]]
}

###############################################################################
# Internal Helpers
###############################################################################

# _bsd_backup_before_restore <path> — backup before restore (02 script)
_bsd_backup_before_restore() {
    local target="$1"
    [[ -e "$target" ]] || return 0
    if [[ -z "$BSD_RESTORE_BACKUP_DIR" ]]; then
        BSD_RESTORE_BACKUP_DIR="$(_bsd_backup_base)/hardening_restore_${TIMESTAMP}"
    fi
    if [[ ! -d "$BSD_RESTORE_BACKUP_DIR" ]]; then
        mkdir -p "$BSD_RESTORE_BACKUP_DIR"
    fi
    local dest="${BSD_RESTORE_BACKUP_DIR}/$(echo "$target" | tr '/' '_')"
    cp -pR "$target" "$dest" 2>/dev/null && \
        log_info "Pre-restore backup: $target -> $dest" || true
}

_bsd_backup_base() {
    echo "/var/backups/hardening"
}

# _bsd_sshd_config_path — find sshd_config on FreeBSD
_bsd_sshd_config_path() {
    if [[ -f /etc/ssh/sshd_config ]]; then
        echo "/etc/ssh/sshd_config"
    elif [[ -f /usr/local/etc/ssh/sshd_config ]]; then
        echo "/usr/local/etc/ssh/sshd_config"
    else
        echo ""
    fi
}

# _bsd_fstab_ensure_option <mountpoint> <option>
# Adds an option to an existing fstab mount entry, or logs skip.
_bsd_fstab_ensure_option() {
    local mountpoint="$1"
    local option="$2"
    local fstab="/etc/fstab"

    if grep -E "^\s*\S+\s+${mountpoint}\s" "$fstab" 2>/dev/null | grep -q "$option"; then
        log_skip "${mountpoint} fstab already contains ${option}"
        return 0
    fi
    if grep -qE "^\s*\S+\s+${mountpoint}\s" "$fstab" 2>/dev/null; then
        sed -i '' -E "s|^(\s*\S+\s+${mountpoint}\s+\S+\s+)(\S+)(.*)|\1\2,${option}\3|" "$fstab"
        log_ok "${mountpoint} fstab: ${option} appended to existing options"
        return 0
    fi
    log_skip "${mountpoint} not found in fstab — cannot add ${option}"
}

###############################################################################
# Hardening Functions (setup_*)
###############################################################################

# [1] PAM configuration
setup_pam() {
    log_info "===== [1] PAM configuration (FreeBSD) ====="

    # FreeBSD uses /etc/pam.d/ and /etc/login.conf for password policies.
    # Modify /etc/pam.d/system if needed for pam_unix hardening.
    local pam_system="/etc/pam.d/system"
    if [[ -f "$pam_system" ]]; then
        backup_file "$pam_system"
        # Ensure pam_unix enforces SHA-512 hashing
        if grep -q 'pam_unix.so' "$pam_system" 2>/dev/null; then
            log_ok "PAM system module present (pam_unix.so)"
        else
            log_skip "PAM system module configuration — manual review recommended"
        fi
    else
        log_skip "/etc/pam.d/system not found — PAM not configured via pam.d"
    fi

    log_ok "PAM configuration check complete (FreeBSD uses login.conf for policies)"
}

# [2] pf firewall
# Safety: calls guard_network_outbound() after config.
setup_firewall() {
    log_info "===== [2] pf firewall ====="

    local pf_conf="/etc/pf.conf"
    backup_file "$pf_conf"

    # -- Detect SSH port --
    local detected_ssh_port=""
    if command -v sshd >/dev/null 2>&1; then
        detected_ssh_port=$(sshd -T 2>/dev/null | grep '^port ' | awk '{print $2}')
    fi
    if [[ -z "$detected_ssh_port" ]]; then
        detected_ssh_port=$(sockstat -4 -l 2>/dev/null | grep 'sshd' | awk '{print $6}' | grep -o '[0-9]*$' | head -1)
    fi
    if [[ -z "$detected_ssh_port" ]]; then
        detected_ssh_port="22"
        log_warn "SSH port detection failed — using default 22"
    elif [[ "$detected_ssh_port" != "22" ]]; then
        log_info "SSH listening port detected: ${detected_ssh_port} (non-standard)"
    fi

    # -- pf allowed ports --
    local profile_ports=""
    if [[ -n "${BSD_CUSTOM_ALLOWED_PORTS}" ]]; then
        # CUSTOM_ALLOWED_PORTS가 설정됨 — 프로파일 무시, 이 포트만 사용
        # port/tcp 형식에서 포트 번호만 추출 (pf는 포트 번호만 사용)
        profile_ports=$(echo "${BSD_CUSTOM_ALLOWED_PORTS}" | tr ' ' '\n' | sed 's|/tcp||; s|/udp||' | sort -un | tr '\n' ' ' | sed 's/ *$//')
        # SSH 포트가 포함되어 있지 않으면 자동 추가
        if ! echo " $profile_ports " | grep -q " ${detected_ssh_port} "; then
            profile_ports="${detected_ssh_port} ${profile_ports}"
        fi
        log_info "pf: CUSTOM_ALLOWED_PORTS 사용 (ports: ${profile_ports})"
    else
        # 폴백: 프로파일 기반 포트
        profile_ports="${BSD_PF_PROFILES[$BSD_PF_PROFILE]:-}"
        if [[ -z "$profile_ports" ]]; then
            log_warn "Unknown pf profile: ${BSD_PF_PROFILE} — using base"
            profile_ports="${BSD_PF_PROFILES[base]}"
        fi
        # Replace 22 with detected SSH port if non-standard
        if [[ "$detected_ssh_port" != "22" ]]; then
            profile_ports="${profile_ports//22/${detected_ssh_port}}"
            log_info "pf profile SSH port replaced: 22 -> ${detected_ssh_port}"
        fi
        log_info "pf profile: ${BSD_PF_PROFILE} (ports: ${profile_ports})"
    fi

    # Build port list macro
    local port_list
    port_list=$(echo "$profile_ports" | tr ' ' ',')

    # -- Write pf.conf --
    cat > "$pf_conf" <<PF_CONF_EOF
# pf.conf — Security hardening (auto-generated: ${TIMESTAMP})
# Profile: ${BSD_PF_PROFILE}

# Macros
ext_if = "$(route -n get default 2>/dev/null | awk '/interface:/{print $2}' || echo "em0")"
allowed_tcp_ports = "{ ${port_list} }"

# Options
set skip on lo0
set block-policy drop
set loginterface \$ext_if

# Scrub
scrub in all

# Default: block inbound, allow outbound
block in log all
pass out all keep state

# Allow inbound on specified ports
pass in on \$ext_if proto tcp from any to any port \$allowed_tcp_ports flags S/SA keep state

# ICMP: allow ping (echo-request/echo-reply) — workstations need ping
pass in  inet proto icmp icmp-type echoreq keep state
pass out inet proto icmp icmp-type echoreq keep state

# ICMPv6 — allow basic types (do NOT disable IPv6)
pass in  inet6 proto icmp6 icmp6-type { echoreq, echorep, unreach, toobig, timex, paramprob, routeradv, routersol, neighbradv, neighbrsol } keep state
pass out inet6 proto icmp6 all keep state

# Anti-spoofing
antispoof quick for \$ext_if

# Tunnel defense: block large ICMP packets (>128 byte payload)
block in  log quick on \$ext_if proto icmp from any to any max-pkt-size $((20 + 8 + BSD_TUNNEL_ICMP_MAX_PAYLOAD))
block out log quick on \$ext_if proto icmp from any to any max-pkt-size $((20 + 8 + BSD_TUNNEL_ICMP_MAX_PAYLOAD))

# Tunnel defense: block outbound DNS over TCP (tunnels use sustained TCP 53)
block out log quick on \$ext_if proto tcp from any to any port 53
PF_CONF_EOF

    chmod 0600 "$pf_conf"
    log_ok "pf.conf written (profile: ${BSD_PF_PROFILE})"

    # -- Enable and load pf --
    sysrc pf_enable="YES" 2>/dev/null || true
    sysrc pflog_enable="YES" 2>/dev/null || true

    if pfctl -nf "$pf_conf" 2>/dev/null; then
        pfctl -f "$pf_conf" 2>/dev/null || log_warn "pf rules load failed"
        if ! pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
            pfctl -e 2>/dev/null || true
        fi
        log_ok "pf rules loaded and enabled"
    else
        log_error "pf.conf syntax error — not loading"
    fi

    # -- SAFETY: verify required outbound ports are not blocked --
    guard_network_outbound

    log_ok "===== [2] pf firewall complete ====="
}

# [3] cron permissions
setup_cron_permissions() {
    log_info "===== [3] cron directory permissions ====="
    for d in /etc/cron.d /var/cron/tabs; do
        if [[ -e "$d" ]]; then
            chmod og-rwx "$d" && chown root:wheel "$d"
            log_ok "Permissions set: $d"
        else
            log_skip "Not found: $d"
        fi
    done
    if [[ -f /etc/crontab ]]; then
        chmod og-rwx /etc/crontab && chown root:wheel /etc/crontab
        log_ok "/etc/crontab permissions set"
    fi
}

# [4] sysctl — kernel security settings (NO IPv6 disable)
setup_sysctl() {
    log_info "===== [4] sysctl kernel security settings ====="
    local sysctl_file="/etc/sysctl.conf"
    backup_file "$sysctl_file"

    # Apply settings
    local failed=0
    for key in "${!BSD_SYSCTL_SETTINGS[@]}"; do
        local val="${BSD_SYSCTL_SETTINGS[$key]}"
        local current_val
        current_val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")

        if [[ "$current_val" == "$val" ]]; then
            log_skip "sysctl ${key}=${val} (already set)"
        else
            if sysctl "${key}=${val}" >/dev/null 2>&1; then
                log_ok "sysctl ${key}=${val}"
            else
                log_warn "sysctl ${key} failed (kernel may not support it)"
                failed=$((failed + 1))
            fi
        fi

        # Persist to /etc/sysctl.conf
        if grep -q "^${key}=" "$sysctl_file" 2>/dev/null; then
            sed -i '' "s|^${key}=.*|${key}=${val}|" "$sysctl_file"
        elif grep -q "^#${key}=" "$sysctl_file" 2>/dev/null; then
            sed -i '' "s|^#${key}=.*|${key}=${val}|" "$sysctl_file"
        else
            echo "${key}=${val}" >> "$sysctl_file"
        fi
    done

    # Try kern.randompid if available
    if sysctl kern.randompid >/dev/null 2>&1; then
        if sysctl kern.randompid=1 >/dev/null 2>&1; then
            log_ok "sysctl kern.randompid=1"
            if ! grep -q "^kern.randompid=" "$sysctl_file" 2>/dev/null; then
                echo "kern.randompid=1" >> "$sysctl_file"
            fi
        else
            log_warn "sysctl kern.randompid=1 failed"
        fi
    fi

    if [[ $failed -gt 0 ]]; then
        log_warn "sysctl: ${failed} settings failed"
    fi
}

# [5] Sensitive file permissions
setup_sensitive_file_permissions() {
    log_info "===== [5] Sensitive file permissions ====="
    for f in "${BSD_FILES_644[@]}"; do
        [[ -f "$f" ]] && chmod 0644 "$f" && log_ok "chmod 0644: $f" || log_skip "Not found: $f"
    done
    for f in "${BSD_FILES_600[@]}"; do
        [[ -f "$f" ]] && chmod 0600 "$f" && log_ok "chmod 0600: $f" || log_skip "Not found: $f"
    done
    for f in "${BSD_FILES_CHOWN[@]}"; do
        [[ -f "$f" ]] && chown root:wheel "$f"
    done
    log_ok "Sensitive file ownership (root:wheel) set"
}

# [6] System accounts nologin
# SAFETY: skip protected accounts (gt, usr)
setup_nologin_accounts() {
    log_info "===== [6] System accounts nologin ====="
    for acct in "${BSD_NOLOGIN_ACCOUNTS[@]}"; do
        # SAFETY: skip protected accounts
        if is_protected_account "$acct"; then
            log_skip "Protected account — skipping nologin: $acct"
            continue
        fi
        if pw usershow "$acct" >/dev/null 2>&1; then
            local current_shell
            current_shell=$(pw usershow "$acct" 2>/dev/null | cut -d: -f10)
            if [[ "$current_shell" == "/usr/sbin/nologin" ]]; then
                log_skip "${acct}: already nologin"
            else
                pw usermod "$acct" -s /usr/sbin/nologin 2>/dev/null && \
                    log_ok "${acct} -> /usr/sbin/nologin" || \
                    log_warn "${acct} shell change failed"
            fi
        fi
    done
}

# [7] sudoers NOPASSWD removal
# SAFETY: exclude gt lines from NOPASSWD removal.
# SAFETY: exclude 00-gt-nopasswd from sudoers.d processing.
# SAFETY: call guard_account_gt() at the end.
setup_sudoers() {
    log_info "===== [7] sudoers NOPASSWD removal ====="
    local sudoers="/usr/local/etc/sudoers"
    local sudoers_d="/usr/local/etc/sudoers.d"

    if [[ -f "$sudoers" ]]; then
        backup_file "$sudoers"
        if grep -q 'NOPASSWD' "$sudoers"; then
            # Remove NOPASSWD from %wheel lines (but NOT gt lines)
            sed -i '' '/^[[:space:]]*gt[[:space:]]/!{s/^\(%wheel[[:space:]][[:space:]]*ALL=(ALL)\)[[:space:]][[:space:]]*NOPASSWD:[[:space:]][[:space:]]*ALL/\1 ALL/;}' "$sudoers"
            sed -i '' '/^[[:space:]]*gt[[:space:]]/!{s/^\(%wheel[[:space:]][[:space:]]*ALL=(ALL:ALL)\)[[:space:]][[:space:]]*NOPASSWD:[[:space:]][[:space:]]*ALL/\1 ALL/;}' "$sudoers"
            # Remove NOPASSWD from individual user lines, but NOT gt
            sed -i '' '/^[[:space:]]*gt[[:space:]]/!{s/^\([^%#][[:alnum:]_.-][[:alnum:]_.-]*[[:space:]][[:space:]]*ALL=(ALL)\)[[:space:]][[:space:]]*NOPASSWD:[[:space:]][[:space:]]*ALL/\1 ALL/;}' "$sudoers"
            sed -i '' '/^[[:space:]]*gt[[:space:]]/!{s/^\([^%#][[:alnum:]_.-][[:alnum:]_.-]*[[:space:]][[:space:]]*ALL=(ALL:ALL)\)[[:space:]][[:space:]]*NOPASSWD:[[:space:]][[:space:]]*ALL/\1 ALL/;}' "$sudoers"
            if visudo -c -f "$sudoers" 2>/dev/null; then
                log_ok "sudoers NOPASSWD removed (gt lines preserved, syntax validated)"
            else
                log_error "sudoers syntax error! Restoring from backup: ${BACKUP_DIR}"
                local backup_sudoers="${BACKUP_DIR}/_usr_local_etc_sudoers"
                [[ -f "$backup_sudoers" ]] && cp "$backup_sudoers" "$sudoers"
            fi
        else
            log_skip "No NOPASSWD in sudoers"
        fi
    fi

    if [[ -d "$sudoers_d" ]]; then
        local nopasswd_files
        nopasswd_files=$(grep -rl 'NOPASSWD' "$sudoers_d/" 2>/dev/null || true)
        if [[ -n "$nopasswd_files" ]]; then
            while IFS= read -r f; do
                # SAFETY: skip gt's sudoers drop-in
                local fname
                fname=$(basename "$f")
                if [[ "$fname" == "00-gt-nopasswd" ]]; then
                    log_skip "Preserving gt NOPASSWD: $f"
                    continue
                fi
                backup_file "$f"
                sed -i '' 's/NOPASSWD://g' "$f" 2>/dev/null
                log_ok "sudoers.d NOPASSWD removed: $f"
            done <<< "$nopasswd_files"
        fi
    fi

    # SAFETY: ensure gt account is properly configured
    guard_account_gt
}

# [8] SUID bit removal
setup_suid_removal() {
    log_info "===== [8] SUID bit removal ====="
    for f in "${BSD_SUID_REMOVE_TARGETS[@]}"; do
        if [[ -f "$f" ]]; then
            if [[ -u "$f" ]]; then
                chmod u-s "$f"
                log_ok "SUID removed: $f"
            else
                log_skip "No SUID: $f"
            fi
        else
            log_skip "File not found: $f"
        fi
    done
}

# [9] Disable unnecessary services
# SAFETY: check is_protected_service() before disabling
setup_disable_services() {
    log_info "===== [9] Disable unnecessary services ====="
    for svc in "${BSD_DISABLE_SERVICES[@]}"; do
        # SAFETY: check protected services
        if is_protected_service "$svc"; then
            log_skip "Protected service — skipping disable: $svc"
            continue
        fi
        if svc_is_enabled "$svc"; then
            svc_disable "$svc"
            log_ok "Disabled: $svc"
        else
            log_skip "Already disabled or not found: $svc"
        fi
    done
}

# [10] Lock accounts with empty passwords
# SAFETY: skip protected accounts (gt, usr)
setup_lock_empty_password() {
    log_info "===== [10] Lock empty password accounts ====="
    local locked_count=0
    while IFS= read -r user; do
        if [[ -n "$user" ]]; then
            # SAFETY: skip protected accounts
            if is_protected_account "$user"; then
                log_skip "Protected account — skipping lock: $user"
                continue
            fi
            pw lock "$user" 2>/dev/null || true
            log_ok "Account locked: $user"
            locked_count=$((locked_count + 1))
        fi
    done < <(awk -F: '($2==""){print $1}' /etc/master.passwd 2>/dev/null)
    if [[ $locked_count -eq 0 ]]; then
        log_skip "No accounts with empty passwords"
    fi
}

# [11] SSH hardening
setup_ssh_hardening() {
    log_info "===== [11] SSH hardening ====="
    local sshd_config
    sshd_config=$(_bsd_sshd_config_path)
    if [[ -z "$sshd_config" ]]; then
        log_skip "sshd_config not found — skipping SSH"
        return
    fi
    backup_file "$sshd_config"

    # FreeBSD: modify sshd_config directly (no sshd_config.d)
    local effective_pw_auth="${BSD_SSH_PASSWORD_AUTH}"
    if [[ "${BSD_SSH_PASSWORD_AUTH}" == "no" ]]; then
        local has_ssh_key=false
        while IFS=: read -r _user _ _ _ _ _ _ _ _home _shell; do
            [[ "$_shell" =~ (nologin|false)$ ]] && continue
            if [[ -f "${_home}/.ssh/authorized_keys" ]] && [[ -s "${_home}/.ssh/authorized_keys" ]]; then
                has_ssh_key=true
                break
            fi
        done < /etc/master.passwd
        if [[ "$has_ssh_key" == "false" ]]; then
            log_warn "No SSH keys found — keeping PasswordAuthentication=yes to avoid lockout"
            effective_pw_auth="yes"
        fi
    fi
    # Protect automation account from password auth lockout
    if [[ -n "${ANSIBLE_ACCOUNT:-}" ]] && [[ "${effective_pw_auth}" == "no" ]]; then
        local ansible_home
        ansible_home=$(pw usershow "$ANSIBLE_ACCOUNT" 2>/dev/null | cut -d: -f9)
        if [[ -n "$ansible_home" ]] && [[ ! -s "${ansible_home}/.ssh/authorized_keys" ]]; then
            log_warn "Automation account '${ANSIBLE_ACCOUNT}' has no SSH key — forcing PasswordAuthentication=yes"
            effective_pw_auth="yes"
        fi
    fi

    # Apply SSH settings by replacing/appending in sshd_config
    local -A ssh_settings=(
        ["PermitRootLogin"]="${BSD_SSH_PERMIT_ROOT_LOGIN}"
        ["PasswordAuthentication"]="${effective_pw_auth}"
        ["MaxAuthTries"]="${BSD_SSH_MAX_AUTH_TRIES}"
        ["PermitEmptyPasswords"]="no"
        ["X11Forwarding"]="no"
        ["AllowTcpForwarding"]="no"
        ["AllowAgentForwarding"]="no"
        ["AllowStreamLocalForwarding"]="no"
        ["PermitTunnel"]="no"
        ["GatewayPorts"]="no"
        ["ClientAliveInterval"]="${BSD_SSH_CLIENT_ALIVE_INTERVAL}"
        ["ClientAliveCountMax"]="${BSD_SSH_CLIENT_ALIVE_COUNT_MAX}"
        ["LoginGraceTime"]="${BSD_SSH_LOGIN_GRACE_TIME}"
        ["Banner"]="/etc/motd"
        ["UsePAM"]="yes"
        ["HostbasedAuthentication"]="no"
        ["IgnoreRhosts"]="yes"
        ["MaxSessions"]="4"
        ["MaxStartups"]="10:30:60"
    )

    for key in "${!ssh_settings[@]}"; do
        local val="${ssh_settings[$key]}"
        if grep -qE "^[[:space:]]*${key}[[:space:]]" "$sshd_config" 2>/dev/null; then
            sed -i '' "s|^[[:space:]]*${key}[[:space:]].*|${key} ${val}|" "$sshd_config"
        elif grep -qE "^[[:space:]]*#[[:space:]]*${key}[[:space:]]" "$sshd_config" 2>/dev/null; then
            sed -i '' "s|^[[:space:]]*#[[:space:]]*${key}[[:space:]].*|${key} ${val}|" "$sshd_config"
        else
            echo "${key} ${val}" >> "$sshd_config"
        fi
    done

    if sshd -t 2>/dev/null; then
        if service sshd reload 2>/dev/null; then
            sleep 1  # Allow sshd to complete reload before continuing
            log_ok "SSH hardening applied and service reloaded"
        else
            log_warn "SSH service reload failed"
        fi
        local verify_root verify_pw
        verify_root=$(sshd -T 2>/dev/null | grep '^permitrootlogin ' | awk '{print $2}')
        verify_pw=$(sshd -T 2>/dev/null | grep '^passwordauthentication ' | awk '{print $2}')
        [[ "$verify_root" == "${BSD_SSH_PERMIT_ROOT_LOGIN}" ]] && \
            log_ok "Verify OK: PermitRootLogin=${verify_root}" || \
            log_warn "Verify FAIL: PermitRootLogin expected=${BSD_SSH_PERMIT_ROOT_LOGIN}, actual=${verify_root}"
        [[ "$verify_pw" == "${effective_pw_auth}" ]] && \
            log_ok "Verify OK: PasswordAuthentication=${verify_pw}" || \
            log_warn "Verify FAIL: PasswordAuthentication expected=${effective_pw_auth}, actual=${verify_pw}"
    else
        log_error "sshd config syntax error — rolling back"
        local backup_sshd="${BACKUP_DIR}/$(echo "$sshd_config" | tr '/' '_')"
        [[ -f "$backup_sshd" ]] && cp "$backup_sshd" "$sshd_config"
    fi
}

# [12] login.conf — FreeBSD password policies
setup_login_conf() {
    log_info "===== [12] login.conf password policies ====="
    local login_conf="/etc/login.conf"
    if [[ ! -f "$login_conf" ]]; then
        log_skip "login.conf not found"
        return
    fi
    backup_file "$login_conf"

    # Set password format to blowfish (bcrypt)
    if grep -q ':passwd_format=' "$login_conf" 2>/dev/null; then
        sed -i '' 's/:passwd_format=[^:]*/:passwd_format=blf:/' "$login_conf"
    else
        # Add to default class
        sed -i '' '/^default:/,/^[^[:space:]]/{
            /:\\$/a\
\t:passwd_format=blf:\\
        }' "$login_conf" 2>/dev/null || true
    fi

    # Set minimum password length
    if grep -q ':minpasswordlen=' "$login_conf" 2>/dev/null; then
        sed -i '' 's/:minpasswordlen=[^:]*/:minpasswordlen=8:/' "$login_conf"
    fi

    # Set mixpasswordcase
    if grep -q ':mixpasswordcase=' "$login_conf" 2>/dev/null; then
        sed -i '' 's/:mixpasswordcase=[^:]*/:mixpasswordcase=true:/' "$login_conf"
    fi

    # Set password aging (warnpassword, warnexpire)
    if grep -q ':passwordtime=' "$login_conf" 2>/dev/null; then
        sed -i '' "s/:passwordtime=[^:]*/:passwordtime=${BSD_PASS_MAX_DAYS}d:/" "$login_conf"
    fi

    # Rebuild login.conf.db
    if command -v cap_mkdb >/dev/null 2>&1; then
        cap_mkdb "$login_conf" 2>/dev/null && \
            log_ok "login.conf.db rebuilt" || \
            log_warn "cap_mkdb failed"
    fi

    log_ok "login.conf password policies applied"
}

# [13] /tmp mount hardening
setup_tmp_mount_hardening() {
    log_info "===== [13] /tmp mount hardening ====="
    backup_file "/etc/fstab"

    # Try to remount /tmp noexec if it is a separate mount
    if mount | grep -q "on /tmp "; then
        if mount | grep "on /tmp " | grep -q 'noexec'; then
            log_skip "/tmp already noexec"
        else
            mount -o noexec /tmp 2>/dev/null && \
                log_ok "/tmp remount noexec" || \
                log_warn "/tmp remount failed"
        fi
    fi

    _bsd_fstab_ensure_option "/tmp" "noexec"
}

# [14] core dump limits
setup_core_dump_limits() {
    log_info "===== [14] Core dump limits ====="
    local sysctl_file="/etc/sysctl.conf"
    backup_file "$sysctl_file"

    # kern.coredump=0
    if grep -q "^kern.coredump=" "$sysctl_file" 2>/dev/null; then
        sed -i '' 's/^kern.coredump=.*/kern.coredump=0/' "$sysctl_file"
    else
        echo "kern.coredump=0" >> "$sysctl_file"
    fi
    sysctl kern.coredump=0 2>/dev/null || true
    log_ok "Core dump disabled (kern.coredump=0)"

    # Also set in /etc/login.conf
    local login_conf="/etc/login.conf"
    if [[ -f "$login_conf" ]]; then
        if grep -q ':coredumpsize=' "$login_conf" 2>/dev/null; then
            sed -i '' 's/:coredumpsize=[^:]*/:coredumpsize=0:/' "$login_conf"
        fi
        cap_mkdb "$login_conf" 2>/dev/null || true
    fi
}

# [15] Legal warning banner
setup_banner() {
    log_info "===== [15] Legal warning banner ====="
    local banner_text="
====================================================================
                    AUTHORIZED ACCESS ONLY
====================================================================
This system is for authorized use only. All activities are monitored
and logged. Unauthorized access is prohibited and will be prosecuted
to the fullest extent of the law.
===================================================================="
    for f in /etc/motd; do
        backup_file "$f"
        echo "$banner_text" > "$f"
        log_ok "Banner set: $f"
    done
}

# [16] Tunnel hardening (process detection, tool removal, NO auditd changes)
setup_tunnel_hardening() {
    log_info "===== [16] Tunnel hardening (process detection / tool removal) ====="
    log_info "  NOTE: pf rules handled by firewall setup; auditd rules handled by orchestrator"

    _bsd_tunnel_detect_processes
    _bsd_tunnel_remove_tools
    # NOTE: NO auditd rule changes — auditd is snapshot-only in 01

    log_ok "[16] Tunnel hardening (non-pf, non-auditd) complete"
}

# -- Tunnel process detection --
_bsd_tunnel_detect_processes() {
    log_info "  Tunnel tool process detection"
    local found=0

    for proc in "${BSD_TUNNEL_TOOL_PROCS[@]}"; do
        if pgrep -x "${proc}" >/dev/null 2>&1; then
            local pids
            pids=$(pgrep -x "${proc}" | tr '\n' ',' | sed 's/,$//')
            log_warn "  Tunnel tool running: ${proc} (PID: ${pids})"
            found=1
        fi
    done

    # Check for non-internal direct DNS queries
    local dns_non_std
    dns_non_std=$(sockstat -4 2>/dev/null \
                  | awk '$6 ~ /:53$/ && $6 !~ /^(127\.|10\.|172\.|192\.168\.)/ {print}' \
                  || true)
    if [[ -n "${dns_non_std}" ]]; then
        log_warn "  Non-internal direct DNS queries detected (possible DNS tunneling):"
        echo "${dns_non_std}" | while IFS= read -r line; do
            log_warn "    -> ${line}"
        done
        found=1
    fi

    [[ $found -eq 0 ]] && log_ok "  No tunnel tool processes detected"
}

# -- Tunnel tool package removal --
_bsd_tunnel_remove_tools() {
    log_info "  Tunnel tool package removal"

    local removed=0
    for tpkg in "${BSD_TUNNEL_PKGS[@]}"; do
        if pkg info "${tpkg}" >/dev/null 2>&1; then
            local rc=0
            pkg delete -y "${tpkg}" >/dev/null 2>&1 || rc=$?
            if [[ $rc -eq 0 ]]; then
                log_ok "  Package removed: ${tpkg}"
            else
                log_warn "  Package removal failed (rc=${rc}): ${tpkg}"
            fi
            removed=$((removed + 1))
        fi
    done
    [[ $removed -gt 0 ]] && pkg autoremove -y >/dev/null 2>&1 || true

    [[ $removed -eq 0 ]] && log_skip "  No tunnel tool packages to remove"

    for bin in "${BSD_TUNNEL_BINS[@]}"; do
        if [[ -f "${bin}" ]]; then
            backup_file "${bin}"
            rm -f "${bin}" 2>/dev/null \
                && log_ok "  Executable deleted: ${bin}" \
                || { chmod a-x "${bin}" 2>/dev/null && log_warn "  Delete failed, exec permission removed: ${bin}"; }
        fi
    done
}

# [auditd] Install only — NO config or rule changes (snapshot-only in 01)
setup_auditd() {
    log_info "===== [auditd] Ensure auditd is available (no config changes) ====="
    if command -v auditd >/dev/null 2>&1; then
        log_skip "auditd already available"
    else
        log_info "Installing auditd..."
        pkg install -y auditd 2>/dev/null || log_warn "auditd install failed (may not be packaged — using base system audit)"
    fi
    # Ensure log directory exists
    if command -v auditd >/dev/null 2>&1 || [[ -f /etc/security/audit_control ]]; then
        mkdir -p /var/audit
        chmod 0700 /var/audit 2>/dev/null || true
        chown root:wheel /var/audit 2>/dev/null || true
    fi
    # NOTE: Do NOT write audit config or modify rules.
    # The orchestrator calls guard_auditd_snapshot_only() separately.
}

###############################################################################
# run_hardening() — Entry point called by 01 orchestrator
###############################################################################
run_hardening() {
    log_info "===== FreeBSD hardening adapter: run_hardening() ====="

    [[ "${HARDEN_PAM}" == "true" ]] && setup_pam || log_skip "[TOGGLE] PAM disabled"
    [[ "${HARDEN_FIREWALL}" == "true" ]] && setup_firewall || log_skip "[TOGGLE] Firewall disabled"
    [[ "${HARDEN_CRON}" == "true" ]] && setup_cron_permissions || log_skip "[TOGGLE] Cron permissions disabled"
    [[ "${HARDEN_SYSCTL}" == "true" ]] && setup_sysctl || log_skip "[TOGGLE] Sysctl disabled"
    [[ "${HARDEN_FILE_PERMISSIONS}" == "true" ]] && setup_sensitive_file_permissions || log_skip "[TOGGLE] File permissions disabled"
    [[ "${HARDEN_ACCOUNTS}" == "true" ]] && setup_nologin_accounts || log_skip "[TOGGLE] Account nologin disabled"
    [[ "${HARDEN_SUDOERS}" == "true" ]] && setup_sudoers || log_skip "[TOGGLE] Sudoers disabled"
    [[ "${HARDEN_SUID}" == "true" ]] && setup_suid_removal || log_skip "[TOGGLE] SUID removal disabled"
    [[ "${HARDEN_SERVICES}" == "true" ]] && setup_disable_services || log_skip "[TOGGLE] Service disable disabled"
    [[ "${HARDEN_EMPTY_PASSWORDS}" == "true" ]] && setup_lock_empty_password || log_skip "[TOGGLE] Empty password lock disabled"
    [[ "${HARDEN_SSH}" == "true" ]] && setup_ssh_hardening || log_skip "[TOGGLE] SSH disabled"
    [[ "${HARDEN_LOGIN_DEFS}" == "true" ]] && setup_login_conf || log_skip "[TOGGLE] Login conf disabled"
    [[ "${HARDEN_MOUNT}" == "true" ]] && setup_tmp_mount_hardening || log_skip "[TOGGLE] Mount hardening disabled"
    [[ "${HARDEN_CORE_DUMP}" == "true" ]] && setup_core_dump_limits || log_skip "[TOGGLE] Core dump disabled"
    [[ "${HARDEN_BANNER}" == "true" ]] && setup_banner || log_skip "[TOGGLE] Banner disabled"
    [[ "${HARDEN_TUNNEL_DEFENSE}" == "true" ]] && setup_tunnel_hardening || log_skip "[TOGGLE] Tunnel defense disabled"
    # auditd install is always run (not toggleable — orchestrator handles snapshot)
    setup_auditd

    log_ok "===== FreeBSD hardening complete ====="
}

###############################################################################
# create_baseline_snapshot() — Called by 01 after hardening
###############################################################################
create_baseline_snapshot() {
    log_info "===== Creating baseline snapshot ====="
    mkdir -p "${BASELINE_SNAPSHOT_DIR}"

    { echo "# Package snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      pkg info 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/packages_baseline.txt" || true

    { echo "# Service state snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      service -e 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/services_baseline.txt" || true

    { echo "# Listening ports snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      sockstat -4 -l 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/ports_baseline.txt" || true

    { echo "# pf rules snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      pfctl -s rules 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/pf_rules_baseline.txt" || true

    { echo "# sysctl settings snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      sysctl -a 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/sysctl_baseline.txt" || true

    { echo "# User accounts snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      cat /etc/passwd 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/passwd_baseline.txt" || true

    local sshd_config
    sshd_config=$(_bsd_sshd_config_path)
    { echo "# SSH config snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      sshd -T 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/sshd_baseline.txt" || true

    { echo "# auditd rules snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      auditctl -l 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/auditd_baseline.txt" || true

    { sysctl -a 2>/dev/null | sed 's/: /=/' | grep -v '^#' | sort
    } > "${BASELINE_SNAPSHOT_DIR}/sysctl_baseline.conf" || true

    { local _perm_targets=(
          "${BSD_FILES_644[@]}" "${BSD_FILES_600[@]}" "${BSD_FILES_O_NORW[@]}"
          /etc/pf.conf
          /etc/sysctl.conf
          /etc/login.conf
      )
      [[ -n "$sshd_config" ]] && _perm_targets+=("$sshd_config")
      for f in "${_perm_targets[@]}"; do
          [[ -e "$f" ]] || continue
          echo "$(stat -f '%Lp' "$f" 2>/dev/null) $(stat -f '%Su:%Sg' "$f" 2>/dev/null) ${f}"
      done
    } > "${BASELINE_SNAPSHOT_DIR}/file_permissions_baseline.txt" || true

    find / -xdev -perm -4000 -type f 2>/dev/null | sort \
        > "${BASELINE_SNAPSHOT_DIR}/suid_files_baseline.txt" || true

    # Enabled services from rc.conf
    { sysrc -a 2>/dev/null | grep '_enable=YES' | sed 's/_enable=.*//' | sort
    } > "${BASELINE_SNAPSHOT_DIR}/enabled_services_baseline.txt" || true

    # Active (running) services
    { service -e 2>/dev/null | sort
    } > "${BASELINE_SNAPSHOT_DIR}/active_services_baseline.txt" || true

    awk -F: '$NF !~ /(nologin|false)/ {print $1":"$NF}' /etc/passwd | sort \
        > "${BASELINE_SNAPSHOT_DIR}/login_accounts_baseline.txt" || true

    pfctl -s rules 2>/dev/null | sort \
        > "${BASELINE_SNAPSHOT_DIR}/pf_rules_sorted_baseline.txt" || true

    auditctl -l 2>/dev/null | sort \
        > "${BASELINE_SNAPSHOT_DIR}/audit_rules_baseline.txt" || true

    { for d in /etc/cron.d /var/cron/tabs /etc/crontab; do
          [[ -e "$d" ]] || continue
          echo "$(stat -f '%Lp' "$d" 2>/dev/null) $(stat -f '%Su:%Sg' "$d" 2>/dev/null) ${d}"
      done
    } > "${BASELINE_SNAPSHOT_DIR}/cron_permissions_baseline.txt" || true

    sshd -T 2>/dev/null | sort \
        > "${BASELINE_SNAPSHOT_DIR}/sshd_effective_baseline.txt" || true

    sockstat -4 -l 2>/dev/null \
        > "${BASELINE_SNAPSHOT_DIR}/listening_ports_baseline.txt" || true

    { echo "PASS_MAX_DAYS=${BSD_PASS_MAX_DAYS}"
      echo "PASS_MIN_DAYS=${BSD_PASS_MIN_DAYS}"
      echo "PASS_WARN_AGE=${BSD_PASS_WARN_AGE}"
      echo "UMASK=${BSD_DEFAULT_UMASK}"
    } > "${BASELINE_SNAPSHOT_DIR}/login_defs_baseline.txt" || true

    # Tunnel process snapshot
    { echo "# Tunnel tool process snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      local _tun_found=false
      for _proc in "${BSD_TUNNEL_TOOL_PROCS[@]}"; do
          pgrep -x "${_proc}" >/dev/null 2>&1 && { echo "RUNNING: ${_proc}"; _tun_found=true; }
      done
      [[ "${_tun_found}" == false ]] && echo "(no tunnel tools detected)"
    } > "${BASELINE_SNAPSHOT_DIR}/tunnel_processes_baseline.txt" || true

    # pf.conf hash
    [[ -f /etc/pf.conf ]] && \
        cp /etc/pf.conf "${BASELINE_SNAPSHOT_DIR}/pf_conf_baseline.conf" || true

    # Integrity hashes
    { local hash_targets=(
          /etc/passwd /etc/master.passwd /etc/group
          /etc/pf.conf /etc/sysctl.conf /etc/login.conf
      )
      [[ -n "$sshd_config" ]] && hash_targets+=("$sshd_config")
      [[ -f /usr/local/etc/sudoers ]] && hash_targets+=("/usr/local/etc/sudoers")
      for f in "${hash_targets[@]}"; do
          [[ -f "$f" ]] && sha256 -q "$f" 2>/dev/null | while read -r h; do echo "$h  $f"; done || true
      done
      while IFS= read -r snap; do
          [[ -f "$snap" ]] && sha256 -q "$snap" 2>/dev/null | while read -r h; do echo "$h  $snap"; done || true
      done < <(find "${BASELINE_SNAPSHOT_DIR}" -maxdepth 1 \
                    \( -name '*.txt' -o -name '*.conf' \) 2>/dev/null)
    } > "${BASELINE_SNAPSHOT_DIR}/INTEGRITY.sha256" || true

    cp "${BASELINE_SNAPSHOT_DIR}/INTEGRITY.sha256" \
       "${BASELINE_SNAPSHOT_DIR}/integrity_hashes.txt" 2>/dev/null || true

    log_ok "Baseline snapshot saved: ${BASELINE_SNAPSHOT_DIR}"
}

###############################################################################
# Check Functions (check_*) — for run_checks()
###############################################################################

# [C1] sysctl check
check_sysctl() {
    log_info "===== [C1] sysctl settings check ====="

    local baseline_file="${BASELINE_SNAPSHOT_DIR}/sysctl_baseline.conf"
    if [[ ! -f "$baseline_file" ]]; then
        log_warn "sysctl baseline file not found — skipping"
        return
    fi

    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue

        local key expected_val
        key="${line%%=*}"
        expected_val="${line#*=}"
        [[ -z "$key" ]] && continue

        if echo "$key" | grep -qE "$BSD_SYSCTL_SKIP_PATTERN"; then
            continue
        fi

        local current_val
        current_val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")

        if [[ "$current_val" == "$expected_val" ]]; then
            log_ok "sysctl ${key} = ${current_val}"
        else
            log_drift "sysctl ${key}: expected=${expected_val}, current=${current_val}"
            if [[ "$MODE" == "auto-restore" ]]; then
                if sysctl "${key}=${expected_val}" >/dev/null 2>&1; then
                    log_restore "sysctl ${key}=${expected_val} restored"
                else
                    log_fail "sysctl ${key} restore failed"
                fi
            fi
        fi
    done < "$baseline_file"
}

# [C2] File permissions check
check_file_permissions() {
    log_info "===== [C2] File permissions check ====="

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
        current_perm=$(stat -f '%Lp' "$filepath" 2>/dev/null)
        current_owner=$(stat -f '%Su:%Sg' "$filepath" 2>/dev/null)
        local drifted=false

        if [[ "$current_perm" != "$expected_perm" ]]; then
            log_drift "Permission changed: $filepath (expected=${expected_perm}, current=${current_perm})"
            drifted=true
            if [[ "$MODE" == "auto-restore" ]]; then
                _bsd_backup_before_restore "$filepath"
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
                _bsd_backup_before_restore "$filepath"
                if chown "$expected_owner" "$filepath" 2>/dev/null; then
                    log_restore "chown ${expected_owner} ${filepath}"
                else
                    log_fail "chown ${expected_owner} ${filepath} failed"
                fi
            fi
        fi

        [[ "$drifted" == "false" ]] && log_ok "OK: $filepath (${current_perm} ${current_owner})"
    done < "$baseline_file"
}

# [C3] SUID files check
check_suid_files() {
    log_info "===== [C3] SUID files check ====="

    local baseline_file="${BASELINE_SNAPSHOT_DIR}/suid_files_baseline.txt"
    if [[ ! -f "$baseline_file" ]]; then
        log_warn "SUID baseline not found — skipping"
        return
    fi

    local current_suid
    current_suid=$(mktemp)
    find / -xdev -perm -4000 -type f 2>/dev/null | sort > "$current_suid"

    local new_suid
    new_suid=$(comm -13 "$baseline_file" "$current_suid")
    if [[ -n "$new_suid" ]]; then
        while IFS= read -r f; do
            log_drift "New SUID file: $f"
            if [[ "$MODE" == "auto-restore" ]]; then
                if chmod u-s "$f" 2>/dev/null; then
                    log_restore "SUID removed: $f"
                else
                    log_fail "SUID remove failed: $f"
                fi
            fi
        done <<< "$new_suid"
    else
        log_ok "No new SUID files"
    fi

    local removed_suid
    removed_suid=$(comm -23 "$baseline_file" "$current_suid")
    if [[ -n "$removed_suid" ]]; then
        while IFS= read -r f; do
            log_info "(info) Baseline SUID file disappeared: $f"
        done <<< "$removed_suid"
    fi

    rm -f "$current_suid"
}

# [C4] Disabled services check
# SAFETY: check is_protected_service() before disabling
check_disabled_services() {
    log_info "===== [C4] Disabled services check ====="

    local baseline_file="${BASELINE_SNAPSHOT_DIR}/enabled_services_baseline.txt"

    if [[ -f "$baseline_file" ]]; then
        local current_services
        current_services=$(mktemp)
        sysrc -a 2>/dev/null | grep '_enable=YES' | sed 's/_enable=.*//' | sort > "$current_services"

        local new_services
        new_services=$(comm -13 "$baseline_file" "$current_services")
        if [[ -n "$new_services" ]]; then
            while IFS= read -r svc; do
                [[ -z "$svc" ]] && continue
                log_drift "New enabled service not in baseline: $svc"
                if [[ "$MODE" == "auto-restore" ]]; then
                    # SAFETY: check protected services
                    if is_protected_service "$svc"; then
                        log_skip "Protected service — skipping disable: $svc"
                        continue
                    fi
                    if echo ",${BSD_SERVICE_ALLOWLIST}," | grep -q ",${svc},"; then
                        log_skip "Allowlist service: ${svc}"
                        continue
                    fi
                    sysrc "${svc}_enable=NO" 2>/dev/null || true
                    service "$svc" stop 2>/dev/null || true
                    log_restore "Service disabled: $svc"
                fi
            done <<< "$new_services"
        else
            log_ok "No new enabled services vs baseline"
        fi

        local removed_services
        removed_services=$(comm -23 "$baseline_file" "$current_services")
        if [[ -n "$removed_services" ]]; then
            while IFS= read -r svc; do
                [[ -z "$svc" ]] && continue
                log_info "(info) Baseline service now disabled: $svc"
            done <<< "$removed_services"
        fi
        rm -f "$current_services"

        # Active services check
        local active_baseline="${BASELINE_SNAPSHOT_DIR}/active_services_baseline.txt"
        if [[ -f "$active_baseline" ]]; then
            local current_active
            current_active=$(mktemp)
            service -e 2>/dev/null | sort > "$current_active"

            local new_active
            new_active=$(comm -13 "$active_baseline" "$current_active")
            if [[ -n "$new_active" ]]; then
                while IFS= read -r svc_path; do
                    [[ -z "$svc_path" ]] && continue
                    local svc_name
                    svc_name=$(basename "$svc_path")
                    log_drift "New active service not in baseline: $svc_name"
                    if [[ "$MODE" == "auto-restore" ]]; then
                        if is_protected_service "$svc_name"; then
                            log_skip "Protected service — skipping stop: $svc_name"
                            continue
                        fi
                        if echo ",${BSD_SERVICE_ALLOWLIST}," | grep -q ",${svc_name},"; then
                            log_skip "Allowlist service: ${svc_name}"
                            continue
                        fi
                        service "$svc_name" stop 2>/dev/null || true
                        log_restore "Service stopped: $svc_name"
                    fi
                done <<< "$new_active"
            else
                log_ok "No new active services vs baseline"
            fi
            rm -f "$current_active"
        fi
    else
        log_warn "Service baseline not found — checking default list"
        for svc in "${BSD_DISABLE_SERVICES[@]}"; do
            if is_protected_service "$svc"; then
                log_skip "Protected service — skipping check: $svc"
                continue
            fi
            if svc_is_enabled "$svc"; then
                log_drift "Service re-enabled: $svc"
                if [[ "$MODE" == "auto-restore" ]]; then
                    svc_disable "$svc"
                    log_restore "Service disabled: $svc"
                fi
            else
                log_ok "Still disabled: $svc"
            fi
        done
    fi
}

# [C5] Login accounts check
# SAFETY: skip protected accounts (gt, usr)
check_login_accounts() {
    log_info "===== [C5] Login accounts check ====="

    local baseline_file="${BASELINE_SNAPSHOT_DIR}/login_accounts_baseline.txt"
    if [[ ! -f "$baseline_file" ]]; then
        log_warn "Account baseline not found — skipping"
        return
    fi

    local current_accounts
    current_accounts=$(mktemp)
    awk -F: '$NF !~ /(nologin|false)/ {print $1":"$NF}' /etc/passwd | sort > "$current_accounts"

    local new_accounts
    new_accounts=$(comm -13 "$baseline_file" "$current_accounts")
    if [[ -n "$new_accounts" ]]; then
        while IFS=: read -r user shell; do
            log_drift "New login-capable account: ${user} (shell: ${shell})"
            if [[ "$MODE" == "auto-restore" ]]; then
                if [[ "$user" == "root" ]]; then
                    log_skip "root account — skipping auto-restore"
                elif is_protected_account "$user"; then
                    log_skip "Protected account — skipping nologin: ${user}"
                elif echo ",${BSD_ACCOUNT_ALLOWLIST}," | grep -q ",${user},"; then
                    log_skip "Allowlist account: ${user}"
                else
                    pw usermod "$user" -s /usr/sbin/nologin 2>/dev/null && \
                        log_restore "${user} -> nologin" || \
                        log_fail "${user} nologin failed"
                fi
            fi
        done <<< "$new_accounts"
    else
        log_ok "No new login-capable accounts"
    fi

    rm -f "$current_accounts"
}

# [C6] pf firewall check
# SAFETY: preserves required outbound ports
check_pf() {
    log_info "===== [C6] pf firewall check ====="

    if ! command -v pfctl >/dev/null 2>&1; then
        log_warn "pfctl not available"
        return
    fi

    # (a) Active state
    if pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
        log_ok "pf active"
    else
        log_drift "pf is not enabled!"
        if [[ "$MODE" == "auto-restore" ]]; then
            pfctl -e 2>/dev/null && \
                log_restore "pf re-enabled" || \
                log_fail "pf enable failed"
        fi
    fi

    # (b) pf.conf integrity
    local baseline_pf="${BASELINE_SNAPSHOT_DIR}/pf_conf_baseline.conf"
    if [[ -f "$baseline_pf" ]] && [[ -f /etc/pf.conf ]]; then
        if ! diff -q /etc/pf.conf "$baseline_pf" >/dev/null 2>&1; then
            log_drift "pf.conf differs from baseline"
            if [[ "$MODE" == "auto-restore" ]]; then
                _bsd_backup_before_restore /etc/pf.conf
                cp "$baseline_pf" /etc/pf.conf
                if pfctl -nf /etc/pf.conf 2>/dev/null; then
                    pfctl -f /etc/pf.conf 2>/dev/null && \
                        log_restore "pf.conf restored from baseline" || \
                        log_fail "pf rules reload failed"
                else
                    log_fail "pf.conf baseline has syntax errors — manual check required"
                fi
            fi
        else
            log_ok "pf.conf matches baseline"
        fi
    else
        log_warn "pf.conf baseline not found — cannot compare"
    fi

    # (c) Rule comparison
    local baseline_rules="${BASELINE_SNAPSHOT_DIR}/pf_rules_sorted_baseline.txt"
    if [[ -f "$baseline_rules" ]]; then
        local current_rules
        current_rules=$(mktemp)
        pfctl -s rules 2>/dev/null | sort > "$current_rules"

        local added_rules
        added_rules=$(comm -13 "$baseline_rules" "$current_rules")
        if [[ -n "$added_rules" ]]; then
            while IFS= read -r rule; do
                [[ -z "$rule" ]] && continue
                log_drift "pf new rule: ${rule}"
            done <<< "$added_rules"
        else
            log_ok "pf rules: match baseline"
        fi

        local removed_rules
        removed_rules=$(comm -23 "$baseline_rules" "$current_rules")
        if [[ -n "$removed_rules" ]]; then
            while IFS= read -r rule; do
                [[ -z "$rule" ]] && continue
                log_drift "pf rule removed: ${rule}"
            done <<< "$removed_rules"
        fi
        rm -f "$current_rules"
    fi

    # SAFETY: verify required outbound ports not blocked
    guard_network_outbound
}

# [C7] sudoers NOPASSWD check
# SAFETY: exclude gt's NOPASSWD from drift detection
check_sudoers() {
    log_info "===== [C7] sudoers NOPASSWD check ====="

    local sudoers="/usr/local/etc/sudoers"
    local sudoers_d="/usr/local/etc/sudoers.d"

    if [[ -f "$sudoers" ]]; then
        if grep -v '^[[:space:]]*gt[[:space:]]' "$sudoers" | grep -q 'NOPASSWD' 2>/dev/null; then
            log_drift "sudoers has NOPASSWD (non-gt lines)!"
            if [[ "$MODE" == "auto-restore" ]]; then
                _bsd_backup_before_restore "$sudoers"
                sed -i '' '/^[[:space:]]*gt[[:space:]]/!{s/^\(%wheel[[:space:]][[:space:]]*ALL=(ALL)\)[[:space:]][[:space:]]*NOPASSWD:[[:space:]][[:space:]]*ALL/\1 ALL/;}' "$sudoers"
                sed -i '' '/^[[:space:]]*gt[[:space:]]/!{s/^\(%wheel[[:space:]][[:space:]]*ALL=(ALL:ALL)\)[[:space:]][[:space:]]*NOPASSWD:[[:space:]][[:space:]]*ALL/\1 ALL/;}' "$sudoers"
                if visudo -c -f "$sudoers" 2>/dev/null; then
                    log_restore "sudoers NOPASSWD removed (gt preserved)"
                else
                    log_fail "sudoers syntax error — manual check required"
                fi
            fi
        else
            log_ok "sudoers: no NOPASSWD (gt excluded from check)"
        fi
    fi

    if [[ -d "$sudoers_d" ]]; then
        local nopasswd_files
        nopasswd_files=$(grep -rl 'NOPASSWD' "$sudoers_d/" 2>/dev/null || true)
        if [[ -n "$nopasswd_files" ]]; then
            while IFS= read -r f; do
                local fname
                fname=$(basename "$f")
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

# [C8] Empty password accounts check
# SAFETY: skip protected accounts
check_empty_passwords() {
    log_info "===== [C8] Empty password accounts check ====="

    local empty_pw_users
    empty_pw_users=$(awk -F: '($2==""){print $1}' /etc/master.passwd 2>/dev/null || true)

    if [[ -n "$empty_pw_users" ]]; then
        while IFS= read -r user; do
            if is_protected_account "$user"; then
                log_skip "Protected account — skipping lock check: $user"
                continue
            fi
            log_drift "Empty password account: $user"
            if [[ "$MODE" == "auto-restore" ]]; then
                pw lock "$user" 2>/dev/null && \
                    log_restore "Account locked: $user" || \
                    log_fail "Account lock failed: $user"
            fi
        done <<< "$empty_pw_users"
    else
        log_ok "No empty password accounts"
    fi
}

# [C9] Suspicious files detection
check_suspicious_files() {
    log_info "===== [C9] Suspicious files detection ====="

    local suspicious_dirs=(/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin)
    for dir in "${suspicious_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local hidden_files
            hidden_files=$(find "$dir" -maxdepth 2 -name '.*' -type f -perm +0111 2>/dev/null || true)
            if [[ -n "$hidden_files" ]]; then
                while IFS= read -r f; do
                    log_drift "Hidden executable: $f"
                done <<< "$hidden_files"
            fi
        fi
    done

    for dir in /tmp /var/tmp; do
        if [[ -d "$dir" ]]; then
            local exec_files
            exec_files=$(find "$dir" -type f -perm +0111 2>/dev/null | head -20 || true)
            if [[ -n "$exec_files" ]]; then
                while IFS= read -r f; do
                    log_drift "Executable in temp dir: $f"
                done <<< "$exec_files"
            fi
        fi
    done

    local unusual_authkeys
    unusual_authkeys=$(find /usr/sbin /sbin /bin -name 'authorized_keys' -type f 2>/dev/null || true)
    if [[ -n "$unusual_authkeys" ]]; then
        while IFS= read -r f; do
            log_drift "Unusual authorized_keys location: $f"
        done <<< "$unusual_authkeys"
    fi

    log_ok "Suspicious files scan complete"
}

# [C10] auditd status check — diff-based against snapshot, restore if drifted
check_auditd() {
    log_info "===== [C10] auditd status check ====="

    # FreeBSD may use its own audit framework or auditd
    if [[ -f /etc/security/audit_control ]]; then
        log_ok "FreeBSD audit_control present"
    fi

    if command -v auditd >/dev/null 2>&1; then
        if service auditd status >/dev/null 2>&1; then
            log_ok "auditd service active"
        else
            log_drift "auditd service not active!"
            if [[ "$MODE" == "auto-restore" ]]; then
                service auditd start 2>/dev/null && \
                    log_restore "auditd restarted" || \
                    log_fail "auditd restart failed"
            fi
        fi
    else
        log_skip "auditd not installed — checking BSM audit"
        if service auditd status >/dev/null 2>&1; then
            log_ok "BSM audit daemon active"
        fi
    fi

    # Diff-based snapshot check
    local snap_dir="${BASELINE_SNAPSHOT_DIR}/auditd"
    if [[ -d "$snap_dir" ]]; then
        # Check auditd.conf / audit_control
        local audit_conf=""
        if [[ -f /etc/security/audit_control ]]; then
            audit_conf="/etc/security/audit_control"
        elif [[ -f /etc/audit/auditd.conf ]]; then
            audit_conf="/etc/audit/auditd.conf"
        elif [[ -f /etc/auditd.conf ]]; then
            audit_conf="/etc/auditd.conf"
        fi
        if [[ -n "$audit_conf" ]] && [[ -f "${snap_dir}/auditd.conf" ]]; then
            if ! diff -q "$audit_conf" "${snap_dir}/auditd.conf" >/dev/null 2>&1; then
                log_drift "audit config differs from baseline snapshot"
                if [[ "$MODE" == "auto-restore" ]]; then
                    _bsd_backup_before_restore "$audit_conf"
                    cp "${snap_dir}/auditd.conf" "$audit_conf" && \
                        log_restore "audit config restored from snapshot" || \
                        log_fail "audit config restore failed"
                    service auditd restart 2>/dev/null || true
                fi
            else
                log_ok "audit config matches baseline snapshot"
            fi
        fi
    fi
}

# [C11] cron permissions check
check_cron_permissions() {
    log_info "===== [C11] cron permissions check ====="

    local baseline_file="${BASELINE_SNAPSHOT_DIR}/cron_permissions_baseline.txt"
    if [[ ! -f "$baseline_file" ]]; then
        log_warn "cron permissions baseline not found — fallback check"
        for d in /etc/cron.d /var/cron/tabs /etc/crontab; do
            [[ -e "$d" ]] || continue
            local perm
            perm=$(stat -f '%Lp' "$d" 2>/dev/null)
            if [[ "${perm: -1}" != "0" ]]; then
                log_drift "cron permission issue: $d (${perm}) — other access possible"
                if [[ "$MODE" == "auto-restore" ]]; then
                    _bsd_backup_before_restore "$d"
                    chmod og-rwx "$d" && chown root:wheel "$d" 2>/dev/null && \
                        log_restore "cron permission restored: $d" || \
                        log_fail "cron permission restore failed: $d"
                fi
            else
                log_ok "cron permission OK: $d (${perm})"
            fi
        done
        return
    fi

    while IFS=' ' read -r expected_perm expected_owner filepath; do
        [[ -z "$filepath" ]] && continue
        [[ -e "$filepath" ]] || continue

        local current_perm current_owner
        current_perm=$(stat -f '%Lp' "$filepath" 2>/dev/null)
        current_owner=$(stat -f '%Su:%Sg' "$filepath" 2>/dev/null)

        if [[ "$current_perm" != "$expected_perm" ]]; then
            log_drift "cron permission changed: $filepath (expected=${expected_perm}, current=${current_perm})"
            if [[ "$MODE" == "auto-restore" ]]; then
                _bsd_backup_before_restore "$filepath"
                chmod "$expected_perm" "$filepath" 2>/dev/null && \
                    log_restore "cron permission restored: $filepath" || \
                    log_fail "cron permission restore failed: $filepath"
            fi
        else
            log_ok "cron permission OK: $filepath (${current_perm})"
        fi
    done < "$baseline_file"
}

# [C12] SSH config check
check_ssh_config() {
    log_info "===== [C12] SSH config check ====="

    if ! command -v sshd >/dev/null 2>&1; then
        log_warn "sshd not installed"
        return
    fi

    if ! service sshd status >/dev/null 2>&1; then
        log_warn "SSH service not active"
    fi

    local sshd_config
    sshd_config=$(_bsd_sshd_config_path)
    if [[ -z "$sshd_config" ]]; then
        log_drift "SSH config file missing"
        return
    fi

    local baseline_file="${BASELINE_SNAPSHOT_DIR}/sshd_effective_baseline.txt"
    if [[ ! -f "$baseline_file" ]]; then
        log_warn "SSH baseline not found — skipping"
        return
    fi

    local effective
    effective=$(sshd -T 2>/dev/null | sort)
    if [[ -z "$effective" ]]; then
        log_warn "sshd -T failed"
        return
    fi

    local check_keys=(
        permitrootlogin passwordauthentication permitemptypasswords
        x11forwarding allowtcpforwarding allowagentforwarding
        maxauthtries hostbasedauthentication ignorerhosts
        clientaliveinterval clientalivecountmax logingracetime
        maxsessions usepam banner
    )

    for key in "${check_keys[@]}"; do
        local baseline_val current_val
        baseline_val=$(grep "^${key} " "$baseline_file" 2>/dev/null | awk '{print $2}')
        current_val=$(echo "$effective" | grep "^${key} " | awk '{print $2}')
        [[ -z "$baseline_val" ]] && continue

        if [[ "$current_val" != "$baseline_val" ]]; then
            log_drift "SSH ${key}: expected=${baseline_val}, current=${current_val:-missing}"
            if [[ "$MODE" == "auto-restore" ]]; then
                _bsd_backup_before_restore "$sshd_config"
                # Restore the setting in sshd_config directly
                local setting_name=""
                case "$key" in
                    permitrootlogin)         setting_name="PermitRootLogin" ;;
                    passwordauthentication)  setting_name="PasswordAuthentication" ;;
                    permitemptypasswords)    setting_name="PermitEmptyPasswords" ;;
                    x11forwarding)           setting_name="X11Forwarding" ;;
                    allowtcpforwarding)      setting_name="AllowTcpForwarding" ;;
                    allowagentforwarding)    setting_name="AllowAgentForwarding" ;;
                    maxauthtries)            setting_name="MaxAuthTries" ;;
                    hostbasedauthentication) setting_name="HostbasedAuthentication" ;;
                    ignorerhosts)            setting_name="IgnoreRhosts" ;;
                    clientaliveinterval)     setting_name="ClientAliveInterval" ;;
                    clientalivecountmax)     setting_name="ClientAliveCountMax" ;;
                    logingracetime)          setting_name="LoginGraceTime" ;;
                    maxsessions)             setting_name="MaxSessions" ;;
                    usepam)                  setting_name="UsePAM" ;;
                    banner)                  setting_name="Banner" ;;
                esac
                if [[ -n "$setting_name" ]]; then
                    if grep -qE "^[[:space:]]*${setting_name}[[:space:]]" "$sshd_config" 2>/dev/null; then
                        sed -i '' "s|^[[:space:]]*${setting_name}[[:space:]].*|${setting_name} ${baseline_val}|" "$sshd_config"
                    else
                        echo "${setting_name} ${baseline_val}" >> "$sshd_config"
                    fi
                fi
                if sshd -t 2>/dev/null; then
                    service sshd reload 2>/dev/null || true
                    sleep 1  # Allow sshd to complete reload before continuing
                    log_restore "SSH ${key}=${baseline_val} restored"
                else
                    log_fail "sshd config syntax error after restore — manual check required"
                fi
            fi
        else
            log_ok "SSH ${key}=${current_val}"
        fi
    done
}

# [C13] Malicious cron/at detection
check_malicious_cron() {
    log_info "===== [C13] Malicious cron/at detection ====="

    local crontab_dir="/var/cron/tabs"
    if [[ -d "$crontab_dir" ]]; then
        for ct in "$crontab_dir"/*; do
            [[ -f "$ct" ]] || continue
            local user
            user=$(basename "$ct")
            if [[ "$user" != "root" ]]; then
                if echo ",${BSD_CRONTAB_ALLOWLIST}," | grep -q ",${user},"; then
                    log_skip "crontab allowlist account: ${user}"
                else
                    log_drift "Non-root user crontab: ${user}"
                    log_info "  Content: $(head -5 "$ct" 2>/dev/null)"
                fi
            fi
            if grep -qiE '(nc[[:space:]]+-[elp]|ncat|bash[[:space:]]+-i|/dev/tcp|python.*socket|wget.*\|.*sh|curl.*\|.*sh|mkfifo|reverse|shell)' "$ct" 2>/dev/null; then
                log_drift "Suspicious crontab command (${user}): $(grep -iE '(nc |ncat|bash -i|/dev/tcp|python.*socket|wget.*sh|curl.*sh|mkfifo|reverse|shell)' "$ct" 2>/dev/null | head -3)"
            fi
        done
    fi

    if [[ -d /etc/cron.d ]]; then
        for f in /etc/cron.d/*; do
            [[ -f "$f" ]] || continue
            if grep -qiE '(nc[[:space:]]+-[elp]|ncat|bash[[:space:]]+-i|/dev/tcp|python.*socket|wget.*\|.*sh|curl.*\|.*sh|mkfifo)' "$f" 2>/dev/null; then
                log_drift "/etc/cron.d suspicious file: $f"
            fi
        done
    fi

    if command -v atq >/dev/null 2>&1; then
        local at_count
        at_count=$(atq 2>/dev/null | wc -l)
        if [[ "$at_count" -gt 0 ]]; then
            log_drift "Pending at jobs: ${at_count}"
            atq 2>/dev/null | while read -r line; do
                log_info "  at: $line"
            done
        else
            log_ok "No pending at jobs"
        fi
    fi

    log_ok "cron/at check complete"
}

# [C14] Network listening ports check
check_network() {
    log_info "===== [C14] Network listening ports check ====="

    local baseline_file="${BASELINE_SNAPSHOT_DIR}/listening_ports_baseline.txt"
    local current_ports
    current_ports=$(sockstat -4 -l 2>/dev/null)

    if [[ -f "$baseline_file" ]]; then
        local current_addrs baseline_addrs
        current_addrs=$(echo "$current_ports" | awk 'NR>1 {print $6}' | sort -u)
        baseline_addrs=$(awk 'NR>1 {print $6}' "$baseline_file" 2>/dev/null | sort -u)

        local new_ports
        new_ports=$(comm -13 <(echo "$baseline_addrs") <(echo "$current_addrs"))
        if [[ -n "$new_ports" ]]; then
            while IFS= read -r addr; do
                local proc_info
                proc_info=$(echo "$current_ports" | grep "$addr" | awk '{print $1, $2}')
                log_drift "New listening port: ${addr} (${proc_info})"
            done <<< "$new_ports"
        else
            log_ok "No new listening ports vs baseline"
        fi
    fi

    local suspect_ports=(4444 5555 6666 7777 8888 9999 1234 31337 12345 54321)
    for port in "${suspect_ports[@]}"; do
        if echo ",${BSD_WHITELISTED_PORTS}," | grep -q ",${port},"; then
            continue
        fi
        if echo "$current_ports" | grep -q ":${port} " 2>/dev/null; then
            local proc
            proc=$(echo "$current_ports" | grep ":${port} " | awk '{print $1, $2}')
            log_drift "Suspicious port listening: :${port} (${proc})"
        fi
    done
}

# [C15] Suspicious processes check
check_suspicious_processes() {
    log_info "===== [C15] Suspicious processes check ====="

    local suspect_patterns='(cryptominer|xmrig|kinsing|kdevtmpfsi|kthreaddi|\.hidden|/tmp/\.)'
    local suspect_procs
    suspect_procs=$(ps auxww 2>/dev/null | grep -iE "$suspect_patterns" | grep -v grep || true)
    if [[ -n "$suspect_procs" ]]; then
        while IFS= read -r line; do
            log_drift "Suspicious process: $line"
        done <<< "$suspect_procs"
    fi

    local tmp_procs
    tmp_procs=$(ps auxww 2>/dev/null | awk '$NF ~ /^(\/tmp\/|\/var\/tmp\/)/' || true)
    if [[ -n "$tmp_procs" ]]; then
        while IFS= read -r line; do
            log_drift "Running from temp path: $line"
        done <<< "$tmp_procs"
    else
        log_ok "No temp path processes"
    fi
}

# [C16] UID 0 backdoor accounts check
check_uid0_accounts() {
    log_info "===== [C16] UID 0 backdoor accounts check ====="

    local uid0_users
    uid0_users=$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null)
    local uid0_count=0

    while IFS= read -r user; do
        uid0_count=$((uid0_count + 1))
        if [[ "$user" != "root" ]] && [[ "$user" != "toor" ]]; then
            log_drift "Non-root UID 0 account: ${user} (possible backdoor!)"
        fi
    done <<< "$uid0_users"

    if [[ "$uid0_count" -le 2 ]]; then
        log_ok "UID 0 accounts: expected (root/toor only)"
    fi
}

# [C17] Tunnel defense check
check_tunnel_defense() {
    log_info "===== [C17] Tunnel defense check ====="

    # (a) pf rules check for tunnel defense
    log_info "  [17-a] pf tunnel defense rules"
    local pf_rules
    pf_rules=$(pfctl -s rules 2>/dev/null || true)

    if echo "$pf_rules" | grep -q "max-pkt-size" 2>/dev/null; then
        log_ok "  ICMP large packet block rule present in pf"
    else
        log_drift "  ICMP large packet block rule missing from pf"
    fi

    if echo "$pf_rules" | grep -q "block.*proto tcp.*port 53" 2>/dev/null; then
        log_ok "  DNS over TCP outbound block present in pf"
    else
        log_drift "  DNS over TCP outbound block missing from pf"
    fi

    # (b) Tunnel tool process detection
    log_info "  [17-b] Tunnel tool process detection"
    local _proc_found=false
    for proc in "${BSD_TUNNEL_TOOL_PROCS[@]}"; do
        if pgrep -x "$proc" >/dev/null 2>&1; then
            local pids
            pids=$(pgrep -x "$proc" | tr '\n' ',' | sed 's/,$//')
            log_drift "  Tunnel tool running: ${proc} (PID: ${pids})"
            _proc_found=true
        fi
    done

    # Check DNS queries via non-standard paths
    local dns_non_std
    dns_non_std=$(sockstat -4 2>/dev/null \
                  | awk '$6 ~ /:53$/ && $6 !~ /^(127\.|10\.|172\.|192\.168\.)/ {print}' \
                  || true)
    if [[ -n "$dns_non_std" ]]; then
        log_drift "  Non-internal direct DNS queries detected (possible DNS tunneling):"
        echo "$dns_non_std" | while IFS= read -r line; do
            log_info "    -> $line"
        done
        _proc_found=true
    fi

    [[ "$_proc_found" == false ]] && log_ok "  No tunnel tools/processes detected"

    # (c) Tunnel tool binary residue check
    log_info "  [17-c] Tunnel tool binary residue check"
    local _bin_found=false
    for bin in "${BSD_TUNNEL_BINS[@]}"; do
        if [[ -f "$bin" ]]; then
            log_drift "  Tunnel tool binary residue: $bin"
            _bin_found=true
            if [[ "$MODE" == "auto-restore" ]]; then
                rm -f "$bin" 2>/dev/null && \
                    log_restore "  Binary deleted: $bin" || \
                    { chmod a-x "$bin" 2>/dev/null && \
                      log_restore "  Exec permission removed (delete failed): $bin" || \
                      log_fail "  Delete/chmod both failed: $bin"; }
            fi
        fi
    done
    [[ "$_bin_found" == false ]] && log_ok "  No residual tunnel tool binaries"
}

###############################################################################
# run_checks() — Entry point called by 02 orchestrator
# Uses global $MODE ("check-only" or "auto-restore")
###############################################################################
run_checks() {
    log_info "===== FreeBSD adapter: run_checks() (mode=${MODE}) ====="

    [[ "${HARDEN_SYSCTL}" == "true" ]] && check_sysctl || log_skip "[TOGGLE] Sysctl check skipped"
    [[ "${HARDEN_FILE_PERMISSIONS}" == "true" ]] && check_file_permissions || log_skip "[TOGGLE] File permissions check skipped"
    [[ "${HARDEN_SUID}" == "true" ]] && check_suid_files || log_skip "[TOGGLE] SUID check skipped"
    [[ "${HARDEN_SERVICES}" == "true" ]] && check_disabled_services || log_skip "[TOGGLE] Service check skipped"
    [[ "${HARDEN_ACCOUNTS}" == "true" ]] && check_login_accounts || log_skip "[TOGGLE] Account check skipped"
    [[ "${HARDEN_FIREWALL}" == "true" ]] && check_pf || log_skip "[TOGGLE] Firewall check skipped"
    [[ "${HARDEN_SUDOERS}" == "true" ]] && check_sudoers || log_skip "[TOGGLE] Sudoers check skipped"
    [[ "${HARDEN_EMPTY_PASSWORDS}" == "true" ]] && check_empty_passwords || log_skip "[TOGGLE] Empty passwords check skipped"
    check_suspicious_files     # [C9] always run
    check_auditd               # [C10] always run
    [[ "${HARDEN_CRON}" == "true" ]] && check_cron_permissions || log_skip "[TOGGLE] Cron check skipped"
    [[ "${HARDEN_SSH}" == "true" ]] && check_ssh_config || log_skip "[TOGGLE] SSH check skipped"
    check_malicious_cron       # [C13] always run (security)
    check_network              # [C14] always run (security)
    check_suspicious_processes # [C15] always run (security)
    check_uid0_accounts        # [C16] always run (security)
    [[ "${HARDEN_TUNNEL_DEFENSE}" == "true" ]] && check_tunnel_defense || log_skip "[TOGGLE] Tunnel defense check skipped"

    log_ok "===== FreeBSD drift checks complete ====="
}

###############################################################################
# kill_other_ssh_sessions() — Called by 01 at end
###############################################################################
kill_other_ssh_sessions() {
    log_info "===== Kill other SSH sessions ====="
    local killed_count=0

    local my_sshd_pids=()
    local check_pid=$$
    local depth=0
    while [[ $depth -lt 10 && $check_pid -gt 1 ]]; do
        local pname pppid
        pname=$(ps -o comm= -p "$check_pid" 2>/dev/null | tr -d ' ')
        pppid=$(ps -o ppid= -p "$check_pid" 2>/dev/null | tr -d ' ')
        if [[ "$pname" == "sshd" ]]; then
            if [[ "$pppid" != "1" && "$pppid" != "0" ]]; then
                my_sshd_pids+=("$check_pid")
            fi
        fi
        check_pid="$pppid"
        depth=$((depth + 1))
    done

    if [[ ${#my_sshd_pids[@]} -eq 0 ]]; then
        log_skip "Cannot find current session sshd process — skipping session kill"
        return 0
    fi
    log_info "  Current session sshd PID: ${my_sshd_pids[*]}"

    while IFS= read -r pid; do
        [[ -z "$pid" ]] && continue

        local is_mine=false
        for my_pid in "${my_sshd_pids[@]}"; do
            if [[ "$pid" == "$my_pid" ]]; then
                is_mine=true
                break
            fi
        done
        [[ "$is_mine" == true ]] && continue

        local ppid
        ppid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
        if [[ "$ppid" == "1" ]] || [[ "$ppid" == "0" ]]; then
            log_info "  Skipping master sshd: PID ${pid}"
            continue
        fi

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

        if kill -HUP "$pid" 2>/dev/null; then
            log_ok "  SSH session killed: PID ${pid} (user: ${user:-unknown})"
            killed_count=$((killed_count + 1))
        else
            log_warn "  SSH session kill failed: PID ${pid}"
        fi
    done < <(pgrep -x sshd 2>/dev/null || true)

    if [[ $killed_count -eq 0 ]]; then
        log_skip "No other SSH sessions to kill"
    else
        log_ok "Total ${killed_count} SSH sessions killed"
    fi
}
