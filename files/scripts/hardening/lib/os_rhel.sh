#!/usr/bin/env bash
# lib/os_rhel.sh — RHEL/Rocky/AlmaLinux hardening adapter
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
# Compatibility: bash 4.0+ (RHEL 7+ always has bash 4.2+)

###############################################################################
# Guard against double-sourcing
###############################################################################
[[ -n "${_OS_RHEL_SH_LOADED:-}" ]] && return 0
_OS_RHEL_SH_LOADED=1

###############################################################################
# Configuration Constants
###############################################################################

# --- Package manager detection ---
if command -v dnf >/dev/null 2>&1; then
    readonly RHEL_PKG_MGR="dnf"
else
    readonly RHEL_PKG_MGR="yum"
fi

# --- PAM password quality (from config.sh) ---
RHEL_PWQUALITY_MINLEN="${PAM_PWQUALITY_MINLEN}"
readonly RHEL_PWQUALITY_DCREDIT=-1
readonly RHEL_PWQUALITY_UCREDIT=-1
readonly RHEL_PWQUALITY_LCREDIT=-1
readonly RHEL_PWQUALITY_OCREDIT=-1
RHEL_PWQUALITY_MINCLASS="${PAM_PWQUALITY_MINCLASS}"
readonly RHEL_PWQUALITY_MAXREPEAT=3
readonly RHEL_PWQUALITY_MAXCLASSREPEAT=3

# --- Blocked kernel modules (from config.sh) ---
IFS=' ' read -ra RHEL_BLOCKED_MODULES <<< "$BLOCKED_MODULES"

# --- sysctl security settings (NO IPv6 disable) ---
declare -A RHEL_SYSCTL_SETTINGS=(
    ["net.ipv4.conf.all.send_redirects"]="0"
    ["net.ipv4.conf.default.send_redirects"]="0"
    ["net.ipv4.conf.all.accept_source_route"]="0"
    ["net.ipv4.conf.default.accept_source_route"]="0"
    ["net.ipv4.conf.all.accept_redirects"]="0"
    ["net.ipv4.conf.default.accept_redirects"]="0"
    ["net.ipv4.conf.all.secure_redirects"]="0"
    ["net.ipv4.conf.default.secure_redirects"]="0"
    ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
    ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
    ["net.ipv4.conf.all.log_martians"]="1"
    ["net.ipv4.conf.default.log_martians"]="1"
    ["net.ipv4.tcp_syncookies"]="1"
    ["kernel.randomize_va_space"]="2"
    ["kernel.sysrq"]="0"
    ["fs.suid_dumpable"]="0"
    ["fs.protected_hardlinks"]="1"
    ["fs.protected_symlinks"]="1"
    # IPv6 hardening (redirect/source-route/RA) — does NOT disable IPv6
    ["net.ipv6.conf.all.accept_redirects"]="0"
    ["net.ipv6.conf.default.accept_redirects"]="0"
    ["net.ipv6.conf.all.accept_source_route"]="0"
    ["net.ipv6.conf.default.accept_source_route"]="0"
    ["net.ipv6.conf.all.accept_ra"]="0"
    ["net.ipv6.conf.default.accept_ra"]="0"
    ["net.ipv6.conf.all.forwarding"]="0"
)
# Conditionally set ip_forward=0 based on config.sh
if [[ "${SYSCTL_DISABLE_IP_FORWARD}" == "true" ]]; then
    RHEL_SYSCTL_SETTINGS["net.ipv4.ip_forward"]="0"
fi

# --- Sensitive file permissions ---
readonly RHEL_FILES_644=(/etc/passwd /etc/group /etc/passwd- /etc/group-)
readonly RHEL_FILES_600=(/etc/shadow /etc/gshadow /etc/shadow- /etc/gshadow-)
readonly RHEL_FILES_CHOWN=(/etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/passwd- /etc/group- /etc/shadow- /etc/gshadow-)

# --- other permission removal targets ---
readonly RHEL_FILES_O_NORW=(
    /etc/fstab /etc/ftpusers /etc/group /etc/hosts
    /etc/hosts.allow /etc/hosts.equiv /etc/ssh
    /etc/hosts.lpd /etc/inetd.conf /etc/login.access
    /etc/login.defs /etc/ssh/sshd_config /etc/sysctl.conf
    /etc/crontab /usr/bin/crontab /usr/bin/at
    /usr/bin/atq /usr/bin/atrm /usr/bin/batch
    /var/log /var/spool/cron
)

# --- SUID removal targets (from config.sh) ---
IFS=' ' read -ra RHEL_SUID_REMOVE_TARGETS <<< "$SUID_REMOVE_TARGETS"

# --- nologin target system accounts (RHEL-specific) ---
readonly RHEL_NOLOGIN_ACCOUNTS=(
    daemon bin adm lp sync shutdown halt mail operator games
    ftp nobody dbus systemd-coredump systemd-resolve
    tss polkitd unbound sssd sshd chrony rngd setroubleshoot
    cockpit-ws cockpit-wsinstance rpc rpcuser nfsnobody saslauth
    postfix ntp abrt avahi avahi-autoipd gdm gnome-initial-setup
    libstoragemgmt oprofile tcpdump saned geoclue flatpak
    colord clevis dnsmasq rtkit pesign pipewire
)
readonly RHEL_FALSE_SHELL_ACCOUNTS=(
    systemd-network systemd-timesync
)

# --- Services to disable (from config.sh) ---
# Convert space-separated string to array, append .service suffix if missing
IFS=' ' read -ra RHEL_DISABLE_SERVICES <<< "$DISABLE_SERVICES"
RHEL_DISABLE_SERVICES=("${RHEL_DISABLE_SERVICES[@]/%/.service}")
# Fix double .service suffix for entries that already had it
RHEL_DISABLE_SERVICES=("${RHEL_DISABLE_SERVICES[@]/%.service.service/.service}")

# --- SSH hardening settings (from config.sh) ---
RHEL_SSH_PERMIT_ROOT_LOGIN="${SSH_PERMIT_ROOT_LOGIN}"
RHEL_SSH_PASSWORD_AUTH="${SSH_PASSWORD_AUTH}"
RHEL_SSH_MAX_AUTH_TRIES="${SSH_MAX_AUTH_TRIES}"
RHEL_SSH_CLIENT_ALIVE_INTERVAL="${SSH_CLIENT_ALIVE_INTERVAL}"
RHEL_SSH_CLIENT_ALIVE_COUNT_MAX="${SSH_CLIENT_ALIVE_COUNT_MAX}"
RHEL_SSH_LOGIN_GRACE_TIME="${SSH_LOGIN_GRACE_TIME}"

# --- Password aging (from config.sh) ---
RHEL_PASS_MAX_DAYS="${PASS_MAX_DAYS}"
RHEL_PASS_MIN_DAYS="${PASS_MIN_DAYS}"
RHEL_PASS_WARN_AGE="${PASS_WARN_AGE}"
RHEL_LOGIN_RETRIES="${LOGIN_RETRIES}"
RHEL_DEFAULT_UMASK="${DEFAULT_UMASK}"

# --- firewalld profile-based port sets (from config.sh) ---
RHEL_FIREWALLD_PROFILE="${HARDENING_PROFILE}"

RHEL_SHM_NOEXEC="${SHM_NOEXEC}"
RHEL_HIDEPID_ENABLED="${HIDEPID_ENABLED}"
RHEL_FAILLOCK_DENY="${FAILLOCK_DENY}"
RHEL_FAILLOCK_UNLOCK_TIME="${FAILLOCK_UNLOCK_TIME}"
RHEL_FAILLOCK_DENY_ROOT="${FAILLOCK_DENY_ROOT}"

declare -A RHEL_FIREWALLD_PROFILES=(
    [base]="22/tcp"
    [web]="22/tcp 80/tcp 443/tcp"
    [ad]="22/tcp 53/tcp 53/udp 88/tcp 389/tcp 389/udp 636/tcp 3268/tcp 3269/tcp"
    [log]="22/tcp 514/udp 1514/tcp 1515/tcp 1516/tcp"
    [full]="22/tcp 53/tcp 53/udp 80/tcp 88/tcp 389/tcp 389/udp 443/tcp 514/udp 636/tcp 953/tcp 1514/tcp 1515/tcp 1516/tcp 3268/tcp 3269/tcp"
)

# --- Tunnel defense settings (from config.sh) ---
RHEL_TUNNEL_DEFENSE_ENABLED="${TUNNEL_DEFENSE_ENABLED}"
RHEL_TUNNEL_ICMP_MAX_PAYLOAD="${TUNNEL_ICMP_MAX_PAYLOAD}"
RHEL_TUNNEL_REMOVE_TOOLS="${TUNNEL_REMOVE_TOOLS}"
readonly RHEL_TUNNEL_DNS_SUSPICIOUS_TOOLS=(iodine iodined dns2tcp dnscapy dnscat dnscat2 dnstunnel)
readonly RHEL_TUNNEL_SOCKS5_PORTS=(1080 1081 8080 8888 9050 9150 1090 3128 8118)
readonly RHEL_TUNNEL_TOOL_PROCS=(
    ptunnel ptunnel-ng icmptunnel icmpsh pingtunnel
    iodine iodined dns2tcp dnscat dnscat2 dnscapy dnstunnel
    chisel ligolo frpc ngrok inlets bore gost
    autossh sshuttle
)
RHEL_TUNNEL_LOCK_RESOLV="${TUNNEL_LOCK_RESOLV}"

# --- Custom allowed ports (from config.sh) ---
RHEL_CUSTOM_ALLOWED_PORTS="${CUSTOM_ALLOWED_PORTS}"

# --- Allowlists (from config.sh) ---
RHEL_WHITELISTED_PORTS="${WHITELISTED_PORTS}"
RHEL_ACCOUNT_ALLOWLIST="${ACCOUNT_ALLOWLIST}"
RHEL_CRONTAB_ALLOWLIST="${CRONTAB_ALLOWLIST}"
RHEL_SERVICE_ALLOWLIST="${SERVICE_ALLOWLIST}"

# --- sysctl skip pattern for checks ---
readonly RHEL_SYSCTL_SKIP_PATTERN='^(dev\.cdrom\.info|fs\.binfmt_misc\.|kernel\.core_modes|kernel\.ns_last_pid|kernel\.random\.uuid|kernel\.random\.boot_id|kernel\.tainted|kernel\.pty\.nr|fs\.dentry-state|fs\.file-nr|fs\.inode-nr|fs\.inode-state|net\.netfilter\.nf_conntrack_count|kernel\.perf_event_max_sample_rate|vm\.stat_interval)'

# --- Tunnel tool binaries ---
readonly RHEL_TUNNEL_BINS=(
    /usr/sbin/iodined /usr/bin/iodine
    /usr/bin/dns2tcp /usr/bin/dnscat
    /usr/local/bin/chisel /usr/local/bin/gost
    /usr/local/bin/ligolo /usr/local/bin/frpc
    /usr/local/bin/bore /usr/local/bin/inlets
    /usr/local/sbin/ptunnel /usr/local/sbin/ptunnel-ng
    /usr/local/bin/dnscat2
)

# --- Tunnel tool packages (rpm names) ---
readonly RHEL_TUNNEL_PKGS=(
    ptunnel ptunnel-ng
    iodine dns2tcp dnscat2
    chisel sshuttle autossh
)

# --- nologin path detection ---
if [[ -f /usr/sbin/nologin ]]; then
    readonly RHEL_NOLOGIN="/usr/sbin/nologin"
elif [[ -f /sbin/nologin ]]; then
    readonly RHEL_NOLOGIN="/sbin/nologin"
else
    readonly RHEL_NOLOGIN="/usr/sbin/nologin"
fi

# --- Restore backup directory (for 02 script) ---
RHEL_RESTORE_BACKUP_DIR=""

###############################################################################
# Package/Service Management Functions
###############################################################################

pkg_install() {
    # Strip dnf-only flags when using yum (yum does not support --allowerasing,
    # --best, --nobest, or --skip-broken in the same form as dnf).
    if [[ "$RHEL_PKG_MGR" == "yum" ]]; then
        local _args=()
        for _a in "$@"; do
            case "$_a" in
                --allowerasing|--best|--nobest) ;;   # drop dnf-only flags
                *) _args+=("$_a") ;;
            esac
        done
        yum install -y "${_args[@]}"
    else
        dnf install -y "$@"
    fi
}

pkg_remove() {
    # Strip dnf-only flags when using yum.
    if [[ "$RHEL_PKG_MGR" == "yum" ]]; then
        local _args=()
        for _a in "$@"; do
            case "$_a" in
                --allowerasing|--best|--nobest) ;;   # drop dnf-only flags
                *) _args+=("$_a") ;;
            esac
        done
        yum remove -y "${_args[@]}" >/dev/null 2>&1 || true
    else
        dnf remove -y "$@" >/dev/null 2>&1 || true
    fi
}

pkg_is_installed() {
    rpm -q "$1" >/dev/null 2>&1
}

svc_enable() {
    local svc="$1"
    if is_protected_service "$svc"; then
        log_skip "svc_enable: refusing to modify protected service '$svc'"
        return 0
    fi
    systemctl enable "$svc" 2>/dev/null
}

svc_disable() {
    local svc="$1"
    if is_protected_service "$svc"; then
        log_skip "svc_disable: refusing to modify protected service '$svc'"
        return 0
    fi
    systemctl disable --now "$svc" 2>/dev/null
}

svc_start() {
    systemctl start "$1" 2>/dev/null
}

svc_restart() {
    systemctl restart "$1" 2>/dev/null
}

svc_is_active() {
    systemctl is-active "$1" >/dev/null 2>&1
}

svc_is_enabled() {
    systemctl is-enabled "$1" >/dev/null 2>&1
}

###############################################################################
# Internal Helpers
###############################################################################

# _rhel_fstab_ensure_mount <mountpoint> <fstab_entry>
_rhel_fstab_ensure_mount() {
    local mountpoint="$1"
    local new_entry="$2"
    local fstab="/etc/fstab"
    local check_keyword="noexec"
    if echo "$new_entry" | grep -q 'hidepid'; then
        check_keyword="hidepid"
    fi
    if grep -E "^\s*\S+\s+${mountpoint}\s" "$fstab" 2>/dev/null | grep -q "$check_keyword"; then
        log_skip "${mountpoint} fstab already contains ${check_keyword}"
        return 0
    fi
    if grep -qE "^\s*\S+\s+${mountpoint}\s" "$fstab" 2>/dev/null; then
        if [[ "$check_keyword" == "hidepid" ]]; then
            sed -i -E "s|^(\s*\S+\s+${mountpoint}\s+\S+\s+)(\S+)(.*)|\1\2,hidepid=2\3|" "$fstab"
            log_ok "${mountpoint} fstab: hidepid=2 appended to existing options"
        else
            grep -v "^[[:space:]]*\S\+[[:space:]]\+${mountpoint}[[:space:]]" "$fstab" > "${fstab}.tmp"
            echo "$new_entry" >> "${fstab}.tmp"
            mv "${fstab}.tmp" "$fstab"
            log_ok "${mountpoint} fstab entry replaced (${check_keyword} added)"
        fi
        return 0
    fi
    echo "$new_entry" >> "$fstab"
    log_ok "${mountpoint} fstab entry added"
}

# _rhel_backup_before_restore <path> — backup before restore (02 script)
_rhel_backup_before_restore() {
    local target="$1"
    [[ -e "$target" ]] || return 0
    if [[ -z "$RHEL_RESTORE_BACKUP_DIR" ]]; then
        RHEL_RESTORE_BACKUP_DIR="$(_rhel_backup_base)/hardening_restore_${TIMESTAMP}"
    fi
    if [[ ! -d "$RHEL_RESTORE_BACKUP_DIR" ]]; then
        mkdir -p "$RHEL_RESTORE_BACKUP_DIR"
    fi
    local dest="${RHEL_RESTORE_BACKUP_DIR}/$(echo "$target" | tr '/' '_')"
    cp -pR "$target" "$dest" 2>/dev/null && \
        log_info "Pre-restore backup: $target -> $dest" || true
}

_rhel_backup_base() {
    echo "/var/backups/hardening"
}

###############################################################################
# firewalld Tunnel Defense Helpers
###############################################################################

# _rhel_firewalld_direct_ensure <ipv> <table> <chain> <priority> <args...>
# Add a direct rule if not already present.
_rhel_firewalld_direct_ensure() {
    local ipv="$1" table="$2" chain="$3" priority="$4"
    shift 4
    local args=("$@")

    if firewall-cmd --direct --query-rule "$ipv" "$table" "$chain" "$priority" "${args[@]}" 2>/dev/null; then
        log_skip "  firewalld direct rule exists: ${chain} ${args[*]}"
        return 0
    fi
    if firewall-cmd --permanent --direct --add-rule "$ipv" "$table" "$chain" "$priority" "${args[@]}" 2>/dev/null; then
        # Also apply at runtime
        firewall-cmd --direct --add-rule "$ipv" "$table" "$chain" "$priority" "${args[@]}" 2>/dev/null || true
        log_ok "  firewalld direct rule added: ${chain} ${args[*]}"
    else
        log_warn "  firewalld direct rule add failed: ${chain} ${args[*]}"
    fi
}

# _rhel_firewalld_write_tunnel_rules
# Applies tunnel defense rules via firewalld direct rules.
_rhel_firewalld_write_tunnel_rules() {
    local icmp_max_len=$((20 + 8 + RHEL_TUNNEL_ICMP_MAX_PAYLOAD))

    log_info "  Applying tunnel defense direct rules to firewalld"

    # -- ICMP large packet blocking --
    _rhel_firewalld_direct_ensure ipv4 filter INPUT 0 \
        -p icmp -m length --length "${icmp_max_len}:65535" \
        -m comment --comment "TUNNEL_ICMP_LARGE_IN" -j DROP

    _rhel_firewalld_direct_ensure ipv4 filter OUTPUT 0 \
        -p icmp -m length --length "${icmp_max_len}:65535" \
        -m comment --comment "TUNNEL_ICMP_LARGE_OUT" -j DROP

    # NOTE: No TUNNEL_ICMP_ECHO_OUT — workstations need ping

    # -- DNS tunnel defense --
    _rhel_firewalld_direct_ensure ipv4 filter OUTPUT 0 \
        -p tcp --dport 53 \
        -m comment --comment "TUNNEL_DNS_TCP_OUT" -j DROP

    _rhel_firewalld_direct_ensure ipv4 filter INPUT 0 \
        -p udp --sport 53 -m length --length 1024:65535 \
        -m comment --comment "TUNNEL_DNS_LARGE_RESP" \
        -j LOG --log-prefix "[TUNNEL_DNS_LARGE_RESP] " --log-level 4

    # -- SOCKS5 tunnel defense --
    if iptables -m string --help 2>&1 | grep -q "string" 2>/dev/null; then
        _rhel_firewalld_direct_ensure ipv4 filter INPUT 0 \
            -p tcp \
            -m string --hex-string "|050100|" --algo bm --from 40 --to 60 \
            -m comment --comment "TUNNEL_SOCKS5_NOAUTH_IN" -j DROP

        _rhel_firewalld_direct_ensure ipv4 filter OUTPUT 0 \
            -p tcp \
            -m string --hex-string "|050100|" --algo bm --from 40 --to 60 \
            -m comment --comment "TUNNEL_SOCKS5_CONN_OUT" -j DROP

        log_ok "  SOCKS5 handshake pattern blocking applied"
    else
        log_warn "  iptables string module unavailable — skipping SOCKS5 pattern blocking"
    fi

    # -- ICMPv6 --
    if command -v ip6tables &>/dev/null; then
        _rhel_firewalld_direct_ensure ipv6 filter INPUT 0 \
            -p icmpv6 --icmpv6-type echo-request \
            -m length --length "${icmp_max_len}:65535" \
            -m comment --comment "TUNNEL_ICMP6_LARGE_IN" -j DROP

        _rhel_firewalld_direct_ensure ipv6 filter OUTPUT 0 \
            -p icmpv6 --icmpv6-type echo-request \
            -m length --length "${icmp_max_len}:65535" \
            -m comment --comment "TUNNEL_ICMP6_LARGE_OUT" -j DROP
    fi

    log_ok "  Tunnel defense direct rules applied to firewalld"
}

# _rhel_tunnel_dns_lock_resolv
_rhel_tunnel_dns_lock_resolv() {
    log_info "  DNS resolv.conf lock"

    if [[ "${RHEL_TUNNEL_LOCK_RESOLV}" != "true" ]]; then
        log_skip "  TUNNEL_LOCK_RESOLV=false — skipping"
        return 0
    fi

    local resolv="/etc/resolv.conf"
    if [[ ! -f "${resolv}" ]]; then
        log_skip "  /etc/resolv.conf not found — skipping"
        return 0
    fi

    # Detection order:
    # 1. systemd-resolved running + resolv.conf is symlink → systemd-resolved manages DNS
    # 2. NetworkManager running + /etc/NetworkManager/ exists → NM manages DNS
    # 3. Neither → direct resolv.conf management (chattr)

    # systemd-resolved (less common on RHEL, but possible)
    if systemctl is-active systemd-resolved &>/dev/null 2>&1; then
        if [[ -L "${resolv}" ]]; then
            log_info "  /etc/resolv.conf is symlink (systemd-resolved managed)"
            local resolved_conf="/etc/systemd/resolved.conf.d/99-tunnel-hardening.conf"
            mkdir -p /etc/systemd/resolved.conf.d
            {
                echo "# DNS tunnel defense — auto-generated: ${TIMESTAMP}"
                echo "[Resolve]"
                echo "DNSSEC=allow-downgrade"
                echo "DNSOverTLS=opportunistic"
                echo "ReadEtcHosts=yes"
            } > "${resolved_conf}"
            systemctl restart systemd-resolved 2>/dev/null || true
            log_ok "  systemd-resolved DNS settings applied: ${resolved_conf}"
            return 0
        fi
    fi

    # NetworkManager typically manages resolv.conf on RHEL
    if systemctl is-active NetworkManager &>/dev/null 2>&1 && [[ -d /etc/NetworkManager ]]; then
        log_info "  NetworkManager manages DNS — skipping chattr on resolv.conf"
        local nm_dns_conf="/etc/NetworkManager/conf.d/99-dns-hardening.conf"
        mkdir -p /etc/NetworkManager/conf.d
        {
            echo "# DNS tunnel defense — auto-generated: ${TIMESTAMP}"
            echo "[main]"
            echo "dns=default"
        } > "${nm_dns_conf}"
        log_ok "  NetworkManager DNS settings applied: ${nm_dns_conf}"
        return 0
    fi

    backup_file "${resolv}"

    {
        echo "# DNS tunnel defense — auto-generated (${TIMESTAMP})"
        echo "# This file is locked with chattr +i."
        grep -v "^#" "${BACKUP_DIR}/$(echo "${resolv}" | tr '/' '_')" 2>/dev/null \
            || grep -v "^#" "${resolv}" 2>/dev/null || true
        echo "options timeout:2 attempts:3 rotate"
    } > "${resolv}"

    # Restore SELinux context
    if command -v restorecon &>/dev/null; then
        restorecon "${resolv}" 2>/dev/null || true
    fi

    if command -v chattr &>/dev/null; then
        chattr -i "${resolv}" 2>/dev/null || true
        chattr +i "${resolv}" 2>/dev/null \
            && log_ok "  /etc/resolv.conf immutable (chattr +i) applied" \
            || log_warn "  chattr +i failed — filesystem may not support it"
    else
        log_warn "  chattr not available — cannot make resolv.conf immutable"
    fi
}

###############################################################################
# Hardening Functions (setup_*)
###############################################################################

# [1] PAM password policy (pwquality)
setup_pam() {
    log_info "===== [1] PAM password policy (pwquality) ====="

    local pwquality_conf="/etc/security/pwquality.conf"
    if [[ ! -f "$pwquality_conf" ]]; then
        # Install libpwquality if missing
        if ! pkg_is_installed "libpwquality"; then
            log_info "Installing libpwquality..."
            pkg_install libpwquality || { log_warn "libpwquality install failed"; return 0; }
        fi
    fi

    if [[ -f "$pwquality_conf" ]]; then
        backup_file "$pwquality_conf"

        {
            echo "# Password quality settings — auto-generated by hardening (${TIMESTAMP})"
            echo "minlen = ${RHEL_PWQUALITY_MINLEN}"
            echo "dcredit = ${RHEL_PWQUALITY_DCREDIT}"
            echo "ucredit = ${RHEL_PWQUALITY_UCREDIT}"
            echo "lcredit = ${RHEL_PWQUALITY_LCREDIT}"
            echo "ocredit = ${RHEL_PWQUALITY_OCREDIT}"
            echo "minclass = ${RHEL_PWQUALITY_MINCLASS}"
            echo "maxrepeat = ${RHEL_PWQUALITY_MAXREPEAT}"
            echo "maxclassrepeat = ${RHEL_PWQUALITY_MAXCLASSREPEAT}"
            echo "enforcing = 1"
        } > "$pwquality_conf"

        # Restore SELinux context
        if command -v restorecon &>/dev/null; then
            restorecon "$pwquality_conf" 2>/dev/null || true
        fi

        log_ok "PAM pwquality applied: minlen=${RHEL_PWQUALITY_MINLEN}, dcredit=${RHEL_PWQUALITY_DCREDIT}"
    else
        log_warn "pwquality.conf not found even after install attempt"
    fi

    # Enable pwquality via authselect if available, else fall back to authconfig
    # (CentOS 7 / RHEL 7) or direct PAM file edits.
    if command -v authselect &>/dev/null; then
        local current_profile
        current_profile=$(authselect current -r 2>/dev/null || true)
        if [[ -n "$current_profile" ]]; then
            if ! echo "$current_profile" | grep -q 'with-pwquality'; then
                authselect enable-feature with-pwquality 2>/dev/null && \
                    log_ok "authselect: with-pwquality enabled" || \
                    log_warn "authselect: with-pwquality enable failed (may need profile select first)"
            else
                log_skip "authselect: with-pwquality already enabled"
            fi
        else
            log_info "authselect: no profile selected — selecting sssd with pwquality"
            authselect select sssd with-pwquality --force 2>/dev/null && \
                log_ok "authselect: sssd profile with-pwquality selected" || \
                log_warn "authselect select failed — PAM config may need manual review"
        fi
    elif command -v authconfig &>/dev/null; then
        # RHEL 7 / CentOS 7 fallback: use authconfig to enable pwquality
        authconfig --enablepwquality --update 2>/dev/null && \
            log_ok "authconfig: pwquality enabled" || \
            log_warn "authconfig --enablepwquality failed — pwquality.conf applied directly"
    else
        log_info "Neither authselect nor authconfig available — pwquality.conf applied directly"
    fi
}

# [2] firewalld firewall + tunnel defense
# Safety: calls guard_network_outbound() after config.
setup_firewall() {
    log_info "===== [2] firewalld firewall + tunnel defense ====="

    # -- Install firewalld --
    if ! command -v firewall-cmd >/dev/null 2>&1; then
        log_info "Installing firewalld..."
        pkg_install firewalld || { log_error "firewalld install failed"; return 0; }
        log_ok "firewalld installed"
    fi

    if ! command -v firewall-cmd >/dev/null 2>&1; then
        log_error "firewall-cmd unavailable — skipping firewalld setup"
        return 0
    fi

    # -- Ensure firewalld is running --
    if ! systemctl is-active firewalld >/dev/null 2>&1; then
        systemctl enable --now firewalld 2>/dev/null || { log_error "firewalld start failed"; return 0; }
        log_ok "firewalld started and enabled"
    fi

    # -- Detect SSH port --
    local detected_ssh_port=""
    detected_ssh_port=$(sshd -T 2>/dev/null | grep '^port ' | awk '{print $2}')
    if [[ -z "$detected_ssh_port" ]]; then
        detected_ssh_port=$(ss -tlnp 2>/dev/null | grep 'sshd' | awk '{print $4}' | grep -oE '[0-9]+$' | head -1)
    fi
    if [[ -z "$detected_ssh_port" ]]; then
        detected_ssh_port="22"
        log_warn "SSH port detection failed — using default 22/tcp"
    elif [[ "$detected_ssh_port" != "22" ]]; then
        log_info "SSH listening port detected: ${detected_ssh_port}/tcp (non-standard)"
    fi

    # -- Set default zone to drop --
    local current_zone
    current_zone=$(firewall-cmd --get-default-zone 2>/dev/null)
    if [[ "$current_zone" != "drop" ]]; then
        firewall-cmd --set-default-zone=drop 2>/dev/null || true
        log_ok "firewalld default zone set to 'drop'"
    else
        log_skip "firewalld default zone already 'drop'"
    fi

    # -- firewalld allowed ports --
    local profile_ports=""
    if [[ -n "${RHEL_CUSTOM_ALLOWED_PORTS}" ]]; then
        # CUSTOM_ALLOWED_PORTS가 설정됨 — 프로파일 무시, 이 포트만 사용
        profile_ports="${RHEL_CUSTOM_ALLOWED_PORTS}"
        # SSH 포트가 포함되어 있지 않으면 자동 추가
        if ! echo "$profile_ports" | grep -qE "(^| )${detected_ssh_port}/tcp( |$)"; then
            profile_ports="${detected_ssh_port}/tcp ${profile_ports}"
        fi
        log_info "firewalld: CUSTOM_ALLOWED_PORTS 사용 (ports: ${profile_ports})"
    else
        # 폴백: 프로파일 기반 포트
        profile_ports="${RHEL_FIREWALLD_PROFILES[$RHEL_FIREWALLD_PROFILE]:-}"
        if [[ -z "$profile_ports" ]]; then
            log_warn "Unknown firewalld profile: ${RHEL_FIREWALLD_PROFILE} — using base"
            profile_ports="${RHEL_FIREWALLD_PROFILES[base]}"
        fi
        if [[ "$detected_ssh_port" != "22" ]]; then
            profile_ports="${profile_ports//22\/tcp/${detected_ssh_port}\/tcp}"
            log_info "firewalld profile SSH port replaced: 22/tcp -> ${detected_ssh_port}/tcp"
        fi
        log_info "firewalld profile: ${RHEL_FIREWALLD_PROFILE} (ports: ${profile_ports})"
    fi

    # -- Allow port rules (persistent) --
    for port_proto in $profile_ports; do
        if firewall-cmd --query-port="$port_proto" 2>/dev/null; then
            log_skip "firewalld rule already exists: $port_proto"
        else
            firewall-cmd --permanent --add-port="$port_proto" 2>/dev/null || \
                log_warn "firewalld add port $port_proto failed"
            log_ok "firewalld allow: $port_proto"
        fi
    done

    # -- Reload to apply persistent rules --
    firewall-cmd --reload 2>/dev/null || log_warn "firewalld reload failed"
    log_ok "firewalld reloaded (profile: ${RHEL_FIREWALLD_PROFILE})"

    # -- Outbound policy --
    if [[ "${OUTBOUND_POLICY}" == "restrict" ]]; then
        log_info "Applying outbound restrict policy via firewalld direct rules"

        # Drop all outbound by default (direct rule, lowest priority)
        firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 10 -j DROP 2>/dev/null || true
        firewall-cmd --permanent --direct --add-rule ipv6 filter OUTPUT 10 -j DROP 2>/dev/null || true

        # Allow established/related
        firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
        firewall-cmd --permanent --direct --add-rule ipv6 filter OUTPUT 0 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

        # Allow loopback
        firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -o lo -j ACCEPT 2>/dev/null || true
        firewall-cmd --permanent --direct --add-rule ipv6 filter OUTPUT 0 -o lo -j ACCEPT 2>/dev/null || true

        # Allow specified outbound ports
        local _priority=1
        for port_proto in ${OUTBOUND_ALLOWED_PORTS}; do
            local _port="${port_proto%%/*}"
            local _proto="${port_proto##*/}"
            firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT $_priority -p "$_proto" --dport "$_port" -j ACCEPT 2>/dev/null || true
            firewall-cmd --permanent --direct --add-rule ipv6 filter OUTPUT $_priority -p "$_proto" --dport "$_port" -j ACCEPT 2>/dev/null || true
            log_ok "firewalld outbound allow: ${port_proto}"
            _priority=$((_priority + 1))
        done

        # ICMP
        if [[ "${OUTBOUND_ALLOW_ICMP}" == "true" ]]; then
            firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 1 -p icmp --icmp-type echo-request -j ACCEPT 2>/dev/null || true
            firewall-cmd --permanent --direct --add-rule ipv6 filter OUTPUT 1 -p icmpv6 --icmpv6-type echo-request -j ACCEPT 2>/dev/null || true
            log_ok "firewalld outbound ICMP: allowed"
        fi

        firewall-cmd --reload 2>/dev/null || true
        log_ok "firewalld outbound restrict policy applied"
    else
        log_ok "firewalld outbound policy: allow (default — no restrictions)"
    fi

    # -- Write tunnel defense direct rules --
    log_info "  Writing tunnel defense direct rules to firewalld"
    _rhel_firewalld_write_tunnel_rules

    # -- DNS resolv.conf lock --
    _rhel_tunnel_dns_lock_resolv

    # -- SAFETY: verify required outbound ports are not blocked --
    guard_network_outbound

    log_ok "===== [2] firewalld + tunnel defense complete ====="
}

# [3] cron permissions
setup_cron_permissions() {
    log_info "===== [3] cron directory permissions ====="
    for d in /etc/cron.{hourly,daily,weekly,monthly,d}; do
        if [[ -e "$d" ]]; then
            chmod og-rwx "$d" && chown root:root "$d"
            log_ok "Permissions set: $d"
        else
            log_skip "Not found: $d"
        fi
    done
    if [[ -f /etc/crontab ]]; then
        chmod og-rwx /etc/crontab && chown root:root /etc/crontab
        log_ok "/etc/crontab permissions set"
    fi
}

# [4] modprobe — kernel module blacklist
setup_modprobe() {
    log_info "===== [4] Kernel module blacklist ====="
    backup_file "/etc/modprobe.d/dev-sec.conf"
    local content=""
    for mod in "${RHEL_BLOCKED_MODULES[@]}"; do
        content+="blacklist ${mod}"$'\n'
        content+="install ${mod} /bin/true"$'\n'
    done
    echo -n "$content" | tee /etc/modprobe.d/dev-sec.conf > /dev/null
    # Restore SELinux context
    if command -v restorecon &>/dev/null; then
        restorecon /etc/modprobe.d/dev-sec.conf 2>/dev/null || true
    fi
    log_ok "Kernel modules blocked: ${RHEL_BLOCKED_MODULES[*]}"
}

# [5] sysctl — kernel security settings (NO IPv6 disable)
setup_sysctl() {
    log_info "===== [5] sysctl kernel security settings ====="
    local sysctl_file="/etc/sysctl.d/99-hardening.conf"
    backup_file "/etc/sysctl.conf"
    backup_file "$sysctl_file"
    if [[ -f /etc/sysctl.d/99-custom.conf ]]; then
        backup_file "/etc/sysctl.d/99-custom.conf"
        rm -f /etc/sysctl.d/99-custom.conf
        log_info "Removed legacy 99-custom.conf (merged into 99-hardening.conf)"
    fi
    {
        echo "# Security hardening sysctl settings (auto-generated: ${TIMESTAMP})"
        for key in "${!RHEL_SYSCTL_SETTINGS[@]}"; do
            echo "${key} = ${RHEL_SYSCTL_SETTINGS[$key]}"
        done
    } | tee "$sysctl_file" > /dev/null
    # Restore SELinux context
    if command -v restorecon &>/dev/null; then
        restorecon "$sysctl_file" 2>/dev/null || true
    fi
    local failed=0
    for key in "${!RHEL_SYSCTL_SETTINGS[@]}"; do
        local current_val
        current_val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
        if [[ "$current_val" == "${RHEL_SYSCTL_SETTINGS[$key]}" ]]; then
            log_skip "sysctl ${key}=${RHEL_SYSCTL_SETTINGS[$key]} (already set)"
        else
            if sysctl -w "${key}=${RHEL_SYSCTL_SETTINGS[$key]}" >/dev/null 2>&1; then
                log_ok "sysctl ${key}=${RHEL_SYSCTL_SETTINGS[$key]}"
            else
                log_warn "sysctl ${key} failed (kernel may not support it)"
                failed=$((failed + 1))
            fi
        fi
    done
    if [[ $failed -gt 0 ]]; then
        log_warn "sysctl: ${failed} settings failed"
    fi
}

# [6] /proc hidepid
setup_proc_hidepid() {
    log_info "===== [6] /proc hidepid ====="
    if [[ "${RHEL_HIDEPID_ENABLED}" != "true" ]]; then
        log_skip "/proc hidepid disabled (HIDEPID_ENABLED=false)"
        return
    fi
    if mount | grep -q "hidepid=2"; then
        log_skip "/proc hidepid=2 already applied"
    else
        if mount -o remount,hidepid=2 /proc 2>/dev/null; then
            log_ok "/proc hidepid=2 applied"
        else
            log_warn "/proc remount failed (may be container environment)"
        fi
    fi
    _rhel_fstab_ensure_mount "/proc" "proc /proc proc defaults,hidepid=2 0 0"
}

# [7] Sensitive file permissions
setup_sensitive_file_permissions() {
    log_info "===== [7] Sensitive file permissions ====="
    for f in "${RHEL_FILES_644[@]}"; do
        [[ -f "$f" ]] && chmod 0644 "$f" && log_ok "chmod 0644: $f" || log_skip "Not found: $f"
    done
    for f in "${RHEL_FILES_600[@]}"; do
        [[ -f "$f" ]] && chmod 0600 "$f" && log_ok "chmod 0600: $f" || log_skip "Not found: $f"
    done
    for f in "${RHEL_FILES_CHOWN[@]}"; do
        [[ -f "$f" ]] && chown root:root "$f"
    done
    log_ok "Sensitive file ownership (root:root) set"
}

# [8] other permission removal (o-rwx)
setup_other_permission_removal() {
    log_info "===== [8] Other permission removal (o-rwx) ====="
    for f in "${RHEL_FILES_O_NORW[@]}"; do
        if [[ -e "$f" ]]; then
            chmod o-rwx "$f"
            log_ok "chmod o-rwx: $f"
        else
            log_skip "Not found: $f"
        fi
    done
}

# [9] System accounts nologin
# SAFETY: skip protected accounts (gt, usr)
setup_nologin_accounts() {
    log_info "===== [9] System accounts nologin ====="
    for acct in "${RHEL_NOLOGIN_ACCOUNTS[@]}"; do
        # SAFETY: skip protected accounts
        if is_protected_account "$acct"; then
            log_skip "Protected account — skipping nologin: $acct"
            continue
        fi
        if id "$acct" &>/dev/null; then
            local current_shell
            current_shell=$(getent passwd "$acct" | cut -d: -f7)
            if [[ "$current_shell" == "$RHEL_NOLOGIN" || "$current_shell" == "/usr/sbin/nologin" || "$current_shell" == "/sbin/nologin" ]]; then
                log_skip "${acct}: already nologin"
            else
                chsh -s "$RHEL_NOLOGIN" "$acct" 2>/dev/null && \
                    log_ok "${acct} -> ${RHEL_NOLOGIN}" || \
                    log_warn "${acct} shell change failed"
            fi
        fi
    done
    for acct in "${RHEL_FALSE_SHELL_ACCOUNTS[@]}"; do
        # SAFETY: skip protected accounts
        if is_protected_account "$acct"; then
            log_skip "Protected account — skipping /bin/false: $acct"
            continue
        fi
        if id "$acct" &>/dev/null; then
            local current_shell
            current_shell=$(getent passwd "$acct" | cut -d: -f7)
            if [[ "$current_shell" == "/bin/false" ]]; then
                log_skip "${acct}: already /bin/false"
            else
                chsh -s /bin/false "$acct" 2>/dev/null && \
                    log_ok "${acct} -> /bin/false" || \
                    log_warn "${acct} shell change failed"
            fi
        fi
    done
}

# [10] sudoers NOPASSWD removal
# SAFETY: exclude gt lines from NOPASSWD removal.
# SAFETY: exclude 00-gt-nopasswd from sudoers.d processing.
# SAFETY: exclude ANSIBLE_ACCOUNT lines from NOPASSWD removal.
# SAFETY: call guard_account_gt() at the end.
setup_sudoers() {
    log_info "===== [10] sudoers NOPASSWD removal ====="

    # Protect ANSIBLE_ACCOUNT NOPASSWD (similar to gt)
    if [[ -n "${ANSIBLE_ACCOUNT:-}" ]]; then
        local ansible_sudoers="/etc/sudoers.d/zz-ansible-nopasswd"
        if [[ ! -f "$ansible_sudoers" ]] || ! grep -q "NOPASSWD" "$ansible_sudoers" 2>/dev/null; then
            echo "${ANSIBLE_ACCOUNT} ALL=(ALL) NOPASSWD: ALL" > "$ansible_sudoers"
            chmod 0440 "$ansible_sudoers"
            if visudo -c -f "$ansible_sudoers" 2>/dev/null; then
                log_ok "Ansible account NOPASSWD preserved: $ansible_sudoers"
            else
                log_error "Ansible sudoers syntax error — removing"
                rm -f "$ansible_sudoers"
            fi
        fi
    fi

    if [[ -f /etc/sudoers ]]; then
        backup_file "/etc/sudoers"
        if grep -q 'NOPASSWD' /etc/sudoers; then
            # Remove NOPASSWD from %wheel lines (but NOT gt or ANSIBLE_ACCOUNT lines)
            if [[ -n "${ANSIBLE_ACCOUNT:-}" ]]; then
                sed -i "/^[[:space:]]*gt[[:space:]]/b; /^[[:space:]]*${ANSIBLE_ACCOUNT}[[:space:]]/b; s/^\(%wheel[[:space:]]\+ALL=(ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/" /etc/sudoers
                sed -i "/^[[:space:]]*gt[[:space:]]/b; /^[[:space:]]*${ANSIBLE_ACCOUNT}[[:space:]]/b; s/^\(%wheel[[:space:]]\+ALL=(ALL:ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/" /etc/sudoers
                # Remove NOPASSWD from individual user lines, but NOT gt or ANSIBLE_ACCOUNT
                sed -i "/^[[:space:]]*gt[[:space:]]/b; /^[[:space:]]*${ANSIBLE_ACCOUNT}[[:space:]]/b; s/^\([^%#][[:alnum:]_.-]\+[[:space:]]\+ALL=(ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/" /etc/sudoers
                sed -i "/^[[:space:]]*gt[[:space:]]/b; /^[[:space:]]*${ANSIBLE_ACCOUNT}[[:space:]]/b; s/^\([^%#][[:alnum:]_.-]\+[[:space:]]\+ALL=(ALL:ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/" /etc/sudoers
            else
                sed -i '/^[[:space:]]*gt[[:space:]]/!{s/^\(%wheel[[:space:]]\+ALL=(ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/}' /etc/sudoers
                sed -i '/^[[:space:]]*gt[[:space:]]/!{s/^\(%wheel[[:space:]]\+ALL=(ALL:ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/}' /etc/sudoers
                # Remove NOPASSWD from individual user lines, but NOT gt
                sed -i '/^[[:space:]]*gt[[:space:]]/!{s/^\([^%#][[:alnum:]_.-]\+[[:space:]]\+ALL=(ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/}' /etc/sudoers
                sed -i '/^[[:space:]]*gt[[:space:]]/!{s/^\([^%#][[:alnum:]_.-]\+[[:space:]]\+ALL=(ALL:ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/}' /etc/sudoers
            fi
            if visudo -c 2>/dev/null; then
                log_ok "sudoers NOPASSWD removed (gt lines preserved, syntax validated)"
            else
                log_error "sudoers syntax error! Restoring from backup: ${BACKUP_DIR}"
                local backup_sudoers="${BACKUP_DIR}/_etc_sudoers"
                [[ -f "$backup_sudoers" ]] && cp "$backup_sudoers" /etc/sudoers
            fi
        else
            log_skip "No NOPASSWD in sudoers"
        fi
    fi
    if [[ -d /etc/sudoers.d ]]; then
        local nopasswd_files
        nopasswd_files=$(grep -rl 'NOPASSWD' /etc/sudoers.d/ 2>/dev/null || true)
        if [[ -n "$nopasswd_files" ]]; then
            while IFS= read -r f; do
                # SAFETY: skip gt's sudoers drop-in and ansible's drop-in
                local fname
                fname=$(basename "$f")
                if [[ "$fname" == "00-gt-nopasswd" ]]; then
                    log_skip "Preserving gt NOPASSWD: $f"
                    continue
                fi
                if [[ "$fname" == "zz-ansible-nopasswd" ]]; then
                    log_skip "Preserving Ansible NOPASSWD: $f"
                    continue
                fi
                backup_file "$f"
                sed -i 's/NOPASSWD://g' "$f" 2>/dev/null
                log_ok "sudoers.d NOPASSWD removed: $f"
            done <<< "$nopasswd_files"
        fi
    fi
    # SAFETY: ensure gt account is properly configured
    guard_account_gt
}

# [11] SUID bit removal
setup_suid_removal() {
    log_info "===== [11] SUID bit removal ====="
    for f in "${RHEL_SUID_REMOVE_TARGETS[@]}"; do
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

# [12] Disable unnecessary services
# SAFETY: check is_protected_service() before disabling
setup_disable_services() {
    log_info "===== [12] Disable unnecessary services ====="
    for svc in "${RHEL_DISABLE_SERVICES[@]}"; do
        # SAFETY: check protected services
        if is_protected_service "$svc"; then
            log_skip "Protected service — skipping disable: $svc"
            continue
        fi
        if systemctl list-unit-files "$svc" &>/dev/null; then
            if systemctl is-enabled "$svc" 2>/dev/null | grep -q "enabled"; then
                systemctl disable --now "$svc" 2>/dev/null || true
                log_ok "Disabled: $svc"
            else
                log_skip "Already disabled: $svc"
            fi
        else
            log_skip "Service not found: $svc"
        fi
    done
}

# [13] Lock accounts with empty passwords
# SAFETY: skip protected accounts (gt, usr)
setup_lock_empty_password() {
    log_info "===== [13] Lock empty password accounts ====="
    local locked_count=0
    while IFS= read -r user; do
        if [[ -n "$user" ]]; then
            # SAFETY: skip protected accounts
            if is_protected_account "$user"; then
                log_skip "Protected account — skipping lock: $user"
                continue
            fi
            passwd -l "$user" 2>/dev/null || true
            log_ok "Account locked: $user"
            locked_count=$((locked_count + 1))
        fi
    done < <(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null)
    if [[ $locked_count -eq 0 ]]; then
        log_skip "No accounts with empty passwords"
    fi
}

# [14] SSH hardening
setup_ssh_hardening() {
    log_info "===== [14] SSH hardening ====="
    local sshd_config="/etc/ssh/sshd_config"
    if [[ ! -f "$sshd_config" ]]; then
        log_skip "sshd_config not found — skipping SSH"
        return
    fi
    backup_file "$sshd_config"
    local hardened_conf="/etc/ssh/sshd_config.d/99-hardening.conf"
    mkdir -p /etc/ssh/sshd_config.d
    local effective_pw_auth="${RHEL_SSH_PASSWORD_AUTH}"
    if [[ "${RHEL_SSH_PASSWORD_AUTH}" == "no" ]]; then
        local has_ssh_key=false
        while IFS=: read -r _user _ _ _ _ _home _shell; do
            [[ "$_shell" =~ (nologin|false)$ ]] && continue
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
        ansible_home=$(getent passwd "$ANSIBLE_ACCOUNT" 2>/dev/null | cut -d: -f6)
        if [[ -n "$ansible_home" ]] && [[ ! -s "${ansible_home}/.ssh/authorized_keys" ]]; then
            log_warn "Automation account '${ANSIBLE_ACCOUNT}' has no SSH key — forcing PasswordAuthentication=yes"
            effective_pw_auth="yes"
        fi
    fi
    tee "$hardened_conf" > /dev/null <<SSHEOF
# === Security hardening (auto-generated: ${TIMESTAMP}) ===
PermitRootLogin ${RHEL_SSH_PERMIT_ROOT_LOGIN}
PasswordAuthentication ${effective_pw_auth}
MaxAuthTries ${RHEL_SSH_MAX_AUTH_TRIES}
PermitEmptyPasswords no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
GatewayPorts no
ClientAliveInterval ${RHEL_SSH_CLIENT_ALIVE_INTERVAL}
ClientAliveCountMax ${RHEL_SSH_CLIENT_ALIVE_COUNT_MAX}
LoginGraceTime ${RHEL_SSH_LOGIN_GRACE_TIME}
Banner /etc/issue.net
UsePAM yes
HostbasedAuthentication no
IgnoreRhosts yes
MaxSessions 4
MaxStartups 10:30:60
SSHEOF
    # Restore SELinux context
    if command -v restorecon &>/dev/null; then
        restorecon "$hardened_conf" 2>/dev/null || true
    fi
    if ! grep -q 'Include /etc/ssh/sshd_config.d/\*.conf' "$sshd_config" 2>/dev/null; then
        sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$sshd_config"
        log_info "sshd_config: Include directive inserted at top"
    fi
    if sshd -t 2>/dev/null; then
        if systemctl reload sshd 2>/dev/null; then
            sleep 1  # Allow sshd to complete reload before continuing
            log_ok "SSH hardening applied and service reloaded"
        else
            log_warn "SSH service reload failed"
        fi
        local verify_root verify_pw
        verify_root=$(sshd -T 2>/dev/null | grep '^permitrootlogin ' | awk '{print $2}')
        verify_pw=$(sshd -T 2>/dev/null | grep '^passwordauthentication ' | awk '{print $2}')
        [[ "$verify_root" == "${RHEL_SSH_PERMIT_ROOT_LOGIN}" ]] && \
            log_ok "Verify OK: PermitRootLogin=${verify_root}" || \
            log_warn "Verify FAIL: PermitRootLogin expected=${RHEL_SSH_PERMIT_ROOT_LOGIN}, actual=${verify_root}"
        [[ "$verify_pw" == "${effective_pw_auth}" ]] && \
            log_ok "Verify OK: PasswordAuthentication=${verify_pw}" || \
            log_warn "Verify FAIL: PasswordAuthentication expected=${effective_pw_auth}, actual=${verify_pw}"
    else
        log_error "sshd config syntax error — rolling back"
        rm -f "$hardened_conf"
    fi
}

# [15] /etc/login.defs password aging
setup_login_defs() {
    log_info "===== [15] /etc/login.defs password aging ====="
    local login_defs="/etc/login.defs"
    if [[ ! -f "$login_defs" ]]; then
        log_skip "login.defs not found"
        return
    fi
    backup_file "$login_defs"
    declare -A LOGINDEFS=(
        ["PASS_MAX_DAYS"]="$RHEL_PASS_MAX_DAYS"
        ["PASS_MIN_DAYS"]="$RHEL_PASS_MIN_DAYS"
        ["PASS_WARN_AGE"]="$RHEL_PASS_WARN_AGE"
        ["LOGIN_RETRIES"]="$RHEL_LOGIN_RETRIES"
        ["UMASK"]="$RHEL_DEFAULT_UMASK"
        ["LOG_OK_LOGINS"]="yes"
        ["ENCRYPT_METHOD"]="SHA512"
        ["SHA_CRYPT_MIN_ROUNDS"]="5000"
    )
    for key in "${!LOGINDEFS[@]}"; do
        local val="${LOGINDEFS[$key]}"
        if grep -qE "^\s*${key}\s" "$login_defs"; then
            sed -i "s/^[[:space:]]*${key}[[:space:]].*/${key}\t\t${val}/" "$login_defs"
        else
            echo -e "${key}\t\t${val}" >> "$login_defs"
        fi
        log_ok "login.defs: ${key}=${val}"
    done
}

# [16] pam_faillock account lockout (via authselect)
setup_pam_faillock() {
    log_info "===== [16] pam_faillock account lockout ====="

    # Write faillock.conf
    local faillock_conf="/etc/security/faillock.conf"
    backup_file "$faillock_conf"
    {
        echo "# Account lockout policy — auto-generated by hardening"
        echo "deny = ${RHEL_FAILLOCK_DENY}"
        echo "unlock_time = ${RHEL_FAILLOCK_UNLOCK_TIME}"
        echo "fail_interval = ${RHEL_FAILLOCK_UNLOCK_TIME}"
        if [[ "${RHEL_FAILLOCK_DENY_ROOT}" == "true" ]]; then
            echo "even_deny_root"
            echo "root_unlock_time = 60"
        fi
    } > "$faillock_conf"
    chmod 0644 "$faillock_conf"
    # Restore SELinux context
    if command -v restorecon &>/dev/null; then
        restorecon "$faillock_conf" 2>/dev/null || true
    fi
    log_ok "faillock.conf written (deny=${RHEL_FAILLOCK_DENY}, unlock_time=${RHEL_FAILLOCK_UNLOCK_TIME}s)"

    # Enable faillock via authselect
    if command -v authselect &>/dev/null; then
        local current_profile
        current_profile=$(authselect current -r 2>/dev/null || true)
        if [[ -n "$current_profile" ]]; then
            if ! echo "$current_profile" | grep -q 'with-faillock'; then
                authselect enable-feature with-faillock 2>/dev/null && \
                    log_ok "authselect: with-faillock enabled" || \
                    log_warn "authselect: with-faillock enable failed"
            else
                log_skip "authselect: with-faillock already enabled"
            fi
        else
            log_info "authselect: no profile — selecting sssd with-faillock"
            authselect select sssd with-faillock --force 2>/dev/null && \
                log_ok "authselect: sssd profile with-faillock selected" || \
                log_warn "authselect select failed — faillock may need manual PAM config"
        fi
    elif command -v authconfig &>/dev/null; then
        # RHEL 7 / CentOS 7 fallback: use authconfig to enable faillock
        authconfig --enablefaillock --update 2>/dev/null && \
            log_ok "authconfig: faillock enabled" || \
            log_warn "authconfig --enablefaillock failed — falling back to manual PAM editing"
    else
        # Fallback: manually configure PAM if neither authselect nor authconfig available
        log_info "Neither authselect nor authconfig available — checking PAM files directly"
        local pam_auth="/etc/pam.d/system-auth"
        local pam_password="/etc/pam.d/password-auth"

        for pam_file in "$pam_auth" "$pam_password"; do
            if [[ -f "$pam_file" ]]; then
                if ! grep -q 'pam_faillock' "$pam_file" 2>/dev/null; then
                    backup_file "$pam_file"
                    # Insert faillock preauth before pam_unix auth line
                    sed -i "/^auth.*pam_unix\.so/i auth        required      pam_faillock.so preauth silent deny=${RHEL_FAILLOCK_DENY} unlock_time=${RHEL_FAILLOCK_UNLOCK_TIME}" "$pam_file" 2>/dev/null || true
                    # Insert faillock authfail after pam_unix auth line
                    sed -i "/^auth.*pam_unix\.so/a auth        [default=die] pam_faillock.so authfail deny=${RHEL_FAILLOCK_DENY} unlock_time=${RHEL_FAILLOCK_UNLOCK_TIME}" "$pam_file" 2>/dev/null || true
                    # Add account line if missing
                    if ! grep -q 'pam_faillock.*account' "$pam_file" 2>/dev/null; then
                        sed -i '/^account.*pam_unix\.so/i account     required      pam_faillock.so' "$pam_file" 2>/dev/null || true
                    fi
                    log_ok "pam_faillock manually added to ${pam_file}"
                else
                    log_skip "pam_faillock already in ${pam_file}"
                fi
            fi
        done
    fi

    log_ok "pam_faillock setup complete"
}

# [17] /tmp, /var/tmp, /dev/shm mount hardening
setup_tmp_mount_hardening() {
    log_info "===== [17] /tmp, /var/tmp, /dev/shm mount hardening ====="
    backup_file "/etc/fstab"
    local mount_targets=("/tmp" "/var/tmp")
    if [[ "${RHEL_SHM_NOEXEC}" == "true" ]]; then
        mount_targets+=("/dev/shm")
    else
        log_skip "/dev/shm noexec disabled (SHM_NOEXEC=false)"
    fi
    for mnt in "${mount_targets[@]}"; do
        if mount | grep -q "on ${mnt} "; then
            if mount | grep "on ${mnt} " | grep -q 'noexec'; then
                log_skip "${mnt} already noexec"
            else
                mount -o remount,noexec,nosuid,nodev "${mnt}" 2>/dev/null && \
                    log_ok "${mnt} remount noexec,nosuid,nodev" || \
                    log_warn "${mnt} remount failed"
            fi
        fi
    done
    _rhel_fstab_ensure_mount "/tmp" \
        "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0"
    _rhel_fstab_ensure_mount "/var/tmp" \
        "tmpfs /var/tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0"
    if [[ "${RHEL_SHM_NOEXEC}" == "true" ]]; then
        _rhel_fstab_ensure_mount "/dev/shm" \
            "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0"
    fi
}

# [18] core dump limits
setup_core_dump_limits() {
    log_info "===== [18] Core dump limits ====="
    local limits_conf="/etc/security/limits.conf"
    backup_file "$limits_conf"
    if ! grep -q '^\*.*hard.*core.*0' "$limits_conf" 2>/dev/null; then
        echo "* hard core 0" >> "$limits_conf"
        log_ok "limits.conf: core dump limit added"
    else
        log_skip "Core dump limit already applied"
    fi
    local coredump_conf="/etc/systemd/coredump.conf"
    if [[ -f "$coredump_conf" ]]; then
        backup_file "$coredump_conf"
        if ! grep -q '^Storage=none' "$coredump_conf" 2>/dev/null; then
            if ! grep -q '^\[Coredump\]' "$coredump_conf" 2>/dev/null; then
                echo -e "\n[Coredump]" >> "$coredump_conf"
                log_info "Added [Coredump] section header to coredump.conf"
            fi
            sed -i 's/^#\?Storage=.*/Storage=none/' "$coredump_conf" 2>/dev/null || \
                echo "Storage=none" >> "$coredump_conf"
            sed -i 's/^#\?ProcessSizeMax=.*/ProcessSizeMax=0/' "$coredump_conf" 2>/dev/null || \
                echo "ProcessSizeMax=0" >> "$coredump_conf"
            systemctl daemon-reload 2>/dev/null
            log_ok "systemd coredump disabled"
        else
            log_skip "systemd coredump already disabled"
        fi
    fi
}

# [19] Global umask
setup_umask() {
    log_info "===== [19] Global umask (${RHEL_DEFAULT_UMASK}) ====="
    local umask_files=(/etc/profile /etc/bashrc /etc/login.defs)
    for f in "${umask_files[@]}"; do
        if [[ -f "$f" ]]; then
            backup_file "$f"
            if grep -qE '^\s*umask\s+[0-9]+' "$f" 2>/dev/null; then
                sed -i "s/^[[:space:]]*umask[[:space:]]\+[0-9]\+/umask ${RHEL_DEFAULT_UMASK}/" "$f"
                log_ok "umask changed: $f -> ${RHEL_DEFAULT_UMASK}"
            else
                echo "umask ${RHEL_DEFAULT_UMASK}" >> "$f"
                log_ok "umask added: $f -> ${RHEL_DEFAULT_UMASK}"
            fi
        fi
    done
}

# [20] Legal warning banner
setup_banner() {
    log_info "===== [20] Legal warning banner ====="
    local banner_text="
====================================================================
                    AUTHORIZED ACCESS ONLY
====================================================================
This system is for authorized use only. All activities are monitored
and logged. Unauthorized access is prohibited and will be prosecuted
to the fullest extent of the law.
===================================================================="
    for f in /etc/issue /etc/issue.net; do
        backup_file "$f"
        echo "$banner_text" > "$f"
        # Restore SELinux context
        if command -v restorecon &>/dev/null; then
            restorecon "$f" 2>/dev/null || true
        fi
        log_ok "Banner set: $f"
    done
    if [[ -d /etc/update-motd.d ]]; then
        chmod -x /etc/update-motd.d/* 2>/dev/null || true
        log_ok "MOTD scripts execution permission removed"
    fi
}

# [21] Tunnel hardening (process detection, tool removal, NO auditd changes)
setup_tunnel_hardening() {
    log_info "===== [21] Tunnel hardening (process detection / tool removal) ====="
    log_info "  NOTE: firewalld direct rules handled by firewall setup; auditd rules handled by orchestrator"

    _rhel_tunnel_detect_processes
    _rhel_tunnel_remove_tools
    # NOTE: NO _tunnel_append_audit_rules — auditd is snapshot-only in 01

    log_ok "[21] Tunnel hardening (non-firewall, non-auditd) complete"
}

# -- Tunnel process detection --
_rhel_tunnel_detect_processes() {
    log_info "  Tunnel tool process detection"
    local found=0

    for proc in "${RHEL_TUNNEL_TOOL_PROCS[@]}"; do
        if pgrep -x "${proc}" &>/dev/null; then
            local pids
            pids=$(pgrep -x "${proc}" | tr '\n' ',' | sed 's/,$//')
            log_warn "  Tunnel tool running: ${proc} (PID: ${pids})"
            local exe_path
            exe_path=$(readlink -f "/proc/$(pgrep -x "${proc}" | head -1)/exe" 2>/dev/null || echo "unknown")
            log_warn "    Executable path: ${exe_path}"
            found=1
        fi
    done

    if ls /proc/*/fd 2>/dev/null | xargs -I{} readlink {} 2>/dev/null \
       | grep -q "net/tun"; then
        log_warn "  TUN device held by process detected"
        found=1
    fi

    local dns_non_std
    dns_non_std=$(ss -unp 2>/dev/null \
                  | awk '$5 ~ /:53$/ && $4 !~ /^(127\.|10\.|172\.|192\.168\.)/ {print}' \
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

# -- Tunnel tool package removal (rpm-based) --
_rhel_tunnel_remove_tools() {
    log_info "  Tunnel tool package removal"

    local removed=0
    for pkg in "${RHEL_TUNNEL_PKGS[@]}"; do
        if rpm -q "${pkg}" &>/dev/null 2>&1; then
            local rc=0
            $RHEL_PKG_MGR remove -y "${pkg}" >/dev/null 2>&1 || rc=$?
            if [[ $rc -eq 0 ]]; then
                log_ok "  Package removed: ${pkg}"
            else
                log_warn "  Package removal failed (rc=${rc}): ${pkg}"
            fi
            removed=$((removed + 1))
        fi
    done

    [[ $removed -eq 0 ]] && log_skip "  No tunnel tool packages to remove"

    for bin in "${RHEL_TUNNEL_BINS[@]}"; do
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
    log_info "===== [auditd] Ensure auditd is installed (no config changes) ====="
    if ! command -v auditd >/dev/null 2>&1; then
        log_info "Installing audit..."
        pkg_install audit || { log_error "audit install failed"; return 0; }
        log_ok "audit installed"
    else
        log_skip "auditd already installed"
    fi
    # Ensure log directory exists
    if command -v auditd >/dev/null 2>&1; then
        mkdir -p /var/log/audit
        touch /var/log/audit/audit.log 2>/dev/null || true
        chown -R root:root /var/log/audit 2>/dev/null || true
        chmod 0600 /var/log/audit/audit.log 2>/dev/null || true
        # Restore SELinux context on audit log directory
        if command -v restorecon &>/dev/null; then
            restorecon -R /var/log/audit 2>/dev/null || true
        fi
    fi
    # NOTE: Do NOT write auditd.conf or modify rules.
    # The orchestrator calls guard_auditd_snapshot_only() separately.
}

###############################################################################
# run_hardening() — Entry point called by 01 orchestrator
###############################################################################
run_hardening() {
    log_info "===== RHEL/Rocky/AlmaLinux hardening adapter: run_hardening() ====="

    [[ "${HARDEN_PAM}" == "true" ]] && setup_pam || log_skip "[TOGGLE] PAM disabled"
    [[ "${HARDEN_FIREWALL}" == "true" ]] && setup_firewall || log_skip "[TOGGLE] Firewall disabled"
    [[ "${HARDEN_CRON}" == "true" ]] && setup_cron_permissions || log_skip "[TOGGLE] Cron permissions disabled"
    [[ "${HARDEN_KERNEL_MODULES}" == "true" ]] && setup_modprobe || log_skip "[TOGGLE] Kernel modules disabled"
    [[ "${HARDEN_SYSCTL}" == "true" ]] && setup_sysctl || log_skip "[TOGGLE] Sysctl disabled"
    [[ "${HARDEN_HIDEPID}" == "true" ]] && setup_proc_hidepid || log_skip "[TOGGLE] Hidepid disabled"
    [[ "${HARDEN_FILE_PERMISSIONS}" == "true" ]] && setup_sensitive_file_permissions || log_skip "[TOGGLE] File permissions disabled"
    [[ "${HARDEN_OTHER_PERMS}" == "true" ]] && setup_other_permission_removal || log_skip "[TOGGLE] Other permissions disabled"
    [[ "${HARDEN_ACCOUNTS}" == "true" ]] && setup_nologin_accounts || log_skip "[TOGGLE] Account nologin disabled"
    [[ "${HARDEN_SUDOERS}" == "true" ]] && setup_sudoers || log_skip "[TOGGLE] Sudoers disabled"
    [[ "${HARDEN_SUID}" == "true" ]] && setup_suid_removal || log_skip "[TOGGLE] SUID removal disabled"
    [[ "${HARDEN_SERVICES}" == "true" ]] && setup_disable_services || log_skip "[TOGGLE] Service disable disabled"
    [[ "${HARDEN_EMPTY_PASSWORDS}" == "true" ]] && setup_lock_empty_password || log_skip "[TOGGLE] Empty password lock disabled"
    [[ "${HARDEN_SSH}" == "true" ]] && setup_ssh_hardening || log_skip "[TOGGLE] SSH disabled"
    [[ "${HARDEN_LOGIN_DEFS}" == "true" ]] && setup_login_defs || log_skip "[TOGGLE] Login defs disabled"
    [[ "${HARDEN_FAILLOCK}" == "true" ]] && setup_pam_faillock || log_skip "[TOGGLE] Faillock disabled"
    [[ "${HARDEN_MOUNT}" == "true" ]] && setup_tmp_mount_hardening || log_skip "[TOGGLE] Mount hardening disabled"
    [[ "${HARDEN_CORE_DUMP}" == "true" ]] && setup_core_dump_limits || log_skip "[TOGGLE] Core dump disabled"
    [[ "${HARDEN_UMASK}" == "true" ]] && setup_umask || log_skip "[TOGGLE] Umask disabled"
    [[ "${HARDEN_BANNER}" == "true" ]] && setup_banner || log_skip "[TOGGLE] Banner disabled"
    [[ "${HARDEN_TUNNEL_DEFENSE}" == "true" ]] && setup_tunnel_hardening || log_skip "[TOGGLE] Tunnel defense disabled"
    # auditd install is always run (not toggleable — orchestrator handles snapshot)
    setup_auditd

    log_ok "===== RHEL/Rocky/AlmaLinux hardening complete ====="
}

###############################################################################
# create_baseline_snapshot() — Called by 01 after hardening
###############################################################################
create_baseline_snapshot() {
    log_info "===== Creating baseline snapshot ====="
    mkdir -p "${BASELINE_SNAPSHOT_DIR}"

    { echo "# Package snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | sort || true
    } > "${BASELINE_SNAPSHOT_DIR}/packages_baseline.txt" || true

    { echo "# Service state snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      systemctl list-units --type=service --state=running 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/services_baseline.txt" || true

    { echo "# Listening ports snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      ss -tlnup 2>/dev/null || netstat -tlnup 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/ports_baseline.txt" || true

    { echo "# iptables rules snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      iptables -S 2>/dev/null || true
      echo ""
      echo "# ip6tables"
      ip6tables -S 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/iptables_baseline.txt" || true

    { echo "# firewalld direct rules snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      firewall-cmd --direct --get-all-rules 2>/dev/null || echo "(none)"
    } > "${BASELINE_SNAPSHOT_DIR}/firewalld_direct_rules_baseline.txt" || true

    { echo "# firewalld zone config snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      firewall-cmd --list-all 2>/dev/null || echo "(none)"
    } > "${BASELINE_SNAPSHOT_DIR}/firewalld_zone_baseline.txt" || true

    { echo "# sysctl settings snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      sysctl -a 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/sysctl_baseline.txt" || true

    { echo "# User accounts snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      cat /etc/passwd 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/passwd_baseline.txt" || true

    { echo "# SSH config snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      sshd -T 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/sshd_baseline.txt" || true

    { echo "# auditd rules snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      auditctl -l 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/auditd_baseline.txt" || true

    { echo "# Tunnel defense firewalld direct rules snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      firewall-cmd --direct --get-all-rules 2>/dev/null | grep -i "TUNNEL" || echo "(none)"
    } > "${BASELINE_SNAPSHOT_DIR}/tunnel_firewalld_direct_baseline.txt" || true

    { echo "# /etc/resolv.conf snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      cat /etc/resolv.conf 2>/dev/null || echo "(none)"
      echo ""
      echo "# chattr attributes:"
      lsattr /etc/resolv.conf 2>/dev/null || echo "(lsattr unavailable)"
    } > "${BASELINE_SNAPSHOT_DIR}/tunnel_resolv_baseline.txt" || true

    { echo "# Tunnel tool process snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      local _tun_found=false
      for _proc in "${RHEL_TUNNEL_TOOL_PROCS[@]}"; do
          pgrep -x "${_proc}" &>/dev/null && { echo "RUNNING: ${_proc}"; _tun_found=true; }
      done
      [[ "${_tun_found}" == false ]] && echo "(no tunnel tools detected)"
    } > "${BASELINE_SNAPSHOT_DIR}/tunnel_processes_baseline.txt" || true

    { sysctl -a 2>/dev/null | sed 's/ = /=/' | grep -v '^#' | sort
    } > "${BASELINE_SNAPSHOT_DIR}/sysctl_baseline.conf" || true

    { local _perm_targets=(
          "${RHEL_FILES_644[@]}" "${RHEL_FILES_600[@]}" "${RHEL_FILES_O_NORW[@]}"
          /etc/ssh/sshd_config.d/99-hardening.conf
          /etc/audit/rules.d/99-hardening.rules
          /etc/sysctl.d/99-hardening.conf
          /etc/modprobe.d/dev-sec.conf
          /etc/security/faillock.conf
          /etc/security/pwquality.conf
      )
      for f in "${_perm_targets[@]}"; do
          [[ -e "$f" ]] || continue
          echo "$(stat -c '%a' "$f" 2>/dev/null) $(stat -c '%U:%G' "$f" 2>/dev/null) ${f}"
      done
    } > "${BASELINE_SNAPSHOT_DIR}/file_permissions_baseline.txt" || true

    find / -xdev -perm -4000 -type f 2>/dev/null | sort \
        > "${BASELINE_SNAPSHOT_DIR}/suid_files_baseline.txt" || true

    systemctl list-unit-files --state=enabled --type=service 2>/dev/null | \
        grep '\.service' | awk '{print $1}' | sort \
        > "${BASELINE_SNAPSHOT_DIR}/enabled_services_baseline.txt" || true

    systemctl list-units --type=service --state=active 2>/dev/null | \
        grep '\.service' | awk '{print $1}' | sort \
        > "${BASELINE_SNAPSHOT_DIR}/active_services_baseline.txt" || true

    awk -F: '$7 !~ /(nologin|false)/ {print $1":"$7}' /etc/passwd | sort \
        > "${BASELINE_SNAPSHOT_DIR}/login_accounts_baseline.txt" || true

    command -v firewall-cmd &>/dev/null && \
        firewall-cmd --list-ports 2>/dev/null | tr ' ' '\n' | sort \
            > "${BASELINE_SNAPSHOT_DIR}/firewalld_ports_baseline.txt" || true

    auditctl -l 2>/dev/null | sort \
        > "${BASELINE_SNAPSHOT_DIR}/audit_rules_baseline.txt" || true

    { for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
               /etc/cron.monthly /etc/cron.d /etc/crontab; do
          [[ -e "$d" ]] || continue
          echo "$(stat -c '%a' "$d" 2>/dev/null) $(stat -c '%U:%G' "$d" 2>/dev/null) ${d}"
      done
    } > "${BASELINE_SNAPSHOT_DIR}/cron_permissions_baseline.txt" || true

    [[ -f /etc/modprobe.d/dev-sec.conf ]] && \
        cp /etc/modprobe.d/dev-sec.conf \
           "${BASELINE_SNAPSHOT_DIR}/modprobe_baseline.conf" || true

    echo "${RHEL_HIDEPID_ENABLED}" > "${BASELINE_SNAPSHOT_DIR}/hidepid_enabled.txt" || true

    sshd -T 2>/dev/null | sort \
        > "${BASELINE_SNAPSHOT_DIR}/sshd_effective_baseline.txt" || true

    ss -tlnp 2>/dev/null \
        > "${BASELINE_SNAPSHOT_DIR}/listening_ports_baseline.txt" || true

    { echo "PASS_MAX_DAYS=${RHEL_PASS_MAX_DAYS}"
      echo "PASS_MIN_DAYS=${RHEL_PASS_MIN_DAYS}"
      echo "PASS_WARN_AGE=${RHEL_PASS_WARN_AGE}"
      echo "LOGIN_RETRIES=${RHEL_LOGIN_RETRIES}"
      echo "UMASK=${RHEL_DEFAULT_UMASK}"
    } > "${BASELINE_SNAPSHOT_DIR}/login_defs_baseline.txt" || true

    # SELinux status snapshot
    { echo "# SELinux snapshot ($(date '+%Y-%m-%d %H:%M:%S'))"
      getenforce 2>/dev/null || echo "(not available)"
      echo ""
      sestatus 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/selinux_baseline.txt" || true

    { local hash_targets=(
          /etc/passwd /etc/shadow /etc/group /etc/gshadow
          /etc/ssh/sshd_config /etc/sudoers
          /etc/audit/rules.d/99-hardening.rules
          /etc/sysctl.d/99-hardening.conf
          /etc/resolv.conf
          /etc/modprobe.d/dev-sec.conf
          /etc/security/faillock.conf
          /etc/security/pwquality.conf
          /etc/ssh/sshd_config.d/99-hardening.conf
      )
      for f in "${hash_targets[@]}"; do
          [[ -f "$f" ]] && sha256sum "$f" 2>/dev/null || true
      done
      while IFS= read -r snap; do
          [[ -f "$snap" ]] && sha256sum "$snap" 2>/dev/null || true
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

# [1] sysctl check
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

        if echo "$key" | grep -qE "$RHEL_SYSCTL_SKIP_PATTERN"; then
            continue
        fi

        local current_val
        current_val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")

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
    done < "$baseline_file"
}

# [2] File permissions check
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
        current_perm=$(stat -c '%a' "$filepath" 2>/dev/null)
        current_owner=$(stat -c '%U:%G' "$filepath" 2>/dev/null)
        local drifted=false

        if [[ "$current_perm" != "$expected_perm" ]]; then
            log_drift "Permission changed: $filepath (expected=${expected_perm}, current=${current_perm})"
            drifted=true
            if [[ "$MODE" == "auto-restore" ]]; then
                _rhel_backup_before_restore "$filepath"
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
                _rhel_backup_before_restore "$filepath"
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

# [3] SUID files check
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

# [4] Disabled services check
# SAFETY: check is_protected_service() before disabling
check_disabled_services() {
    log_info "===== [C4] Disabled services check ====="

    local baseline_file="${BASELINE_SNAPSHOT_DIR}/enabled_services_baseline.txt"

    if [[ -f "$baseline_file" ]]; then
        local current_services
        current_services=$(mktemp)
        systemctl list-unit-files --state=enabled --type=service 2>/dev/null | \
            grep '\.service' | awk '{print $1}' | sort > "$current_services"

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
                    if echo ",${RHEL_SERVICE_ALLOWLIST}," | grep -q ",${svc},"; then
                        log_skip "Allowlist service: ${svc}"
                        continue
                    fi
                    systemctl disable --now "$svc" 2>/dev/null || true
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

        local active_baseline="${BASELINE_SNAPSHOT_DIR}/active_services_baseline.txt"
        if [[ -f "$active_baseline" ]]; then
            local current_active
            current_active=$(mktemp)
            systemctl list-units --type=service --state=active 2>/dev/null | \
                grep '\.service' | awk '{print $1}' | sort > "$current_active"

            local new_active
            new_active=$(comm -13 "$active_baseline" "$current_active")
            if [[ -n "$new_active" ]]; then
                while IFS= read -r svc; do
                    [[ -z "$svc" ]] && continue
                    log_drift "New active service not in baseline: $svc"
                    if [[ "$MODE" == "auto-restore" ]]; then
                        # SAFETY: check protected services
                        if is_protected_service "$svc"; then
                            log_skip "Protected service — skipping stop: $svc"
                            continue
                        fi
                        if echo ",${RHEL_SERVICE_ALLOWLIST}," | grep -q ",${svc},"; then
                            log_skip "Allowlist service: ${svc}"
                            continue
                        fi
                        systemctl stop "$svc" 2>/dev/null || true
                        log_restore "Service stopped: $svc"
                    fi
                done <<< "$new_active"
            else
                log_ok "No new active services vs baseline"
            fi
            rm -f "$current_active"
        fi
    else
        log_warn "Service baseline not found — checking default list"
        local target_services=(
            avahi-daemon.service cups.service cups-browsed.service bluetooth.service
        )
        for svc in "${target_services[@]}"; do
            # SAFETY: check protected services
            if is_protected_service "$svc"; then
                log_skip "Protected service — skipping check: $svc"
                continue
            fi
            if ! systemctl list-unit-files "$svc" &>/dev/null 2>&1; then
                log_ok "Service not installed: $svc"
                continue
            fi
            local is_enabled is_active
            is_enabled=$(systemctl is-enabled "$svc" 2>/dev/null || echo "unknown")
            is_active=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
            if [[ "$is_enabled" == "enabled" ]] || [[ "$is_active" == "active" ]]; then
                log_drift "Service re-enabled: $svc (enabled=${is_enabled}, active=${is_active})"
                if [[ "$MODE" == "auto-restore" ]]; then
                    systemctl disable --now "$svc" 2>/dev/null || true
                    log_restore "Service disabled: $svc"
                fi
            else
                log_ok "Still disabled: $svc"
            fi
        done
    fi
}

# [5] Login accounts check
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
    awk -F: '$7 !~ /(nologin|false)/ {print $1":"$7}' /etc/passwd | sort > "$current_accounts"

    local new_accounts
    new_accounts=$(comm -13 "$baseline_file" "$current_accounts")
    if [[ -n "$new_accounts" ]]; then
        while IFS=: read -r user shell; do
            log_drift "New login-capable account: ${user} (shell: ${shell})"
            if [[ "$MODE" == "auto-restore" ]]; then
                if [[ "$user" == "root" ]]; then
                    log_skip "root account — skipping auto-restore"
                # SAFETY: skip protected accounts
                elif is_protected_account "$user"; then
                    log_skip "Protected account — skipping nologin: ${user}"
                elif echo ",${RHEL_ACCOUNT_ALLOWLIST}," | grep -q ",${user},"; then
                    log_skip "Allowlist account: ${user}"
                else
                    chsh -s "$RHEL_NOLOGIN" "$user" 2>/dev/null && \
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

# [6] firewalld firewall check
# SAFETY: preserves required outbound ports
check_firewall() {
    log_info "===== [C6] firewalld firewall check ====="

    if ! command -v firewall-cmd >/dev/null 2>&1; then
        log_warn "firewall-cmd not installed"
        return
    fi

    # (a) Active state
    if ! firewall-cmd --state >/dev/null 2>&1; then
        log_drift "firewalld is not running!"
        if [[ "$MODE" == "auto-restore" ]]; then
            systemctl start firewalld 2>/dev/null && \
                log_restore "firewalld restarted" || \
                log_fail "firewalld start failed"
        fi
    else
        log_ok "firewalld active"
    fi

    # (b) Default zone
    local current_zone
    current_zone=$(firewall-cmd --get-default-zone 2>/dev/null)
    if [[ "$current_zone" != "drop" ]]; then
        log_drift "firewalld default zone changed: ${current_zone} (expected: drop)"
        if [[ "$MODE" == "auto-restore" ]]; then
            firewall-cmd --set-default-zone=drop 2>/dev/null && \
                log_restore "firewalld default zone restored to drop" || \
                log_fail "firewalld zone restore failed"
        fi
    else
        log_ok "firewalld default zone: drop"
    fi

    # (c) Port drift
    local baseline_ports="${BASELINE_SNAPSHOT_DIR}/firewalld_ports_baseline.txt"
    if [[ -f "$baseline_ports" ]]; then
        local current_ports_file
        current_ports_file=$(mktemp)
        firewall-cmd --list-ports 2>/dev/null | tr ' ' '\n' | sort > "$current_ports_file"

        local added_ports
        added_ports=$(comm -13 "$baseline_ports" "$current_ports_file")
        if [[ -n "$added_ports" ]]; then
            while IFS= read -r port; do
                [[ -z "$port" ]] && continue
                log_drift "firewalld new port: ${port}"
                if [[ "$MODE" == "auto-restore" ]]; then
                    firewall-cmd --permanent --remove-port="$port" 2>/dev/null || true
                    firewall-cmd --remove-port="$port" 2>/dev/null || true
                    log_restore "firewalld port removed: ${port}"
                fi
            done <<< "$added_ports"
        else
            log_ok "firewalld ports: match baseline"
        fi

        local removed_ports
        removed_ports=$(comm -23 "$baseline_ports" "$current_ports_file")
        if [[ -n "$removed_ports" ]]; then
            while IFS= read -r port; do
                [[ -z "$port" ]] && continue
                log_drift "firewalld port removed: ${port}"
                if [[ "$MODE" == "auto-restore" ]]; then
                    firewall-cmd --permanent --add-port="$port" 2>/dev/null || true
                    firewall-cmd --add-port="$port" 2>/dev/null || true
                    log_restore "firewalld port restored: ${port}"
                fi
            done <<< "$removed_ports"
        fi
        rm -f "$current_ports_file"
    else
        log_warn "firewalld ports baseline not found — cannot compare"
    fi

    # (d) Tunnel defense direct rules check
    local tunnel_baseline="${BASELINE_SNAPSHOT_DIR}/tunnel_firewalld_direct_baseline.txt"
    if [[ -f "$tunnel_baseline" ]] && ! grep -q '(none)' "$tunnel_baseline" 2>/dev/null; then
        local current_tunnel_rules
        current_tunnel_rules=$(firewall-cmd --direct --get-all-rules 2>/dev/null | grep -i "TUNNEL" || true)
        local baseline_tunnel_rules
        baseline_tunnel_rules=$(grep -v '^#' "$tunnel_baseline" 2>/dev/null | grep -i "TUNNEL" || true)

        if [[ -z "$current_tunnel_rules" ]]; then
            log_drift "firewalld tunnel defense direct rules missing"
            if [[ "$MODE" == "auto-restore" ]]; then
                log_warn "  Tunnel defense rules restore requires re-running 01 script"
            fi
        elif [[ "$current_tunnel_rules" != "$baseline_tunnel_rules" ]]; then
            log_drift "firewalld tunnel defense direct rules differ from baseline"
        else
            log_ok "firewalld tunnel defense direct rules integrity OK"
        fi
    fi

    # SAFETY: verify required outbound ports not blocked
    guard_network_outbound
}

# [7] sudoers NOPASSWD check
# SAFETY: exclude gt's NOPASSWD from drift detection
# SAFETY: exclude ANSIBLE_ACCOUNT's NOPASSWD from drift detection
check_sudoers() {
    log_info "===== [C7] sudoers NOPASSWD check ====="

    if [[ -f /etc/sudoers ]]; then
        # Check for NOPASSWD excluding gt and ANSIBLE_ACCOUNT lines
        local _sudoers_check
        _sudoers_check=$(grep -v '^[[:space:]]*gt[[:space:]]' /etc/sudoers)
        if [[ -n "${ANSIBLE_ACCOUNT:-}" ]]; then
            _sudoers_check=$(printf '%s\n' "$_sudoers_check" | grep -v "^[[:space:]]*${ANSIBLE_ACCOUNT}[[:space:]]")
        fi
        if printf '%s\n' "$_sudoers_check" | grep -q 'NOPASSWD' 2>/dev/null; then
            log_drift "sudoers has NOPASSWD (non-gt lines)!"
            if [[ "$MODE" == "auto-restore" ]]; then
                _rhel_backup_before_restore /etc/sudoers
                # Remove NOPASSWD from non-gt, non-ansible lines (wheel group)
                if [[ -n "${ANSIBLE_ACCOUNT:-}" ]]; then
                    sed -i "/^[[:space:]]*gt[[:space:]]/b; /^[[:space:]]*${ANSIBLE_ACCOUNT}[[:space:]]/b; s/^\(%wheel[[:space:]]\+ALL=(ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/" /etc/sudoers
                    sed -i "/^[[:space:]]*gt[[:space:]]/b; /^[[:space:]]*${ANSIBLE_ACCOUNT}[[:space:]]/b; s/^\(%wheel[[:space:]]\+ALL=(ALL:ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/" /etc/sudoers
                else
                    sed -i '/^[[:space:]]*gt[[:space:]]/!{s/^\(%wheel[[:space:]]\+ALL=(ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/}' /etc/sudoers
                    sed -i '/^[[:space:]]*gt[[:space:]]/!{s/^\(%wheel[[:space:]]\+ALL=(ALL:ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/}' /etc/sudoers
                fi
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
        nopasswd_files=$(grep -rl 'NOPASSWD' /etc/sudoers.d/ 2>/dev/null || true)
        if [[ -n "$nopasswd_files" ]]; then
            while IFS= read -r f; do
                local fname
                fname=$(basename "$f")
                # SAFETY: skip gt's sudoers drop-in
                if [[ "$fname" == "00-gt-nopasswd" ]]; then
                    log_ok "gt NOPASSWD preserved: $f"
                    continue
                fi
                # SAFETY: skip ansible's sudoers drop-in
                if [[ "$fname" == "zz-ansible-nopasswd" ]]; then
                    log_ok "Ansible NOPASSWD preserved: $f"
                    continue
                fi
                log_drift "sudoers.d NOPASSWD file: $f"
            done <<< "$nopasswd_files"
        else
            log_ok "sudoers.d: no NOPASSWD (gt excluded)"
        fi
    fi
}

# [8] Empty password accounts check
# SAFETY: skip protected accounts
check_empty_passwords() {
    log_info "===== [C8] Empty password accounts check ====="

    local empty_pw_users
    empty_pw_users=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null || true)

    if [[ -n "$empty_pw_users" ]]; then
        while IFS= read -r user; do
            # SAFETY: skip protected accounts
            if is_protected_account "$user"; then
                log_skip "Protected account — skipping lock check: $user"
                continue
            fi
            log_drift "Empty password account: $user"
            if [[ "$MODE" == "auto-restore" ]]; then
                passwd -l "$user" 2>/dev/null && \
                    log_restore "Account locked: $user" || \
                    log_fail "Account lock failed: $user"
            fi
        done <<< "$empty_pw_users"
    else
        log_ok "No empty password accounts"
    fi
}

# [9] Suspicious files detection
check_suspicious_files() {
    log_info "===== [C9] Suspicious files detection ====="

    local suspicious_dirs=(/bin /sbin /usr/bin /usr/sbin /usr/lib/systemd)
    for dir in "${suspicious_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local hidden_files
            hidden_files=$(find "$dir" -maxdepth 2 -name '.*' -type f -executable 2>/dev/null || true)
            if [[ -n "$hidden_files" ]]; then
                while IFS= read -r f; do
                    log_drift "Hidden executable: $f"
                done <<< "$hidden_files"
            fi
        fi
    done

    for dir in /tmp /dev/shm /var/tmp; do
        if [[ -d "$dir" ]]; then
            local exec_files
            exec_files=$(find "$dir" -type f -executable 2>/dev/null | head -20 || true)
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

# [10] auditd status check — diff-based against snapshot, restore if drifted
check_auditd() {
    log_info "===== [C10] auditd status check ====="

    if ! command -v auditctl >/dev/null 2>&1; then
        log_warn "auditctl not found — auditd not installed"
        return
    fi

    if systemctl is-active auditd 2>/dev/null | grep -q "active"; then
        log_ok "auditd service active"
    else
        log_drift "auditd service not active!"
        if [[ "$MODE" == "auto-restore" ]]; then
            systemctl start auditd 2>/dev/null && \
                log_restore "auditd restarted" || \
                log_fail "auditd restart failed"
        fi
    fi

    local rule_count
    rule_count=$(auditctl -l 2>/dev/null | grep -cv '^No rules' || echo "0")
    local baseline_rule_file="${BASELINE_SNAPSHOT_DIR}/audit_rules_baseline.txt"
    local expected_rules=15
    if [[ -f "$baseline_rule_file" ]]; then
        expected_rules=$(grep -cv '^No rules\|^$' "$baseline_rule_file" 2>/dev/null || echo "15")
        [[ "$expected_rules" -eq 0 ]] && expected_rules=15
    fi
    if [[ "$rule_count" -lt "$expected_rules" ]]; then
        log_drift "auditd rules insufficient (${rule_count}, expected: ${expected_rules}+)"
    else
        log_ok "auditd rules: ${rule_count} (expected: ${expected_rules}+)"
    fi

    local rules_file="/etc/audit/rules.d/99-hardening.rules"
    if [[ ! -f "$rules_file" ]]; then
        log_drift "auditd hardening rules file missing: $rules_file"
    else
        log_ok "auditd rules file exists: $rules_file"
        if grep -q 'tunnel_' "$rules_file" 2>/dev/null; then
            log_ok "auditd tunnel detection rules present"
        else
            log_drift "auditd tunnel detection rules missing: $rules_file"
        fi
    fi

    # Diff-based snapshot check
    local snap_dir="${BASELINE_SNAPSHOT_DIR}/auditd"
    if [[ -d "$snap_dir" ]]; then
        # Check auditd.conf
        local auditd_conf=""
        if [[ -f /etc/audit/auditd.conf ]]; then
            auditd_conf="/etc/audit/auditd.conf"
        elif [[ -f /etc/auditd.conf ]]; then
            auditd_conf="/etc/auditd.conf"
        fi
        if [[ -n "$auditd_conf" ]] && [[ -f "${snap_dir}/auditd.conf" ]]; then
            if ! diff -q "$auditd_conf" "${snap_dir}/auditd.conf" >/dev/null 2>&1; then
                log_drift "auditd.conf differs from baseline snapshot"
                if [[ "$MODE" == "auto-restore" ]]; then
                    _rhel_backup_before_restore "$auditd_conf"
                    cp "${snap_dir}/auditd.conf" "$auditd_conf" && \
                        log_restore "auditd.conf restored from snapshot" || \
                        log_fail "auditd.conf restore failed"
                    # Restore SELinux context
                    if command -v restorecon &>/dev/null; then
                        restorecon "$auditd_conf" 2>/dev/null || true
                    fi
                    svc_restart auditd || true
                fi
            else
                log_ok "auditd.conf matches baseline snapshot"
            fi
        fi

        # Check rules.d
        if [[ -d "${snap_dir}/rules.d" ]]; then
            local snap_rule
            for snap_rule in "${snap_dir}/rules.d/"*; do
                [[ -f "$snap_rule" ]] || continue
                local rule_name
                rule_name=$(basename "$snap_rule")
                local live_rule="/etc/audit/rules.d/${rule_name}"
                if [[ ! -f "$live_rule" ]]; then
                    log_drift "auditd rule file missing: ${live_rule}"
                    if [[ "$MODE" == "auto-restore" ]]; then
                        cp "$snap_rule" "$live_rule" && \
                            log_restore "auditd rule file restored: ${live_rule}" || \
                            log_fail "auditd rule file restore failed: ${live_rule}"
                        # Restore SELinux context
                        if command -v restorecon &>/dev/null; then
                            restorecon "$live_rule" 2>/dev/null || true
                        fi
                    fi
                elif ! diff -q "$live_rule" "$snap_rule" >/dev/null 2>&1; then
                    log_drift "auditd rule file differs from snapshot: ${live_rule}"
                    if [[ "$MODE" == "auto-restore" ]]; then
                        _rhel_backup_before_restore "$live_rule"
                        cp "$snap_rule" "$live_rule" && \
                            log_restore "auditd rule file restored: ${live_rule}" || \
                            log_fail "auditd rule file restore failed: ${live_rule}"
                        if command -v restorecon &>/dev/null; then
                            restorecon "$live_rule" 2>/dev/null || true
                        fi
                    fi
                else
                    log_ok "auditd rule file OK: ${live_rule}"
                fi
            done
            # Reload if any restores happened
            if [[ "$MODE" == "auto-restore" ]]; then
                augenrules --load 2>/dev/null || auditctl -R "$rules_file" 2>/dev/null || true
            fi
        fi
    fi
}

# [11] PAM password policy check
check_pam_policy() {
    log_info "===== [C11] PAM password policy check ====="

    local pwquality_conf="/etc/security/pwquality.conf"
    if [[ -f "$pwquality_conf" ]]; then
        if grep -q "minlen" "$pwquality_conf" 2>/dev/null; then
            log_ok "PAM pwquality config present"
        else
            log_drift "PAM pwquality config tampered (missing minlen)"
        fi
    else
        log_drift "PAM pwquality config file missing"
    fi

    local faillock_conf="/etc/security/faillock.conf"
    if [[ -f "$faillock_conf" ]]; then
        if grep -q 'deny' "$faillock_conf" 2>/dev/null; then
            log_ok "faillock deny setting present"
        else
            log_drift "faillock.conf missing deny setting"
        fi
    else
        log_drift "faillock.conf missing — account lockout policy not applied"
    fi

    # Check authselect features
    if command -v authselect &>/dev/null; then
        local current_profile
        current_profile=$(authselect current -r 2>/dev/null || true)
        if [[ -n "$current_profile" ]]; then
            if echo "$current_profile" | grep -q 'with-faillock'; then
                log_ok "authselect: with-faillock enabled"
            else
                log_drift "authselect: with-faillock not enabled"
            fi
        fi
    else
        # Fallback: check PAM files directly
        local pam_auth="/etc/pam.d/system-auth"
        if [[ -f "$pam_auth" ]]; then
            if grep -q 'pam_faillock' "$pam_auth" 2>/dev/null; then
                log_ok "PAM system-auth has faillock"
            else
                log_drift "PAM system-auth missing faillock"
            fi
        fi
    fi
}

# [12] cron permissions check
check_cron_permissions() {
    log_info "===== [C12] cron permissions check ====="

    local baseline_file="${BASELINE_SNAPSHOT_DIR}/cron_permissions_baseline.txt"
    if [[ ! -f "$baseline_file" ]]; then
        log_warn "cron permissions baseline not found — fallback to other permission check"
        for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
                  /etc/cron.monthly /etc/cron.d /etc/crontab; do
            [[ -e "$d" ]] || continue
            local perm
            perm=$(stat -c '%a' "$d" 2>/dev/null)
            if [[ "${perm: -1}" != "0" ]]; then
                log_drift "cron permission issue: $d (${perm}) — other access possible"
                if [[ "$MODE" == "auto-restore" ]]; then
                    _rhel_backup_before_restore "$d"
                    chmod og-rwx "$d" && chown root:root "$d" 2>/dev/null && \
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
        current_perm=$(stat -c '%a' "$filepath" 2>/dev/null)
        current_owner=$(stat -c '%U:%G' "$filepath" 2>/dev/null)

        if [[ "$current_perm" != "$expected_perm" ]]; then
            log_drift "cron permission changed: $filepath (expected=${expected_perm}, current=${current_perm})"
            if [[ "$MODE" == "auto-restore" ]]; then
                _rhel_backup_before_restore "$filepath"
                chmod "$expected_perm" "$filepath" 2>/dev/null && \
                    log_restore "cron permission restored: $filepath" || \
                    log_fail "cron permission restore failed: $filepath"
            fi
        else
            log_ok "cron permission OK: $filepath (${current_perm})"
        fi
    done < "$baseline_file"
}

# [13] Kernel module blacklist check
check_modprobe_blacklist() {
    log_info "===== [C13] Kernel module blacklist check ====="

    local devsec_conf="/etc/modprobe.d/dev-sec.conf"
    local baseline_file="${BASELINE_SNAPSHOT_DIR}/modprobe_baseline.conf"

    if [[ ! -f "$devsec_conf" ]]; then
        log_drift "Kernel module blacklist file missing: $devsec_conf"
        if [[ "$MODE" == "auto-restore" ]] && [[ -f "$baseline_file" ]]; then
            _rhel_backup_before_restore "$devsec_conf"
            cp "$baseline_file" "$devsec_conf" && \
                log_restore "modprobe blacklist restored" || \
                log_fail "modprobe blacklist restore failed"
            if command -v restorecon &>/dev/null; then
                restorecon "$devsec_conf" 2>/dev/null || true
            fi
        fi
        return
    fi

    if [[ -f "$baseline_file" ]]; then
        if ! diff -q "$devsec_conf" "$baseline_file" >/dev/null 2>&1; then
            log_drift "Kernel module blacklist file tampered"
            if [[ "$MODE" == "auto-restore" ]]; then
                _rhel_backup_before_restore "$devsec_conf"
                cp "$baseline_file" "$devsec_conf" && \
                    log_restore "modprobe blacklist restored" || \
                    log_fail "modprobe blacklist restore failed"
                if command -v restorecon &>/dev/null; then
                    restorecon "$devsec_conf" 2>/dev/null || true
                fi
            fi
        else
            log_ok "Kernel module blacklist OK"
        fi
    else
        local required_mods=(cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat usb-storage)
        for mod in "${required_mods[@]}"; do
            if ! grep -q "install ${mod} /bin/true" "$devsec_conf" 2>/dev/null; then
                log_drift "Missing blocked module: ${mod}"
            fi
        done
    fi
}

# [14] /proc hidepid check
check_proc_hidepid() {
    log_info "===== [C14] /proc hidepid check ====="

    local hidepid_flag="${BASELINE_SNAPSHOT_DIR}/hidepid_enabled.txt"
    if [[ -f "$hidepid_flag" ]]; then
        local flag_val
        flag_val=$(cat "$hidepid_flag" 2>/dev/null | tr -d '[:space:]')
        if [[ "$flag_val" == "false" ]]; then
            log_skip "/proc hidepid intentionally disabled (HIDEPID_ENABLED=false) — skipping"
            return
        fi
    fi

    if mount | grep -q 'hidepid=2'; then
        log_ok "/proc hidepid=2 active"
        return
    fi

    local is_virtual=false
    if systemd-detect-virt --quiet 2>/dev/null; then
        is_virtual=true
    elif grep -qiE '(vmware|virtualbox|kvm|xen|hyper-v|lxc|docker|container)' \
         /sys/class/dmi/id/product_name 2>/dev/null; then
        is_virtual=true
    elif [[ -f /.dockerenv ]] || grep -q 'container=' /proc/1/environ 2>/dev/null; then
        is_virtual=true
    fi

    if [[ "$is_virtual" == "true" ]]; then
        log_warn "/proc hidepid=2 not applied (virtual/container environment — remount may fail)"
        if [[ "$MODE" == "auto-restore" ]]; then
            if mount -o remount,hidepid=2 /proc 2>/dev/null; then
                log_restore "/proc hidepid=2 re-applied"
            else
                log_warn "/proc hidepid=2 re-apply failed — reboot may be needed for fstab entry"
            fi
        fi
    else
        log_drift "/proc hidepid=2 disabled!"
        if [[ "$MODE" == "auto-restore" ]]; then
            mount -o remount,hidepid=2 /proc 2>/dev/null && \
                log_restore "/proc hidepid=2 re-applied" || \
                log_fail "/proc hidepid=2 re-apply failed"
        fi
    fi
}

# [15] SSH config check
check_ssh_config() {
    log_info "===== [C15] SSH config check ====="

    if ! command -v sshd >/dev/null 2>&1; then
        log_warn "sshd not installed"
        return
    fi

    if ! systemctl is-active sshd 2>/dev/null | grep -q "active"; then
        log_warn "SSH service not active"
    fi

    if [[ ! -f /etc/ssh/sshd_config.d/99-hardening.conf ]]; then
        log_drift "SSH hardening config missing: /etc/ssh/sshd_config.d/99-hardening.conf"
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
                local hardened_conf="/etc/ssh/sshd_config.d/99-hardening.conf"
                _rhel_backup_before_restore "$hardened_conf"
                {
                    echo "# === Security hardening (auto-restore: $(date '+%Y%m%d_%H%M%S')) ==="
                    for rkey in "${check_keys[@]}"; do
                        local rval
                        rval=$(grep "^${rkey} " "$baseline_file" 2>/dev/null | awk '{print $2}')
                        [[ -z "$rval" ]] && continue
                        case "$rkey" in
                            permitrootlogin)         echo "PermitRootLogin ${rval}" ;;
                            passwordauthentication)  echo "PasswordAuthentication ${rval}" ;;
                            permitemptypasswords)    echo "PermitEmptyPasswords ${rval}" ;;
                            x11forwarding)           echo "X11Forwarding ${rval}" ;;
                            allowtcpforwarding)      echo "AllowTcpForwarding ${rval}" ;;
                            allowagentforwarding)    echo "AllowAgentForwarding ${rval}" ;;
                            maxauthtries)            echo "MaxAuthTries ${rval}" ;;
                            hostbasedauthentication) echo "HostbasedAuthentication ${rval}" ;;
                            ignorerhosts)            echo "IgnoreRhosts ${rval}" ;;
                            clientaliveinterval)     echo "ClientAliveInterval ${rval}" ;;
                            clientalivecountmax)     echo "ClientAliveCountMax ${rval}" ;;
                            logingracetime)          echo "LoginGraceTime ${rval}" ;;
                            maxsessions)             echo "MaxSessions ${rval}" ;;
                            usepam)                  echo "UsePAM ${rval}" ;;
                            banner)                  echo "Banner ${rval}" ;;
                        esac
                    done
                } > "${hardened_conf}.tmp"
                if cp "${hardened_conf}.tmp" "$hardened_conf" && sshd -t 2>/dev/null; then
                    rm -f "${hardened_conf}.tmp"
                    # Restore SELinux context
                    if command -v restorecon &>/dev/null; then
                        restorecon "$hardened_conf" 2>/dev/null || true
                    fi
                    systemctl reload sshd 2>/dev/null || true
                    sleep 1  # Allow sshd to complete reload before continuing
                    log_restore "SSH drop-in regenerated and reloaded"
                else
                    rm -f "${hardened_conf}.tmp"
                    local bk_file="${RHEL_RESTORE_BACKUP_DIR}/$(echo "$hardened_conf" | tr '/' '_')"
                    if [[ -f "$bk_file" ]]; then
                        cp "$bk_file" "$hardened_conf" 2>/dev/null
                        if sshd -t 2>/dev/null; then
                            systemctl reload sshd 2>/dev/null || true
                            sleep 1  # Allow sshd to complete reload before continuing
                            log_warn "SSH drop-in regeneration failed — rolled back from backup"
                        else
                            log_fail "SSH rollback also failed sshd -t — manual check required"
                        fi
                    else
                        log_fail "SSH drop-in regeneration failed — no backup, manual check required"
                    fi
                fi
                break  # Only regenerate once
            fi
        else
            log_ok "SSH ${key}=${current_val}"
        fi
    done
}

# [16] Malicious cron/at detection
check_malicious_cron() {
    log_info "===== [C16] Malicious cron/at detection ====="

    # RHEL uses /var/spool/cron (not crontabs subdir)
    local crontab_dir="/var/spool/cron"
    if [[ -d "$crontab_dir" ]]; then
        for ct in "$crontab_dir"/*; do
            [[ -f "$ct" ]] || continue
            local user
            user=$(basename "$ct")
            if [[ "$user" != "root" ]]; then
                if echo ",${RHEL_CRONTAB_ALLOWLIST}," | grep -q ",${user},"; then
                    log_skip "crontab allowlist account: ${user}"
                else
                    log_drift "Non-root user crontab: ${user}"
                    log_info "  Content: $(head -5 "$ct" 2>/dev/null)"
                fi
            fi
            if grep -qiE '(nc\s+-[elp]|ncat|bash\s+-i|/dev/tcp|python.*socket|wget.*\|.*sh|curl.*\|.*sh|mkfifo|reverse|shell)' "$ct" 2>/dev/null; then
                log_drift "Suspicious crontab command (${user}): $(grep -iE '(nc |ncat|bash -i|/dev/tcp|python.*socket|wget.*sh|curl.*sh|mkfifo|reverse|shell)' "$ct" 2>/dev/null | head -3)"
            fi
        done
    fi

    if [[ -d /etc/cron.d ]]; then
        for f in /etc/cron.d/*; do
            [[ -f "$f" ]] || continue
            if grep -qiE '(nc\s+-[elp]|ncat|bash\s+-i|/dev/tcp|python.*socket|wget.*\|.*sh|curl.*\|.*sh|mkfifo)' "$f" 2>/dev/null; then
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

# [17] Network listening ports check
check_network() {
    log_info "===== [C17] Network listening ports check ====="

    local baseline_file="${BASELINE_SNAPSHOT_DIR}/listening_ports_baseline.txt"
    local current_ports
    current_ports=$(ss -tlnp 2>/dev/null)

    if [[ -f "$baseline_file" ]]; then
        local current_addrs baseline_addrs
        current_addrs=$(echo "$current_ports" | awk 'NR>1 {print $4}' | sort -u)
        baseline_addrs=$(awk 'NR>1 {print $4}' "$baseline_file" 2>/dev/null | sort -u)

        local new_ports
        new_ports=$(comm -13 <(echo "$baseline_addrs") <(echo "$current_addrs"))
        if [[ -n "$new_ports" ]]; then
            while IFS= read -r addr; do
                local proc_info
                proc_info=$(echo "$current_ports" | grep "$addr" | awk '{print $NF}')
                log_drift "New listening port: ${addr} (${proc_info})"
            done <<< "$new_ports"
        else
            log_ok "No new listening ports vs baseline"
        fi
    fi

    local suspect_ports=(4444 5555 6666 7777 8888 9999 1234 31337 12345 54321)
    for port in "${suspect_ports[@]}"; do
        if echo ",${RHEL_WHITELISTED_PORTS}," | grep -q ",${port},"; then
            continue
        fi
        if echo "$current_ports" | grep -q ":${port} " 2>/dev/null; then
            local proc
            proc=$(echo "$current_ports" | grep ":${port} " | awk '{print $NF}')
            log_drift "Suspicious port listening: :${port} (${proc})"
        fi
    done

    local ext_conns
    ext_conns=$(ss -tnp state established 2>/dev/null | \
        awk 'NR>1 && $5 !~ /^(127\.|::1|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|169\.254\.)/ {print $4, $5, $NF}' | head -20)
    if [[ -n "$ext_conns" ]]; then
        log_info "External ESTABLISHED connections:"
        while IFS= read -r line; do
            log_info "  $line"
        done <<< "$ext_conns"
    fi
}

# [18] Suspicious processes check
check_suspicious_processes() {
    log_info "===== [C18] Suspicious processes check ====="

    local deleted_procs
    deleted_procs=$(ls -la /proc/*/exe 2>/dev/null | grep '(deleted)' | grep -v '/memfd:' || true)
    if [[ -n "$deleted_procs" ]]; then
        while IFS= read -r line; do
            log_drift "Deleted binary running: $line"
        done <<< "$deleted_procs"
    else
        log_ok "No deleted binary processes"
    fi

    local suspect_patterns='(cryptominer|xmrig|kinsing|kdevtmpfsi|kthreaddi|\.hidden|/dev/shm/|/tmp/\.)'
    local suspect_procs
    suspect_procs=$(ps auxww 2>/dev/null | grep -iE "$suspect_patterns" | grep -v grep || true)
    if [[ -n "$suspect_procs" ]]; then
        while IFS= read -r line; do
            log_drift "Suspicious process: $line"
        done <<< "$suspect_procs"
    fi

    local tmp_procs
    tmp_procs=$(ls -la /proc/*/exe 2>/dev/null | grep -E '(/tmp/|/dev/shm/|/var/tmp/)' || true)
    if [[ -n "$tmp_procs" ]]; then
        while IFS= read -r line; do
            log_drift "Running from temp path: $line"
        done <<< "$tmp_procs"
    else
        log_ok "No temp path processes"
    fi
}

# [19] UID 0 backdoor accounts check
check_uid0_accounts() {
    log_info "===== [C19] UID 0 backdoor accounts check ====="

    local uid0_users
    uid0_users=$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null)
    local uid0_count=0

    while IFS= read -r user; do
        uid0_count=$((uid0_count + 1))
        if [[ "$user" != "root" ]]; then
            log_drift "Non-root UID 0 account: ${user} (possible backdoor!)"
        fi
    done <<< "$uid0_users"

    if [[ "$uid0_count" -le 1 ]]; then
        log_ok "UID 0 accounts: root only"
    fi
}

# [20] login.defs password aging check
check_login_defs() {
    log_info "===== [C20] login.defs password aging check ====="

    local login_defs="/etc/login.defs"
    if [[ ! -f "$login_defs" ]]; then
        log_warn "login.defs not found"
        return
    fi

    local baseline_file="${BASELINE_SNAPSHOT_DIR}/login_defs_baseline.txt"
    if [[ ! -f "$baseline_file" ]]; then
        log_warn "login.defs baseline not found — skipping"
        return
    fi

    while IFS='=' read -r key expected_val; do
        [[ -z "$key" || "$key" == \#* ]] && continue
        local current_val
        current_val=$(awk -v k="$key" '$1==k {print $2}' "$login_defs" 2>/dev/null)

        if [[ -z "$current_val" ]]; then
            log_drift "login.defs ${key}: expected=${expected_val}, current=unset"
        elif [[ "$current_val" != "$expected_val" ]]; then
            log_drift "login.defs ${key}: expected=${expected_val}, current=${current_val}"
            if [[ "$MODE" == "auto-restore" ]]; then
                _rhel_backup_before_restore "$login_defs"
                sed -i "s/^\([[:space:]]*${key}[[:space:]]\+\).*/\1${expected_val}/" "$login_defs" 2>/dev/null && \
                    log_restore "login.defs ${key}=${expected_val} restored" || \
                    log_fail "login.defs ${key} restore failed"
            fi
        else
            log_ok "login.defs ${key}=${current_val}"
        fi
    done < "$baseline_file"
}

# [21] Tunnel defense check (firewalld direct rules integrated version)
check_tunnel_defense() {
    log_info "===== [C21] Tunnel defense check (firewalld direct rules integrated) ====="

    local _tunnel_reload_needed=false

    # (a) Runtime ICMP tunnel defense rules
    log_info "  [21-a] ICMP tunnel defense runtime rules"

    if command -v iptables &>/dev/null; then
        if iptables -S INPUT 2>/dev/null | grep -q 'TUNNEL_ICMP_LARGE_IN'; then
            log_ok "  ICMP large packet inbound block active"
        else
            log_drift "  ICMP large packet inbound block missing"
            _tunnel_reload_needed=true
        fi

        if iptables -S OUTPUT 2>/dev/null | grep -q 'TUNNEL_ICMP_LARGE_OUT'; then
            log_ok "  ICMP large packet outbound block active"
        else
            log_drift "  ICMP large packet outbound block missing"
            _tunnel_reload_needed=true
        fi
    fi

    # ICMPv6
    if command -v ip6tables &>/dev/null; then
        if ip6tables -S INPUT 2>/dev/null | grep -q 'TUNNEL_ICMP6_LARGE_IN'; then
            log_ok "  ICMPv6 large packet block active"
        else
            log_drift "  ICMPv6 large packet block missing"
            _tunnel_reload_needed=true
        fi
    fi

    # (b) Runtime DNS tunnel defense rules
    log_info "  [21-b] DNS tunnel defense runtime rules"

    if command -v iptables &>/dev/null; then
        if iptables -S OUTPUT 2>/dev/null | grep -q 'TUNNEL_DNS_TCP_OUT'; then
            log_ok "  DNS over TCP outbound block active"
        else
            log_drift "  DNS over TCP outbound block missing"
            _tunnel_reload_needed=true
        fi

        if iptables -S INPUT 2>/dev/null | grep -q 'TUNNEL_DNS_LARGE_RESP'; then
            log_ok "  Large DNS response logging rule active"
        else
            log_drift "  Large DNS response logging rule missing"
            _tunnel_reload_needed=true
        fi
    fi

    # resolv.conf immutable lock check
    # Detection order mirrors _rhel_tunnel_dns_lock_resolv:
    # 1. systemd-resolved + symlink → no chattr needed
    # 2. NetworkManager + /etc/NetworkManager/ → check NM conf.d file
    # 3. direct management → check chattr
    if systemctl is-active systemd-resolved &>/dev/null 2>&1 && [[ -L /etc/resolv.conf ]]; then
        log_ok "  /etc/resolv.conf is symlink (systemd-resolved managed — chattr not needed)"
    elif systemctl is-active NetworkManager &>/dev/null 2>&1 && [[ -d /etc/NetworkManager ]]; then
        local nm_dns_conf="/etc/NetworkManager/conf.d/99-dns-hardening.conf"
        if [[ -f "${nm_dns_conf}" ]]; then
            log_ok "  NetworkManager DNS hardening conf present: ${nm_dns_conf}"
        else
            log_drift "  NetworkManager DNS hardening conf missing: ${nm_dns_conf}"
            if [[ "$MODE" == "auto-restore" ]]; then
                mkdir -p /etc/NetworkManager/conf.d
                {
                    echo "# DNS tunnel defense — auto-generated: ${TIMESTAMP}"
                    echo "[main]"
                    echo "dns=default"
                } > "${nm_dns_conf}" && \
                    log_restore "  NetworkManager DNS hardening conf re-created" || \
                    log_fail "  NetworkManager DNS hardening conf re-create failed"
            fi
        fi
    elif command -v lsattr &>/dev/null; then
        if lsattr /etc/resolv.conf 2>/dev/null | grep -q '^....i'; then
            log_ok "  /etc/resolv.conf immutable lock (chattr +i) active"
        else
            log_drift "  /etc/resolv.conf immutable lock removed"
            if [[ "$MODE" == "auto-restore" ]]; then
                chattr +i /etc/resolv.conf 2>/dev/null && \
                    log_restore "  resolv.conf immutable lock re-applied" || \
                    log_fail "  resolv.conf immutable lock re-apply failed"
            fi
        fi
    fi

    # resolv.conf content comparison with baseline
    local resolv_baseline="${BASELINE_SNAPSHOT_DIR}/tunnel_resolv_baseline.txt"
    if [[ -f "$resolv_baseline" ]]; then
        local baseline_resolv_content
        baseline_resolv_content=$(awk '/^# chattr/{exit} /^#/{next} {print}' \
                                   "$resolv_baseline" 2>/dev/null | grep -v '^$' | sort || true)
        local current_resolv_content
        current_resolv_content=$(grep -v '^#' /etc/resolv.conf 2>/dev/null | grep -v '^$' | sort || true)

        if [[ -n "$baseline_resolv_content" ]] && \
           [[ "$baseline_resolv_content" != "$current_resolv_content" ]]; then
            log_drift "  /etc/resolv.conf content differs from baseline (possible DNS redirect)"
            log_info "  Baseline: $(echo "$baseline_resolv_content" | head -3)"
            log_info "  Current:  $(echo "$current_resolv_content" | head -3)"
        else
            log_ok "  /etc/resolv.conf content OK"
        fi
    fi

    # (c) Runtime SOCKS5 tunnel defense rules
    log_info "  [21-c] SOCKS5 tunnel defense runtime rules"

    if command -v iptables &>/dev/null && iptables -m string --help 2>&1 | grep -q "string" 2>/dev/null; then
        if iptables -S INPUT 2>/dev/null | grep -q 'TUNNEL_SOCKS5_NOAUTH_IN'; then
            log_ok "  SOCKS5 No-Auth handshake inbound block active"
        else
            log_drift "  SOCKS5 No-Auth handshake inbound block missing"
            _tunnel_reload_needed=true
        fi

        if iptables -S OUTPUT 2>/dev/null | grep -q 'TUNNEL_SOCKS5_CONN_OUT'; then
            log_ok "  SOCKS5 CONNECT outbound block active"
        else
            log_drift "  SOCKS5 CONNECT outbound block missing"
            _tunnel_reload_needed=true
        fi
    else
        log_skip "  iptables string module unavailable — SOCKS5 pattern check skipped"
    fi

    # firewalld reload for missing runtime rules
    if [[ "$_tunnel_reload_needed" == true ]]; then
        if [[ "$MODE" == "auto-restore" ]]; then
            if command -v firewall-cmd &>/dev/null && firewall-cmd --state >/dev/null 2>&1; then
                log_info "  Runtime tunnel rules missing — firewall-cmd --reload to re-apply"
                if firewall-cmd --reload 2>/dev/null; then
                    log_restore "  firewalld reload complete — tunnel defense restored"
                else
                    log_fail "  firewalld reload failed — check firewalld status"
                fi
            else
                log_fail "  firewalld not available — re-run 01 script"
            fi
        else
            log_info "  (check-only mode) Runtime rule restore: run with --auto-restore"
        fi
    fi

    # (d) Tunnel tool process detection
    log_info "  [21-d] Tunnel tool process detection"
    local _proc_found=false
    for proc in "${RHEL_TUNNEL_TOOL_PROCS[@]}"; do
        if pgrep -x "$proc" &>/dev/null; then
            local pids
            pids=$(pgrep -x "$proc" | tr '\n' ',' | sed 's/,$//')
            log_drift "  Tunnel tool running: ${proc} (PID: ${pids})"
            _proc_found=true
        fi
    done

    if ls /proc/*/fd 2>/dev/null | xargs -I{} readlink {} 2>/dev/null \
       | grep -q "net/tun" 2>/dev/null; then
        log_drift "  TUN device held by process detected (possible tunneling)"
        _proc_found=true
    fi

    local dns_non_std
    dns_non_std=$(ss -unp 2>/dev/null \
                  | awk '$5 ~ /:53$/ && $4 !~ /^(127\.|10\.|172\.|192\.168\.)/ {print}' \
                  || true)
    if [[ -n "$dns_non_std" ]]; then
        log_drift "  Non-internal direct DNS queries detected (possible DNS tunneling):"
        echo "$dns_non_std" | while IFS= read -r line; do
            log_info "    -> $line"
        done
        _proc_found=true
    fi

    [[ "$_proc_found" == false ]] && log_ok "  No tunnel tools/TUN processes detected"

    # (e) auditd tunnel detection rules detailed check
    log_info "  [21-e] auditd tunnel detection rules check"
    if command -v auditctl &>/dev/null; then
        local rules_file="/etc/audit/rules.d/99-hardening.rules"

        if [[ ! -f "$rules_file" ]]; then
            log_drift "  auditd rules file missing: ${rules_file}"
        else
            local audit_keys=(
                tunnel_icmp
                tunnel_dns
                tunnel_dns_config
                tunnel_tun_create
                tunnel_raw_socket
                tunnel_socks5
                tunnel_net_config
            )
            local audit_descs=(
                "ICMP tunnel tool audit"
                "DNS tunnel tool audit"
                "resolv.conf tampering audit"
                "TUN/TAP creation audit"
                "raw socket creation audit"
                "SOCKS5 tool audit"
                "Network interface change audit"
            )

            for i in "${!audit_keys[@]}"; do
                local key="${audit_keys[$i]}"
                local desc="${audit_descs[$i]}"
                if grep -q "\-k ${key}" "$rules_file" 2>/dev/null; then
                    log_ok "  auditd rule OK: ${desc} (${key})"
                else
                    log_drift "  auditd rule missing: ${desc} (${key})"
                fi
            done

            local audit_runtime
            audit_runtime=$(auditctl -l 2>/dev/null || true)
            if [[ -n "$audit_runtime" ]]; then
                local loaded_tunnel_count
                loaded_tunnel_count=$(echo "$audit_runtime" | grep -c '\-k tunnel_' || true)
                if [[ "$loaded_tunnel_count" -gt 0 ]]; then
                    log_ok "  auditd runtime tunnel rules loaded: ${loaded_tunnel_count}"
                else
                    log_warn "  auditd runtime has no tunnel_ rules — augenrules reload may be needed"
                fi
            else
                log_warn "  auditctl -l output empty (immutable mode or service inactive)"
            fi
        fi
    else
        log_skip "  auditctl not found — auditd tunnel rules check unavailable"
    fi

    # (f) Tunnel tool binary residue check
    log_info "  [21-f] Tunnel tool binary residue check"
    local _bin_found=false
    for bin in "${RHEL_TUNNEL_BINS[@]}"; do
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

# [22] SELinux status check
check_selinux() {
    log_info "===== [C22] SELinux status check ====="

    if ! command -v getenforce &>/dev/null; then
        log_skip "SELinux tools not available"
        return
    fi

    local selinux_status
    selinux_status=$(getenforce 2>/dev/null || echo "unknown")

    case "$selinux_status" in
        Enforcing)
            log_ok "SELinux is Enforcing"
            ;;
        Permissive)
            log_drift "SELinux is Permissive (should be Enforcing)"
            if [[ "$MODE" == "auto-restore" ]]; then
                setenforce 1 2>/dev/null && \
                    log_restore "SELinux set to Enforcing" || \
                    log_fail "SELinux setenforce 1 failed"
            fi
            ;;
        Disabled)
            log_drift "SELinux is Disabled (should be Enforcing)"
            log_warn "SELinux cannot be re-enabled at runtime — reboot required"
            ;;
        *)
            log_warn "SELinux status unknown: ${selinux_status}"
            ;;
    esac
}

###############################################################################
# run_checks() — Entry point called by 02 orchestrator
# Uses global $MODE ("check-only" or "auto-restore")
###############################################################################
run_checks() {
    log_info "===== RHEL/Rocky/AlmaLinux adapter: run_checks() (mode=${MODE}) ====="

    [[ "${HARDEN_SYSCTL}" == "true" ]] && check_sysctl || log_skip "[TOGGLE] Sysctl check skipped"
    [[ "${HARDEN_FILE_PERMISSIONS}" == "true" ]] && check_file_permissions || log_skip "[TOGGLE] File permissions check skipped"
    [[ "${HARDEN_SUID}" == "true" ]] && check_suid_files || log_skip "[TOGGLE] SUID check skipped"
    [[ "${HARDEN_SERVICES}" == "true" ]] && check_disabled_services || log_skip "[TOGGLE] Service check skipped"
    [[ "${HARDEN_ACCOUNTS}" == "true" ]] && check_login_accounts || log_skip "[TOGGLE] Account check skipped"
    [[ "${HARDEN_FIREWALL}" == "true" ]] && check_firewall || log_skip "[TOGGLE] Firewall check skipped"
    [[ "${HARDEN_SUDOERS}" == "true" ]] && check_sudoers || log_skip "[TOGGLE] Sudoers check skipped"
    [[ "${HARDEN_EMPTY_PASSWORDS}" == "true" ]] && check_empty_passwords || log_skip "[TOGGLE] Empty passwords check skipped"
    check_suspicious_files     # [C9] always run
    check_auditd               # [C10] always run
    [[ "${HARDEN_PAM}" == "true" ]] && check_pam_policy || log_skip "[TOGGLE] PAM check skipped"
    [[ "${HARDEN_CRON}" == "true" ]] && check_cron_permissions || log_skip "[TOGGLE] Cron check skipped"
    [[ "${HARDEN_KERNEL_MODULES}" == "true" ]] && check_modprobe_blacklist || log_skip "[TOGGLE] Kernel modules check skipped"
    [[ "${HARDEN_HIDEPID}" == "true" ]] && check_proc_hidepid || log_skip "[TOGGLE] Hidepid check skipped"
    [[ "${HARDEN_SSH}" == "true" ]] && check_ssh_config || log_skip "[TOGGLE] SSH check skipped"
    check_malicious_cron       # [C16] always run (security)
    check_network              # [C17] always run (security)
    check_suspicious_processes # [C18] always run (security)
    check_uid0_accounts        # [C19] always run (security)
    [[ "${HARDEN_LOGIN_DEFS}" == "true" ]] && check_login_defs || log_skip "[TOGGLE] Login defs check skipped"
    [[ "${HARDEN_TUNNEL_DEFENSE}" == "true" ]] && check_tunnel_defense || log_skip "[TOGGLE] Tunnel defense check skipped"
    check_selinux              # [C22] always run (SELinux status)

    log_ok "===== RHEL/Rocky/AlmaLinux drift checks complete ====="
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
