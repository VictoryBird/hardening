#!/bin/bash
set -euo pipefail

###############################################################################
# 베이스라인 하드닝 스크립트 (ICMP/DNS/SOCKS5 터널링 방어 통합본)
#
# 변경 이력:
#   - [27] ICMP/DNS/SOCKS5 터널링 방어 iptables 규칙을 [3] UFW 설정에 통합
#     · UFW 활성화 직후 /etc/ufw/after.rules 에 터널링 방어 블록 삽입
#     · UFW reload / 재부팅 후에도 규칙 영속 보장
#     · SOCKS5 string 매칭: $'\x05\x01\x00' → --hex-string '|050100|'
#     · -C/-A comment 불일치 제거 → _ufw_ipt_ensure() 헬퍼로 일원화
#   - [27] setup_tunnel_hardening() 에서 iptables 관련 함수 제거
#     · _tunnel_detect_processes, _tunnel_remove_tools, _tunnel_append_audit_rules 유지
#     · _tunnel_icmp_harden, _tunnel_dns_harden, _tunnel_socks5_harden 제거
#       (해당 로직은 setup_ufw() → _ufw_apply_tunnel_rules() 로 이관)
###############################################################################

# =============================================================================
# [설정 섹션]
# =============================================================================
readonly SCRIPT_NAME="$(basename "$0")"
readonly HOSTNAME="$(hostname)"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

_LOG_DIR="/var/log/hardening"
if mkdir -p "$_LOG_DIR" 2>/dev/null && [[ -w "$_LOG_DIR" ]]; then
    readonly LOGFILE="${_LOG_DIR}/${TIMESTAMP}_${HOSTNAME}_baseline_hardening.log"
else
    readonly LOGFILE="/tmp/${TIMESTAMP}_${HOSTNAME}_baseline_hardening.log"
fi
readonly BACKUP_DIR="/var/backups/hardening_${TIMESTAMP}"
readonly BASELINE_SNAPSHOT_DIR="/var/backups/hardening_baseline"

# --- auditd 설정값 ---
readonly AUDIT_LOG_FILE="/var/log/audit/audit.log"
readonly AUDIT_LOG_FORMAT="RAW"
readonly AUDIT_FLUSH="INCREMENTAL"
readonly AUDIT_FREQ="50"
readonly AUDIT_NUM_LOGS="5"
readonly AUDIT_MAX_LOG_FILE="10"
readonly AUDIT_MAX_LOG_FILE_ACTION="ROTATE"
readonly AUDIT_SPACE_LEFT="75"
readonly AUDIT_SPACE_LEFT_ACTION="SYSLOG"
readonly AUDIT_ADMIN_SPACE_LEFT="50"
readonly AUDIT_ADMIN_SPACE_LEFT_ACTION="SUSPEND"
readonly AUDIT_DISK_FULL_ACTION="SUSPEND"
readonly AUDIT_DISK_ERROR_ACTION="SUSPEND"

# --- PAM 비밀번호 정책 ---
readonly PAM_PASSWDQC_MIN="disabled,24,12,8,7"

# --- 차단할 커널 모듈 ---
readonly BLOCKED_MODULES=(cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat usb-storage)

# --- sysctl 보안 설정 ---
declare -A SYSCTL_SETTINGS=(
    ["net.ipv4.ip_forward"]="0"
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
    ["net.ipv6.conf.all.accept_redirects"]="0"
    ["net.ipv6.conf.default.accept_redirects"]="0"
    ["net.ipv6.conf.all.accept_source_route"]="0"
    ["net.ipv6.conf.default.accept_source_route"]="0"
    ["net.ipv6.conf.all.accept_ra"]="0"
    ["net.ipv6.conf.default.accept_ra"]="0"
    ["net.ipv6.conf.all.forwarding"]="0"
)

# --- 민감 파일 권한 ---
readonly FILES_644=(/etc/passwd /etc/group /etc/passwd- /etc/group-)
readonly FILES_600=(/etc/shadow /etc/gshadow /etc/shadow- /etc/gshadow-)
readonly FILES_CHOWN=(/etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/passwd- /etc/group- /etc/shadow- /etc/gshadow-)

# --- other 권한 제거 대상 파일 ---
readonly FILES_O_NORW=(
    /etc/fstab /etc/ftpusers /etc/group /etc/hosts
    /etc/hosts.allow /etc/hosts.equiv /etc/ssh
    /etc/hosts.lpd /etc/inetd.conf /etc/login.access
    /etc/login.defs /etc/ssh/sshd_config /etc/sysctl.conf
    /etc/crontab /usr/bin/crontab /usr/bin/at
    /usr/bin/atq /usr/bin/atrm /usr/bin/batch
    /var/log /var/spool/cron/crontabs
)

# --- SUID 제거 대상 ---
readonly SUID_REMOVE_TARGETS=(
    /usr/bin/nmap
    /usr/bin/bash
    /usr/bin/dash
    /usr/bin/find
    /usr/bin/less
    /usr/bin/pkexec
    /usr/bin/at
    /usr/bin/newgrp
    /usr/bin/chfn
    /usr/bin/chsh
)

# --- nologin 설정 대상 시스템 계정 ---
readonly NOLOGIN_ACCOUNTS=(
    daemon bin sys games man lp mail news uucp proxy
    www-data backup list irc gnats nobody _apt
    systemd-network systemd-resolve messagebus systemd-timesync
    sshd syslog uuidd tcpdump landscape fwupd-refresh usbmux
    dnsmasq rtkit kernoops systemd-oom avahi-autoipd nm-openvpn
    avahi cups-pk-helper saned colord sssd geoclue pulse
    ntp postfix xrdp
)
readonly FALSE_SHELL_ACCOUNTS=(
    pollinate tss lxd whoopsie speech-dispatcher
    gnome-initial-setup hplip gdm
)

# --- 비활성화 대상 서비스 ---
readonly DISABLE_SERVICES=(
    avahi-daemon.service
    cups.service
    cups-browsed.service
    bluetooth.service
)

# --- SSH 하드닝 설정 ---
readonly SSH_PERMIT_ROOT_LOGIN="prohibit-password"
readonly SSH_PASSWORD_AUTH="no"
readonly SSH_MAX_AUTH_TRIES="4"
readonly SSH_CLIENT_ALIVE_INTERVAL="300"
readonly SSH_CLIENT_ALIVE_COUNT_MAX="2"
readonly SSH_LOGIN_GRACE_TIME="60"

# --- 패스워드 에이징 설정 (/etc/login.defs) ---
readonly PASS_MAX_DAYS="90"
readonly PASS_MIN_DAYS="7"
readonly PASS_WARN_AGE="14"
readonly LOGIN_RETRIES="3"
readonly DEFAULT_UMASK="027"

# --- UFW 역할 기반 프로파일 ---
readonly UFW_PROFILE="${UFW_PROFILE:-base}"

readonly SHM_NOEXEC="${SHM_NOEXEC:-true}"
readonly AUDIT_IMMUTABLE="${AUDIT_IMMUTABLE:-true}"
readonly HIDEPID_ENABLED="${HIDEPID_ENABLED:-true}"
readonly FAILLOCK_DENY_ROOT="${FAILLOCK_DENY_ROOT:-false}"

declare -A UFW_PROFILES=(
    [base]="22/tcp"
    [web]="22/tcp 80/tcp 443/tcp"
    [ad]="22/tcp 53/tcp 53/udp 88/tcp 389/tcp 389/udp 636/tcp 3268/tcp 3269/tcp"
    [log]="22/tcp 514/udp 1514/tcp 1515/tcp 1516/tcp"
    [full]="22/tcp 53/tcp 53/udp 80/tcp 88/tcp 389/tcp 389/udp 443/tcp 514/udp 636/tcp 953/tcp 1514/tcp 1515/tcp 1516/tcp 3268/tcp 3269/tcp"
)

# =============================================================================
# [설정 섹션] ICMP / DNS / SOCKS5 터널링 방어 설정
# =============================================================================

# ICMP 터널링 방어
# 허용할 최대 ICMP payload 바이트 (일반 ping은 56~1472B, 터널링은 수백~수천 B)
readonly TUNNEL_ICMP_MAX_PAYLOAD=128

# DNS 터널링 방어
readonly TUNNEL_DNS_SUSPICIOUS_TOOLS=(iodine iodined dns2tcp dnscapy dnscat dnscat2 dnstunnel)

# SOCKS5 터널링 방어
readonly TUNNEL_SOCKS5_PORTS=(1080 1081 8080 8888 9050 9150 1090 3128 8118)
readonly TUNNEL_SOCKS5_DETECT_PAYLOAD=true

# 공통 터널링 도구 프로세스명
readonly TUNNEL_TOOL_PROCS=(
    ptunnel ptunnel-ng icmptunnel icmpsh pingtunnel
    iodine iodined dns2tcp dnscat dnscat2 dnscapy dnstunnel
    chisel ligolo frpc ngrok inlets bore gost
    autossh sshuttle
)

# 터널링 방어 auditd 규칙 파일 경로
readonly TUNNEL_AUDIT_RULES_FILE="/etc/audit/rules.d/99-hardening.rules"

# /etc/resolv.conf DNS 서버를 허용 목록으로 잠금 여부
readonly TUNNEL_LOCK_RESOLV="${TUNNEL_LOCK_RESOLV:-true}"

# UFW after.rules 내 터널링 방어 블록 마커
# (idempotent 삽입 판별에 사용)
readonly UFW_TUNNEL_MARKER="# TUNNEL_HARDENING_BLOCK_BEGIN"

# =============================================================================
# [로그 함수]
# =============================================================================
log_info()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]  $*"; }
log_warn()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]  $*"; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2; }
log_ok()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [OK]    $*"; }
log_skip()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SKIP]  $*"; }

# =============================================================================
# [유틸리티 함수]
# =============================================================================
create_backup_dir() {
    if [[ ! -d "$BACKUP_DIR" ]]; then
        mkdir -p "$BACKUP_DIR"
        log_info "백업 디렉토리 생성: $BACKUP_DIR"
    fi
}

backup_file() {
    local src="$1"
    if [[ -f "$src" ]]; then
        local dest="${BACKUP_DIR}/$(echo "$src" | tr '/' '_')"
        cp -a "$src" "$dest"
        log_info "백업: $src -> $dest"
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "이 스크립트는 root 권한으로 실행해야 합니다."
        log_error "사용법: sudo $SCRIPT_NAME"
        exit 1
    fi
}

check_environment() {
    if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
        log_error "bash 4.0 이상 필요 (현재: ${BASH_VERSION})"
        exit 1
    fi
    if [[ -f /etc/os-release ]]; then
        local distro version
        distro=$(. /etc/os-release && echo "${ID:-unknown}")
        version=$(. /etc/os-release && echo "${VERSION_ID:-unknown}")
        log_info "배포판: ${distro} ${version} (bash ${BASH_VERSION})"
        case "$distro" in
            ubuntu|debian) ;;
            *)
                log_warn "이 스크립트는 Ubuntu/Debian 계열에 최적화되어 있습니다"
                log_warn "RHEL/CentOS 등에서는 일부 명령이 동작하지 않을 수 있습니다"
                ;;
        esac
    else
        log_warn "/etc/os-release 없음 — 배포판 확인 불가"
    fi
}

cleanup_old_backups() {
    log_info "===== 오래된 백업 정리 (30일+) ====="
    local old_dirs
    old_dirs=$(find /var/backups -maxdepth 1 -name 'hardening_*' -type d -mtime +30 2>/dev/null || true)
    if [[ -n "$old_dirs" ]]; then
        while IFS= read -r d; do
            [[ "$d" == "$BASELINE_SNAPSHOT_DIR" ]] && continue
            rm -rf "$d"
            log_ok "오래된 백업 삭제: $d"
        done <<< "$old_dirs"
    else
        log_skip "정리할 오래된 백업 없음"
    fi
}

_fstab_ensure_mount() {
    local mountpoint="$1"
    local new_entry="$2"
    local fstab="/etc/fstab"
    local check_keyword="noexec"
    if echo "$new_entry" | grep -q 'hidepid'; then
        check_keyword="hidepid"
    fi
    if grep -E "^\s*\S+\s+${mountpoint}\s" "$fstab" 2>/dev/null | grep -q "$check_keyword"; then
        log_skip "${mountpoint} fstab 이미 ${check_keyword} 포함"
        return 0
    fi
    if grep -qE "^\s*\S+\s+${mountpoint}\s" "$fstab" 2>/dev/null; then
        if [[ "$check_keyword" == "hidepid" ]]; then
            sed -i -E "s|^(\s*\S+\s+${mountpoint}\s+\S+\s+)(\S+)(.*)|\1\2,hidepid=2\3|" "$fstab"
            log_ok "${mountpoint} fstab 기존 옵션에 hidepid=2 추가"
        else
            grep -v "^[[:space:]]*\S\+[[:space:]]\+${mountpoint}[[:space:]]" "$fstab" > "${fstab}.tmp"
            echo "$new_entry" >> "${fstab}.tmp"
            mv "${fstab}.tmp" "$fstab"
            log_ok "${mountpoint} fstab 엔트리 교체 (${check_keyword} 추가)"
        fi
        return 0
    fi
    echo "$new_entry" >> "$fstab"
    log_ok "${mountpoint} fstab 엔트리 추가"
}

# =============================================================================
# [UFW 터널링 방어 헬퍼]
#
# _ufw_ipt_ensure <chain> <rule_args...>
#   - iptables -C 로 규칙 존재 여부를 확인한 뒤 없을 때만 -A 로 추가한다.
#   - comment는 rule_args 안에 이미 포함된 것을 그대로 사용하므로
#     -C / -A 간 comment 불일치 문제가 발생하지 않는다.
# =============================================================================
_ufw_ipt_ensure() {
    local chain="$1"; shift
    local args=("$@")

    if iptables -C "${chain}" "${args[@]}" 2>/dev/null; then
        log_skip "  iptables 규칙 이미 존재: ${chain} ${args[*]}"
        return 0
    fi
    if iptables -A "${chain}" "${args[@]}" 2>/dev/null; then
        log_ok "  iptables 규칙 추가: ${chain} ${args[*]}"
    else
        log_warn "  iptables 규칙 추가 실패: ${chain} ${args[*]}"
    fi
}

_ufw_ip6t_ensure() {
    local chain="$1"; shift
    local args=("$@")

    if ip6tables -C "${chain}" "${args[@]}" 2>/dev/null; then
        log_skip "  ip6tables 규칙 이미 존재: ${chain} ${args[*]}"
        return 0
    fi
    if ip6tables -A "${chain}" "${args[@]}" 2>/dev/null; then
        log_ok "  ip6tables 규칙 추가: ${chain} ${args[*]}"
    else
        log_warn "  ip6tables 규칙 추가 실패: ${chain} ${args[*]}"
    fi
}

# =============================================================================
# _ufw_write_tunnel_after_rules
#
# /etc/ufw/after.rules 와 /etc/ufw/after6.rules 에 터널링 방어 블록을 삽입한다.
# UFW는 `ufw enable` / `ufw reload` 시 after.rules를 iptables-restore로 적용하므로
# 여기에 규칙을 넣으면 UFW 재로드 후에도 규칙이 유지된다.
#
# 멱등성(idempotent): 파일에 UFW_TUNNEL_MARKER가 이미 있으면 덮어쓰지 않는다.
# =============================================================================
_ufw_write_tunnel_after_rules() {
    local after_rules="/etc/ufw/after.rules"
    local after6_rules="/etc/ufw/after6.rules"
    local icmp_max_len=$((20 + 8 + TUNNEL_ICMP_MAX_PAYLOAD))

    # ── IPv4 after.rules ──────────────────────────────────────────────────────
    backup_file "${after_rules}"

    if grep -q "${UFW_TUNNEL_MARKER}" "${after_rules}" 2>/dev/null; then
        log_skip "  after.rules: 터널링 방어 블록 이미 존재 — 덮어쓰기 생략"
    else
        cat >> "${after_rules}" <<AFTER_RULES_EOF

${UFW_TUNNEL_MARKER}
# 자동 생성: ${TIMESTAMP}  — 수동 편집 금지, 스크립트로 재생성할 것
*filter

# ── ICMP 터널링 방어 ──────────────────────────────────────────────────────────
# ① 대형 ICMP 인바운드 차단 (터널링은 MTU 크기 payload 사용)
-A ufw-before-input  -p icmp -m length --length ${icmp_max_len}:65535 \
  -m comment --comment "TUNNEL_ICMP_LARGE_IN"  -j LOG --log-prefix "[TUNNEL_ICMP_LARGE_IN] " --log-level 4
-A ufw-before-input  -p icmp -m length --length ${icmp_max_len}:65535 \
  -m comment --comment "TUNNEL_ICMP_LARGE_IN"  -j DROP

# ② 대형 ICMP 아웃바운드 차단
-A ufw-before-output -p icmp -m length --length ${icmp_max_len}:65535 \
  -m comment --comment "TUNNEL_ICMP_LARGE_OUT" -j LOG --log-prefix "[TUNNEL_ICMP_LARGE_OUT] " --log-level 4
-A ufw-before-output -p icmp -m length --length ${icmp_max_len}:65535 \
  -m comment --comment "TUNNEL_ICMP_LARGE_OUT" -j DROP

# ③ 아웃바운드 ICMP echo-request 차단 (서버→외부 ping 불필요)
-A ufw-before-output -p icmp --icmp-type echo-request \
  -m comment --comment "TUNNEL_ICMP_ECHO_OUT"  -j DROP

# ── DNS 터널링 방어 ──────────────────────────────────────────────────────────
# ① 아웃바운드 DNS over TCP 차단 (터널링은 TCP 53 연속 사용)
-A ufw-before-output -p tcp --dport 53 \
  -m comment --comment "TUNNEL_DNS_TCP_OUT"    -j LOG --log-prefix "[TUNNEL_DNS_TCP] " --log-level 4
-A ufw-before-output -p tcp --dport 53 \
  -m comment --comment "TUNNEL_DNS_TCP_OUT"    -j DROP

# ② 대형 DNS 응답 로깅 (1024B 이상 — DROP 아님, DNSSEC 오탐 방지)
-A ufw-before-input  -p udp --sport 53 -m length --length 1024:65535 \
  -m comment --comment "TUNNEL_DNS_LARGE_RESP" -j LOG --log-prefix "[TUNNEL_DNS_LARGE_RESP] " --log-level 4

# ── SOCKS5 터널링 방어 ───────────────────────────────────────────────────────
# ① SOCKS5 No-Auth 핸드셰이크 인바운드 차단
#    hex: 05 01 00 = VER=5, NMETHODS=1, METHOD=NO_AUTH
-A ufw-before-input  -p tcp \
  -m string --hex-string "|050100|" --algo bm --from 40 --to 60 \
  -m comment --comment "TUNNEL_SOCKS5_NOAUTH_IN" -j LOG --log-prefix "[TUNNEL_SOCKS5_NOAUTH] " --log-level 4
-A ufw-before-input  -p tcp \
  -m string --hex-string "|050100|" --algo bm --from 40 --to 60 \
  -m comment --comment "TUNNEL_SOCKS5_NOAUTH_IN" -j DROP

# ② SOCKS5 CONNECT 아웃바운드 차단 (서버가 외부 SOCKS5로 접속 시도)
-A ufw-before-output -p tcp \
  -m string --hex-string "|050100|" --algo bm --from 40 --to 60 \
  -m comment --comment "TUNNEL_SOCKS5_CONN_OUT" -j DROP

COMMIT
# TUNNEL_HARDENING_BLOCK_END
AFTER_RULES_EOF
        log_ok "  after.rules: 터널링 방어 블록 삽입 완료"
    fi

    # ── IPv6 after6.rules ─────────────────────────────────────────────────────
    backup_file "${after6_rules}"

    if grep -q "${UFW_TUNNEL_MARKER}" "${after6_rules}" 2>/dev/null; then
        log_skip "  after6.rules: 터널링 방어 블록 이미 존재 — 덮어쓰기 생략"
    else
        cat >> "${after6_rules}" <<AFTER6_RULES_EOF

${UFW_TUNNEL_MARKER}
# 자동 생성: ${TIMESTAMP}
*filter

# ICMPv6 대형 패킷 차단 (echo-request 기준)
-A ufw6-before-input  -p icmpv6 --icmpv6-type echo-request \
  -m length --length ${icmp_max_len}:65535 \
  -m comment --comment "TUNNEL_ICMP6_LARGE_IN" -j DROP

-A ufw6-before-output -p icmpv6 --icmpv6-type echo-request \
  -m length --length ${icmp_max_len}:65535 \
  -m comment --comment "TUNNEL_ICMP6_LARGE_OUT" -j DROP

COMMIT
# TUNNEL_HARDENING_BLOCK_END
AFTER6_RULES_EOF
        log_ok "  after6.rules: ICMPv6 터널링 방어 블록 삽입 완료"
    fi
}

# =============================================================================
# _ufw_apply_tunnel_rules_runtime
#
# UFW reload 없이 현재 실행 중인 iptables에도 즉시 규칙을 반영한다.
# after.rules는 다음 UFW reload/재부팅 시 자동 적용되지만,
# 이 함수는 현재 세션에서 즉시 효력을 발생시키기 위해 호출한다.
# _ufw_ipt_ensure 헬퍼를 사용하므로 중복 삽입이 발생하지 않는다.
# =============================================================================
_ufw_apply_tunnel_rules_runtime() {
    log_info "  [3-tunnel] 런타임 iptables 터널링 방어 규칙 즉시 적용"

    if ! command -v iptables &>/dev/null; then
        log_warn "  iptables 없음 — 런타임 적용 건너뜀"
        return 0
    fi

    local icmp_max_len=$((20 + 8 + TUNNEL_ICMP_MAX_PAYLOAD))

    # ── ICMP 터널링 방어 ──────────────────────────────────────────────────────
    # UFW 체인(ufw-before-input)에 삽입 — UFW 외부 INPUT 체인에 직접 쓰지 않음
    # (UFW reload 시 INPUT 체인은 UFW가 재구성하므로 ufw-before-* 체인이 안전)
    _ufw_ipt_ensure ufw-before-input \
        -p icmp -m length --length "${icmp_max_len}:65535" \
        -m comment --comment "TUNNEL_ICMP_LARGE_IN" -j DROP

    _ufw_ipt_ensure ufw-before-output \
        -p icmp -m length --length "${icmp_max_len}:65535" \
        -m comment --comment "TUNNEL_ICMP_LARGE_OUT" -j DROP

    _ufw_ipt_ensure ufw-before-output \
        -p icmp --icmp-type echo-request \
        -m comment --comment "TUNNEL_ICMP_ECHO_OUT" -j DROP

    # ── DNS 터널링 방어 ───────────────────────────────────────────────────────
    _ufw_ipt_ensure ufw-before-output \
        -p tcp --dport 53 \
        -m comment --comment "TUNNEL_DNS_TCP_OUT" -j DROP

    _ufw_ipt_ensure ufw-before-input \
        -p udp --sport 53 -m length --length 1024:65535 \
        -m comment --comment "TUNNEL_DNS_LARGE_RESP" \
        -j LOG --log-prefix "[TUNNEL_DNS_LARGE_RESP] " --log-level 4

    # ── SOCKS5 터널링 방어 ────────────────────────────────────────────────────
    # string 모듈 사용 가능 여부 확인
    if iptables -m string --help 2>&1 | grep -q "string"; then
        # --hex-string 으로 null byte 포함 바이너리 패턴을 안전하게 지정
        # |050100| = 0x05(SOCKS5) 0x01(NMETHODS=1) 0x00(NO_AUTH)
        _ufw_ipt_ensure ufw-before-input \
            -p tcp \
            -m string --hex-string "|050100|" --algo bm --from 40 --to 60 \
            -m comment --comment "TUNNEL_SOCKS5_NOAUTH_IN" -j DROP

        _ufw_ipt_ensure ufw-before-output \
            -p tcp \
            -m string --hex-string "|050100|" --algo bm --from 40 --to 60 \
            -m comment --comment "TUNNEL_SOCKS5_CONN_OUT" -j DROP

        log_ok "  SOCKS5 핸드셰이크 패턴 차단 적용 (hex-string 매칭)"
    else
        log_warn "  iptables string 모듈 없음 — SOCKS5 패턴 차단 건너뜀"
    fi

    # ── ICMPv6 ────────────────────────────────────────────────────────────────
    if command -v ip6tables &>/dev/null; then
        _ufw_ip6t_ensure ufw6-before-input \
            -p icmpv6 --icmpv6-type echo-request \
            -m length --length "${icmp_max_len}:65535" \
            -m comment --comment "TUNNEL_ICMP6_LARGE_IN" -j DROP

        _ufw_ip6t_ensure ufw6-before-output \
            -p icmpv6 --icmpv6-type echo-request \
            -m length --length "${icmp_max_len}:65535" \
            -m comment --comment "TUNNEL_ICMP6_LARGE_OUT" -j DROP
    fi

    log_ok "  런타임 터널링 방어 규칙 적용 완료"
}

# =============================================================================
# [1] auditd: 감사 로깅 시스템 설치 및 구성
# =============================================================================
setup_auditd() {
    log_info "===== [1] auditd 감사 로깅 설정 ====="
    if ! command -v auditd >/dev/null 2>&1; then
        log_info "auditd 설치 중..."
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y auditd || { log_error "auditd 설치 실패"; return 0; }
        log_ok "auditd 설치 완료"
    else
        log_skip "auditd 이미 설치됨"
    fi
    if command -v auditd >/dev/null 2>&1; then
        backup_file "/etc/audit/auditd.conf"
        tee /etc/audit/auditd.conf > /dev/null <<EOF
log_file = ${AUDIT_LOG_FILE}
log_format = ${AUDIT_LOG_FORMAT}
flush = ${AUDIT_FLUSH}
freq = ${AUDIT_FREQ}
num_logs = ${AUDIT_NUM_LOGS}
max_log_file = ${AUDIT_MAX_LOG_FILE}
max_log_file_action = ${AUDIT_MAX_LOG_FILE_ACTION}
space_left = ${AUDIT_SPACE_LEFT}
space_left_action = ${AUDIT_SPACE_LEFT_ACTION}
admin_space_left = ${AUDIT_ADMIN_SPACE_LEFT}
admin_space_left_action = ${AUDIT_ADMIN_SPACE_LEFT_ACTION}
disk_full_action = ${AUDIT_DISK_FULL_ACTION}
disk_error_action = ${AUDIT_DISK_ERROR_ACTION}
EOF
        log_ok "auditd.conf 구성 완료"
        mkdir -p /var/log/audit
        touch /var/log/audit/audit.log
        chown -R root:root /var/log/audit
        chmod 0600 /var/log/audit/audit.log
        if systemctl restart auditd 2>/dev/null; then
            log_ok "auditd 서비스 재시작 성공"
        else
            log_warn "auditd 서비스 재시작 실패 (컨테이너 환경일 수 있음)"
        fi
    fi
}

# =============================================================================
# [2] PAM: 패스워드 보안 정책 강화
# =============================================================================
setup_pam() {
    log_info "===== [2] PAM 패스워드 정책 설정 ====="
    if [[ -d /usr/share/pam-configs ]]; then
        backup_file "/usr/share/pam-configs/passwdqc"
        for pf in /etc/pam.d/common-password /etc/pam.d/common-auth; do
            backup_file "$pf"
        done
        if [[ -f /usr/share/pam-configs/passwdqc ]] && \
           grep -q "min=${PAM_PASSWDQC_MIN}" /usr/share/pam-configs/passwdqc 2>/dev/null; then
            log_skip "PAM passwdqc 이미 적용됨"
        else
            printf "Name: passwdqc\nDefault: yes\nPriority: 1024\nPassword-Type: Primary\nPassword:\n    requisite pam_passwdqc.so min=%s\n" "$PAM_PASSWDQC_MIN" \
                | tee /usr/share/pam-configs/passwdqc > /dev/null
            DEBIAN_FRONTEND=noninteractive pam-auth-update --package || log_warn "pam-auth-update 경고 발생"
            log_ok "PAM passwdqc 적용 완료"
        fi
    else
        log_skip "/usr/share/pam-configs 없음 — PAM 건너뜀"
    fi
}

# =============================================================================
# [3] UFW: 방화벽 기본 정책 + 포트 규칙 + 터널링 방어 (통합)
#
# 변경점:
#   - UFW 활성화 후 _ufw_write_tunnel_after_rules() 로 after.rules 영구 등록
#   - _ufw_apply_tunnel_rules_runtime() 으로 현재 세션에 즉시 적용
#   - UFW reload 시 after.rules 가 자동 재적용되므로 규칙 영속성 보장
#   - /etc/resolv.conf 잠금(_tunnel_dns_lock_resolv)도 여기서 호출
# =============================================================================
setup_ufw() {
    log_info "===== [3] UFW 방화벽 설정 + 터널링 방어 통합 ====="

    # ── UFW 설치 ─────────────────────────────────────────────────────────────
    if ! command -v ufw >/dev/null 2>&1; then
        log_info "ufw 설치 중..."
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y ufw || { log_error "ufw 설치 실패"; return 0; }
        log_ok "ufw 설치 완료"
    fi

    if ! command -v ufw >/dev/null 2>&1; then
        log_error "ufw 사용 불가 — UFW 설정 건너뜀"
        return 0
    fi

    backup_file "/etc/default/ufw"
    backup_file "/etc/ufw/after.rules"
    backup_file "/etc/ufw/after6.rules"

    # ── SSH 포트 감지 ─────────────────────────────────────────────────────────
    local detected_ssh_port=""
    detected_ssh_port=$(sshd -T 2>/dev/null | grep '^port ' | awk '{print $2}')
    if [[ -z "$detected_ssh_port" ]]; then
        detected_ssh_port=$(ss -tlnp 2>/dev/null | grep 'sshd' | awk '{print $4}' | grep -oP '[0-9]+$' | head -1)
    fi
    if [[ -z "$detected_ssh_port" ]]; then
        detected_ssh_port="22"
        log_warn "SSH 포트 감지 실패 — 기본값 22/tcp 사용"
    elif [[ "$detected_ssh_port" != "22" ]]; then
        log_info "SSH 리스닝 포트 감지: ${detected_ssh_port}/tcp (비표준)"
    fi

    # ── UFW 프로파일 포트 선정 ────────────────────────────────────────────────
    local profile_ports="${UFW_PROFILES[$UFW_PROFILE]:-}"
    if [[ -z "$profile_ports" ]]; then
        log_warn "알 수 없는 UFW 프로파일: ${UFW_PROFILE} — base 사용"
        profile_ports="${UFW_PROFILES[base]}"
    fi
    if [[ "$detected_ssh_port" != "22" ]]; then
        profile_ports="${profile_ports//22\/tcp/${detected_ssh_port}\/tcp}"
        log_info "UFW 프로파일 SSH 포트 교체: 22/tcp -> ${detected_ssh_port}/tcp"
    fi
    log_info "UFW 프로파일: ${UFW_PROFILE} (포트: ${profile_ports})"

    # ── 기본 정책 ─────────────────────────────────────────────────────────────
    ufw default deny incoming  2>/dev/null || true
    ufw default allow outgoing 2>/dev/null || true
    log_ok "UFW 기본 정책 설정 (deny incoming / allow outgoing)"

    # ── 포트 허용 규칙 ────────────────────────────────────────────────────────
    for port_proto in $profile_ports; do
        if ufw status 2>/dev/null | awk '{print $1}' | grep -qxF "$port_proto"; then
            log_skip "UFW 규칙 이미 존재: $port_proto"
        else
            ufw allow "$port_proto" 2>/dev/null || log_warn "UFW allow $port_proto 실패"
            log_ok "UFW allow: $port_proto"
        fi
    done

    # ── UFW 활성화 ───────────────────────────────────────────────────────────
    ufw --force enable 2>/dev/null || log_warn "UFW 활성화 실패"
    log_ok "UFW 활성화 완료 (프로파일: ${UFW_PROFILE})"

    # ── 터널링 방어 블록을 after.rules 에 영구 등록 ──────────────────────────
    # UFW 활성화 이후에 after.rules 를 수정해야 UFW 의 초기 flush 에 덮이지 않음
    log_info "  [3-tunnel] after.rules 터널링 방어 블록 등록"
    _ufw_write_tunnel_after_rules

    # ── UFW reload 로 after.rules 즉시 반영 ──────────────────────────────────
    # reload는 UFW 체인을 재구성하므로 after.rules 내용이 iptables에 반영됨
    if ufw reload 2>/dev/null; then
        log_ok "  [3-tunnel] UFW reload 완료 — after.rules 터널링 규칙 반영됨"
    else
        log_warn "  [3-tunnel] UFW reload 실패 — 런타임 직접 적용으로 대체"
        # reload 실패 시 런타임에 직접 삽입 (현재 세션만 유효)
        _ufw_apply_tunnel_rules_runtime
    fi

    # ── DNS 설정 잠금 (/etc/resolv.conf) ─────────────────────────────────────
    _tunnel_dns_lock_resolv

    log_ok "===== [3] UFW + 터널링 방어 설정 완료 ====="
}

# =============================================================================
# [4] cron: 예약작업 디렉토리 접근권한 제한
# =============================================================================
setup_cron_permissions() {
    log_info "===== [4] cron 디렉토리 권한 설정 ====="
    for d in /etc/cron.{hourly,daily,weekly,monthly,d}; do
        if [[ -e "$d" ]]; then
            chmod og-rwx "$d" && chown root:root "$d"
            log_ok "권한 설정: $d"
        else
            log_skip "없음: $d"
        fi
    done
    if [[ -f /etc/crontab ]]; then
        chmod og-rwx /etc/crontab && chown root:root /etc/crontab
        log_ok "/etc/crontab 권한 설정 완료"
    fi
}

# =============================================================================
# [5] modprobe: 위험 커널 모듈 차단
# =============================================================================
setup_modprobe() {
    log_info "===== [5] 위험 커널 모듈 차단 ====="
    backup_file "/etc/modprobe.d/dev-sec.conf"
    local content=""
    for mod in "${BLOCKED_MODULES[@]}"; do
        content+="blacklist ${mod}"$'\n'
        content+="install ${mod} /bin/true"$'\n'
    done
    echo -n "$content" | tee /etc/modprobe.d/dev-sec.conf > /dev/null
    log_ok "커널 모듈 차단: ${BLOCKED_MODULES[*]}"
}

# =============================================================================
# [6] sysctl: 커널 보안 설정
# =============================================================================
setup_sysctl() {
    log_info "===== [6] sysctl 커널 보안 설정 ====="
    local sysctl_file="/etc/sysctl.d/99-hardening.conf"
    backup_file "/etc/sysctl.conf"
    backup_file "$sysctl_file"
    if [[ -f /etc/sysctl.d/99-custom.conf ]]; then
        backup_file "/etc/sysctl.d/99-custom.conf"
        rm -f /etc/sysctl.d/99-custom.conf
        log_info "기존 99-custom.conf 제거 (99-hardening.conf로 통합)"
    fi
    {
        echo "# 보안 하드닝 sysctl 설정 (자동 생성: ${TIMESTAMP})"
        for key in "${!SYSCTL_SETTINGS[@]}"; do
            echo "${key} = ${SYSCTL_SETTINGS[$key]}"
        done
    } | tee "$sysctl_file" > /dev/null
    local failed=0
    for key in "${!SYSCTL_SETTINGS[@]}"; do
        local current_val
        current_val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
        if [[ "$current_val" == "${SYSCTL_SETTINGS[$key]}" ]]; then
            log_skip "sysctl ${key}=${SYSCTL_SETTINGS[$key]} (이미 적용)"
        else
            if sysctl -w "${key}=${SYSCTL_SETTINGS[$key]}" >/dev/null 2>&1; then
                log_ok "sysctl ${key}=${SYSCTL_SETTINGS[$key]}"
            else
                log_warn "sysctl ${key} 설정 실패 (커널 미지원일 수 있음)"
                failed=$((failed + 1))
            fi
        fi
    done
    if [[ $failed -gt 0 ]]; then
        log_warn "sysctl ${failed}개 항목 실패"
    fi
}

# =============================================================================
# [7] /proc hidepid
# =============================================================================
setup_proc_hidepid() {
    log_info "===== [7] /proc hidepid 설정 ====="
    if [[ "${HIDEPID_ENABLED}" != "true" ]]; then
        log_skip "/proc hidepid 비활성 (HIDEPID_ENABLED=false)"
        return
    fi
    if mount | grep -q "hidepid=2"; then
        log_skip "/proc hidepid=2 이미 적용됨"
    else
        if mount -o remount,hidepid=2 /proc 2>/dev/null; then
            log_ok "/proc hidepid=2 적용"
        else
            log_warn "/proc remount 실패 (컨테이너 환경일 수 있음)"
        fi
    fi
    _fstab_ensure_mount "/proc" "proc /proc proc defaults,hidepid=2 0 0"
}

# =============================================================================
# [8] 민감 파일 권한 최소화
# =============================================================================
setup_sensitive_file_permissions() {
    log_info "===== [8] 민감 파일 권한 설정 ====="
    for f in "${FILES_644[@]}"; do
        [[ -f "$f" ]] && chmod 0644 "$f" && log_ok "chmod 0644: $f" || log_skip "없음: $f"
    done
    for f in "${FILES_600[@]}"; do
        [[ -f "$f" ]] && chmod 0600 "$f" && log_ok "chmod 0600: $f" || log_skip "없음: $f"
    done
    for f in "${FILES_CHOWN[@]}"; do
        [[ -f "$f" ]] && chown root:root "$f"
    done
    log_ok "민감 파일 소유자(root:root) 설정 완료"
}

# =============================================================================
# [9] other 권한 제거 (o-rwx)
# =============================================================================
setup_other_permission_removal() {
    log_info "===== [9] other 권한 제거 (o-rwx) ====="
    for f in "${FILES_O_NORW[@]}"; do
        if [[ -e "$f" ]]; then
            chmod o-rwx "$f"
            log_ok "chmod o-rwx: $f"
        else
            log_skip "없음: $f"
        fi
    done
}

# =============================================================================
# [10] 시스템 계정 nologin 설정
# =============================================================================
setup_nologin_accounts() {
    log_info "===== [10] 시스템 계정 nologin 설정 ====="
    for acct in "${NOLOGIN_ACCOUNTS[@]}"; do
        if id "$acct" &>/dev/null; then
            local current_shell
            current_shell=$(getent passwd "$acct" | cut -d: -f7)
            if [[ "$current_shell" == "/usr/sbin/nologin" ]]; then
                log_skip "${acct}: 이미 nologin"
            else
                chsh -s /usr/sbin/nologin "$acct" 2>/dev/null && \
                    log_ok "${acct} -> /usr/sbin/nologin" || \
                    log_warn "${acct} 셸 변경 실패"
            fi
        fi
    done
    for acct in "${FALSE_SHELL_ACCOUNTS[@]}"; do
        if id "$acct" &>/dev/null; then
            local current_shell
            current_shell=$(getent passwd "$acct" | cut -d: -f7)
            if [[ "$current_shell" == "/bin/false" ]]; then
                log_skip "${acct}: 이미 /bin/false"
            else
                chsh -s /bin/false "$acct" 2>/dev/null && \
                    log_ok "${acct} -> /bin/false" || \
                    log_warn "${acct} 셸 변경 실패"
            fi
        fi
    done
}

# =============================================================================
# [11] sudoers NOPASSWD 제거
# =============================================================================
setup_sudoers() {
    log_info "===== [11] sudoers NOPASSWD 제거 ====="
    if [[ -f /etc/sudoers ]]; then
        backup_file "/etc/sudoers"
        if grep -q 'NOPASSWD' /etc/sudoers; then
            sed -i 's/^\(%sudo[[:space:]]\+ALL=(ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/' /etc/sudoers
            sed -i 's/^\(%sudo[[:space:]]\+ALL=(ALL:ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/' /etc/sudoers
            sed -i 's/^\([^%#][[:alnum:]_.-]\+[[:space:]]\+ALL=(ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/' /etc/sudoers
            sed -i 's/^\([^%#][[:alnum:]_.-]\+[[:space:]]\+ALL=(ALL:ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/' /etc/sudoers
            if visudo -c 2>/dev/null; then
                log_ok "sudoers NOPASSWD 제거 완료 (문법 검증 통과)"
            else
                log_error "sudoers 문법 오류! 백업에서 복원하세요: ${BACKUP_DIR}"
                local backup_sudoers="${BACKUP_DIR}/_etc_sudoers"
                [[ -f "$backup_sudoers" ]] && cp "$backup_sudoers" /etc/sudoers
            fi
        else
            log_skip "sudoers에 NOPASSWD 없음"
        fi
    fi
    if [[ -d /etc/sudoers.d ]]; then
        local nopasswd_files
        nopasswd_files=$(grep -rl 'NOPASSWD' /etc/sudoers.d/ 2>/dev/null || true)
        if [[ -n "$nopasswd_files" ]]; then
            while IFS= read -r f; do
                backup_file "$f"
                sed -i 's/NOPASSWD://g' "$f" 2>/dev/null
                log_ok "sudoers.d NOPASSWD 제거: $f"
            done <<< "$nopasswd_files"
        fi
    fi
}

# =============================================================================
# [12] SUID 비트 제거
# =============================================================================
setup_suid_removal() {
    log_info "===== [12] SUID 비트 제거 ====="
    for f in "${SUID_REMOVE_TARGETS[@]}"; do
        if [[ -f "$f" ]]; then
            if [[ -u "$f" ]]; then
                chmod u-s "$f"
                log_ok "SUID 제거: $f"
            else
                log_skip "SUID 없음: $f"
            fi
        else
            log_skip "파일 없음: $f"
        fi
    done
}

# =============================================================================
# [13] 불필요 서비스 비활성화
# =============================================================================
setup_disable_services() {
    log_info "===== [13] 불필요 서비스 비활성화 ====="
    for svc in "${DISABLE_SERVICES[@]}"; do
        if systemctl list-unit-files "$svc" &>/dev/null; then
            if systemctl is-enabled "$svc" 2>/dev/null | grep -q "enabled"; then
                systemctl disable --now "$svc" 2>/dev/null || true
                log_ok "비활성화: $svc"
            else
                log_skip "이미 비활성: $svc"
            fi
        else
            log_skip "서비스 없음: $svc"
        fi
    done
}

# =============================================================================
# [14] 비밀번호 없는 계정 잠금
# =============================================================================
setup_lock_empty_password() {
    log_info "===== [14] 비밀번호 없는 계정 잠금 ====="
    local locked_count=0
    while IFS= read -r user; do
        if [[ -n "$user" ]]; then
            passwd -l "$user" 2>/dev/null || true
            log_ok "계정 잠금: $user"
            locked_count=$((locked_count + 1))
        fi
    done < <(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null)
    if [[ $locked_count -eq 0 ]]; then
        log_skip "비밀번호 없는 계정 없음"
    fi
}

# =============================================================================
# [15] SSH 하드닝
# =============================================================================
setup_ssh_hardening() {
    log_info "===== [15] SSH 하드닝 ====="
    local sshd_config="/etc/ssh/sshd_config"
    if [[ ! -f "$sshd_config" ]]; then
        log_skip "sshd_config 없음 — SSH 건너뜀"
        return
    fi
    backup_file "$sshd_config"
    local hardened_conf="/etc/ssh/sshd_config.d/99-hardening.conf"
    mkdir -p /etc/ssh/sshd_config.d
    local effective_pw_auth="${SSH_PASSWORD_AUTH}"
    if [[ "${SSH_PASSWORD_AUTH}" == "no" ]]; then
        local has_ssh_key=false
        while IFS=: read -r _user _ _ _ _ _home _shell; do
            [[ "$_shell" =~ (nologin|false)$ ]] && continue
            if [[ -f "${_home}/.ssh/authorized_keys" ]] && [[ -s "${_home}/.ssh/authorized_keys" ]]; then
                has_ssh_key=true
                break
            fi
        done < /etc/passwd
        if [[ "$has_ssh_key" == "false" ]]; then
            log_warn "SSH 키가 없는 상태에서 PasswordAuthentication=no 설정 시 잠금 위험"
            log_warn "PasswordAuthentication=yes 로 유지합니다 (authorized_keys 등록 후 재실행)"
            effective_pw_auth="yes"
        fi
    fi
    tee "$hardened_conf" > /dev/null <<SSHEOF
# === 보안 하드닝 (자동 생성: ${TIMESTAMP}) ===
PermitRootLogin ${SSH_PERMIT_ROOT_LOGIN}
PasswordAuthentication ${effective_pw_auth}
MaxAuthTries ${SSH_MAX_AUTH_TRIES}
PermitEmptyPasswords no
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
GatewayPorts no
ClientAliveInterval ${SSH_CLIENT_ALIVE_INTERVAL}
ClientAliveCountMax ${SSH_CLIENT_ALIVE_COUNT_MAX}
LoginGraceTime ${SSH_LOGIN_GRACE_TIME}
Banner /etc/issue.net
UsePAM yes
HostbasedAuthentication no
IgnoreRhosts yes
MaxSessions 4
MaxStartups 10:30:60
SSHEOF
    if ! grep -q 'Include /etc/ssh/sshd_config.d/\*.conf' "$sshd_config" 2>/dev/null; then
        sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$sshd_config"
        log_info "sshd_config 첫 줄에 Include 지시문 삽입"
    fi
    if sshd -t 2>/dev/null; then
        if systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null; then
            log_ok "SSH 하드닝 적용 및 서비스 reload 완료"
        else
            log_warn "SSH 서비스 reload 실패"
        fi
        local verify_root verify_pw
        verify_root=$(sshd -T 2>/dev/null | grep '^permitrootlogin ' | awk '{print $2}')
        verify_pw=$(sshd -T 2>/dev/null | grep '^passwordauthentication ' | awk '{print $2}')
        [[ "$verify_root" == "${SSH_PERMIT_ROOT_LOGIN}" ]] && \
            log_ok "검증 OK: PermitRootLogin=${verify_root}" || \
            log_warn "검증 실패: PermitRootLogin 기대=${SSH_PERMIT_ROOT_LOGIN}, 실제=${verify_root}"
        [[ "$verify_pw" == "${effective_pw_auth}" ]] && \
            log_ok "검증 OK: PasswordAuthentication=${verify_pw}" || \
            log_warn "검증 실패: PasswordAuthentication 기대=${effective_pw_auth}, 실제=${verify_pw}"
    else
        log_error "sshd 설정 문법 오류 — 롤백"
        rm -f "$hardened_conf"
    fi
}

# =============================================================================
# [16] auditd 감사 룰 설정
# =============================================================================
setup_auditd_rules() {
    log_info "===== [16] auditd 감사 룰 설정 ====="
    if ! command -v auditctl >/dev/null 2>&1; then
        log_skip "auditctl 없음 — 감사 룰 건너뜀"
        return
    fi
    local rules_file="/etc/audit/rules.d/99-hardening.rules"
    mkdir -p /etc/audit/rules.d
    backup_file "$rules_file"
    tee "$rules_file" > /dev/null <<'AUDITEOF'
# === 보안 하드닝 감사 룰 ===
-b 8192
-f 1

# 인증/권한 관련 파일 변경 감시
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# sudoers 변경 감시
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# SSH 설정 변경 감시
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# PAM 설정 변경 감시
-w /etc/pam.d/ -p wa -k pam_config

# 시간 변경 감시
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-w /etc/localtime -p wa -k time-change

# 커널 모듈 로딩 감시
-a always,exit -F arch=b64 -S init_module -S delete_module -S finit_module -k modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# 네트워크 설정 변경 감시
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl

# cron 변경 감시
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# 로그인/로그아웃 이벤트
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# 권한 상승 명령 실행 감시
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k privilege_escalation
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k privilege_escalation

# 파일 삭제 감시
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

AUDITEOF

    if [[ "${AUDIT_IMMUTABLE}" == "true" ]]; then
        echo "-e 2" >> "$rules_file"
        log_info "auditd immutable 모드 활성 (-e 2) — 재부팅 전까지 룰 변경 불가"
    else
        log_info "auditd immutable 비활성 (런타임 규칙 변경 가능)"
    fi
    if augenrules --load 2>/dev/null; then
        log_ok "auditd 감사 룰 로드 완료"
    elif auditctl -R "$rules_file" 2>/dev/null; then
        log_ok "auditctl로 룰 직접 로드"
    else
        log_warn "감사 룰 로드 실패 — 재부팅 후 적용됩니다"
    fi
}

# =============================================================================
# [17] /etc/login.defs 패스워드 에이징 정책
# =============================================================================
setup_login_defs() {
    log_info "===== [17] /etc/login.defs 패스워드 에이징 정책 ====="
    local login_defs="/etc/login.defs"
    if [[ ! -f "$login_defs" ]]; then
        log_skip "login.defs 없음"
        return
    fi
    backup_file "$login_defs"
    declare -A LOGINDEFS=(
        ["PASS_MAX_DAYS"]="$PASS_MAX_DAYS"
        ["PASS_MIN_DAYS"]="$PASS_MIN_DAYS"
        ["PASS_WARN_AGE"]="$PASS_WARN_AGE"
        ["LOGIN_RETRIES"]="$LOGIN_RETRIES"
        ["UMASK"]="$DEFAULT_UMASK"
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

# =============================================================================
# [18] pam_faillock 계정 잠금 정책 (브루트포스 방어)
# =============================================================================
setup_pam_faillock() {
    log_info "===== [18] pam_faillock 계정 잠금 정책 ====="
    if ! find /usr/lib /lib -name 'pam_faillock.so' -print -quit 2>/dev/null | grep -q .; then
        log_warn "pam_faillock 모듈 없음 — libpam-modules 패키지 확인 필요"
        return 0
    fi
    if [[ ! -d /usr/share/pam-configs ]]; then
        log_skip "/usr/share/pam-configs 없음 — faillock 건너뜀"
        return 0
    fi
    local faillock_conf="/etc/security/faillock.conf"
    backup_file "$faillock_conf"
    {
        echo "# 계정 잠금 정책 — 하드닝 자동 생성"
        echo "deny = 5"
        echo "unlock_time = 900"
        echo "fail_interval = 900"
        if [[ "${FAILLOCK_DENY_ROOT}" == "true" ]]; then
            echo "even_deny_root"
            echo "root_unlock_time = 60"
        fi
    } > "$faillock_conf"
    chmod 0644 "$faillock_conf"
    log_ok "faillock.conf 작성 완료 (deny=5, unlock_time=900s)"
    local pam_faillock_config="/usr/share/pam-configs/faillock"
    if [[ -f "$pam_faillock_config" ]]; then
        log_skip "pam_faillock pam-configs 이미 존재함 — 재적용 생략"
        return 0
    fi
    for pf in /etc/pam.d/common-auth /etc/pam.d/common-account; do
        backup_file "$pf"
    done
    cat > "$pam_faillock_config" <<'PAMEOF'
Name: Faillock account lockout on failed logins
Default: yes
Priority: 768
Auth-Type: Primary
Auth:
        required                    pam_faillock.so preauth silent
        [success=1 default=bad]     pam_unix.so
        [default=die]               pam_faillock.so authfail
        sufficient                  pam_faillock.so authsucc
Auth-Initial:
        required                    pam_faillock.so preauth silent
        [success=1 default=bad]     pam_unix.so
        [default=die]               pam_faillock.so authfail
        sufficient                  pam_faillock.so authsucc
Account-Type: Primary
Account:
        required                    pam_faillock.so
Account-Initial:
        required                    pam_faillock.so
PAMEOF
    if ! DEBIAN_FRONTEND=noninteractive pam-auth-update --package 2>/dev/null; then
        log_error "pam-auth-update 실패 — faillock 완전 롤백"
        _pam_faillock_rollback
        return 0
    fi
    log_ok "pam-auth-update 완료"
    local pam_auth="/etc/pam.d/common-auth"
    local all_ok=true
    declare -A CHECK_PATTERNS=(
        ["preauth"]="pam_faillock\.so.*preauth"
        ["pam_unix"]="pam_unix\.so"
        ["authfail"]="pam_faillock\.so.*authfail"
        ["authsucc"]="pam_faillock\.so.*authsucc"
    )
    for label in preauth pam_unix authfail authsucc; do
        local pattern="${CHECK_PATTERNS[$label]}"
        if grep -qE "$pattern" "$pam_auth" 2>/dev/null; then
            log_ok "검증 OK: ${label}"
        else
            log_error "검증 실패: ${label} — common-auth에 없음"
            all_ok=false
        fi
    done
    if [[ "$all_ok" == "false" ]]; then
        log_error "PAM 스택 검증 실패 — 완전 롤백"
        _pam_faillock_rollback
        return 0
    fi
    log_ok "pam_faillock 설정 완료 및 검증 통과"
}

_pam_faillock_rollback() {
    local pam_faillock_config="/usr/share/pam-configs/faillock"
    rm -f "$pam_faillock_config"
    DEBIAN_FRONTEND=noninteractive pam-auth-update --package 2>/dev/null || true
    local bk_auth="${BACKUP_DIR}/_etc_pam.d_common-auth"
    local bk_acct="${BACKUP_DIR}/_etc_pam.d_common-account"
    if [[ -f "$bk_auth" ]]; then
        cp "$bk_auth" /etc/pam.d/common-auth
        log_warn "common-auth 백업 복원 완료"
    fi
    if [[ -f "$bk_acct" ]]; then
        cp "$bk_acct" /etc/pam.d/common-account
        log_warn "common-account 백업 복원 완료"
    fi
    log_warn "pam_faillock 미적용 상태로 복원됨"
}

# =============================================================================
# [19] /tmp, /var/tmp, /dev/shm 마운트 하드닝
# =============================================================================
setup_tmp_mount_hardening() {
    log_info "===== [19] /tmp, /var/tmp, /dev/shm 마운트 하드닝 ====="
    backup_file "/etc/fstab"
    local mount_targets=("/tmp" "/var/tmp")
    if [[ "${SHM_NOEXEC}" == "true" ]]; then
        mount_targets+=("/dev/shm")
    else
        log_skip "/dev/shm noexec 비활성 (SHM_NOEXEC=false)"
    fi
    for mnt in "${mount_targets[@]}"; do
        if mount | grep -q "on ${mnt} "; then
            if mount | grep "on ${mnt} " | grep -q 'noexec'; then
                log_skip "${mnt} 이미 noexec 적용됨"
            else
                mount -o remount,noexec,nosuid,nodev "${mnt}" 2>/dev/null && \
                    log_ok "${mnt} remount noexec,nosuid,nodev" || \
                    log_warn "${mnt} remount 실패"
            fi
        fi
    done
    _fstab_ensure_mount "/tmp" \
        "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0"
    _fstab_ensure_mount "/var/tmp" \
        "tmpfs /var/tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0"
    if [[ "${SHM_NOEXEC}" == "true" ]]; then
        _fstab_ensure_mount "/dev/shm" \
            "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0"
    fi
}

# =============================================================================
# [20] core dump 제한
# =============================================================================
setup_core_dump_limits() {
    log_info "===== [20] core dump 제한 ====="
    local limits_conf="/etc/security/limits.conf"
    backup_file "$limits_conf"
    if ! grep -q '^\*.*hard.*core.*0' "$limits_conf" 2>/dev/null; then
        echo "* hard core 0" >> "$limits_conf"
        log_ok "limits.conf: core dump 제한 추가"
    else
        log_skip "core dump 제한 이미 적용됨"
    fi
    local coredump_conf="/etc/systemd/coredump.conf"
    if [[ -f "$coredump_conf" ]]; then
        backup_file "$coredump_conf"
        if ! grep -q '^Storage=none' "$coredump_conf" 2>/dev/null; then
            if ! grep -q '^\[Coredump\]' "$coredump_conf" 2>/dev/null; then
                echo -e "\n[Coredump]" >> "$coredump_conf"
                log_info "coredump.conf에 [Coredump] 섹션 헤더 추가"
            fi
            sed -i 's/^#\?Storage=.*/Storage=none/' "$coredump_conf" 2>/dev/null || \
                echo "Storage=none" >> "$coredump_conf"
            sed -i 's/^#\?ProcessSizeMax=.*/ProcessSizeMax=0/' "$coredump_conf" 2>/dev/null || \
                echo "ProcessSizeMax=0" >> "$coredump_conf"
            systemctl daemon-reload 2>/dev/null
            log_ok "systemd coredump 비활성화"
        else
            log_skip "systemd coredump 이미 비활성"
        fi
    fi
}

# =============================================================================
# [21] 전역 umask 설정
# =============================================================================
setup_umask() {
    log_info "===== [21] 전역 umask 설정 (${DEFAULT_UMASK}) ====="
    local umask_files=(/etc/profile /etc/bash.bashrc /etc/login.defs)
    for f in "${umask_files[@]}"; do
        if [[ -f "$f" ]]; then
            backup_file "$f"
            if grep -qE '^\s*umask\s+[0-9]+' "$f" 2>/dev/null; then
                sed -i "s/^[[:space:]]*umask[[:space:]]\+[0-9]\+/umask ${DEFAULT_UMASK}/" "$f"
                log_ok "umask 변경: $f -> ${DEFAULT_UMASK}"
            else
                echo "umask ${DEFAULT_UMASK}" >> "$f"
                log_ok "umask 추가: $f -> ${DEFAULT_UMASK}"
            fi
        fi
    done
}

# =============================================================================
# [22] 법적 경고 배너 설정
# =============================================================================
setup_banner() {
    log_info "===== [22] 법적 경고 배너 설정 ====="
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
        log_ok "배너 설정: $f"
    done
    if [[ -d /etc/update-motd.d ]]; then
        chmod -x /etc/update-motd.d/* 2>/dev/null || true
        log_ok "MOTD 스크립트 실행 권한 제거"
    fi
}

# =============================================================================
# [27] 터널링 방어 (iptables 제외 — 나머지 항목)
#
# iptables 규칙은 setup_ufw() 내부에서 처리하므로 여기서는 제외.
# 유지 항목:
#   27-1  터널링 도구 프로세스 탐지
#   27-6  범용 터널링 도구 제거
#   27-7  auditd 터널링 탐지 규칙 추가
# =============================================================================
setup_tunnel_hardening() {
    log_info "===== [27] 터널링 방어 (프로세스 탐지 / 도구 제거 / auditd) ====="
    log_info "  ※ iptables 규칙은 [3] UFW 설정에서 after.rules 로 통합 처리됨"

    _tunnel_detect_processes   # 27-1
    _tunnel_remove_tools       # 27-6
    _tunnel_append_audit_rules # 27-7

    log_ok "[27] 터널링 방어 (비-iptables) 완료"
}

# ─── 27-1. 터널링 도구 프로세스 탐지 ─────────────────────────────────────
_tunnel_detect_processes() {
    log_info "  [27-1] 터널링 도구 프로세스 탐지"
    local found=0

    for proc in "${TUNNEL_TOOL_PROCS[@]}"; do
        if pgrep -x "${proc}" &>/dev/null; then
            local pids
            pids=$(pgrep -x "${proc}" | tr '\n' ',' | sed 's/,$//')
            log_warn "  ⚠ 터널링 도구 실행 중: ${proc} (PID: ${pids})"
            local exe_path
            exe_path=$(readlink -f "/proc/$(pgrep -x "${proc}" | head -1)/exe" 2>/dev/null || echo "알 수 없음")
            log_warn "    실행 경로: ${exe_path}"
            found=1
        fi
    done

    if ls /proc/*/fd 2>/dev/null | xargs -I{} readlink {} 2>/dev/null \
       | grep -q "net/tun"; then
        log_warn "  ⚠ TUN 디바이스를 점유한 프로세스 탐지"
        found=1
    fi

    local dns_non_std
    dns_non_std=$(ss -unp 2>/dev/null \
                  | awk '$5 ~ /:53$/ && $4 !~ /^(127\.|10\.|172\.|192\.168\.)/ {print}' \
                  || true)
    if [[ -n "${dns_non_std}" ]]; then
        log_warn "  ⚠ 비내부망으로의 직접 DNS 쿼리 탐지 (DNS 터널링 가능성):"
        echo "${dns_non_std}" | while IFS= read -r line; do
            log_warn "    → ${line}"
        done
        found=1
    fi

    [[ $found -eq 0 ]] && log_ok "  탐지된 터널링 도구 프로세스 없음"
}

# ─── 27-4. DNS 설정 잠금 (setup_ufw 에서 호출) ───────────────────────────
_tunnel_dns_lock_resolv() {
    log_info "  [3-tunnel / 27-4] /etc/resolv.conf DNS 설정 잠금"

    if [[ "${TUNNEL_LOCK_RESOLV}" != "true" ]]; then
        log_skip "  TUNNEL_LOCK_RESOLV=false — 건너뜀"
        return 0
    fi

    local resolv="/etc/resolv.conf"
    if [[ ! -f "${resolv}" ]]; then
        log_skip "  /etc/resolv.conf 없음 — 건너뜀"
        return 0
    fi

    if systemctl is-active systemd-resolved &>/dev/null 2>&1; then
        if [[ -L "${resolv}" ]]; then
            log_info "  /etc/resolv.conf가 심볼릭 링크 (systemd-resolved 관리 중)"
            local resolved_conf="/etc/systemd/resolved.conf.d/99-tunnel-hardening.conf"
            mkdir -p /etc/systemd/resolved.conf.d
            backup_file "/etc/systemd/resolved.conf" 2>/dev/null || true
            {
                echo "# DNS 터널링 방어 — resolv.conf 잠금 (자동 생성: ${TIMESTAMP})"
                echo "[Resolve]"
                echo "DNSSEC=allow-downgrade"
                echo "DNSOverTLS=opportunistic"
                echo "ReadEtcHosts=yes"
            } > "${resolved_conf}"
            systemctl restart systemd-resolved 2>/dev/null || true
            log_ok "  systemd-resolved DNS 서버 고정: ${resolved_conf}"
        fi
        return 0
    fi

    backup_file "${resolv}"

    {
        echo "# DNS 터널링 방어 — 하드닝 자동 생성 (${TIMESTAMP})"
        echo "# 이 파일은 chattr +i 로 잠겨 있습니다."
        grep -v "^#" "${BACKUP_DIR}/$(echo "${resolv}" | tr '/' '_')" 2>/dev/null \
            || grep -v "^#" "${resolv}" 2>/dev/null || true
        echo "options timeout:2 attempts:3 rotate"
    } > "${resolv}"

    if command -v chattr &>/dev/null; then
        chattr -i "${resolv}" 2>/dev/null || true
        chattr +i "${resolv}" 2>/dev/null \
            && log_ok "  /etc/resolv.conf 불변(chattr +i) 설정 완료" \
            || log_warn "  chattr +i 실패 — 파일시스템 미지원일 수 있음"
    else
        log_warn "  chattr 없음 — resolv.conf 불변 처리 불가"
    fi
}

# ─── 27-6. 터널링 도구 패키지 제거 ──────────────────────────────────────
_tunnel_remove_tools() {
    log_info "  [27-6] 터널링 도구 패키지 제거"

    local distro="unknown"
    [[ -f /etc/os-release ]] && distro=$(. /etc/os-release && echo "${ID:-unknown}")

    local tunnel_pkgs=(
        ptunnel ptunnel-ng
        iodine dns2tcp dnscat2
        chisel sshuttle autossh
    )

    local removed=1
    case "${distro}" in
        ubuntu|debian)
            for pkg in "${tunnel_pkgs[@]}"; do
                if dpkg -s "${pkg}" &>/dev/null 2>&1; then
                    local rc=0
                    DEBIAN_FRONTEND=noninteractive \
                        apt-get purge -y "${pkg}" \
                        -o Dpkg::Options::="--force-confdef" \
                        >/dev/null 2>&1 || rc=$?
                    if [[ $rc -eq 0 ]]; then
                        log_ok "  패키지 제거: ${pkg}"
                    else
                        log_warn "  패키지 제거 실패 (rc=${rc}): ${pkg}"
                    fi
                    removed=$((removed + 1))
                fi
            done
            [[ $removed -gt 1 ]] && \
                DEBIAN_FRONTEND=noninteractive apt-get autoremove -y \
                    >/dev/null 2>&1 || true
            ;;
        rhel|centos|rocky|almalinux|fedora|amzn)
            for pkg in "${tunnel_pkgs[@]}"; do
                if rpm -q "${pkg}" &>/dev/null 2>&1; then
                    local rc=0
                    yum remove -y "${pkg}" >/dev/null 2>&1 || rc=$?
                    [[ $rc -eq 0 ]] \
                        && log_ok "  패키지 제거: ${pkg}" \
                        || log_warn "  패키지 제거 실패 (rc=${rc}): ${pkg}"
                    removed=$((removed + 1))
                fi
            done
            ;;
        *)
            log_warn "  알 수 없는 OS — 패키지 자동 제거 건너뜀 (수동 확인 필요)"
            ;;
    esac

    [[ $removed -eq 1 ]] && log_skip "  제거할 터널링 도구 패키지 없음"

    local tunnel_bins=(
        /usr/sbin/iodined /usr/bin/iodine
        /usr/bin/dns2tcp /usr/bin/dnscat
        /usr/local/bin/chisel /usr/local/bin/gost
        /usr/local/bin/ligolo /usr/local/bin/frpc
        /usr/local/bin/bore /usr/local/bin/inlets
        /usr/local/sbin/ptunnel /usr/local/sbin/ptunnel-ng
    )
    for bin in "${tunnel_bins[@]}"; do
        if [[ -f "${bin}" ]]; then
            backup_file "${bin}"
            rm -f "${bin}" 2>/dev/null \
                && log_ok "  실행 파일 삭제: ${bin}" \
                || { chmod a-x "${bin}" 2>/dev/null && log_warn "  삭제 실패, 실행 권한 제거: ${bin}"; }
        fi
    done
}

# ─── 27-7. auditd 터널링 탐지 규칙 추가 ─────────────────────────────────
_tunnel_append_audit_rules() {
    log_info "  [27-7] auditd 터널링 탐지 규칙 추가"

    if ! command -v auditctl &>/dev/null; then
        log_skip "  auditctl 없음 — 건너뜀"
        return 0
    fi

    if [[ ! -f "${TUNNEL_AUDIT_RULES_FILE}" ]]; then
        log_warn "  ${TUNNEL_AUDIT_RULES_FILE} 없음 — setup_auditd_rules 미실행?"
        return 0
    fi

    local immutable_active=false
    if grep -q "^-e 2" "${TUNNEL_AUDIT_RULES_FILE}" 2>/dev/null; then
        immutable_active=true
        sed -i '/^-e 2$/d' "${TUNNEL_AUDIT_RULES_FILE}"
    fi

    if grep -q "tunnel_" "${TUNNEL_AUDIT_RULES_FILE}" 2>/dev/null; then
        log_skip "  터널링 auditd 규칙 이미 존재함"
    else
        cat >> "${TUNNEL_AUDIT_RULES_FILE}" << 'TUNNELAUDIT'

# ── ICMP / DNS / SOCKS5 터널링 탐지 감사 룰 ──────────────────────────────

# ICMP 터널링 도구 실행 감사
-w /usr/sbin/ptunnel           -p x -k tunnel_icmp
-w /usr/local/sbin/ptunnel-ng  -p x -k tunnel_icmp
-w /usr/bin/icmptunnel         -p x -k tunnel_icmp
-w /usr/bin/icmpsh             -p x -k tunnel_icmp
-w /usr/bin/pingtunnel         -p x -k tunnel_icmp

# DNS 터널링 도구 실행 감사
-w /usr/bin/iodine              -p x -k tunnel_dns
-w /usr/sbin/iodined            -p x -k tunnel_dns
-w /usr/bin/dns2tcp             -p x -k tunnel_dns
-w /usr/bin/dnscat              -p x -k tunnel_dns
-w /usr/local/bin/dnscat2       -p x -k tunnel_dns

# /etc/resolv.conf 수정 감사
-w /etc/resolv.conf             -p wa -k tunnel_dns_config
-w /etc/systemd/resolved.conf   -p wa -k tunnel_dns_config
-w /etc/systemd/resolved.conf.d/ -p wa -k tunnel_dns_config

# UFW after.rules 수정 감사 (터널링 방어 규칙 변조 탐지)
-w /etc/ufw/after.rules         -p wa -k tunnel_ufw_rules
-w /etc/ufw/after6.rules        -p wa -k tunnel_ufw_rules

# TUN/TAP 디바이스 생성 감사
-a always,exit -F arch=b64 -S ioctl -F a1=0x400454ca -k tunnel_tun_create
-a always,exit -F arch=b64 -S ioctl -F a1=0x400454cb -k tunnel_tap_create

# raw socket 생성 감사 (ICMP 터널링은 raw socket 사용)
-a always,exit -F arch=b64 -S socket -F a0=2 -F a1=3 -k tunnel_raw_socket
-a always,exit -F arch=b32 -S socket -F a0=2 -F a1=3 -k tunnel_raw_socket

# SOCKS5 터널링 도구 실행 감사
-w /usr/local/bin/chisel    -p x -k tunnel_socks5
-w /usr/local/bin/gost      -p x -k tunnel_socks5
-w /usr/local/bin/ligolo    -p x -k tunnel_socks5
-w /usr/local/bin/frpc      -p x -k tunnel_socks5
-w /usr/local/bin/inlets    -p x -k tunnel_socks5
-w /usr/local/bin/bore      -p x -k tunnel_socks5
-w /usr/bin/autossh         -p x -k tunnel_socks5
-w /usr/bin/sshuttle        -p x -k tunnel_socks5

# 네트워크 인터페이스 구성 변경 감사
-w /sbin/ip       -p x -k tunnel_net_config
-w /sbin/ifconfig -p x -k tunnel_net_config
-w /sbin/route    -p x -k tunnel_net_config
TUNNELAUDIT
        log_ok "  터널링 auditd 규칙 추가 완료"
    fi

    if [[ "${immutable_active}" == true ]]; then
        echo "-e 2" >> "${TUNNEL_AUDIT_RULES_FILE}"
    fi

    if augenrules --load 2>/dev/null; then
        log_ok "  auditd 규칙 재로드 완료"
    elif auditctl -R "${TUNNEL_AUDIT_RULES_FILE}" 2>/dev/null; then
        log_ok "  auditctl 직접 로드 완료"
    else
        log_warn "  auditd 규칙 재로드 실패 — 재부팅 후 적용됩니다"
    fi
}

# =============================================================================
# [23] 베이스라인 스냅샷 생성
# =============================================================================
create_baseline_snapshot() {
    log_info "===== [23] 베이스라인 스냅샷 생성 ====="
    mkdir -p "${BASELINE_SNAPSHOT_DIR}"

    { echo "# 설치 패키지 스냅샷 ($(date '+%Y-%m-%d %H:%M:%S'))"
      command -v dpkg &>/dev/null && dpkg -l 2>/dev/null \
          || command -v rpm &>/dev/null && rpm -qa 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/packages_baseline.txt" || true

    { echo "# 서비스 상태 스냅샷 ($(date '+%Y-%m-%d %H:%M:%S'))"
      systemctl list-units --type=service --state=running 2>/dev/null \
          || service --status-all 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/services_baseline.txt" || true

    { echo "# 리스닝 포트 스냅샷 ($(date '+%Y-%m-%d %H:%M:%S'))"
      ss -tlnup 2>/dev/null || netstat -tlnup 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/ports_baseline.txt" || true

    { echo "# iptables 규칙 스냅샷 ($(date '+%Y-%m-%d %H:%M:%S'))"
      iptables -S 2>/dev/null || true
      echo ""
      echo "# ip6tables"
      ip6tables -S 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/iptables_baseline.txt" || true

    { echo "# UFW 터널링 방어 after.rules 스냅샷 ($(date '+%Y-%m-%d %H:%M:%S'))"
      grep -A 100 "${UFW_TUNNEL_MARKER}" /etc/ufw/after.rules 2>/dev/null \
          || echo "(없음)"
    } > "${BASELINE_SNAPSHOT_DIR}/tunnel_ufw_after_rules_baseline.txt" || true

    { echo "# sysctl 설정 스냅샷 ($(date '+%Y-%m-%d %H:%M:%S'))"
      sysctl -a 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/sysctl_baseline.txt" || true

    { echo "# 사용자 계정 스냅샷 ($(date '+%Y-%m-%d %H:%M:%S'))"
      cat /etc/passwd 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/passwd_baseline.txt" || true

    { echo "# SSH 설정 스냅샷 ($(date '+%Y-%m-%d %H:%M:%S'))"
      sshd -T 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/sshd_baseline.txt" || true

    { echo "# auditd 규칙 스냅샷 ($(date '+%Y-%m-%d %H:%M:%S'))"
      auditctl -l 2>/dev/null || true
    } > "${BASELINE_SNAPSHOT_DIR}/auditd_baseline.txt" || true

    { echo "# ICMP 터널링 방어 iptables 규칙 스냅샷 ($(date '+%Y-%m-%d %H:%M:%S'))"
      iptables -S 2>/dev/null | grep -i "TUNNEL_ICMP" || echo "(없음)"
    } > "${BASELINE_SNAPSHOT_DIR}/tunnel_icmp_iptables_baseline.txt" || true

    { echo "# DNS 터널링 방어 iptables 규칙 스냅샷 ($(date '+%Y-%m-%d %H:%M:%S'))"
      iptables -S 2>/dev/null | grep -i "TUNNEL_DNS" || echo "(없음)"
    } > "${BASELINE_SNAPSHOT_DIR}/tunnel_dns_iptables_baseline.txt" || true

    { echo "# /etc/resolv.conf 스냅샷 ($(date '+%Y-%m-%d %H:%M:%S'))"
      cat /etc/resolv.conf 2>/dev/null || echo "(없음)"
      echo ""
      echo "# chattr 속성:"
      lsattr /etc/resolv.conf 2>/dev/null || echo "(lsattr 불가)"
    } > "${BASELINE_SNAPSHOT_DIR}/tunnel_resolv_baseline.txt" || true

    { echo "# 터널링 도구 프로세스 스냅샷 ($(date '+%Y-%m-%d %H:%M:%S'))"
      local _tun_found=false
      for _proc in "${TUNNEL_TOOL_PROCS[@]}"; do
          pgrep -x "${_proc}" &>/dev/null && { echo "RUNNING: ${_proc}"; _tun_found=true; }
      done
      [[ "${_tun_found}" == false ]] && echo "(탐지된 터널링 도구 없음)"
    } > "${BASELINE_SNAPSHOT_DIR}/tunnel_processes_baseline.txt" || true

    { sysctl -a 2>/dev/null | sed 's/ = /=/' | grep -v '^#' | sort
    } > "${BASELINE_SNAPSHOT_DIR}/sysctl_baseline.conf" || true

    { local _perm_targets=(
          "${FILES_644[@]}" "${FILES_600[@]}" "${FILES_O_NORW[@]}"
          /etc/ssh/sshd_config.d/99-hardening.conf
          /etc/audit/rules.d/99-hardening.rules
          /etc/sysctl.d/99-hardening.conf
          /etc/modprobe.d/dev-sec.conf
          /etc/security/faillock.conf
          /etc/ufw/after.rules
          /etc/ufw/after6.rules
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

    command -v ufw &>/dev/null && \
        ufw status 2>/dev/null | grep -iE 'ALLOW|DENY|REJECT|LIMIT' | \
            sed 's/[[:space:]]\+/ /g' | sort \
            > "${BASELINE_SNAPSHOT_DIR}/ufw_rules_baseline.txt" || true

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

    echo "${HIDEPID_ENABLED}" > "${BASELINE_SNAPSHOT_DIR}/hidepid_enabled.txt" || true

    sshd -T 2>/dev/null | sort \
        > "${BASELINE_SNAPSHOT_DIR}/sshd_effective_baseline.txt" || true

    ss -tlnp 2>/dev/null \
        > "${BASELINE_SNAPSHOT_DIR}/listening_ports_baseline.txt" || true

    { echo "PASS_MAX_DAYS=${PASS_MAX_DAYS}"
      echo "PASS_MIN_DAYS=${PASS_MIN_DAYS}"
      echo "PASS_WARN_AGE=${PASS_WARN_AGE}"
      echo "LOGIN_RETRIES=${LOGIN_RETRIES}"
      echo "UMASK=${DEFAULT_UMASK}"
    } > "${BASELINE_SNAPSHOT_DIR}/login_defs_baseline.txt" || true

    { local hash_targets=(
          /etc/passwd /etc/shadow /etc/group /etc/gshadow
          /etc/ssh/sshd_config /etc/sudoers
          /etc/audit/rules.d/99-hardening.rules
          /etc/sysctl.d/99-hardening.conf
          /etc/resolv.conf
          /etc/modprobe.d/dev-sec.conf
          /etc/security/faillock.conf
          /etc/ssh/sshd_config.d/99-hardening.conf
          /etc/ufw/after.rules
          /etc/ufw/after6.rules
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

    log_ok "[23] 베이스라인 스냅샷 저장 완료: ${BASELINE_SNAPSHOT_DIR}"
}

# =============================================================================
# [24] 현재 세션 외 다른 SSH 세션 종료
# =============================================================================
kill_other_ssh_sessions() {
    log_info "===== [24] 다른 SSH 세션 종료 ====="
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
        log_skip "현재 세션의 sshd 프로세스를 찾을 수 없음 — 세션 종료 건너뜀"
        return 0
    fi
    log_info "  현재 세션 sshd PID: ${my_sshd_pids[*]}"

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
            log_info "  마스터 sshd 제외: PID ${pid}"
            continue
        fi

        local user
        user=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
        if kill -HUP "$pid" 2>/dev/null; then
            log_ok "  SSH 세션 종료: PID ${pid} (사용자: ${user:-unknown})"
            killed_count=$((killed_count + 1))
        else
            log_warn "  SSH 세션 종료 실패: PID ${pid}"
        fi
    done < <(pgrep -x sshd 2>/dev/null || true)

    if [[ $killed_count -eq 0 ]]; then
        log_skip "종료할 다른 SSH 세션 없음"
    else
        log_ok "총 ${killed_count}개 SSH 세션 종료 완료"
    fi
}

# =============================================================================
# [상태 점검] --check 옵션
# =============================================================================
check_tunnel_status() {
    echo ""
    echo "══════════════════════════════════════════════════════"
    echo " ICMP / DNS / SOCKS5 터널링 방어 현황 점검"
    echo " (UFW after.rules 통합 버전)"
    echo "══════════════════════════════════════════════════════"

    echo ""
    echo "[1] UFW after.rules 터널링 방어 블록 등록 여부"
    if grep -q "${UFW_TUNNEL_MARKER}" /etc/ufw/after.rules 2>/dev/null; then
        log_ok   "  ✔  after.rules 터널링 방어 블록 존재"
    else
        log_warn "  ⚠  after.rules 터널링 방어 블록 없음"
    fi
    if grep -q "${UFW_TUNNEL_MARKER}" /etc/ufw/after6.rules 2>/dev/null; then
        log_ok   "  ✔  after6.rules ICMPv6 터널링 방어 블록 존재"
    else
        log_warn "  ⚠  after6.rules ICMPv6 터널링 방어 블록 없음"
    fi

    echo ""
    echo "[2] 런타임 iptables ICMP 터널링 방어 상태"
    local icmp_max_len=$((20 + 8 + TUNNEL_ICMP_MAX_PAYLOAD))
    if iptables -S 2>/dev/null | grep -q "TUNNEL_ICMP_LARGE_IN"; then
        log_ok   "  ✔  ICMP 대형 패킷 차단 적용됨 (>${TUNNEL_ICMP_MAX_PAYLOAD}B payload)"
    else
        log_warn "  ⚠  ICMP 대형 패킷 차단 미적용 (UFW reload 필요할 수 있음)"
    fi
    if iptables -S 2>/dev/null | grep -q "TUNNEL_ICMP_ECHO_OUT"; then
        log_ok   "  ✔  아웃바운드 ICMP echo-request 차단 적용됨"
    else
        log_warn "  ⚠  아웃바운드 ICMP echo-request 차단 미적용"
    fi

    echo ""
    echo "[3] 런타임 iptables DNS 터널링 방어 상태"
    if iptables -S 2>/dev/null | grep -q "TUNNEL_DNS_TCP_OUT"; then
        log_ok   "  ✔  DNS over TCP 아웃바운드 차단 적용됨"
    else
        log_warn "  ⚠  DNS over TCP 아웃바운드 차단 미적용"
    fi
    if [[ "${TUNNEL_LOCK_RESOLV}" == "true" ]]; then
        if lsattr /etc/resolv.conf 2>/dev/null | grep -q "i"; then
            log_ok   "  ✔  /etc/resolv.conf 불변 잠금 적용됨"
        else
            log_warn "  ⚠  /etc/resolv.conf 불변 잠금 미적용"
        fi
    fi

    echo ""
    echo "[4] 런타임 iptables SOCKS5 터널링 방어 상태"
    if iptables -S 2>/dev/null | grep -q "TUNNEL_SOCKS5_NOAUTH_IN"; then
        log_ok   "  ✔  SOCKS5 핸드셰이크 패턴 차단 적용됨"
    else
        log_warn "  ⚠  SOCKS5 핸드셰이크 패턴 차단 미적용"
    fi

    echo ""
    echo "[5] 터널링 도구 프로세스 탐지"
    local tunnel_found=0
    for proc in "${TUNNEL_TOOL_PROCS[@]}"; do
        if pgrep -x "${proc}" &>/dev/null; then
            log_warn "  ⚠  터널링 도구 실행 중: ${proc} (PID: $(pgrep -x "${proc}" | tr "\n" ","))"
            tunnel_found=1
        fi
    done
    [[ $tunnel_found -eq 0 ]] && log_ok "  ✔  탐지된 터널링 도구 없음"

    echo ""
    echo "[6] auditd 터널링 탐지 룰 상태"
    if command -v auditctl &>/dev/null; then
        local tunnel_rules
        tunnel_rules=$(auditctl -l 2>/dev/null | grep -c "tunnel_" || echo "0")
        [[ "${tunnel_rules}" -gt 0 ]] \
            && log_ok   "  ✔  터널링 auditd 룰 ${tunnel_rules}개 로드됨" \
            || log_warn "  ⚠  터널링 auditd 룰 없음"
    else
        log_skip "  auditctl 없음 — 확인 불가"
    fi

    echo ""
    echo "══════════════════════════════════════════════════════"
}

# =============================================================================
# [메인 실행부]
# =============================================================================
main() {
    local mode="${1:-harden}"

    if [[ "${mode}" == "--check" ]]; then
        check_root
        check_tunnel_status
        exit 0
    fi

    log_info "============================================================"
    log_info "베이스라인 하드닝 시작: 호스트=${HOSTNAME}"
    log_info "로그: ${LOGFILE}"
    log_info "============================================================"

    check_root
    check_environment
    create_backup_dir

    setup_auditd                      # [1]
    setup_pam                         # [2]
    setup_ufw                         # [3] ← UFW + 터널링 방어 iptables 통합
    setup_cron_permissions            # [4]
    setup_modprobe                    # [5]
    setup_sysctl                      # [6]
    setup_proc_hidepid                # [7]
    setup_sensitive_file_permissions  # [8]
    setup_other_permission_removal    # [9]
    setup_nologin_accounts            # [10]
    setup_sudoers                     # [11]
    setup_suid_removal                # [12]
    setup_disable_services            # [13]
    setup_lock_empty_password         # [14]
    setup_ssh_hardening               # [15]
    setup_auditd_rules                # [16]
    setup_login_defs                  # [17]
    setup_pam_faillock                # [18]
    setup_tmp_mount_hardening         # [19]
    setup_core_dump_limits            # [20]
    setup_umask                       # [21]
    setup_banner                      # [22]
    setup_tunnel_hardening            # [27] ← 프로세스 탐지 / 도구 제거 / auditd만
    cleanup_old_backups
    create_baseline_snapshot          # [23]

    log_info "============================================================"
    log_info "베이스라인 하드닝 완료"
    log_info "백업: ${BACKUP_DIR}"
    log_info "스냅샷: ${BASELINE_SNAPSHOT_DIR}"
    log_info "로그: ${LOGFILE}"
    log_info "============================================================"

    kill_other_ssh_sessions           # [24]
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@" 2>&1 | tee -a "$LOGFILE"
fi