#!/bin/bash
set -euo pipefail

###############################################################################
# pre_hardening_snapshot.sh
#
# 목적:
#   baseline_hardening.sh 실행 이전에 시스템 현재 상태를 전항목 스냅샷으로
#   수집하여, 하드닝 후 비교(diff) 및 롤백 판단에 활용한다.
#
# 수집 항목:
#   [01] 시스템 기본 정보
#   [02] 설치 패키지 목록
#   [03] 실행 중인 서비스
#   [04] 리스닝 포트 / 소켓
#   [05] iptables / ip6tables 규칙
#   [06] UFW 상태 및 after.rules
#   [07] sysctl 커널 파라미터
#   [08] 커널 모듈 (로드됨 / blacklist)
#   [09] /proc 마운트 옵션 (hidepid)
#   [10] 민감 파일 권한 및 소유자
#   [11] other 권한 대상 파일 권한
#   [12] SUID/SGID 파일 전체 목록
#   [13] 사용자 계정 / 셸 / 잠금 상태
#   [14] 비밀번호 없는 계정
#   [15] sudoers (NOPASSWD 포함 여부)
#   [16] SSH sshd_config 유효 설정
#   [17] PAM 설정 (common-auth, common-password, common-account)
#   [18] pam_faillock / faillock.conf
#   [19] auditd 설정 및 현재 로드된 룰
#   [20] login.defs 패스워드 에이징
#   [21] umask (전역 설정 파일)
#   [22] /etc/issue / /etc/issue.net 배너
#   [23] /tmp, /var/tmp, /dev/shm 마운트 옵션
#   [24] core dump 설정
#   [25] cron 디렉토리 권한
#   [26] 비활성화 대상 서비스 상태 (avahi, cups, bluetooth)
#   [27] 터널링 방어 현황
#       [27-1] 터널링 도구 프로세스
#       [27-2] TUN/TAP 디바이스
#       [27-3] DNS 직접 쿼리 탐지
#       [27-4] /etc/resolv.conf 및 chattr 상태
#       [27-5] SOCKS5 포트 리스닝 여부
#       [27-6] 터널링 도구 패키지/바이너리 존재 여부
#       [27-7] auditd 터널링 탐지 룰
#   [28] 무결성 해시 (SHA-256)
#
# 사용법:
#   sudo bash pre_hardening_snapshot.sh [출력_디렉토리]
#
# 출력:
#   PRE_SNAPSHOT_DIR (기본: /var/backups/pre_hardening_<타임스탬프>)
#   └─ 각 항목별 .txt / .conf 파일
#   └─ INTEGRITY.sha256  (전체 스냅샷 파일 해시)
#   └─ SUMMARY.txt       (항목별 수집 결과 요약)
###############################################################################

# =============================================================================
# [설정]
# =============================================================================
readonly SCRIPT_NAME="$(basename "$0")"
readonly HOSTNAME_VAL="$(hostname)"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# 출력 디렉토리 (인수로 재지정 가능)
readonly PRE_SNAPSHOT_DIR="${1:-/var/backups/pre_hardening_${TIMESTAMP}}"

# 로그 파일
readonly LOGFILE="${PRE_SNAPSHOT_DIR}/snapshot.log"

# 하드닝 스크립트와 동일한 대상 정의
# (baseline_hardening.sh 설정 섹션과 반드시 동기화)
readonly FILES_644=(/etc/passwd /etc/group /etc/passwd- /etc/group-)
readonly FILES_600=(/etc/shadow /etc/gshadow /etc/shadow- /etc/gshadow-)
readonly FILES_O_NORW=(
    /etc/fstab /etc/ftpusers /etc/group /etc/hosts
    /etc/hosts.allow /etc/hosts.equiv /etc/ssh
    /etc/hosts.lpd /etc/inetd.conf /etc/login.access
    /etc/login.defs /etc/ssh/sshd_config /etc/sysctl.conf
    /etc/crontab /usr/bin/crontab /usr/bin/at
    /usr/bin/atq /usr/bin/atrm /usr/bin/batch
    /var/log /var/spool/cron/crontabs
)
readonly SUID_REMOVE_TARGETS=(
    /usr/bin/nmap /usr/bin/bash /usr/bin/dash /usr/bin/find
    /usr/bin/less /usr/bin/pkexec /usr/bin/at
    /usr/bin/newgrp /usr/bin/chfn /usr/bin/chsh
)
readonly DISABLE_SERVICES=(
    avahi-daemon.service cups.service cups-browsed.service bluetooth.service
)
readonly TUNNEL_TOOL_PROCS=(
    ptunnel ptunnel-ng icmptunnel icmpsh pingtunnel
    iodine iodined dns2tcp dnscat dnscat2 dnscapy dnstunnel
    chisel ligolo frpc ngrok inlets bore gost autossh sshuttle
)
readonly TUNNEL_SOCKS5_PORTS=(1080 1081 8080 8888 9050 9150 1090 3128 8118)
readonly UFW_TUNNEL_MARKER="# TUNNEL_HARDENING_BLOCK_BEGIN"

# =============================================================================
# [로그 함수]
# =============================================================================
_log()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"; }
log_ok()  { _log "[OK]    $*"; }
log_info(){ _log "[INFO]  $*"; }
log_warn(){ _log "[WARN]  $*"; }
log_skip(){ _log "[SKIP]  $*"; }

# =============================================================================
# [헬퍼: 섹션 헤더 출력]
# =============================================================================
section() {
    local title="$1"
    _log "===== ${title} ====="
}

# =============================================================================
# [헬퍼: 파일에 섹션 헤더 + 명령 결과 저장]
#
# snap_cmd <출력파일> <제목> <명령...>
#   - 명령 실패 시 "(수집 실패 또는 해당 없음)" 을 기록하고 계속 진행
# =============================================================================
snap_cmd() {
    local outfile="$1"; shift
    local title="$1";   shift
    {
        echo "# ========================================"
        echo "# ${title}"
        echo "# 수집 시각: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# 호스트:    ${HOSTNAME_VAL}"
        echo "# ========================================"
        "$@" 2>/dev/null || echo "(수집 실패 또는 해당 없음)"
        echo ""
    } >> "${outfile}"
}

# =============================================================================
# [헬퍼: 파일 권한 + 소유자 한 줄 출력]
# =============================================================================
stat_line() {
    local f="$1"
    if [[ -e "$f" ]]; then
        printf "%-50s  perm=%-4s  owner=%-15s  type=%s\n" \
            "$f" \
            "$(stat -c '%a' "$f" 2>/dev/null)" \
            "$(stat -c '%U:%G' "$f" 2>/dev/null)" \
            "$(stat -c '%F' "$f" 2>/dev/null)"
    else
        printf "%-50s  (존재하지 않음)\n" "$f"
    fi
}

# =============================================================================
# [사전 확인]
# =============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[ERROR] root 권한 필요: sudo bash ${SCRIPT_NAME}"
        exit 1
    fi
}

# =============================================================================
# [초기화]
# =============================================================================
init_snapshot_dir() {
    mkdir -p "${PRE_SNAPSHOT_DIR}"
    # 로그 파일 초기화
    : > "$LOGFILE"
    log_info "스냅샷 디렉토리: ${PRE_SNAPSHOT_DIR}"
    log_info "호스트: ${HOSTNAME_VAL} / 수집 시각: ${TIMESTAMP}"
}

# =============================================================================
# [01] 시스템 기본 정보
# =============================================================================
snap_system_info() {
    section "[01] 시스템 기본 정보"
    local out="${PRE_SNAPSHOT_DIR}/01_system_info.txt"
    : > "$out"

    snap_cmd "$out" "OS 릴리즈" cat /etc/os-release
    snap_cmd "$out" "커널 버전" uname -a
    snap_cmd "$out" "호스트명" hostname -f
    snap_cmd "$out" "업타임" uptime
    snap_cmd "$out" "시스템 날짜/시간" date
    snap_cmd "$out" "CPU 정보" lscpu
    snap_cmd "$out" "메모리 정보" free -h
    snap_cmd "$out" "디스크 사용량" df -hT
    snap_cmd "$out" "마운트 목록" mount | sort
    snap_cmd "$out" "fstab" cat /etc/fstab
    snap_cmd "$out" "환경 변수 (root)" env | sort

    log_ok "[01] 시스템 기본 정보 → 01_system_info.txt"
}

# =============================================================================
# [02] 설치 패키지 목록
# =============================================================================
snap_packages() {
    section "[02] 설치 패키지 목록"
    local out="${PRE_SNAPSHOT_DIR}/02_packages.txt"
    : > "$out"

    if command -v dpkg &>/dev/null; then
        snap_cmd "$out" "dpkg -l (전체 패키지)" dpkg -l
        snap_cmd "$out" "apt 수동 설치 패키지" apt-mark showmanual
    elif command -v rpm &>/dev/null; then
        snap_cmd "$out" "rpm -qa (전체 패키지)" rpm -qa --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'
    else
        echo "(패키지 관리자 미탐지)" >> "$out"
    fi

    log_ok "[02] 패키지 목록 → 02_packages.txt"
}

# =============================================================================
# [03] 실행 중인 서비스
# =============================================================================
snap_services() {
    section "[03] 실행 중인 서비스"
    local out="${PRE_SNAPSHOT_DIR}/03_services.txt"
    : > "$out"

    snap_cmd "$out" "systemctl - 활성화된 서비스" \
        systemctl list-unit-files --type=service --state=enabled
    snap_cmd "$out" "systemctl - 실행 중 서비스" \
        systemctl list-units --type=service --state=running
    snap_cmd "$out" "systemctl - 전체 서비스 상태" \
        systemctl list-units --type=service --all
    snap_cmd "$out" "하드닝 비활성화 대상 서비스 현재 상태" bash -c '
        for svc in avahi-daemon.service cups.service cups-browsed.service bluetooth.service; do
            printf "%-35s  enabled=%-8s  active=%s\n" \
                "$svc" \
                "$(systemctl is-enabled "$svc" 2>/dev/null || echo N/A)" \
                "$(systemctl is-active  "$svc" 2>/dev/null || echo N/A)"
        done
    '

    log_ok "[03] 서비스 목록 → 03_services.txt"
}

# =============================================================================
# [04] 리스닝 포트 / 소켓
# =============================================================================
snap_ports() {
    section "[04] 리스닝 포트 / 소켓"
    local out="${PRE_SNAPSHOT_DIR}/04_ports.txt"
    : > "$out"

    snap_cmd "$out" "ss -tlnup (TCP/UDP 리스닝)" ss -tlnup
    snap_cmd "$out" "ss -xlnup (Unix 소켓 리스닝)" ss -xlnup
    snap_cmd "$out" "netstat -tlnup (대체)" netstat -tlnup

    log_ok "[04] 포트/소켓 → 04_ports.txt"
}

# =============================================================================
# [05] iptables / ip6tables 규칙
# =============================================================================
snap_iptables() {
    section "[05] iptables / ip6tables 규칙"
    local out="${PRE_SNAPSHOT_DIR}/05_iptables.txt"
    : > "$out"

    snap_cmd "$out" "iptables -S (IPv4 전체 규칙)"  iptables -S
    snap_cmd "$out" "iptables -L -n -v (IPv4 상세)" iptables -L -n -v
    snap_cmd "$out" "ip6tables -S (IPv6 전체 규칙)"  ip6tables -S
    snap_cmd "$out" "ip6tables -L -n -v (IPv6 상세)" ip6tables -L -n -v

    # 터널링 관련 규칙만 별도 추출
    {
        echo "# === 터널링 관련 규칙 추출 ==="
        iptables -S 2>/dev/null | grep -i "TUNNEL" || echo "(없음)"
    } >> "$out"

    log_ok "[05] iptables → 05_iptables.txt"
}

# =============================================================================
# [06] UFW 상태 및 after.rules
# =============================================================================
snap_ufw() {
    section "[06] UFW 상태 및 after.rules"
    local out="${PRE_SNAPSHOT_DIR}/06_ufw.txt"
    : > "$out"

    if command -v ufw &>/dev/null; then
        snap_cmd "$out" "UFW 상태 (verbose)" ufw status verbose
        snap_cmd "$out" "UFW 기본 정책" ufw status numbered
        snap_cmd "$out" "/etc/default/ufw" cat /etc/default/ufw
        snap_cmd "$out" "/etc/ufw/after.rules" cat /etc/ufw/after.rules
        snap_cmd "$out" "/etc/ufw/after6.rules" cat /etc/ufw/after6.rules
        snap_cmd "$out" "/etc/ufw/before.rules" cat /etc/ufw/before.rules
        snap_cmd "$out" "/etc/ufw/before6.rules" cat /etc/ufw/before6.rules
        snap_cmd "$out" "/etc/ufw/user.rules" cat /etc/ufw/user.rules
        # 터널링 방어 블록 존재 여부
        {
            echo "# === UFW 터널링 방어 블록 존재 여부 ==="
            if grep -q "${UFW_TUNNEL_MARKER}" /etc/ufw/after.rules 2>/dev/null; then
                echo "after.rules:  터널링 방어 블록 존재 (하드닝 적용됨)"
            else
                echo "after.rules:  터널링 방어 블록 없음 (하드닝 미적용)"
            fi
            if grep -q "${UFW_TUNNEL_MARKER}" /etc/ufw/after6.rules 2>/dev/null; then
                echo "after6.rules: 터널링 방어 블록 존재 (하드닝 적용됨)"
            else
                echo "after6.rules: 터널링 방어 블록 없음 (하드닝 미적용)"
            fi
        } >> "$out"
    else
        echo "UFW 미설치" >> "$out"
    fi

    log_ok "[06] UFW → 06_ufw.txt"
}

# =============================================================================
# [07] sysctl 커널 파라미터
# =============================================================================
snap_sysctl() {
    section "[07] sysctl 커널 파라미터"
    local out="${PRE_SNAPSHOT_DIR}/07_sysctl.txt"
    : > "$out"

    snap_cmd "$out" "sysctl -a (전체)" sysctl -a

    # 하드닝 대상 파라미터만 별도 추출
    {
        echo "# === 하드닝 대상 sysctl 파라미터 현재값 ==="
        local keys=(
            net.ipv4.ip_forward
            net.ipv4.conf.all.send_redirects
            net.ipv4.conf.default.send_redirects
            net.ipv4.conf.all.accept_source_route
            net.ipv4.conf.default.accept_source_route
            net.ipv4.conf.all.accept_redirects
            net.ipv4.conf.default.accept_redirects
            net.ipv4.conf.all.secure_redirects
            net.ipv4.conf.default.secure_redirects
            net.ipv4.icmp_echo_ignore_broadcasts
            net.ipv4.icmp_ignore_bogus_error_responses
            net.ipv4.conf.all.log_martians
            net.ipv4.conf.default.log_martians
            net.ipv4.tcp_syncookies
            kernel.randomize_va_space
            kernel.sysrq
            fs.suid_dumpable
            fs.protected_hardlinks
            fs.protected_symlinks
            net.ipv6.conf.all.accept_redirects
            net.ipv6.conf.default.accept_redirects
            net.ipv6.conf.all.accept_source_route
            net.ipv6.conf.default.accept_source_route
            net.ipv6.conf.all.accept_ra
            net.ipv6.conf.default.accept_ra
            net.ipv6.conf.all.forwarding
        )
        for k in "${keys[@]}"; do
            local val
            val=$(sysctl -n "$k" 2>/dev/null || echo "N/A")
            printf "%-55s = %s\n" "$k" "$val"
        done
    } >> "$out"

    snap_cmd "$out" "/etc/sysctl.conf" cat /etc/sysctl.conf
    snap_cmd "$out" "/etc/sysctl.d/ 디렉토리" ls -la /etc/sysctl.d/
    for f in /etc/sysctl.d/*.conf; do
        [[ -f "$f" ]] && snap_cmd "$out" "${f}" cat "${f}"
    done

    log_ok "[07] sysctl → 07_sysctl.txt"
}

# =============================================================================
# [08] 커널 모듈 (로드됨 / blacklist)
# =============================================================================
snap_modules() {
    section "[08] 커널 모듈"
    local out="${PRE_SNAPSHOT_DIR}/08_kernel_modules.txt"
    : > "$out"

    snap_cmd "$out" "lsmod (로드된 모듈 전체)" lsmod
    snap_cmd "$out" "/etc/modprobe.d/ 파일 목록" ls -la /etc/modprobe.d/

    for f in /etc/modprobe.d/*.conf; do
        [[ -f "$f" ]] && snap_cmd "$out" "${f}" cat "${f}"
    done

    # 하드닝 대상 모듈 로드 여부 확인
    {
        echo "# === 하드닝 차단 대상 모듈 현재 로드 여부 ==="
        for mod in cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat usb-storage; do
            if lsmod 2>/dev/null | grep -qw "^${mod}"; then
                printf "%-20s  LOADED (하드닝 후 차단 예정)\n" "$mod"
            else
                printf "%-20s  not loaded\n" "$mod"
            fi
        done
    } >> "$out"

    log_ok "[08] 커널 모듈 → 08_kernel_modules.txt"
}

# =============================================================================
# [09] /proc 마운트 옵션 (hidepid)
# =============================================================================
snap_proc_hidepid() {
    section "[09] /proc hidepid 상태"
    local out="${PRE_SNAPSHOT_DIR}/09_proc_hidepid.txt"
    : > "$out"

    snap_cmd "$out" "/proc 마운트 옵션" bash -c 'mount | grep " on /proc "'
    snap_cmd "$out" "findmnt /proc" findmnt /proc
    {
        echo "# === hidepid 적용 여부 ==="
        if mount | grep " on /proc " | grep -q "hidepid=2"; then
            echo "hidepid=2 적용됨"
        else
            echo "hidepid=2 미적용 (하드닝 후 적용 예정)"
        fi
    } >> "$out"

    log_ok "[09] /proc hidepid → 09_proc_hidepid.txt"
}

# =============================================================================
# [10] 민감 파일 권한 및 소유자 (644 / 600 대상)
# =============================================================================
snap_sensitive_file_permissions() {
    section "[10] 민감 파일 권한"
    local out="${PRE_SNAPSHOT_DIR}/10_sensitive_file_perms.txt"
    : > "$out"

    {
        echo "# === 하드닝 chmod 0644 대상 ==="
        for f in "${FILES_644[@]}"; do stat_line "$f"; done
        echo ""
        echo "# === 하드닝 chmod 0600 대상 ==="
        for f in "${FILES_600[@]}"; do stat_line "$f"; done
        echo ""
        echo "# === chattr 상태 (shadow / gshadow) ==="
        for f in /etc/shadow /etc/gshadow /etc/shadow- /etc/gshadow-; do
            [[ -e "$f" ]] && lsattr "$f" 2>/dev/null || printf "%-50s (없음)\n" "$f"
        done
    } >> "$out"

    log_ok "[10] 민감 파일 권한 → 10_sensitive_file_perms.txt"
}

# =============================================================================
# [11] other 권한 대상 파일 권한
# =============================================================================
snap_other_permissions() {
    section "[11] other 권한 대상 파일"
    local out="${PRE_SNAPSHOT_DIR}/11_other_permissions.txt"
    : > "$out"

    {
        echo "# === 하드닝 o-rwx 대상 파일 현재 권한 ==="
        for f in "${FILES_O_NORW[@]}"; do stat_line "$f"; done
    } >> "$out"

    log_ok "[11] other 권한 → 11_other_permissions.txt"
}

# =============================================================================
# [12] SUID/SGID 파일 전체 목록
# =============================================================================
snap_suid() {
    section "[12] SUID/SGID 파일"
    local out="${PRE_SNAPSHOT_DIR}/12_suid_sgid.txt"
    : > "$out"

    snap_cmd "$out" "SUID 파일 전체 (find -perm -4000)" \
        find / -xdev -perm -4000 -type f -ls
    snap_cmd "$out" "SGID 파일 전체 (find -perm -2000)" \
        find / -xdev -perm -2000 -type f -ls

    {
        echo "# === 하드닝 SUID 제거 대상 파일 현재 상태 ==="
        for f in "${SUID_REMOVE_TARGETS[@]}"; do
            if [[ -f "$f" ]]; then
                local suid_flag
                suid_flag=$( [[ -u "$f" ]] && echo "SUID 있음" || echo "SUID 없음" )
                printf "%-40s  %s  (perm: %s)\n" \
                    "$f" "$suid_flag" "$(stat -c '%a' "$f" 2>/dev/null)"
            else
                printf "%-40s  (파일 없음)\n" "$f"
            fi
        done
    } >> "$out"

    log_ok "[12] SUID/SGID → 12_suid_sgid.txt"
}

# =============================================================================
# [13] 사용자 계정 / 셸 / 잠금 상태
# =============================================================================
snap_accounts() {
    section "[13] 사용자 계정"
    local out="${PRE_SNAPSHOT_DIR}/13_accounts.txt"
    : > "$out"

    snap_cmd "$out" "/etc/passwd (전체)" cat /etc/passwd
    snap_cmd "$out" "/etc/group (전체)"  cat /etc/group

    {
        echo "# === 로그인 가능 계정 (nologin / false 셸 제외) ==="
        awk -F: '$7 !~ /(nologin|false)/ {print $1" : "  $7}' /etc/passwd | sort

        echo ""
        echo "# === 계정별 잠금 상태 ==="
        while IFS=: read -r user _ _ _ _ _ shell; do
            local status
            status=$(passwd -S "$user" 2>/dev/null | awk '{print $2}' || echo "N/A")
            printf "%-30s  shell=%-30s  status=%s\n" "$user" "$shell" "$status"
        done < /etc/passwd
    } >> "$out"

    log_ok "[13] 계정 목록 → 13_accounts.txt"
}

# =============================================================================
# [14] 비밀번호 없는 계정
# =============================================================================
snap_empty_password() {
    section "[14] 비밀번호 없는 계정"
    local out="${PRE_SNAPSHOT_DIR}/14_empty_password_accounts.txt"
    : > "$out"

    {
        echo "# === 비밀번호 없는 계정 (/etc/shadow 기준) ==="
        local empty_pw_accounts
        empty_pw_accounts=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null || true)
        if [[ -n "$empty_pw_accounts" ]]; then
            echo "$empty_pw_accounts"
            echo ""
            echo "⚠  위 계정은 하드닝 후 잠금(passwd -l) 처리됩니다."
        else
            echo "(비밀번호 없는 계정 없음)"
        fi
    } >> "$out"

    log_ok "[14] 빈 패스워드 → 14_empty_password_accounts.txt"
}

# =============================================================================
# [15] sudoers (NOPASSWD 포함 여부)
# =============================================================================
snap_sudoers() {
    section "[15] sudoers"
    local out="${PRE_SNAPSHOT_DIR}/15_sudoers.txt"
    : > "$out"

    snap_cmd "$out" "/etc/sudoers (visudo -c 검증)" visudo -c
    snap_cmd "$out" "/etc/sudoers 내용" cat /etc/sudoers
    snap_cmd "$out" "/etc/sudoers.d/ 파일 목록" ls -la /etc/sudoers.d/ 2>/dev/null

    for f in /etc/sudoers.d/*; do
        [[ -f "$f" ]] && snap_cmd "$out" "${f}" cat "${f}"
    done

    {
        echo "# === NOPASSWD 포함 라인 ==="
        grep -rn 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
            || echo "(NOPASSWD 없음)"
    } >> "$out"

    log_ok "[15] sudoers → 15_sudoers.txt"
}

# =============================================================================
# [16] SSH sshd_config 유효 설정
# =============================================================================
snap_ssh() {
    section "[16] SSH 설정"
    local out="${PRE_SNAPSHOT_DIR}/16_ssh.txt"
    : > "$out"

    snap_cmd "$out" "sshd -T (유효 설정 전체)" sshd -T
    snap_cmd "$out" "/etc/ssh/sshd_config 원본" cat /etc/ssh/sshd_config
    snap_cmd "$out" "/etc/ssh/sshd_config.d/ 목록" ls -la /etc/ssh/sshd_config.d/ 2>/dev/null

    for f in /etc/ssh/sshd_config.d/*.conf; do
        [[ -f "$f" ]] && snap_cmd "$out" "${f}" cat "${f}"
    done

    {
        echo "# === 하드닝 대상 SSH 파라미터 현재값 ==="
        local params=(
            permitrootlogin passwordauthentication maxauthtries
            permitemptypasswords x11forwarding allowtcpforwarding
            allowagentforwarding allowstreamlocalforwarding permittunnel
            gatewayports clientaliveinterval clientalivecountmax
            logingracetime banner usepam hostbasedauthentication
            ignorerhosts maxsessions maxstartups
        )
        for p in "${params[@]}"; do
            local val
            val=$(sshd -T 2>/dev/null | grep "^${p} " | awk '{$1=""; print $0}' | xargs || echo "N/A")
            printf "%-40s = %s\n" "$p" "$val"
        done
    } >> "$out"

    log_ok "[16] SSH 설정 → 16_ssh.txt"
}

# =============================================================================
# [17] PAM 설정
# =============================================================================
snap_pam() {
    section "[17] PAM 설정"
    local out="${PRE_SNAPSHOT_DIR}/17_pam.txt"
    : > "$out"

    for f in /etc/pam.d/common-auth /etc/pam.d/common-password \
             /etc/pam.d/common-account /etc/pam.d/common-session; do
        [[ -f "$f" ]] && snap_cmd "$out" "$f" cat "$f"
    done

    snap_cmd "$out" "/usr/share/pam-configs/ 목록" ls -la /usr/share/pam-configs/ 2>/dev/null

    for f in passwdqc faillock; do
        [[ -f "/usr/share/pam-configs/${f}" ]] && \
            snap_cmd "$out" "/usr/share/pam-configs/${f}" cat "/usr/share/pam-configs/${f}"
    done

    {
        echo "# === pam_passwdqc 적용 여부 ==="
        if grep -q 'pam_passwdqc' /etc/pam.d/common-password 2>/dev/null; then
            echo "common-password: pam_passwdqc 적용됨"
            grep 'pam_passwdqc' /etc/pam.d/common-password 2>/dev/null
        else
            echo "common-password: pam_passwdqc 미적용"
        fi
    } >> "$out"

    log_ok "[17] PAM → 17_pam.txt"
}

# =============================================================================
# [18] pam_faillock / faillock.conf
# =============================================================================
snap_faillock() {
    section "[18] pam_faillock"
    local out="${PRE_SNAPSHOT_DIR}/18_faillock.txt"
    : > "$out"

    snap_cmd "$out" "/etc/security/faillock.conf" cat /etc/security/faillock.conf

    {
        echo "# === pam_faillock 모듈 존재 여부 ==="
        find /usr/lib /lib -name 'pam_faillock.so' 2>/dev/null \
            | while IFS= read -r f; do echo "발견: $f"; done \
            || echo "(pam_faillock.so 없음)"
        echo ""
        echo "# === 잠긴 계정 목록 (faillock --user) ==="
        while IFS=: read -r user _; do
            local fl_out
            fl_out=$(faillock --user "$user" 2>/dev/null || true)
            if echo "$fl_out" | grep -q "When"; then
                echo "${user}:"
                echo "$fl_out"
            fi
        done < /etc/passwd
    } >> "$out"

    log_ok "[18] faillock → 18_faillock.txt"
}

# =============================================================================
# [19] auditd 설정 및 현재 로드된 룰
# =============================================================================
snap_auditd() {
    section "[19] auditd 설정 / 룰"
    local out="${PRE_SNAPSHOT_DIR}/19_auditd.txt"
    : > "$out"

    snap_cmd "$out" "/etc/audit/auditd.conf" cat /etc/audit/auditd.conf
    snap_cmd "$out" "auditctl -s (커널 상태)" auditctl -s
    snap_cmd "$out" "auditctl -l (현재 로드된 룰)" auditctl -l
    snap_cmd "$out" "/etc/audit/rules.d/ 목록" ls -la /etc/audit/rules.d/ 2>/dev/null

    for f in /etc/audit/rules.d/*.rules; do
        [[ -f "$f" ]] && snap_cmd "$out" "${f}" cat "${f}"
    done

    snap_cmd "$out" "systemctl status auditd" systemctl status auditd --no-pager

    log_ok "[19] auditd → 19_auditd.txt"
}

# =============================================================================
# [20] login.defs 패스워드 에이징
# =============================================================================
snap_login_defs() {
    section "[20] login.defs 패스워드 에이징"
    local out="${PRE_SNAPSHOT_DIR}/20_login_defs.txt"
    : > "$out"

    snap_cmd "$out" "/etc/login.defs 전체" cat /etc/login.defs

    {
        echo "# === 하드닝 대상 파라미터 현재값 ==="
        local params=(PASS_MAX_DAYS PASS_MIN_DAYS PASS_WARN_AGE LOGIN_RETRIES UMASK ENCRYPT_METHOD SHA_CRYPT_MIN_ROUNDS)
        for p in "${params[@]}"; do
            local val
            val=$(grep -E "^\s*${p}\s" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "(미설정)")
            printf "%-30s = %s\n" "$p" "$val"
        done
    } >> "$out"

    log_ok "[20] login.defs → 20_login_defs.txt"
}

# =============================================================================
# [21] umask 전역 설정
# =============================================================================
snap_umask() {
    section "[21] umask 설정"
    local out="${PRE_SNAPSHOT_DIR}/21_umask.txt"
    : > "$out"

    {
        echo "# === 현재 세션 umask ==="
        umask

        echo ""
        echo "# === 전역 설정 파일의 umask 라인 ==="
        for f in /etc/profile /etc/bash.bashrc /etc/login.defs; do
            if [[ -f "$f" ]]; then
                local hits
                hits=$(grep -n 'umask' "$f" 2>/dev/null || true)
                if [[ -n "$hits" ]]; then
                    echo "--- ${f} ---"
                    echo "$hits"
                else
                    echo "--- ${f} --- (umask 설정 없음)"
                fi
            fi
        done
    } >> "$out"

    log_ok "[21] umask → 21_umask.txt"
}

# =============================================================================
# [22] /etc/issue / /etc/issue.net 배너
# =============================================================================
snap_banner() {
    section "[22] 배너"
    local out="${PRE_SNAPSHOT_DIR}/22_banner.txt"
    : > "$out"

    snap_cmd "$out" "/etc/issue 현재 내용" cat /etc/issue
    snap_cmd "$out" "/etc/issue.net 현재 내용" cat /etc/issue.net
    snap_cmd "$out" "/etc/update-motd.d/ 목록 (실행 권한 여부)" \
        ls -la /etc/update-motd.d/ 2>/dev/null

    log_ok "[22] 배너 → 22_banner.txt"
}

# =============================================================================
# [23] /tmp, /var/tmp, /dev/shm 마운트 옵션
# =============================================================================
snap_tmp_mounts() {
    section "[23] /tmp /var/tmp /dev/shm 마운트 옵션"
    local out="${PRE_SNAPSHOT_DIR}/23_tmp_mounts.txt"
    : > "$out"

    {
        echo "# === 현재 마운트 옵션 ==="
        for mnt in /tmp /var/tmp /dev/shm; do
            printf "%-15s  " "$mnt"
            mount | grep " on ${mnt} " || echo "(마운트 정보 없음)"
        done

        echo ""
        echo "# === noexec / nosuid / nodev 적용 여부 ==="
        for mnt in /tmp /var/tmp /dev/shm; do
            local opts
            opts=$(mount | grep " on ${mnt} " | grep -oP '\(.*?\)' || echo "(마운트 없음)")
            printf "%-15s  %s\n" "$mnt" "$opts"
        done
    } >> "$out"

    snap_cmd "$out" "findmnt -l" findmnt -l

    log_ok "[23] tmp 마운트 → 23_tmp_mounts.txt"
}

# =============================================================================
# [24] core dump 설정
# =============================================================================
snap_core_dump() {
    section "[24] core dump 설정"
    local out="${PRE_SNAPSHOT_DIR}/24_core_dump.txt"
    : > "$out"

    snap_cmd "$out" "현재 core dump 크기 제한 (ulimit -c)" bash -c 'ulimit -c'
    snap_cmd "$out" "/etc/security/limits.conf (core 관련 라인)" \
        bash -c 'grep -i "core" /etc/security/limits.conf 2>/dev/null || echo "(설정 없음)"'
    snap_cmd "$out" "/etc/systemd/coredump.conf" cat /etc/systemd/coredump.conf
    snap_cmd "$out" "sysctl fs.suid_dumpable" sysctl fs.suid_dumpable
    snap_cmd "$out" "sysctl kernel.core_pattern" sysctl kernel.core_pattern

    log_ok "[24] core dump → 24_core_dump.txt"
}

# =============================================================================
# [25] cron 디렉토리 권한
# =============================================================================
snap_cron() {
    section "[25] cron 권한"
    local out="${PRE_SNAPSHOT_DIR}/25_cron.txt"
    : > "$out"

    {
        echo "# === cron 디렉토리 / 파일 현재 권한 ==="
        for target in /etc/crontab \
                      /etc/cron.hourly /etc/cron.daily \
                      /etc/cron.weekly /etc/cron.monthly /etc/cron.d \
                      /var/spool/cron/crontabs; do
            stat_line "$target"
        done
    } >> "$out"

    snap_cmd "$out" "crontab -l (root)" crontab -l
    snap_cmd "$out" "/etc/crontab 내용" cat /etc/crontab
    snap_cmd "$out" "/etc/cron.d/ 목록" ls -la /etc/cron.d/ 2>/dev/null

    log_ok "[25] cron → 25_cron.txt"
}

# =============================================================================
# [26] 비활성화 대상 서비스 현재 상태 (중복 상세)
# =============================================================================
snap_disable_services_detail() {
    section "[26] 비활성화 대상 서비스 상세"
    local out="${PRE_SNAPSHOT_DIR}/26_disable_services.txt"
    : > "$out"

    for svc in "${DISABLE_SERVICES[@]}"; do
        {
            echo "# ── ${svc} ──"
            systemctl status "${svc}" --no-pager 2>/dev/null \
                || echo "(서비스 없음 또는 상태 조회 실패)"
            echo ""
        } >> "$out"
    done

    log_ok "[26] 비활성화 대상 서비스 → 26_disable_services.txt"
}

# =============================================================================
# [27] 터널링 방어 현황
# =============================================================================
snap_tunnel() {
    section "[27] 터널링 방어 현황"
    local out="${PRE_SNAPSHOT_DIR}/27_tunnel_defense.txt"
    : > "$out"

    # ── [27-1] 터널링 도구 프로세스 ─────────────────────────────────────────
    {
        echo "# ========================================"
        echo "# [27-1] 터널링 도구 프로세스 실행 여부"
        echo "# ========================================"
        local found=0
        for proc in "${TUNNEL_TOOL_PROCS[@]}"; do
            if pgrep -x "${proc}" &>/dev/null; then
                local pids
                pids=$(pgrep -x "${proc}" | tr '\n' ',' | sed 's/,$//')
                local exe
                exe=$(readlink -f "/proc/$(pgrep -x "${proc}" | head -1)/exe" 2>/dev/null || echo "알 수 없음")
                printf "RUNNING: %-20s  PID=%-15s  exe=%s\n" "${proc}" "${pids}" "${exe}"
                found=1
            fi
        done
        [[ $found -eq 0 ]] && echo "(탐지된 터널링 도구 없음)"
    } >> "$out"

    # ── [27-2] TUN/TAP 디바이스 ─────────────────────────────────────────────
    {
        echo ""
        echo "# ========================================"
        echo "# [27-2] TUN/TAP 디바이스"
        echo "# ========================================"
        ip link show type tun 2>/dev/null || true
        ip link show type tap 2>/dev/null || true
        ls -la /dev/net/tun 2>/dev/null || echo "/dev/net/tun 없음"
        echo ""
        echo "# TUN/TAP 점유 프로세스:"
        ls /proc/*/fd 2>/dev/null \
            | xargs -I{} readlink {} 2>/dev/null \
            | grep -i "net/tun" \
            || echo "(TUN/TAP 점유 프로세스 없음)"
    } >> "$out"

    # ── [27-3] DNS 직접 쿼리 탐지 ───────────────────────────────────────────
    {
        echo ""
        echo "# ========================================"
        echo "# [27-3] 비내부망 DNS 직접 쿼리 탐지"
        echo "# ========================================"
        local dns_non_std
        dns_non_std=$(ss -unp 2>/dev/null \
            | awk '$5 ~ /:53$/ && $4 !~ /^(127\.|10\.|172\.|192\.168\.)/ {print}' \
            || true)
        if [[ -n "${dns_non_std}" ]]; then
            echo "⚠ 비내부망 직접 DNS 쿼리 탐지:"
            echo "${dns_non_std}"
        else
            echo "(탐지 없음)"
        fi
    } >> "$out"

    # ── [27-4] /etc/resolv.conf 및 chattr ───────────────────────────────────
    {
        echo ""
        echo "# ========================================"
        echo "# [27-4] /etc/resolv.conf 상태"
        echo "# ========================================"
        cat /etc/resolv.conf 2>/dev/null || echo "(없음)"
        echo ""
        echo "# resolv.conf 타입 및 chattr:"
        stat_line /etc/resolv.conf
        if [[ -L /etc/resolv.conf ]]; then
            echo "심볼릭 링크 → $(readlink -f /etc/resolv.conf 2>/dev/null)"
        fi
        lsattr /etc/resolv.conf 2>/dev/null || echo "(lsattr 불가)"
        echo ""
        echo "# systemd-resolved 상태:"
        systemctl is-active systemd-resolved 2>/dev/null \
            && systemctl status systemd-resolved --no-pager 2>/dev/null \
            || echo "(systemd-resolved 비활성)"
    } >> "$out"

    # ── [27-5] SOCKS5 포트 리스닝 여부 ──────────────────────────────────────
    {
        echo ""
        echo "# ========================================"
        echo "# [27-5] SOCKS5 의심 포트 리스닝 여부"
        echo "# ========================================"
        local socks_found=0
        for port in "${TUNNEL_SOCKS5_PORTS[@]}"; do
            local hits
            hits=$(ss -tlnp 2>/dev/null | awk -v p=":${port}$" '$4 ~ p {print}' || true)
            if [[ -n "$hits" ]]; then
                echo "LISTENING port ${port}/tcp:"
                echo "$hits"
                socks_found=1
            fi
        done
        [[ $socks_found -eq 0 ]] && echo "(SOCKS5 의심 포트 리스닝 없음)"
    } >> "$out"

    # ── [27-6] 터널링 도구 패키지/바이너리 존재 여부 ────────────────────────
    {
        echo ""
        echo "# ========================================"
        echo "# [27-6] 터널링 도구 패키지/바이너리 존재 여부"
        echo "# ========================================"
        local tunnel_pkgs=(ptunnel ptunnel-ng iodine dns2tcp dnscat2 chisel sshuttle autossh)

        echo "## 패키지 설치 여부:"
        for pkg in "${tunnel_pkgs[@]}"; do
            if command -v dpkg &>/dev/null; then
                if dpkg -s "${pkg}" &>/dev/null 2>&1; then
                    echo "INSTALLED (dpkg): ${pkg}"
                fi
            elif command -v rpm &>/dev/null; then
                if rpm -q "${pkg}" &>/dev/null 2>&1; then
                    echo "INSTALLED (rpm): ${pkg}"
                fi
            fi
        done

        echo ""
        echo "## 바이너리 존재 여부:"
        local tunnel_bins=(
            /usr/sbin/iodined /usr/bin/iodine /usr/bin/dns2tcp
            /usr/bin/dnscat /usr/local/bin/dnscat2
            /usr/local/bin/chisel /usr/local/bin/gost
            /usr/local/bin/ligolo /usr/local/bin/frpc
            /usr/local/bin/bore /usr/local/bin/inlets
            /usr/local/sbin/ptunnel /usr/local/sbin/ptunnel-ng
            /usr/bin/autossh /usr/bin/sshuttle
        )
        local bin_found=0
        for bin in "${tunnel_bins[@]}"; do
            if [[ -f "$bin" ]]; then
                echo "EXISTS: $bin  ($(stat -c '%a' "$bin" 2>/dev/null))"
                bin_found=1
            fi
        done
        [[ $bin_found -eq 0 ]] && echo "(하드닝 대상 바이너리 없음)"
    } >> "$out"

    # ── [27-7] auditd 터널링 탐지 룰 ────────────────────────────────────────
    {
        echo ""
        echo "# ========================================"
        echo "# [27-7] auditd 터널링 탐지 룰 (로드됨)"
        echo "# ========================================"
        if command -v auditctl &>/dev/null; then
            local tunnel_rules
            tunnel_rules=$(auditctl -l 2>/dev/null | grep "tunnel_" || true)
            if [[ -n "$tunnel_rules" ]]; then
                echo "$tunnel_rules"
            else
                echo "(터널링 탐지 룰 없음 — 하드닝 후 추가 예정)"
            fi
        else
            echo "(auditctl 없음)"
        fi
    } >> "$out"

    log_ok "[27] 터널링 방어 → 27_tunnel_defense.txt"
}

# =============================================================================
# [28] 무결성 해시 (SHA-256)
# =============================================================================
generate_integrity_hashes() {
    section "[28] 무결성 해시 생성"
    local hash_file="${PRE_SNAPSHOT_DIR}/INTEGRITY.sha256"

    # 핵심 설정 파일 해시
    {
        echo "# ========================================"
        echo "# 핵심 설정 파일 SHA-256 해시"
        echo "# 생성 시각: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# ========================================"
        local hash_targets=(
            /etc/passwd /etc/shadow /etc/group /etc/gshadow
            /etc/ssh/sshd_config
            /etc/sudoers
            /etc/audit/auditd.conf
            /etc/sysctl.conf
            /etc/resolv.conf
            /etc/modprobe.d/dev-sec.conf
            /etc/security/faillock.conf
            /etc/ufw/after.rules
            /etc/ufw/after6.rules
            /etc/ufw/before.rules
            /etc/pam.d/common-auth
            /etc/pam.d/common-password
            /etc/pam.d/common-account
            /etc/login.defs
            /etc/issue
            /etc/issue.net
            /etc/fstab
            /etc/security/limits.conf
        )
        for f in "${hash_targets[@]}"; do
            [[ -f "$f" ]] && sha256sum "$f" 2>/dev/null || printf "%-64s  %s (없음)\n" "-" "$f"
        done

        echo ""
        echo "# ========================================"
        echo "# 스냅샷 파일 SHA-256 해시"
        echo "# ========================================"
        find "${PRE_SNAPSHOT_DIR}" -maxdepth 1 \
            \( -name '*.txt' -o -name '*.conf' -o -name '*.log' \) \
            ! -name 'INTEGRITY.sha256' \
            -exec sha256sum {} \; 2>/dev/null | sort
    } > "${hash_file}"

    log_ok "[28] 무결성 해시 → INTEGRITY.sha256"
}

# =============================================================================
# [SUMMARY] 수집 결과 요약
# =============================================================================
generate_summary() {
    local summary="${PRE_SNAPSHOT_DIR}/SUMMARY.txt"

    {
        echo "========================================================================"
        echo " 하드닝 전 스냅샷 요약 보고서"
        echo " 호스트:    ${HOSTNAME_VAL}"
        echo " 수집 시각: $(date '+%Y-%m-%d %H:%M:%S')"
        echo " 저장 위치: ${PRE_SNAPSHOT_DIR}"
        echo "========================================================================"

        echo ""
        echo "[시스템]"
        uname -r 2>/dev/null | xargs -I{} echo "  커널: {}"
        . /etc/os-release 2>/dev/null && echo "  OS: ${PRETTY_NAME:-unknown}" || true

        echo ""
        echo "[계정]"
        local login_count nologin_count empty_pw_count
        login_count=$(awk -F: '$7 !~ /(nologin|false)/ {c++} END {print c+0}' /etc/passwd)
        nologin_count=$(awk -F: '$7 ~ /(nologin|false)/ {c++} END {print c+0}' /etc/passwd)
        empty_pw_count=$(awk -F: '($2==""){c++} END {print c+0}' /etc/shadow 2>/dev/null || echo 0)
        echo "  로그인 가능 계정: ${login_count}개"
        echo "  nologin/false 계정: ${nologin_count}개"
        echo "  빈 패스워드 계정: ${empty_pw_count}개 $([ "${empty_pw_count}" -gt 0 ] && echo '⚠' || true)"

        echo ""
        echo "[sudoers]"
        local nopasswd_count
        nopasswd_count=$(grep -rc 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
        echo "  NOPASSWD 라인 수: ${nopasswd_count}개 $([ "${nopasswd_count}" -gt 0 ] && echo '⚠ (하드닝 후 제거 예정)' || true)"

        echo ""
        echo "[SSH]"
        local root_login pw_auth
        root_login=$(sshd -T 2>/dev/null | grep '^permitrootlogin ' | awk '{print $2}' || echo "N/A")
        pw_auth=$(sshd -T 2>/dev/null | grep '^passwordauthentication ' | awk '{print $2}' || echo "N/A")
        echo "  PermitRootLogin: ${root_login}"
        echo "  PasswordAuthentication: ${pw_auth}"

        echo ""
        echo "[UFW]"
        if command -v ufw &>/dev/null; then
            ufw status 2>/dev/null | head -3 | sed 's/^/  /'
        else
            echo "  UFW 미설치"
        fi

        echo ""
        echo "[터널링 도구 프로세스]"
        local tun_proc_count=0
        for proc in "${TUNNEL_TOOL_PROCS[@]}"; do
            pgrep -x "${proc}" &>/dev/null && tun_proc_count=$((tun_proc_count + 1))
        done
        echo "  실행 중인 터널링 도구: ${tun_proc_count}개 $([ "${tun_proc_count}" -gt 0 ] && echo '⚠' || true)"

        echo ""
        echo "[SUID 파일]"
        local suid_count
        suid_count=$(find / -xdev -perm -4000 -type f 2>/dev/null | wc -l)
        echo "  시스템 전체 SUID 파일: ${suid_count}개"

        echo ""
        echo "[비활성화 대상 서비스 현재 상태]"
        for svc in "${DISABLE_SERVICES[@]}"; do
            local active_state
            active_state=$(systemctl is-active "${svc}" 2>/dev/null || echo "N/A")
            printf "  %-35s  %s\n" "${svc}" "${active_state}"
        done

        echo ""
        echo "[스냅샷 파일 목록]"
        find "${PRE_SNAPSHOT_DIR}" -maxdepth 1 -type f | sort | sed 's/^/  /'

        echo ""
        echo "========================================================================"
        echo " 스냅샷 수집 완료. baseline_hardening.sh 실행 후 아래 명령으로 비교:"
        echo ""
        echo "   diff -u ${PRE_SNAPSHOT_DIR}/07_sysctl.txt <(sysctl -a | sort)"
        echo "   diff -u ${PRE_SNAPSHOT_DIR}/05_iptables.txt <(iptables -S)"
        echo "   diff -u ${PRE_SNAPSHOT_DIR}/16_ssh.txt <(sshd -T | sort)"
        echo "========================================================================"
    } > "${summary}"

    cat "${summary}"
}

# =============================================================================
# [메인]
# =============================================================================
main() {
    check_root
    init_snapshot_dir

    log_info "============================================================"
    log_info "하드닝 전 스냅샷 수집 시작"
    log_info "호스트: ${HOSTNAME_VAL}  /  저장: ${PRE_SNAPSHOT_DIR}"
    log_info "============================================================"

    snap_system_info                # [01]
    snap_packages                   # [02]
    snap_services                   # [03]
    snap_ports                      # [04]
    snap_iptables                   # [05]
    snap_ufw                        # [06]
    snap_sysctl                     # [07]
    snap_modules                    # [08]
    snap_proc_hidepid               # [09]
    snap_sensitive_file_permissions # [10]
    snap_other_permissions          # [11]
    snap_suid                       # [12]
    snap_accounts                   # [13]
    snap_empty_password             # [14]
    snap_sudoers                    # [15]
    snap_ssh                        # [16]
    snap_pam                        # [17]
    snap_faillock                   # [18]
    snap_auditd                     # [19]
    snap_login_defs                 # [20]
    snap_umask                      # [21]
    snap_banner                     # [22]
    snap_tmp_mounts                 # [23]
    snap_core_dump                  # [24]
    snap_cron                       # [25]
    snap_disable_services_detail    # [26]
    snap_tunnel                     # [27]
    generate_integrity_hashes       # [28]
    generate_summary

    log_info "============================================================"
    log_info "스냅샷 수집 완료: ${PRE_SNAPSHOT_DIR}"
    log_info "============================================================"
}

main "$@"