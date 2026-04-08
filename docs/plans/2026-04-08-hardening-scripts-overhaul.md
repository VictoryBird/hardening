# Hardening Scripts Overhaul - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the existing Ubuntu/Debian hardening scripts into a multi-OS framework supporting RHEL, FreeBSD, and macOS, while adding safety guards for protected accounts/services, network constraints, and green team agent preservation.

**Architecture:** Extract a shared library of OS-detection and helper functions (`lib/common.sh`), then create per-OS adapter modules (`lib/os_debian.sh`, `lib/os_rhel.sh`, `lib/os_freebsd.sh`, `lib/os_macos.sh`) that implement a common interface. The main scripts (`01_baseline_hardening.sh`, `02_check_and_restore.sh`) become thin orchestrators that source the appropriate adapter. Safety constraints (protected accounts, network rules, gtmon agent) are enforced in the common library as pre/post-flight checks that cannot be bypassed.

**Tech Stack:** POSIX sh + bash 4.0+ (Linux/FreeBSD), zsh/bash (macOS), standard Unix utilities

---

## Scope Decomposition

This plan covers **5 independent sub-projects** that should be executed in order (later phases depend on earlier ones):

| Phase | Description | Dependency |
|-------|-------------|------------|
| Phase 1 | Common library + OS detection + safety framework | None |
| Phase 2 | Refactor existing Debian/Ubuntu scripts to use the library | Phase 1 |
| Phase 3 | RHEL/Rocky/AlmaLinux adapter | Phase 1 |
| Phase 4 | FreeBSD adapter | Phase 1 |
| Phase 5 | macOS adapter | Phase 1 |

---

## Critical Safety Constraints (applies to ALL phases)

These constraints MUST be enforced by the common library. Every OS adapter must call these checks.

### C1: Account Protection

```
root    → 변경 가능 (Linux, BSD only). macOS에서는 root 건드리지 않음
gt      → 절대 삭제 금지, 변경 금지. sudo group + NOPASSWD 유지 필수
          - Linux: gt must be in sudo group with NOPASSWD
          - FreeBSD: gt must be in wheel group with NOPASSWD  
          - macOS: gt must be in admin group
usr     → 삭제 금지, 비밀번호 변경 가능하되 변경 시 stdout에 출력 필수
```

### C2: Network Protection

```
- IPv4/IPv6 듀얼스택 서비스: 원래 양쪽 리스닝이면 양쪽 모두 유지
- DNS 이름 변경 금지 (hostname 변경 금지)
- authoritative DNS 서버 IP 변경 금지
- 워크스테이션 아웃바운드 필수 허용:
  SSH(22), HTTP(80), HTTPS(443), HTTP-Alt(8080), 
  POP3(110), POP3S(995), IMAP(143), IMAPS(993), 
  FTP(21), ICMP ping
  → IPv4 + IPv6 모두
```

### C3: Green Team Agent Protection

```
- gtmon 바이너리 보호:
  *nix:  /opt/gtmon OR /usr/bin/gtmon
  macOS: /Users/gt/scoringbot/scoringbot

- gtmon 자동시작 메커니즘 보호:
  systemd: gtmon.service
  rc:      gtmon (FreeBSD)
  launchd: net.cr14.gtmon.plist (macOS)

- 서비스 헬퍼 보호:
  FreeBSD: fscd

- gtmon은 root로 실행 (*nix)
- gtmon의 네트워크/프로세스/파일시스템 접근 차단 금지
- DNS 정상 동작 필수
- 아웃바운드 HTTP(80), HTTPS(443), SSH(22) 차단 금지
```

### C4: auditd 정책

```
- 01 스크립트: auditd 설정값을 변경하지 않고 현재 설정을 저장(스냅샷)만 함
- 02 스크립트: 저장된 스냅샷과 현재 상태를 diff하여 변경 탐지 및 복원
```

---

## File Structure

```
hardening/
├── lib/
│   ├── common.sh              # OS 감지, 로깅, 백업, 안전장치(C1-C4)
│   ├── safety_guards.sh       # 계정/네트워크/gtmon 보호 전용 함수
│   ├── os_debian.sh           # Debian/Ubuntu 어댑터 (기존 로직 리팩터링)
│   ├── os_rhel.sh             # RHEL/Rocky/AlmaLinux 어댑터
│   ├── os_freebsd.sh          # FreeBSD 어댑터
│   └── os_macos.sh            # macOS 어댑터
├── 01_baseline_hardening.sh   # v4: 오케스트레이터 (OS별 어댑터 호출)
├── 02_check_and_restore.sh    # v4: 오케스트레이터 (OS별 점검/복원)
├── 01_baseline_hardening_v3.sh  # 기존 (보존)
├── 02_check_and_restore_v3.sh   # 기존 (보존)
└── docs/
    └── plans/
        └── 2026-04-08-hardening-scripts-overhaul.md
```

### 각 파일의 역할

| 파일 | 역할 |
|------|------|
| `lib/common.sh` | OS 감지(`detect_os`), 로깅 함수, 백업 함수, 패키지 매니저 추상화, 서비스 매니저 추상화, 설정 변수 |
| `lib/safety_guards.sh` | `guard_account_gt()`, `guard_account_usr()`, `guard_network_outbound()`, `guard_gtmon_agent()`, `guard_dns()`, `guard_auditd_readonly()` — 모든 OS 공통 |
| `lib/os_debian.sh` | `pkg_install()`, `pkg_remove()`, `svc_enable()`, `svc_disable()`, `fw_setup()`, `pam_setup()` 등 Debian 구현 |
| `lib/os_rhel.sh` | 동일 인터페이스의 RHEL 구현 (dnf/yum, firewalld, SELinux 고려) |
| `lib/os_freebsd.sh` | 동일 인터페이스의 FreeBSD 구현 (pkg, pf/ipfw, rc.conf) |
| `lib/os_macos.sh` | 동일 인터페이스의 macOS 구현 (brew 불필요, pf, launchd, defaults) |
| `01_baseline_hardening.sh` | 메인 진입점 — `detect_os` → 어댑터 source → 순차 실행 |
| `02_check_and_restore.sh` | 메인 진입점 — `detect_os` → 스냅샷 비교 → 어댑터별 복원 |

---

## Phase 1: Common Library + Safety Framework

### Task 1.1: lib/common.sh — OS 감지 및 로깅

**Files:**
- Create: `lib/common.sh`

- [ ] **Step 1: common.sh 기본 구조 작성**

```bash
#!/usr/bin/env bash
# lib/common.sh — 하드닝 프레임워크 공통 라이브러리
# 사용법: source "$(dirname "$0")/lib/common.sh"

set -euo pipefail

# ─── 전역 상수 ───────────────────────────────────────────────────
readonly HARDENING_VERSION="4.0.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
readonly LIB_DIR="${SCRIPT_DIR}/lib"
readonly HOSTNAME_ORIG="$(hostname)"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# ─── OS 감지 ─────────────────────────────────────────────────────
# OS_FAMILY: debian | rhel | freebsd | macos
# OS_ID:     ubuntu, debian, rocky, almalinux, rhel, freebsd, macos
# OS_VERSION: 22.04, 9.3, 14.0, etc.
detect_os() {
    local uname_s
    uname_s="$(uname -s)"

    case "$uname_s" in
        Linux)
            if [[ -f /etc/os-release ]]; then
                # shellcheck source=/dev/null
                . /etc/os-release
                OS_ID="${ID:-unknown}"
                OS_VERSION="${VERSION_ID:-unknown}"
                case "$OS_ID" in
                    ubuntu|debian)
                        OS_FAMILY="debian"
                        ;;
                    rhel|rocky|almalinux|centos|fedora)
                        OS_FAMILY="rhel"
                        ;;
                    *)
                        OS_FAMILY="unknown"
                        log_warn "미지원 Linux 배포판: ${OS_ID}"
                        ;;
                esac
            else
                OS_FAMILY="unknown"
                OS_ID="unknown"
                OS_VERSION="unknown"
            fi
            ;;
        FreeBSD)
            OS_FAMILY="freebsd"
            OS_ID="freebsd"
            OS_VERSION="$(freebsd-version -u 2>/dev/null | cut -d- -f1 || uname -r)"
            ;;
        Darwin)
            OS_FAMILY="macos"
            OS_ID="macos"
            OS_VERSION="$(sw_vers -productVersion 2>/dev/null || echo 'unknown')"
            ;;
        *)
            OS_FAMILY="unknown"
            OS_ID="unknown"
            OS_VERSION="unknown"
            log_error "미지원 OS: ${uname_s}"
            ;;
    esac

    readonly OS_FAMILY OS_ID OS_VERSION
    log_info "OS 감지: family=${OS_FAMILY}, id=${OS_ID}, version=${OS_VERSION}"
}

# ─── 로깅 ────────────────────────────────────────────────────────
_LOG_DIR="/var/log/hardening"
if ! mkdir -p "$_LOG_DIR" 2>/dev/null || [[ ! -w "$_LOG_DIR" ]]; then
    _LOG_DIR="/tmp"
fi

log_info()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]    $*"; }
log_ok()      { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [OK]      $*"; }
log_skip()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SKIP]    $*"; }
log_warn()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]    $*"; }
log_error()   { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR]   $*" >&2; }
log_drift()   { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [DRIFT]   $*"; DRIFT_COUNT=$((DRIFT_COUNT + 1)); }
log_restore() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [RESTORE] $*"; RESTORE_COUNT=$((RESTORE_COUNT + 1)); }
log_fail()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [FAIL]    $*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# 카운터 (02 스크립트용)
DRIFT_COUNT=0
RESTORE_COUNT=0
FAIL_COUNT=0

# ─── 권한 확인 ───────────────────────────────────────────────────
require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "root 권한 필요: sudo $0"
        exit 1
    fi
}

# macOS에서는 root 대신 관리자 권한 확인도 허용
require_privileged() {
    if [[ "$OS_FAMILY" == "macos" ]]; then
        if [[ $EUID -ne 0 ]] && ! groups | grep -q admin; then
            log_error "root 또는 admin 그룹 권한 필요"
            exit 1
        fi
    else
        require_root
    fi
}

# ─── 백업 ────────────────────────────────────────────────────────
BACKUP_DIR="/var/backups/hardening_${TIMESTAMP}"
BASELINE_SNAPSHOT_DIR="/var/backups/hardening_baseline"

# macOS/FreeBSD 경로 보정
if [[ "$OS_FAMILY" == "macos" ]]; then
    BACKUP_DIR="/Library/Caches/hardening_${TIMESTAMP}"
    BASELINE_SNAPSHOT_DIR="/Library/Caches/hardening_baseline"
fi

create_backup_dir() {
    mkdir -p "$BACKUP_DIR"
    log_info "백업 디렉토리: $BACKUP_DIR"
}

backup_file() {
    local src="$1"
    [[ -f "$src" ]] || return 0
    local dest="${BACKUP_DIR}/$(echo "$src" | tr '/' '_')"
    cp -a "$src" "$dest" 2>/dev/null || cp "$src" "$dest"
    log_info "백업: $src -> $dest"
}

# ─── OS 어댑터 로드 ──────────────────────────────────────────────
load_os_adapter() {
    local adapter="${LIB_DIR}/os_${OS_FAMILY}.sh"
    if [[ ! -f "$adapter" ]]; then
        log_error "OS 어댑터 없음: $adapter"
        log_error "지원 OS: debian, rhel, freebsd, macos"
        exit 1
    fi
    # shellcheck source=/dev/null
    source "$adapter"
    log_info "OS 어댑터 로드: $adapter"
}
```

- [ ] **Step 2: 테스트 — OS 감지 함수 단독 실행 검증**

로컬 macOS에서 테스트:
```bash
cd /Users/siotzeut_mini/claude/hardening
bash -c 'source lib/common.sh; detect_os; echo "FAMILY=$OS_FAMILY ID=$OS_ID VER=$OS_VERSION"'
```
Expected: `FAMILY=macos ID=macos VER=<macOS 버전>`

- [ ] **Step 3: 커밋**

```bash
git add lib/common.sh
git commit -m "feat: add common library with OS detection and logging framework"
```

---

### Task 1.2: lib/safety_guards.sh — 안전장치

**Files:**
- Create: `lib/safety_guards.sh`

이 파일은 모든 OS 어댑터에서 호출되는 안전장치 함수들을 포함. 하드닝 함수가 실행되기 전/후에 반드시 호출되어야 함.

- [ ] **Step 1: safety_guards.sh 작성**

```bash
#!/usr/bin/env bash
# lib/safety_guards.sh — 계정/네트워크/gtmon 보호 안전장치
# 의존: lib/common.sh가 먼저 source되어 있어야 함

# ═════════════════════════════════════════════════════════════════
# [G1] 보호 계정 목록
# ═════════════════════════════════════════════════════════════════

# gt 계정: 절대 삭제/변경 금지
readonly PROTECTED_ACCOUNT_GT="gt"

# usr 계정: 삭제 금지, 비밀번호 변경은 가능하되 반드시 출력
readonly PROTECTED_ACCOUNT_USR="usr"

# ═════════════════════════════════════════════════════════════════
# [G1] 계정 보호 — gt
# ═════════════════════════════════════════════════════════════════
# gt 계정이 존재하고 sudo/wheel NOPASSWD 상태인지 확인.
# 하드닝이 이를 해치지 않도록 보장.
guard_account_gt() {
    log_info "[GUARD] gt 계정 보호 확인"

    # gt 계정 존재 확인
    if ! id "$PROTECTED_ACCOUNT_GT" &>/dev/null; then
        log_warn "[GUARD] gt 계정이 존재하지 않음 — 생성하지 않음(원본 유지 원칙)"
        return 0
    fi

    case "$OS_FAMILY" in
        debian|rhel)
            # sudo 그룹 확인 (debian: sudo, rhel: wheel)
            local sudo_group="sudo"
            [[ "$OS_FAMILY" == "rhel" ]] && sudo_group="wheel"

            if ! id -nG "$PROTECTED_ACCOUNT_GT" | grep -qw "$sudo_group"; then
                log_warn "[GUARD] gt가 ${sudo_group} 그룹에 없음 — 추가"
                usermod -aG "$sudo_group" "$PROTECTED_ACCOUNT_GT"
                log_ok "[GUARD] gt -> ${sudo_group} 그룹 추가 완료"
            fi

            # NOPASSWD 확인/보장
            local gt_sudoers="/etc/sudoers.d/00-gt-nopasswd"
            if [[ ! -f "$gt_sudoers" ]] || ! grep -q "NOPASSWD" "$gt_sudoers" 2>/dev/null; then
                echo "${PROTECTED_ACCOUNT_GT} ALL=(ALL) NOPASSWD: ALL" > "$gt_sudoers"
                chmod 0440 "$gt_sudoers"
                if visudo -c -f "$gt_sudoers" 2>/dev/null; then
                    log_ok "[GUARD] gt NOPASSWD sudoers 설정 보장: $gt_sudoers"
                else
                    log_error "[GUARD] gt sudoers 문법 오류 — 수동 확인 필요"
                    rm -f "$gt_sudoers"
                fi
            else
                log_ok "[GUARD] gt NOPASSWD 이미 설정됨"
            fi
            ;;
        freebsd)
            # wheel 그룹 + NOPASSWD
            if ! pw groupshow wheel | grep -qw "$PROTECTED_ACCOUNT_GT" 2>/dev/null; then
                pw groupmod wheel -m "$PROTECTED_ACCOUNT_GT"
                log_ok "[GUARD] gt -> wheel 그룹 추가 (FreeBSD)"
            fi
            local gt_sudoers="/usr/local/etc/sudoers.d/00-gt-nopasswd"
            if [[ ! -f "$gt_sudoers" ]] || ! grep -q "NOPASSWD" "$gt_sudoers" 2>/dev/null; then
                echo "${PROTECTED_ACCOUNT_GT} ALL=(ALL) NOPASSWD: ALL" > "$gt_sudoers"
                chmod 0440 "$gt_sudoers"
                log_ok "[GUARD] gt NOPASSWD sudoers 설정 보장 (FreeBSD)"
            fi
            ;;
        macos)
            # admin 그룹 확인
            if ! dscl . -read /Groups/admin GroupMembership 2>/dev/null | grep -qw "$PROTECTED_ACCOUNT_GT"; then
                dseditgroup -o edit -a "$PROTECTED_ACCOUNT_GT" -t user admin 2>/dev/null || true
                log_ok "[GUARD] gt -> admin 그룹 추가 (macOS)"
            fi
            # macOS sudoers
            local gt_sudoers="/etc/sudoers.d/00-gt-nopasswd"
            if [[ ! -f "$gt_sudoers" ]] || ! grep -q "NOPASSWD" "$gt_sudoers" 2>/dev/null; then
                echo "${PROTECTED_ACCOUNT_GT} ALL=(ALL) NOPASSWD: ALL" > "$gt_sudoers"
                chmod 0440 "$gt_sudoers"
                log_ok "[GUARD] gt NOPASSWD sudoers 설정 보장 (macOS)"
            fi
            ;;
    esac

    log_ok "[GUARD] gt 계정 보호 확인 완료"
}

# ═════════════════════════════════════════════════════════════════
# [G1] 계정 보호 — usr
# ═════════════════════════════════════════════════════════════════
# usr 계정은 삭제 금지. 비밀번호 변경 시 반드시 새 비밀번호를 stdout에 출력.
guard_account_usr() {
    log_info "[GUARD] usr 계정 보호 확인"

    if ! id "$PROTECTED_ACCOUNT_USR" &>/dev/null; then
        log_warn "[GUARD] usr 계정 존재하지 않음"
        return 0
    fi

    log_ok "[GUARD] usr 계정 존재 확인됨 — 삭제 금지 플래그 유지"
}

# usr 비밀번호를 변경하는 유일한 허용된 경로.
# 반드시 이 함수를 통해서만 usr 비밀번호를 변경할 것.
change_usr_password() {
    local new_password="$1"

    if [[ -z "$new_password" ]]; then
        log_error "[GUARD] usr 비밀번호 변경: 새 비밀번호가 비어있음"
        return 1
    fi

    case "$OS_FAMILY" in
        debian|rhel)
            echo "${PROTECTED_ACCOUNT_USR}:${new_password}" | chpasswd
            ;;
        freebsd)
            echo "$new_password" | pw mod user "$PROTECTED_ACCOUNT_USR" -h 0
            ;;
        macos)
            dscl . -passwd "/Users/${PROTECTED_ACCOUNT_USR}" "$new_password"
            ;;
    esac

    log_ok "[GUARD] ========================================"
    log_ok "[GUARD] usr 계정 비밀번호 변경됨"
    log_ok "[GUARD] 새 비밀번호: ${new_password}"
    log_ok "[GUARD] ========================================"
    echo ""
    echo "╔══════════════════════════════════════════╗"
    echo "║  usr 계정 비밀번호 변경됨                ║"
    echo "║  새 비밀번호: ${new_password}"
    echo "╚══════════════════════════════════════════╝"
    echo ""
}

# ═════════════════════════════════════════════════════════════════
# [G2] 네트워크 보호
# ═════════════════════════════════════════════════════════════════

# 방화벽 규칙 적용 전/후에 호출하여 필수 아웃바운드 트래픽이 차단되지 않았는지 확인
guard_network_outbound() {
    log_info "[GUARD] 필수 아웃바운드 포트 허용 확인"

    # 워크스테이션 필수 아웃바운드 포트 (TCP)
    local required_outbound_tcp=(22 80 443 8080 110 995 143 993 21)
    # ICMP ping은 별도 처리

    # 이 포트들은 방화벽에서 아웃바운드 차단되지 않아야 함
    # 반환값: 차단된 포트 목록 (없으면 빈 문자열)
    local blocked_ports=""

    case "$OS_FAMILY" in
        debian)
            if command -v ufw &>/dev/null; then
                local default_out
                default_out=$(ufw status verbose 2>/dev/null | grep "Default:" | grep -oP 'outgoing: \K\w+' || echo "allow")
                if [[ "$default_out" != "allow" ]]; then
                    # outgoing이 deny/reject면 각 포트가 명시적 allow인지 확인
                    for port in "${required_outbound_tcp[@]}"; do
                        if ! ufw status 2>/dev/null | grep -qE "^${port}/tcp.*ALLOW OUT"; then
                            blocked_ports+=" ${port}/tcp"
                        fi
                    done
                fi
            fi
            ;;
        rhel)
            if command -v firewall-cmd &>/dev/null; then
                # firewalld는 기본적으로 outbound를 허용하므로 
                # direct rules로 차단했는지만 확인
                local direct_rules
                direct_rules=$(firewall-cmd --direct --get-all-rules 2>/dev/null || true)
                for port in "${required_outbound_tcp[@]}"; do
                    if echo "$direct_rules" | grep -qE "DROP.*dport ${port}"; then
                        blocked_ports+=" ${port}/tcp"
                    fi
                done
            fi
            ;;
        freebsd)
            # pf.conf에서 block out 규칙 확인
            if [[ -f /etc/pf.conf ]]; then
                for port in "${required_outbound_tcp[@]}"; do
                    if grep -qE "block.*out.*port\s+${port}" /etc/pf.conf 2>/dev/null; then
                        blocked_ports+=" ${port}/tcp"
                    fi
                done
            fi
            ;;
        macos)
            # macOS pf
            if [[ -f /etc/pf.conf ]]; then
                for port in "${required_outbound_tcp[@]}"; do
                    if grep -qE "block.*out.*port\s+${port}" /etc/pf.conf 2>/dev/null; then
                        blocked_ports+=" ${port}/tcp"
                    fi
                done
            fi
            ;;
    esac

    if [[ -n "$blocked_ports" ]]; then
        log_error "[GUARD] 필수 아웃바운드 포트 차단 감지:${blocked_ports}"
        log_error "[GUARD] 이 포트들은 워크스테이션 운영에 필수 — 방화벽 규칙 수정 필요"
        return 1
    fi

    log_ok "[GUARD] 필수 아웃바운드 포트 모두 허용 확인됨"
    return 0
}

# hostname/DNS 변경 금지 검증
guard_dns_unchanged() {
    log_info "[GUARD] DNS 이름 변경 여부 확인"

    local current_hostname
    current_hostname="$(hostname)"

    if [[ "$current_hostname" != "$HOSTNAME_ORIG" ]]; then
        log_error "[GUARD] 호스트명 변경 감지! 원본=${HOSTNAME_ORIG}, 현재=${current_hostname}"
        log_error "[GUARD] 스코어링 엔진이 DNS 이름에 의존 — 복원 필요"
        # 자동 복원
        hostname "$HOSTNAME_ORIG" 2>/dev/null || hostnamectl set-hostname "$HOSTNAME_ORIG" 2>/dev/null || true
        log_ok "[GUARD] 호스트명 복원: ${HOSTNAME_ORIG}"
    else
        log_ok "[GUARD] 호스트명 변경 없음: ${current_hostname}"
    fi
}

# IPv4/IPv6 듀얼스택 보호
guard_ipv6_preserved() {
    log_info "[GUARD] IPv6 서비스 접근성 확인"

    # sysctl에서 IPv6 disable 여부 확인 (Linux only)
    if [[ "$OS_FAMILY" == "debian" || "$OS_FAMILY" == "rhel" ]]; then
        local ipv6_disabled
        ipv6_disabled=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "0")
        if [[ "$ipv6_disabled" == "1" ]]; then
            log_error "[GUARD] IPv6가 비활성화됨 — 원래 IPv6 리스닝 서비스에 접근 불가"
            log_error "[GUARD] 하드닝에서 IPv6를 비활성화하면 안 됨"
            sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
            log_ok "[GUARD] IPv6 재활성화"
        fi
    fi
}

# ═════════════════════════════════════════════════════════════════
# [G3] 그린팀 에이전트(gtmon) 보호
# ═════════════════════════════════════════════════════════════════
guard_gtmon_agent() {
    log_info "[GUARD] gtmon 에이전트 보호 확인"

    local gtmon_binary=""
    local gtmon_service=""

    case "$OS_FAMILY" in
        debian|rhel)
            # 바이너리 확인
            if [[ -f /opt/gtmon ]]; then
                gtmon_binary="/opt/gtmon"
            elif [[ -f /usr/bin/gtmon ]]; then
                gtmon_binary="/usr/bin/gtmon"
            fi
            gtmon_service="gtmon.service"

            if [[ -n "$gtmon_binary" ]]; then
                # 실행 권한 보존 확인
                if [[ ! -x "$gtmon_binary" ]]; then
                    chmod +x "$gtmon_binary"
                    log_warn "[GUARD] gtmon 실행 권한 복원: $gtmon_binary"
                fi
                log_ok "[GUARD] gtmon 바이너리 존재: $gtmon_binary"
            else
                log_warn "[GUARD] gtmon 바이너리 없음 (/opt/gtmon, /usr/bin/gtmon)"
            fi

            # systemd 서비스 확인
            if systemctl list-unit-files "$gtmon_service" &>/dev/null 2>&1; then
                if ! systemctl is-active "$gtmon_service" &>/dev/null; then
                    log_warn "[GUARD] gtmon 서비스 비활성 — 시작"
                    systemctl start "$gtmon_service" 2>/dev/null || true
                fi
                if ! systemctl is-enabled "$gtmon_service" &>/dev/null; then
                    log_warn "[GUARD] gtmon 서비스 자동시작 비활성 — 활성화"
                    systemctl enable "$gtmon_service" 2>/dev/null || true
                fi
                log_ok "[GUARD] gtmon 서비스 확인 완료"
            fi
            ;;

        freebsd)
            if [[ -f /opt/gtmon ]]; then
                gtmon_binary="/opt/gtmon"
            elif [[ -f /usr/bin/gtmon ]]; then
                gtmon_binary="/usr/bin/gtmon"
            fi

            if [[ -n "$gtmon_binary" ]] && [[ ! -x "$gtmon_binary" ]]; then
                chmod +x "$gtmon_binary"
                log_warn "[GUARD] gtmon 실행 권한 복원: $gtmon_binary"
            fi

            # rc 서비스 확인
            if service gtmon status &>/dev/null 2>&1 || [[ -f /usr/local/etc/rc.d/gtmon ]]; then
                if ! service gtmon status 2>/dev/null | grep -qi "running"; then
                    service gtmon start 2>/dev/null || true
                    log_warn "[GUARD] gtmon rc 서비스 시작"
                fi
                # rc.conf에 gtmon_enable 확인
                if ! sysrc -n gtmon_enable 2>/dev/null | grep -qi "YES"; then
                    sysrc gtmon_enable=YES 2>/dev/null || true
                    log_warn "[GUARD] gtmon rc.conf 자동시작 활성화"
                fi
            fi

            # fscd 서비스 헬퍼 보호
            if service fscd status &>/dev/null 2>&1 || [[ -f /usr/local/etc/rc.d/fscd ]]; then
                if ! service fscd status 2>/dev/null | grep -qi "running"; then
                    service fscd start 2>/dev/null || true
                    log_warn "[GUARD] fscd 서비스 헬퍼 시작"
                fi
            fi
            ;;

        macos)
            gtmon_binary="/Users/gt/scoringbot/scoringbot"
            if [[ -f "$gtmon_binary" ]]; then
                if [[ ! -x "$gtmon_binary" ]]; then
                    chmod +x "$gtmon_binary"
                    log_warn "[GUARD] scoringbot 실행 권한 복원"
                fi
                log_ok "[GUARD] scoringbot 바이너리 존재: $gtmon_binary"
            else
                log_warn "[GUARD] scoringbot 바이너리 없음: $gtmon_binary"
            fi

            # launchd plist 확인
            local plist="net.cr14.gtmon"
            if launchctl list 2>/dev/null | grep -q "$plist"; then
                log_ok "[GUARD] gtmon launchd job 활성"
            else
                # plist 파일 찾아서 로드 시도
                local plist_path=""
                for p in /Library/LaunchDaemons/${plist}.plist \
                         /Library/LaunchAgents/${plist}.plist; do
                    [[ -f "$p" ]] && plist_path="$p" && break
                done
                if [[ -n "$plist_path" ]]; then
                    launchctl load -w "$plist_path" 2>/dev/null || true
                    log_warn "[GUARD] gtmon launchd job 재로드: $plist_path"
                else
                    log_warn "[GUARD] gtmon plist 없음"
                fi
            fi
            ;;
    esac
}

# ═════════════════════════════════════════════════════════════════
# [G4] auditd 읽기 전용 보호 (01 스크립트에서 사용)
# ═════════════════════════════════════════════════════════════════
# 01 스크립트에서 auditd 설정을 변경하지 않고 현재 상태만 저장
guard_auditd_snapshot_only() {
    log_info "[GUARD] auditd — 변경 없이 현재 설정 스냅샷만 저장"

    local snapshot_dir="${BASELINE_SNAPSHOT_DIR}"
    mkdir -p "$snapshot_dir"

    # auditd.conf 스냅샷
    if [[ -f /etc/audit/auditd.conf ]]; then
        cp -a /etc/audit/auditd.conf "${snapshot_dir}/auditd_conf_snapshot.txt"
        log_ok "[GUARD] auditd.conf 스냅샷 저장"
    else
        log_warn "[GUARD] /etc/audit/auditd.conf 없음"
    fi

    # audit rules 스냅샷
    if command -v auditctl &>/dev/null; then
        auditctl -l 2>/dev/null > "${snapshot_dir}/audit_rules_snapshot.txt" || true
        log_ok "[GUARD] auditd 규칙 스냅샷 저장"
    fi

    # rules.d 디렉토리 스냅샷
    if [[ -d /etc/audit/rules.d ]]; then
        mkdir -p "${snapshot_dir}/audit_rules_d"
        cp -a /etc/audit/rules.d/* "${snapshot_dir}/audit_rules_d/" 2>/dev/null || true
        log_ok "[GUARD] audit rules.d 스냅샷 저장"
    fi

    # auditd 서비스 상태
    if command -v systemctl &>/dev/null; then
        systemctl is-active auditd 2>/dev/null > "${snapshot_dir}/auditd_service_status.txt" || true
    fi
}

# ═════════════════════════════════════════════════════════════════
# [통합] 모든 가드를 한 번에 실행
# ═════════════════════════════════════════════════════════════════
run_all_guards() {
    log_info "======== 안전장치 점검 시작 ========"
    guard_account_gt
    guard_account_usr
    guard_gtmon_agent
    guard_dns_unchanged
    guard_ipv6_preserved
    guard_network_outbound || log_warn "[GUARD] 아웃바운드 포트 문제 — 방화벽 설정 후 재확인 필요"
    log_info "======== 안전장치 점검 완료 ========"
}

# ═════════════════════════════════════════════════════════════════
# [헬퍼] 계정 삭제/변경 전 보호 계정 확인
# ═════════════════════════════════════════════════════════════════
# 계정을 삭제/잠금/셸변경하려는 모든 함수에서 이것을 먼저 호출
is_protected_account() {
    local account="$1"
    case "$account" in
        "$PROTECTED_ACCOUNT_GT")
            log_warn "[GUARD] gt 계정은 보호 대상 — 작업 차단"
            return 0  # true = protected
            ;;
        "$PROTECTED_ACCOUNT_USR")
            log_warn "[GUARD] usr 계정은 삭제 금지 대상"
            return 0
            ;;
    esac
    return 1  # not protected
}

# 서비스 비활성화 전 gtmon 관련 서비스인지 확인
is_protected_service() {
    local service="$1"
    case "$service" in
        gtmon.service|gtmon|fscd|net.cr14.gtmon*)
            log_warn "[GUARD] ${service}는 그린팀 에이전트 서비스 — 비활성화 차단"
            return 0
            ;;
    esac
    return 1
}

# 방화벽 규칙 추가 전 gtmon 필수 포트 차단 여부 확인
is_gtmon_required_port() {
    local port="$1"
    local direction="${2:-out}"  # in or out

    if [[ "$direction" == "out" ]]; then
        case "$port" in
            80|443|22)
                return 0  # gtmon 필수 아웃바운드 포트
                ;;
        esac
    fi
    return 1
}
```

- [ ] **Step 2: 테스트 — safety_guards 함수 로드 확인**

```bash
cd /Users/siotzeut_mini/claude/hardening
bash -c '
source lib/common.sh
detect_os
source lib/safety_guards.sh
# is_protected_account 테스트
if is_protected_account "gt"; then echo "PASS: gt is protected"; fi
if is_protected_account "usr"; then echo "PASS: usr is protected"; fi
if ! is_protected_account "randomuser"; then echo "PASS: randomuser is not protected"; fi
'
```
Expected: 3개 PASS 출력

- [ ] **Step 3: 커밋**

```bash
git add lib/safety_guards.sh
git commit -m "feat: add safety guards for protected accounts, network, and gtmon agent"
```

---

## Phase 2: Debian/Ubuntu 어댑터 리팩터링

### Task 2.1: lib/os_debian.sh — 기존 로직 어댑터화

**Files:**
- Create: `lib/os_debian.sh`
- Reference: `01_baseline_hardening_v3.sh` (기존 전체 로직)

기존 v3의 Debian 전용 함수들을 어댑터 인터페이스로 감싸되, 다음 핵심 변경 적용:

1. **모든 계정 조작 함수**: `is_protected_account()` 체크 추가
2. **모든 서비스 조작 함수**: `is_protected_service()` 체크 추가
3. **UFW 설정**: 필수 아웃바운드 포트 보장 + IPv6 유지
4. **sudoers 변경**: gt의 NOPASSWD 보존
5. **auditd**: 01에서는 스냅샷만, 02에서 diff/복원

- [ ] **Step 1: os_debian.sh 기본 구조 작성**

```bash
#!/usr/bin/env bash
# lib/os_debian.sh — Debian/Ubuntu 하드닝 어댑터
# 의존: lib/common.sh, lib/safety_guards.sh

# ─── 패키지 관리 ─────────────────────────────────────────────────
pkg_install() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y "$@"
}

pkg_remove() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get purge -y "$@"
    apt-get autoremove -y
}

pkg_is_installed() {
    dpkg -s "$1" &>/dev/null
}

# ─── 서비스 관리 ─────────────────────────────────────────────────
svc_enable() {
    local svc="$1"
    if is_protected_service "$svc"; then return 0; fi
    systemctl enable "$svc" 2>/dev/null
}

svc_disable() {
    local svc="$1"
    if is_protected_service "$svc"; then return 0; fi
    systemctl disable --now "$svc" 2>/dev/null
}

svc_start() {
    systemctl start "$1" 2>/dev/null
}

svc_restart() {
    systemctl restart "$1" 2>/dev/null
}

svc_is_active() {
    systemctl is-active "$1" &>/dev/null
}

svc_is_enabled() {
    systemctl is-enabled "$1" &>/dev/null
}

# ─── 방화벽 ──────────────────────────────────────────────────────
# (기존 setup_ufw 로직 + 안전장치)

# ─── sysctl ──────────────────────────────────────────────────────
# IPv6를 disable하지 않도록 주의
# net.ipv6.conf.all.disable_ipv6는 절대 1로 설정하지 않음

# ... (각 하드닝 함수를 어댑터 인터페이스로 구현)
```

**주요 변경사항 (v3 대비):**

- [ ] **Step 2: 계정 관련 함수에 보호 계정 체크 추가**

기존 `setup_nologin_accounts()`, `setup_lock_empty_password()`, `check_login_accounts()` 등에서:

```bash
# 기존 v3 코드 (위험):
# for acct in "${NOLOGIN_ACCOUNTS[@]}"; do
#     chsh -s /usr/sbin/nologin "$acct"
# done

# 신규 v4 코드 (안전):
setup_nologin_accounts() {
    log_info "===== 시스템 계정 nologin 설정 ====="
    for acct in "${NOLOGIN_ACCOUNTS[@]}"; do
        # 보호 계정 체크
        if is_protected_account "$acct"; then
            log_skip "[GUARD] ${acct} — 보호 계정, 건너뜀"
            continue
        fi
        if id "$acct" &>/dev/null; then
            local current_shell
            current_shell=$(getent passwd "$acct" | cut -d: -f7)
            if [[ "$current_shell" != "/usr/sbin/nologin" ]]; then
                chsh -s /usr/sbin/nologin "$acct" 2>/dev/null && \
                    log_ok "${acct} -> /usr/sbin/nologin" || \
                    log_warn "${acct} 셸 변경 실패"
            fi
        fi
    done
}
```

- [ ] **Step 3: sudoers 함수에서 gt NOPASSWD 보존**

```bash
# 기존 v3 (위험 — gt의 NOPASSWD까지 제거):
# sed -i 's/NOPASSWD://g' "$f" 2>/dev/null

# 신규 v4 (안전):
setup_sudoers() {
    log_info "===== sudoers NOPASSWD 제거 (gt 제외) ====="
    if [[ -f /etc/sudoers ]]; then
        backup_file "/etc/sudoers"
        # gt 라인을 제외하고 NOPASSWD 제거
        # %sudo, %wheel 등 그룹 라인의 NOPASSWD 제거
        sed -i '/^'"${PROTECTED_ACCOUNT_GT}"'/!s/^\(%sudo[[:space:]]\+ALL=(ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/' /etc/sudoers
        sed -i '/^'"${PROTECTED_ACCOUNT_GT}"'/!s/^\(%sudo[[:space:]]\+ALL=(ALL:ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/' /etc/sudoers
        # 일반 사용자의 NOPASSWD 제거 (gt 제외)
        sed -i '/^'"${PROTECTED_ACCOUNT_GT}"'/!s/^\([^%#][[:alnum:]_.-]\+[[:space:]]\+ALL=(ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/' /etc/sudoers
        if visudo -c 2>/dev/null; then
            log_ok "sudoers NOPASSWD 제거 완료 (gt 제외, 문법 검증 통과)"
        else
            log_error "sudoers 문법 오류! 백업에서 복원"
            cp "${BACKUP_DIR}/_etc_sudoers" /etc/sudoers 2>/dev/null || true
        fi
    fi

    # sudoers.d 파일들 처리 (gt 전용 파일 제외)
    if [[ -d /etc/sudoers.d ]]; then
        local nopasswd_files
        nopasswd_files=$(grep -rl 'NOPASSWD' /etc/sudoers.d/ 2>/dev/null || true)
        if [[ -n "$nopasswd_files" ]]; then
            while IFS= read -r f; do
                # gt 전용 sudoers 파일은 건너뜀
                if [[ "$(basename "$f")" == "00-gt-nopasswd" ]]; then
                    log_skip "[GUARD] gt NOPASSWD 파일 보존: $f"
                    continue
                fi
                # 파일 내에 gt 계정 라인이 있으면 그 라인만 보존
                backup_file "$f"
                local gt_line
                gt_line=$(grep "^${PROTECTED_ACCOUNT_GT}" "$f" 2>/dev/null || true)
                sed -i '/^'"${PROTECTED_ACCOUNT_GT}"'/!s/NOPASSWD://g' "$f" 2>/dev/null
                log_ok "sudoers.d NOPASSWD 제거 (gt 제외): $f"
            done <<< "$nopasswd_files"
        fi
    fi

    # gt NOPASSWD 재확인 (guard가 보장)
    guard_account_gt
}
```

- [ ] **Step 4: UFW 설정에서 필수 아웃바운드 포트 보장**

```bash
setup_ufw() {
    log_info "===== UFW 방화벽 설정 ====="

    # (기존 UFW 설정 로직 유지)
    # ...

    # ★ 추가: 필수 아웃바운드 포트 보장
    # 아웃바운드 기본 정책이 allow이면 별도 조치 불필요
    # deny일 경우 필수 포트 명시적 허용
    local outgoing_policy
    outgoing_policy=$(grep 'DEFAULT_OUTPUT_POLICY' /etc/default/ufw 2>/dev/null | cut -d'"' -f2 || echo "ACCEPT")

    if [[ "$outgoing_policy" != "ACCEPT" ]]; then
        log_info "아웃바운드 정책이 ${outgoing_policy} — 필수 포트 명시적 허용"
        local required_out_ports=(22 80 443 8080 110 995 143 993 21)
        for port in "${required_out_ports[@]}"; do
            ufw allow out "${port}/tcp" 2>/dev/null || true
        done
        # ICMP ping 허용
        # (after.rules에서 echo-request 차단하는 규칙 제거 필요!)
        log_ok "필수 아웃바운드 포트 허용 완료"
    fi

    # ★ 추가: gtmon 아웃바운드 포트 보장 (80, 443, 22)
    # 이미 위에서 처리되지만, 명시적으로 한번 더 확인
    guard_network_outbound || log_warn "아웃바운드 포트 문제 감지"

    # ★ 수정: ICMP echo-request 아웃바운드 차단 제거
    # 기존 v3는 서버→외부 ping을 차단했으나,
    # 워크스테이션은 ICMP ping을 사용할 수 있어야 함
    # after.rules에서 TUNNEL_ICMP_ECHO_OUT 규칙을 조건부로만 적용

    # (나머지 기존 터널링 방어 로직 유지)
}
```

- [ ] **Step 5: auditd — 01에서 설정 변경 대신 스냅샷만 저장**

```bash
# 기존 v3의 setup_auditd() 는 auditd.conf를 직접 수정했음
# v4에서는 01 스크립트에서 스냅샷만 저장

setup_auditd() {
    log_info "===== auditd 설정 스냅샷 저장 (변경 없음) ====="

    # auditd 설치 확인 (미설치 시 설치는 수행)
    if ! command -v auditd >/dev/null 2>&1; then
        log_info "auditd 설치 중..."
        pkg_install auditd || { log_error "auditd 설치 실패"; return 0; }
        log_ok "auditd 설치 완료"
    fi

    # 기존 설정을 변경하지 않고 스냅샷만 저장
    guard_auditd_snapshot_only

    log_ok "auditd 설정 스냅샷 저장 완료 (설정 변경 없음)"
}
```

- [ ] **Step 6: 02 스크립트의 auditd 점검 — diff 기반 복원**

```bash
# 02 스크립트에서 사용하는 auditd 점검 함수
check_auditd() {
    log_info "===== auditd 상태 점검 (diff 기반) ====="

    if ! command -v auditctl >/dev/null 2>&1; then
        log_warn "auditctl 없음"
        return
    fi

    # 서비스 활성 상태 확인
    if ! svc_is_active auditd; then
        log_drift "auditd 서비스 비활성!"
        if [[ "$MODE" == "auto-restore" ]]; then
            svc_start auditd && log_restore "auditd 재시작" || log_fail "auditd 재시작 실패"
        fi
    else
        log_ok "auditd 서비스 활성"
    fi

    # auditd.conf diff 확인
    local conf_snapshot="${BASELINE_DIR}/auditd_conf_snapshot.txt"
    if [[ -f "$conf_snapshot" ]] && [[ -f /etc/audit/auditd.conf ]]; then
        if ! diff -q "$conf_snapshot" /etc/audit/auditd.conf >/dev/null 2>&1; then
            log_drift "auditd.conf 변경 감지!"
            if [[ "$MODE" == "auto-restore" ]]; then
                backup_before_restore /etc/audit/auditd.conf
                cp "$conf_snapshot" /etc/audit/auditd.conf
                svc_restart auditd && \
                    log_restore "auditd.conf 베이스라인에서 복원" || \
                    log_fail "auditd.conf 복원 후 재시작 실패"
            fi
        else
            log_ok "auditd.conf 변경 없음"
        fi
    fi

    # audit rules diff 확인
    local rules_snapshot="${BASELINE_DIR}/audit_rules_snapshot.txt"
    if [[ -f "$rules_snapshot" ]]; then
        local current_rules
        current_rules=$(auditctl -l 2>/dev/null || true)
        local snapshot_rules
        snapshot_rules=$(cat "$rules_snapshot")

        if [[ "$current_rules" != "$snapshot_rules" ]]; then
            log_drift "auditd 규칙 변경 감지!"
            if [[ "$MODE" == "auto-restore" ]]; then
                # rules.d에서 복원
                local rules_d_snapshot="${BASELINE_DIR}/audit_rules_d"
                if [[ -d "$rules_d_snapshot" ]]; then
                    cp -a "$rules_d_snapshot"/* /etc/audit/rules.d/ 2>/dev/null || true
                    augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/99-hardening.rules 2>/dev/null || true
                    log_restore "auditd 규칙 베이스라인에서 복원"
                else
                    log_fail "auditd rules.d 스냅샷 없음 — 복원 불가"
                fi
            fi
        else
            log_ok "auditd 규칙 변경 없음"
        fi
    fi
}
```

- [ ] **Step 7: 전체 os_debian.sh를 완성하여 작성**

나머지 기존 v3 함수들을 모두 어댑터 형식으로 포팅. 각 함수에서:
- `is_protected_account()` 체크 삽입
- `is_protected_service()` 체크 삽입
- IPv6 보존 확인
- 아웃바운드 포트 보존 확인

- [ ] **Step 8: 커밋**

```bash
git add lib/os_debian.sh
git commit -m "feat: refactor Debian/Ubuntu hardening into adapter pattern with safety guards"
```

---

### Task 2.2: 오케스트레이터 스크립트 (01, 02) 리팩터링

**Files:**
- Create: `01_baseline_hardening.sh` (v4)
- Create: `02_check_and_restore.sh` (v4)

- [ ] **Step 1: 01_baseline_hardening.sh v4 오케스트레이터 작성**

```bash
#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# 베이스라인 하드닝 스크립트 v4 (멀티 OS)
#
# 지원 OS: Debian/Ubuntu, RHEL/Rocky/AlmaLinux, FreeBSD, macOS
# 사용법:  sudo bash 01_baseline_hardening.sh [OPTIONS]
#
# OPTIONS:
#   --check        터널링 방어 현황만 점검
#   --profile=X    UFW/방화벽 프로파일 (base|web|ad|log|full)
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 공통 라이브러리 로드
source "${SCRIPT_DIR}/lib/common.sh"

# OS 감지
detect_os

# 안전장치 로드
source "${SCRIPT_DIR}/lib/safety_guards.sh"

# OS 어댑터 로드
load_os_adapter

# ─── 메인 ────────────────────────────────────────────────────────
main() {
    local mode="${1:-harden}"

    if [[ "$mode" == "--check" ]]; then
        require_root
        check_tunnel_status  # 어댑터에서 구현
        exit 0
    fi

    # 설정 파일 로그 디렉토리
    LOGFILE="${_LOG_DIR}/${TIMESTAMP}_${HOSTNAME_ORIG}_baseline_hardening.log"

    log_info "============================================================"
    log_info "베이스라인 하드닝 시작: 호스트=${HOSTNAME_ORIG}, OS=${OS_FAMILY}/${OS_ID}"
    log_info "로그: ${LOGFILE}"
    log_info "============================================================"

    require_privileged
    create_backup_dir

    # ★ 사전 안전장치 점검
    run_all_guards

    # ★ auditd: 설정 변경 없이 스냅샷만 저장 (C4 요구사항)
    guard_auditd_snapshot_only

    # OS별 하드닝 실행 (어댑터의 run_hardening 함수)
    run_hardening

    # ★ 사후 안전장치 재확인
    run_all_guards

    # 베이스라인 스냅샷 생성 (어댑터의 create_baseline_snapshot 함수)
    create_baseline_snapshot

    log_info "============================================================"
    log_info "베이스라인 하드닝 완료"
    log_info "백업: ${BACKUP_DIR}"
    log_info "스냅샷: ${BASELINE_SNAPSHOT_DIR}"
    log_info "로그: ${LOGFILE}"
    log_info "============================================================"

    # 다른 SSH 세션 종료 (Linux/FreeBSD만)
    if [[ "$OS_FAMILY" != "macos" ]]; then
        kill_other_ssh_sessions  # 어댑터에서 구현
    fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@" 2>&1 | tee -a "${LOGFILE:-/tmp/hardening_${TIMESTAMP}.log}"
fi
```

- [ ] **Step 2: 02_check_and_restore.sh v4 오케스트레이터 작성**

```bash
#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# 점검/복원 스크립트 v4 (멀티 OS)
#
# 동작 모드:
#   --check-only   : 점검만 수행 (기본값)
#   --auto-restore : 변경 자동 복원
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "${SCRIPT_DIR}/lib/common.sh"
detect_os
source "${SCRIPT_DIR}/lib/safety_guards.sh"
load_os_adapter

# 동작 모드
MODE="check-only"
[[ "${1:-}" == "--auto-restore" ]] && MODE="auto-restore"

LOGFILE="${_LOG_DIR}/${TIMESTAMP}_${HOSTNAME_ORIG}_check_result.log"

main() {
    log_info "============================================================"
    log_info "베이스라인 점검 시작: 호스트=${HOSTNAME_ORIG}, 모드=${MODE}, OS=${OS_FAMILY}"
    log_info "============================================================"

    require_privileged

    if [[ ! -d "$BASELINE_SNAPSHOT_DIR" ]]; then
        log_error "베이스라인 스냅샷 없음: $BASELINE_SNAPSHOT_DIR"
        log_error "먼저 01_baseline_hardening.sh를 실행하세요."
        exit 1
    fi

    # ★ 안전장치 점검 (매 실행마다)
    run_all_guards

    # OS별 점검 실행 (어댑터의 run_checks 함수)
    run_checks

    # ★ auditd diff 확인 및 복원 (C4 요구사항)
    check_auditd

    # ★ 사후 안전장치 재확인
    run_all_guards

    # 정리 및 리포트
    cleanup_old_backups
    send_alert
    print_summary
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@" 2>&1 | tee -a "$LOGFILE"
fi
```

- [ ] **Step 3: 커밋**

```bash
git add 01_baseline_hardening.sh 02_check_and_restore.sh
git commit -m "feat: add v4 multi-OS orchestrator scripts"
```

---

## Phase 3: RHEL/Rocky/AlmaLinux 어댑터

### Task 3.1: lib/os_rhel.sh

**Files:**
- Create: `lib/os_rhel.sh`

Debian 어댑터와 동일한 인터페이스를 RHEL 계열로 구현. 주요 차이점:

| 항목 | Debian | RHEL |
|------|--------|------|
| 패키지 관리 | apt | dnf/yum |
| 방화벽 | ufw | firewalld |
| sudo 그룹 | sudo | wheel |
| PAM 패스워드 | passwdqc + pam-auth-update | pwquality + authselect |
| SELinux | N/A | 고려 필요 (설정 변경 시 context 유지) |
| 네트워크 설정 | /etc/network/ 또는 netplan | NetworkManager (/etc/sysconfig/network-scripts/) |
| 서비스 관리 | systemd | systemd (동일) |

- [ ] **Step 1: os_rhel.sh 패키지/서비스 기본 함수 작성**

```bash
#!/usr/bin/env bash
# lib/os_rhel.sh — RHEL/Rocky/AlmaLinux 하드닝 어댑터

# ─── 패키지 관리 ─────────────────────────────────────────────────
pkg_install() {
    if command -v dnf &>/dev/null; then
        dnf install -y "$@"
    else
        yum install -y "$@"
    fi
}

pkg_remove() {
    if command -v dnf &>/dev/null; then
        dnf remove -y "$@"
    else
        yum remove -y "$@"
    fi
}

pkg_is_installed() {
    rpm -q "$1" &>/dev/null
}

# ─── 서비스 관리 (systemd — Debian과 동일) ────────────────────────
svc_enable()     { is_protected_service "$1" && return 0; systemctl enable "$1" 2>/dev/null; }
svc_disable()    { is_protected_service "$1" && return 0; systemctl disable --now "$1" 2>/dev/null; }
svc_start()      { systemctl start "$1" 2>/dev/null; }
svc_restart()    { systemctl restart "$1" 2>/dev/null; }
svc_is_active()  { systemctl is-active "$1" &>/dev/null; }
svc_is_enabled() { systemctl is-enabled "$1" &>/dev/null; }
```

- [ ] **Step 2: firewalld 기반 방화벽 설정**

```bash
# ─── 방화벽 (firewalld) ─────────────────────────────────────────
setup_firewall() {
    log_info "===== firewalld 방화벽 설정 ====="

    if ! command -v firewall-cmd &>/dev/null; then
        log_info "firewalld 설치 중..."
        pkg_install firewalld || { log_error "firewalld 설치 실패"; return 0; }
    fi

    systemctl enable --now firewalld 2>/dev/null

    # 기본 정책: 인바운드 drop (public zone)
    firewall-cmd --set-default-zone=public 2>/dev/null || true

    # 프로파일별 포트 허용
    local profile_ports="${UFW_PROFILE:-base}"
    declare -A FIREWALLD_PROFILES=(
        [base]="22/tcp"
        [web]="22/tcp 80/tcp 443/tcp"
        [ad]="22/tcp 53/tcp 53/udp 88/tcp 389/tcp 389/udp 636/tcp 3268/tcp 3269/tcp"
        [log]="22/tcp 514/udp 1514/tcp 1515/tcp 1516/tcp"
    )

    local ports="${FIREWALLD_PROFILES[$profile_ports]:-${FIREWALLD_PROFILES[base]}}"
    for port_proto in $ports; do
        firewall-cmd --permanent --add-port="$port_proto" 2>/dev/null || true
        log_ok "firewalld allow: $port_proto"
    done

    # ★ 아웃바운드는 firewalld 기본적으로 허용이므로 별도 처리 불필요
    # ★ 단, direct rules로 차단하지 않도록 주의

    firewall-cmd --reload 2>/dev/null || true
    log_ok "firewalld 설정 완료"

    # 안전장치 확인
    guard_network_outbound || log_warn "아웃바운드 포트 문제"
}
```

- [ ] **Step 3: PAM 설정 (pwquality + authselect)**

```bash
setup_pam() {
    log_info "===== PAM 패스워드 정책 (pwquality) ====="

    if ! pkg_is_installed "libpwquality"; then
        pkg_install libpwquality || { log_warn "libpwquality 설치 실패"; return 0; }
    fi

    local pwquality_conf="/etc/security/pwquality.conf"
    backup_file "$pwquality_conf"

    cat > "$pwquality_conf" <<'EOF'
# 하드닝 자동 생성 — 패스워드 품질 정책
minlen = 8
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
minclass = 3
maxrepeat = 3
maxclassrepeat = 0
EOF
    chmod 0644 "$pwquality_conf"
    log_ok "pwquality.conf 설정 완료"

    # authselect 사용 (RHEL 8+)
    if command -v authselect &>/dev/null; then
        authselect select sssd with-faillock --force 2>/dev/null || \
        authselect select minimal with-faillock --force 2>/dev/null || \
            log_warn "authselect 설정 실패 — 수동 확인 필요"
        log_ok "authselect faillock 프로파일 적용"
    fi
}
```

- [ ] **Step 4: nologin 경로 차이 처리**

```bash
# RHEL에서는 nologin 경로가 다를 수 있음
get_nologin_path() {
    if [[ -f /usr/sbin/nologin ]]; then
        echo "/usr/sbin/nologin"
    elif [[ -f /sbin/nologin ]]; then
        echo "/sbin/nologin"
    else
        echo "/bin/false"
    fi
}

setup_nologin_accounts() {
    log_info "===== 시스템 계정 nologin 설정 ====="
    local nologin_path
    nologin_path=$(get_nologin_path)

    # RHEL 시스템 계정 목록 (Debian과 다소 다름)
    local rhel_system_accounts=(
        bin daemon adm lp sync shutdown halt mail
        operator games ftp nobody systemd-network
        dbus polkitd sshd postfix chrony
        tcpdump tss unbound rpc rpcuser nfsnobody
    )

    for acct in "${rhel_system_accounts[@]}"; do
        if is_protected_account "$acct"; then
            log_skip "[GUARD] ${acct} — 보호 계정"
            continue
        fi
        if id "$acct" &>/dev/null; then
            local current_shell
            current_shell=$(getent passwd "$acct" | cut -d: -f7)
            if [[ "$current_shell" != "$nologin_path" && "$current_shell" != "/bin/false" ]]; then
                usermod -s "$nologin_path" "$acct" 2>/dev/null && \
                    log_ok "${acct} -> ${nologin_path}" || \
                    log_warn "${acct} 셸 변경 실패"
            fi
        fi
    done
}
```

- [ ] **Step 5: run_hardening / run_checks / create_baseline_snapshot 구현**

```bash
# 오케스트레이터가 호출하는 메인 함수
run_hardening() {
    setup_pam
    setup_firewall
    setup_cron_permissions
    setup_modprobe
    setup_sysctl
    setup_proc_hidepid
    setup_sensitive_file_permissions
    setup_other_permission_removal
    setup_nologin_accounts
    setup_sudoers          # gt NOPASSWD 보존
    setup_suid_removal
    setup_disable_services
    setup_lock_empty_password
    setup_ssh_hardening
    setup_login_defs
    setup_pam_faillock
    setup_tmp_mount_hardening
    setup_core_dump_limits
    setup_umask
    setup_banner
    setup_tunnel_hardening
}

run_checks() {
    check_sysctl
    check_file_permissions
    check_suid_files
    check_disabled_services
    check_login_accounts
    check_firewall          # firewalld 점검
    check_sudoers
    check_empty_passwords
    check_suspicious_files
    check_pam_policy
    check_cron_permissions
    check_modprobe_blacklist
    check_proc_hidepid
    check_ssh_config
    check_malicious_cron
    check_network
    check_suspicious_processes
    check_uid0_accounts
    check_login_defs
    check_tunnel_defense
}

create_baseline_snapshot() {
    # Debian과 유사하지만 rpm -qa, firewall-cmd 사용
    log_info "===== 베이스라인 스냅샷 생성 ====="
    mkdir -p "${BASELINE_SNAPSHOT_DIR}"

    rpm -qa --queryformat '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | sort \
        > "${BASELINE_SNAPSHOT_DIR}/packages_baseline.txt" || true

    firewall-cmd --list-all 2>/dev/null \
        > "${BASELINE_SNAPSHOT_DIR}/firewall_baseline.txt" || true

    # (나머지 스냅샷은 Debian과 동일한 로직)
    # ... sysctl, passwd, sshd, audit 등
}
```

- [ ] **Step 6: 커밋**

```bash
git add lib/os_rhel.sh
git commit -m "feat: add RHEL/Rocky/AlmaLinux hardening adapter"
```

---

## Phase 4: FreeBSD 어댑터

### Task 4.1: lib/os_freebsd.sh

**Files:**
- Create: `lib/os_freebsd.sh`

FreeBSD 주요 차이점:

| 항목 | Linux | FreeBSD |
|------|-------|---------|
| 패키지 관리 | apt/dnf | pkg |
| 방화벽 | ufw/firewalld | pf (packet filter) 또는 ipfw |
| 서비스 관리 | systemd | rc.d (service/sysrc) |
| 사용자 관리 | useradd/usermod | pw |
| sudo 그룹 | sudo/wheel | wheel |
| PAM | /etc/pam.d/ | /etc/pam.d/ (유사하나 모듈 경로 다름) |
| 감사 | auditd | auditd (FreeBSD audit도 있음) |
| sysctl | /etc/sysctl.d/ | /etc/sysctl.conf |
| 경로 | /usr/sbin/nologin | /usr/sbin/nologin |
| sudoers | /etc/sudoers.d/ | /usr/local/etc/sudoers.d/ |
| gtmon | gtmon.service | rc gtmon + fscd |

- [ ] **Step 1: os_freebsd.sh 기본 구조**

```bash
#!/usr/bin/env bash
# lib/os_freebsd.sh — FreeBSD 하드닝 어댑터

# ─── 패키지 관리 ─────────────────────────────────────────────────
pkg_install()      { pkg install -y "$@"; }
pkg_remove()       { pkg delete -y "$@"; }
pkg_is_installed() { pkg info "$1" &>/dev/null; }

# ─── 서비스 관리 (rc.d) ─────────────────────────────────────────
svc_enable() {
    local svc="$1"
    is_protected_service "$svc" && return 0
    sysrc "${svc}_enable=YES" 2>/dev/null
}

svc_disable() {
    local svc="$1"
    is_protected_service "$svc" && return 0
    sysrc "${svc}_enable=NO" 2>/dev/null
    service "$svc" stop 2>/dev/null || true
}

svc_start()      { service "$1" start 2>/dev/null; }
svc_restart()    { service "$1" restart 2>/dev/null; }
svc_is_active()  { service "$1" status &>/dev/null; }
svc_is_enabled() { sysrc -n "${1}_enable" 2>/dev/null | grep -qi "YES"; }
```

- [ ] **Step 2: pf 방화벽 설정**

```bash
setup_firewall() {
    log_info "===== pf 방화벽 설정 ====="

    local pf_conf="/etc/pf.conf"
    backup_file "$pf_conf"

    # 현재 리스닝 중인 서비스 포트 감지 (IPv4+IPv6)
    local listening_ports
    listening_ports=$(sockstat -l -4 -6 2>/dev/null | awk 'NR>1 {print $6}' | \
                      grep -oP ':\K[0-9]+$' | sort -un || true)

    # 프로파일별 인바운드 허용 포트
    local profile="${UFW_PROFILE:-base}"
    local allow_ports="22"
    case "$profile" in
        web) allow_ports="22 80 443" ;;
        ad)  allow_ports="22 53 88 389 636 3268 3269" ;;
        log) allow_ports="22 514 1514 1515 1516" ;;
        full) allow_ports="22 53 80 88 389 443 514 636 953 1514 1515 1516 3268 3269" ;;
    esac

    cat > "$pf_conf" <<PFEOF
# pf.conf — 하드닝 자동 생성 ($(date '+%Y-%m-%d %H:%M:%S'))

# 매크로
allowed_tcp_in = "{ ${allow_ports} }"

# 옵션
set skip on lo0
set block-policy drop
set state-policy if-bound

# 기본 정책
block in all
pass out all keep state

# 인바운드 허용
pass in proto tcp to port \$allowed_tcp_in keep state

# ICMP 허용 (gtmon + 워크스테이션 요구사항)
pass in  proto icmp all
pass out proto icmp all

# ICMPv6 (NDP 등 필수)
pass in  proto icmp6 all
pass out proto icmp6 all

# ★ gtmon 아웃바운드 필수 포트 (이미 pass out all이지만 명시적 보장)
# pass out proto tcp to port { 22 80 443 }
PFEOF

    # pf 활성화
    sysrc pf_enable=YES 2>/dev/null
    if service pf reload 2>/dev/null || pfctl -f "$pf_conf" 2>/dev/null; then
        log_ok "pf 방화벽 설정 및 로드 완료"
    else
        log_warn "pf 로드 실패 — 수동 확인 필요"
    fi

    guard_network_outbound || log_warn "아웃바운드 포트 문제"
}
```

- [ ] **Step 3: FreeBSD sysctl (파일 구조 차이)**

```bash
setup_sysctl() {
    log_info "===== sysctl 커널 보안 설정 ====="

    # FreeBSD sysctl은 /etc/sysctl.conf 단일 파일
    local sysctl_conf="/etc/sysctl.conf"
    backup_file "$sysctl_conf"

    # FreeBSD 전용 sysctl 설정
    declare -A SYSCTL_SETTINGS=(
        ["security.bsd.see_other_uids"]="0"
        ["security.bsd.see_other_gids"]="0"
        ["security.bsd.unprivileged_read_msgbuf"]="0"
        ["security.bsd.unprivileged_proc_debug"]="0"
        ["security.bsd.stack_guard_page"]="1"
        ["kern.randompid"]="1"
        ["net.inet.tcp.blackhole"]="2"
        ["net.inet.udp.blackhole"]="1"
        ["net.inet.icmp.drop_redirect"]="1"
        ["net.inet.tcp.drop_synfin"]="1"
        ["net.inet.ip.random_id"]="1"
        ["net.inet.ip.redirect"]="0"
        ["net.inet6.ip6.redirect"]="0"
        # ★ IPv6 비활성화 금지
        # ["net.inet6.ip6.accept_rtadv"]="0"  # RA는 비활성화 가능
    )

    {
        echo "# 보안 하드닝 sysctl 설정 (자동 생성)"
        for key in "${!SYSCTL_SETTINGS[@]}"; do
            echo "${key}=${SYSCTL_SETTINGS[$key]}"
        done
    } > "$sysctl_conf"

    for key in "${!SYSCTL_SETTINGS[@]}"; do
        sysctl "${key}=${SYSCTL_SETTINGS[$key]}" >/dev/null 2>&1 || \
            log_warn "sysctl ${key} 설정 실패"
    done

    log_ok "sysctl 설정 완료"
}
```

- [ ] **Step 4: FreeBSD 사용자 관리 (pw 명령)**

```bash
setup_nologin_accounts() {
    log_info "===== 시스템 계정 nologin 설정 ====="

    local freebsd_system_accounts=(
        bin tty kmem games news man
        operator sshd smmsp mailnull bind
        unbound proxy _pflogd _dhcp _ntp
        auditdistd hast
    )

    for acct in "${freebsd_system_accounts[@]}"; do
        if is_protected_account "$acct"; then
            log_skip "[GUARD] ${acct} — 보호 계정"
            continue
        fi
        if pw usershow "$acct" &>/dev/null; then
            local current_shell
            current_shell=$(pw usershow "$acct" -7 2>/dev/null)
            if [[ "$current_shell" != "/usr/sbin/nologin" ]]; then
                pw usermod "$acct" -s /usr/sbin/nologin 2>/dev/null && \
                    log_ok "${acct} -> nologin" || \
                    log_warn "${acct} 셸 변경 실패"
            fi
        fi
    done
}

setup_sudoers() {
    log_info "===== sudoers NOPASSWD 제거 (gt 제외) ====="

    # FreeBSD: sudoers 경로가 /usr/local/etc/sudoers
    local sudoers="/usr/local/etc/sudoers"
    local sudoers_d="/usr/local/etc/sudoers.d"

    if [[ -f "$sudoers" ]]; then
        backup_file "$sudoers"
        # gt 라인 제외하고 NOPASSWD 제거
        sed -i '' '/^'"${PROTECTED_ACCOUNT_GT}"'/!s/NOPASSWD://g' "$sudoers" 2>/dev/null || true
        if visudo -c -f "$sudoers" 2>/dev/null; then
            log_ok "sudoers NOPASSWD 제거 (gt 제외)"
        else
            log_error "sudoers 문법 오류 — 복원"
            cp "${BACKUP_DIR}/$(echo "$sudoers" | tr '/' '_')" "$sudoers" 2>/dev/null || true
        fi
    fi

    # gt NOPASSWD 재보장
    guard_account_gt
}
```

- [ ] **Step 5: SSH — FreeBSD 경로 차이**

```bash
setup_ssh_hardening() {
    log_info "===== SSH 하드닝 ====="

    local sshd_config="/etc/ssh/sshd_config"
    if [[ ! -f "$sshd_config" ]]; then
        # FreeBSD에서 경로가 다를 수 있음
        sshd_config="/usr/local/etc/ssh/sshd_config"
    fi
    [[ -f "$sshd_config" ]] || { log_skip "sshd_config 없음"; return; }

    backup_file "$sshd_config"

    # FreeBSD는 sshd_config.d 디렉토리가 없을 수 있음
    # 직접 sshd_config에 설정 추가/변경
    local settings=(
        "PermitRootLogin prohibit-password"
        "MaxAuthTries 4"
        "PermitEmptyPasswords no"
        "X11Forwarding no"
        "AllowTcpForwarding no"
        "AllowAgentForwarding no"
        "ClientAliveInterval 300"
        "ClientAliveCountMax 2"
        "LoginGraceTime 60"
        "UsePAM yes"
        "HostbasedAuthentication no"
        "IgnoreRhosts yes"
        "MaxSessions 4"
    )

    for setting in "${settings[@]}"; do
        local key="${setting%% *}"
        if grep -qE "^#?${key}" "$sshd_config"; then
            sed -i '' "s/^#*${key}.*/${setting}/" "$sshd_config"
        else
            echo "$setting" >> "$sshd_config"
        fi
    done

    if sshd -t 2>/dev/null; then
        service sshd reload 2>/dev/null && log_ok "SSH 하드닝 적용" || \
            log_warn "SSH reload 실패"
    else
        log_error "sshd 설정 문법 오류 — 롤백"
        cp "${BACKUP_DIR}/$(echo "$sshd_config" | tr '/' '_')" "$sshd_config" 2>/dev/null || true
    fi
}
```

- [ ] **Step 6: run_hardening / run_checks 구현 + 커밋**

```bash
git add lib/os_freebsd.sh
git commit -m "feat: add FreeBSD hardening adapter with pf firewall and rc.d service management"
```

---

## Phase 5: macOS 어댑터

### Task 5.1: lib/os_macos.sh

**Files:**
- Create: `lib/os_macos.sh`

macOS 주요 차이점:

| 항목 | Linux | macOS |
|------|-------|-------|
| 패키지 관리 | apt/dnf | 기본 도구 없음 (brew 가정하지 않음) |
| 방화벽 | ufw/firewalld | pf + Application Firewall (socketfilterfw) |
| 서비스 관리 | systemd/rc.d | launchd (launchctl) |
| 사용자 관리 | useradd/pw | dscl/sysadminctl |
| 감사 | auditd | OpenBSM (praudit, auditd) |
| sysctl | /etc/sysctl.conf | /etc/sysctl.conf (제한적) |
| 파일 권한 | chmod/chown | chmod/chown + SIP 제약 |
| 경로 | /etc/ | /etc/ + /Library/ |
| gtmon | gtmon.service | net.cr14.gtmon.plist |
| root | 변경 가능 | 변경 금지 (SIP/TCC 제약) |
| SSH | sshd | Remote Login (systemsetup) |

- [ ] **Step 1: os_macos.sh 기본 구조**

```bash
#!/usr/bin/env bash
# lib/os_macos.sh — macOS 하드닝 어댑터
# 주의: macOS는 SIP(System Integrity Protection) 때문에 
#       시스템 파일 수정에 제약이 있음

# ─── 패키지 관리 (macOS에서는 최소한만) ──────────────────────────
pkg_install()      { log_warn "macOS: 패키지 설치 미지원 — 수동 설치 필요: $*"; }
pkg_remove()       { log_warn "macOS: 패키지 제거 미지원 — 수동 제거 필요: $*"; }
pkg_is_installed() { return 1; }

# ─── 서비스 관리 (launchd) ───────────────────────────────────────
svc_enable() {
    local svc="$1"
    is_protected_service "$svc" && return 0
    local plist_path
    plist_path=$(_find_plist "$svc")
    if [[ -n "$plist_path" ]]; then
        launchctl load -w "$plist_path" 2>/dev/null
    fi
}

svc_disable() {
    local svc="$1"
    is_protected_service "$svc" && return 0
    local plist_path
    plist_path=$(_find_plist "$svc")
    if [[ -n "$plist_path" ]]; then
        launchctl unload -w "$plist_path" 2>/dev/null
    fi
}

svc_start() {
    local plist_path
    plist_path=$(_find_plist "$1")
    [[ -n "$plist_path" ]] && launchctl load "$plist_path" 2>/dev/null
}

svc_restart() {
    svc_disable "$1"
    svc_enable "$1"
}

svc_is_active() {
    launchctl list 2>/dev/null | grep -q "$1"
}

svc_is_enabled() {
    svc_is_active "$1"
}

_find_plist() {
    local name="$1"
    for dir in /Library/LaunchDaemons /Library/LaunchAgents \
               /System/Library/LaunchDaemons ~/Library/LaunchAgents; do
        local f="${dir}/${name}.plist"
        [[ -f "$f" ]] && echo "$f" && return 0
        # 와일드카드 매칭
        local match
        match=$(ls "${dir}"/*"${name}"*.plist 2>/dev/null | head -1)
        [[ -n "$match" ]] && echo "$match" && return 0
    done
    return 1
}
```

- [ ] **Step 2: macOS 방화벽 (pf + Application Firewall)**

```bash
setup_firewall() {
    log_info "===== macOS 방화벽 설정 ====="

    # Application Firewall 활성화
    if command -v /usr/libexec/ApplicationFirewall/socketfilterfw &>/dev/null; then
        /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on 2>/dev/null
        /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on 2>/dev/null
        log_ok "Application Firewall 활성화 + 스텔스 모드"
    fi

    # pf 설정
    local pf_conf="/etc/pf.conf"
    backup_file "$pf_conf"

    # macOS 기본 pf.conf를 보존하면서 보안 규칙 추가
    # ★ 주의: macOS pf는 com.apple 앵커를 포함하므로 완전 덮어쓰기 금지
    if ! grep -q "# HARDENING_RULES" "$pf_conf" 2>/dev/null; then
        cat >> "$pf_conf" <<'PFEOF'

# HARDENING_RULES — 하드닝 자동 생성
# 인바운드 차단 기본 정책 (macOS 기본 앵커 이후)
block in on ! lo0

# SSH 허용 (Remote Login 활성 시)
pass in proto tcp to port 22 keep state

# ICMP 허용 (워크스테이션 요구사항)
pass proto icmp all
pass proto icmp6 all

# 아웃바운드 전부 허용 (워크스테이션 + gtmon 요구사항)
pass out all keep state
# END HARDENING_RULES
PFEOF
        pfctl -f "$pf_conf" 2>/dev/null && log_ok "pf 규칙 추가" || \
            log_warn "pf 로드 실패"
    else
        log_skip "pf 하드닝 규칙 이미 존재"
    fi

    guard_network_outbound || log_warn "아웃바운드 포트 문제"
}
```

- [ ] **Step 3: macOS 시스템 설정 하드닝**

```bash
setup_macos_system() {
    log_info "===== macOS 시스템 설정 하드닝 ====="

    # 자동 로그인 비활성화
    defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || true
    log_ok "자동 로그인 비활성화"

    # 화면 보호기 비밀번호
    defaults write com.apple.screensaver askForPassword -int 1 2>/dev/null || true
    defaults write com.apple.screensaver askForPasswordDelay -int 0 2>/dev/null || true
    log_ok "화면 보호기 비밀번호 즉시 요구 설정"

    # 원격 Apple Events 비활성화
    systemsetup -setremoteappleevents off 2>/dev/null || true
    log_ok "원격 Apple Events 비활성화"

    # Guest 계정 비활성화
    defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false 2>/dev/null || true
    log_ok "Guest 계정 비활성화"

    # Bluetooth 공유 비활성화
    defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false 2>/dev/null || true

    # AirDrop 비활성화
    defaults write com.apple.NetworkBrowser DisableAirDrop -bool true 2>/dev/null || true

    # FileVault 상태 확인 (활성화는 대화형이므로 경고만)
    if ! fdesetup status 2>/dev/null | grep -q "On"; then
        log_warn "FileVault 비활성 — 수동 활성화 권장: sudo fdesetup enable"
    fi

    # Gatekeeper 활성화
    spctl --master-enable 2>/dev/null || true
    log_ok "Gatekeeper 활성화"

    # SIP 상태 확인
    if csrutil status 2>/dev/null | grep -q "disabled"; then
        log_warn "SIP 비활성화됨! 보안 위험 — 복구 모드에서 csrutil enable 실행 필요"
    else
        log_ok "SIP 활성 상태"
    fi
}
```

- [ ] **Step 4: macOS SSH 하드닝**

```bash
setup_ssh_hardening() {
    log_info "===== SSH 하드닝 (macOS) ====="

    local sshd_config="/etc/ssh/sshd_config"
    [[ -f "$sshd_config" ]] || { log_skip "sshd_config 없음 — Remote Login 비활성?"; return; }

    backup_file "$sshd_config"

    # macOS sshd_config 수정 (sed -i '' macOS 문법)
    local settings=(
        "PermitRootLogin no"    # ★ macOS에서는 root 로그인 완전 차단
        "MaxAuthTries 4"
        "PermitEmptyPasswords no"
        "X11Forwarding no"
        "AllowTcpForwarding no"
        "ClientAliveInterval 300"
        "ClientAliveCountMax 2"
        "LoginGraceTime 60"
        "HostbasedAuthentication no"
        "IgnoreRhosts yes"
        "MaxSessions 4"
    )

    for setting in "${settings[@]}"; do
        local key="${setting%% *}"
        if grep -qE "^#?${key}" "$sshd_config"; then
            sed -i '' "s/^#*${key}.*/${setting}/" "$sshd_config"
        else
            echo "$setting" >> "$sshd_config"
        fi
    done

    # macOS sshd 재시작은 launchctl
    launchctl unload /System/Library/LaunchDaemons/ssh.plist 2>/dev/null || true
    launchctl load /System/Library/LaunchDaemons/ssh.plist 2>/dev/null || true
    log_ok "SSH 하드닝 적용"
}
```

- [ ] **Step 5: macOS 계정 관리**

```bash
setup_nologin_accounts() {
    log_info "===== macOS 시스템 계정 보호 ====="

    # macOS는 시스템 계정이 이미 /usr/bin/false로 설정됨
    # 추가적으로 숨겨진 사용자 확인
    local login_users
    login_users=$(dscl . -list /Users UniqueID 2>/dev/null | \
                  awk '$2 >= 500 && $1 != "nobody" {print $1}')

    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        if is_protected_account "$user"; then
            log_skip "[GUARD] ${user} — 보호 계정"
            continue
        fi
        log_info "로그인 가능 사용자: $user (UID $(dscl . -read /Users/$user UniqueID 2>/dev/null | awk '{print $2}'))"
    done <<< "$login_users"
}
```

- [ ] **Step 6: run_hardening / run_checks / create_baseline_snapshot**

```bash
run_hardening() {
    setup_macos_system
    setup_firewall
    setup_ssh_hardening
    setup_nologin_accounts
    setup_sudoers
    setup_banner
    # macOS에서는 적용하지 않는 항목:
    # - auditd 설정 변경 (C4: 스냅샷만)
    # - PAM (macOS는 별도 인증 프레임워크)
    # - sysctl (macOS에서 제한적)
    # - modprobe (N/A)
    # - hidepid (N/A)
}

run_checks() {
    check_firewall
    check_ssh_config
    check_macos_system_settings
    check_login_accounts
    check_sudoers
    check_suspicious_processes
    check_suspicious_files
    check_network
}

create_baseline_snapshot() {
    log_info "===== macOS 베이스라인 스냅샷 생성 ====="
    mkdir -p "${BASELINE_SNAPSHOT_DIR}"

    # 설치된 앱 목록
    ls /Applications/ > "${BASELINE_SNAPSHOT_DIR}/applications_baseline.txt" 2>/dev/null || true

    # 시스템 설정 스냅샷
    defaults read /Library/Preferences/com.apple.loginwindow \
        > "${BASELINE_SNAPSHOT_DIR}/loginwindow_baseline.txt" 2>/dev/null || true

    # pf 규칙
    pfctl -sr > "${BASELINE_SNAPSHOT_DIR}/pf_rules_baseline.txt" 2>/dev/null || true

    # 사용자 목록
    dscl . -list /Users UniqueID > "${BASELINE_SNAPSHOT_DIR}/users_baseline.txt" 2>/dev/null || true

    # SSH 설정
    [[ -f /etc/ssh/sshd_config ]] && \
        cp /etc/ssh/sshd_config "${BASELINE_SNAPSHOT_DIR}/sshd_config_baseline.txt" || true

    # scoringbot 상태
    if [[ -f /Users/gt/scoringbot/scoringbot ]]; then
        ls -la /Users/gt/scoringbot/scoringbot \
            > "${BASELINE_SNAPSHOT_DIR}/scoringbot_baseline.txt" 2>/dev/null || true
    fi

    log_ok "macOS 베이스라인 스냅샷 저장 완료"
}
```

- [ ] **Step 7: 커밋**

```bash
git add lib/os_macos.sh
git commit -m "feat: add macOS hardening adapter with pf, launchd, and system settings"
```

---

## Phase 6: 통합 테스트 및 마무리

### Task 6.1: 통합 테스트 매트릭스

- [ ] **Step 1: 각 OS에서 01 스크립트 실행 검증**

```
# Debian/Ubuntu VM
sudo bash 01_baseline_hardening.sh --profile=web

# RHEL/Rocky VM  
sudo bash 01_baseline_hardening.sh --profile=base

# FreeBSD VM
sudo bash 01_baseline_hardening.sh --profile=base

# macOS
sudo bash 01_baseline_hardening.sh
```

각 실행 후 확인 사항:
1. gt 계정 존재 + sudo NOPASSWD 유지
2. usr 계정 존재 + 변경 비밀번호 출력 확인
3. gtmon 바이너리/서비스 정상
4. 아웃바운드 필수 포트 열림
5. IPv4/IPv6 모두 접근 가능
6. hostname 변경 없음
7. auditd 설정 변경 없음 (스냅샷만 저장)

- [ ] **Step 2: 02 스크립트 점검 모드 검증**

```
sudo bash 02_check_and_restore.sh --check-only
```

- [ ] **Step 3: 02 스크립트 자동 복원 모드 검증**

```
# 일부러 drift 생성 후 복원 테스트
sudo bash 02_check_and_restore.sh --auto-restore
```

- [ ] **Step 4: 최종 커밋**

```bash
git add -A
git commit -m "feat: complete multi-OS hardening framework v4 with safety guards"
```

---

## 요약: v3 → v4 주요 변경 매트릭스

| 항목 | v3 (현재) | v4 (계획) |
|------|-----------|-----------|
| OS 지원 | Debian/Ubuntu only | Debian, RHEL, FreeBSD, macOS |
| 아키텍처 | 단일 파일 | common lib + OS adapter 패턴 |
| gt 계정 | 보호 없음 (삭제/변경 위험) | `is_protected_account()` 가드 |
| usr 계정 | 보호 없음 | 삭제 금지 + 비밀번호 변경 시 출력 |
| NOPASSWD | 모든 사용자에서 제거 | gt 제외하고 제거 |
| 아웃바운드 | 제한 없음/과도한 차단 | 필수 포트 보장 (22,80,443,8080,110,995,143,993,21,ICMP) |
| IPv6 | 고려 부족 | 듀얼스택 보존 필수 |
| DNS/hostname | 변경 가능 | 변경 금지 가드 |
| gtmon | 보호 없음 | 바이너리/서비스/네트워크 보호 |
| auditd (01) | 설정 직접 변경 | 스냅샷만 저장 (변경 없음) |
| auditd (02) | 부분적 diff | 완전한 diff + 스냅샷 기반 복원 |
| ICMP echo 차단 | 서버 outbound ping 차단 | 워크스테이션은 ping 허용 |
| 방화벽 | UFW only | UFW / firewalld / pf |
