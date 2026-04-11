#!/bin/bash
set -euo pipefail

###############################################################################
# ② 점검/복원 스크립트 (훈련 중 주기적 실행)
#
# 목적: 베이스라인 스냅샷과 현재 상태를 비교하여 변경(drift)을 탐지하고,
#       필요 시 자동으로 복원한다.
#
# 변경 이력 (01_baseline_hardening_integrated.sh 호환):
#   [21] check_tunnel_defense 전면 재작성
#     · ICMP/DNS/SOCKS5 iptables 규칙 검증 → UFW after.rules 존재 여부 우선 확인
#     · after.rules 마커(TUNNEL_HARDENING_BLOCK_BEGIN) 기반 멱등 점검
#     · 런타임 규칙 소실 시 `ufw reload` 로 after.rules 재적용 (복원)
#     · 개별 iptables -A 복원 제거 → after.rules 재적용으로 일원화
#     · tunnel_ufw_after_rules_baseline.txt 스냅샷 파일 활용
#   [6] check_ufw — after.rules 무결성 점검 항목 추가
#
# 동작 모드:
#   --check-only   : 점검만 수행, 변경하지 않음 (기본값)
#   --auto-restore : 변경된 설정을 자동 복원
#
# 실행 조건: root 권한 필요
# 사용법:
#   sudo bash 02_check_and_restore.sh                  # 점검만
#   sudo bash 02_check_and_restore.sh --auto-restore   # 점검 + 자동 복원
#
# 의존: 01_baseline_hardening_integrated.sh 로 생성된 베이스라인 스냅샷
#       (/var/backups/hardening_baseline/)
###############################################################################

# =============================================================================
# [설정]
# =============================================================================
readonly SCRIPT_NAME="$(basename "$0")"
readonly HOSTNAME="$(hostname)"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

_LOG_DIR="/var/log/hardening"
if mkdir -p "$_LOG_DIR" 2>/dev/null && [[ -w "$_LOG_DIR" ]]; then
    readonly LOGFILE="${_LOG_DIR}/${TIMESTAMP}_${HOSTNAME}_check_result.log"
else
    readonly LOGFILE="/tmp/${TIMESTAMP}_${HOSTNAME}_check_result.log"
fi

readonly BASELINE_DIR="/var/backups/hardening_baseline"

# UFW after.rules 터널링 방어 블록 마커 (01과 동일해야 함)
readonly UFW_TUNNEL_MARKER="# TUNNEL_HARDENING_BLOCK_BEGIN"

# 동작 모드
MODE="check-only"
if [[ "${1:-}" == "--auto-restore" ]]; then
    MODE="auto-restore"
fi

# 의심 포트 점검 제외 (쉼표 구분)
WHITELISTED_PORTS="${WHITELISTED_PORTS:-}"

# 자동 잠금 제외 계정 (쉼표 구분)
ACCOUNT_ALLOWLIST="${ACCOUNT_ALLOWLIST:-}"

# crontab 허용 사용자 목록 (쉼표 구분)
CRONTAB_ALLOWLIST="${CRONTAB_ALLOWLIST:-}"

# 서비스 자동 중지/비활성화 제외 목록 (쉼표 구분)
SERVICE_ALLOWLIST="${SERVICE_ALLOWLIST:-}"

# 카운터
DRIFT_COUNT=0
RESTORE_COUNT=0
FAIL_COUNT=0

# 복원 전 백업 디렉토리
RESTORE_BACKUP_DIR="/var/backups/hardening_restore_${TIMESTAMP}"

# =============================================================================
# [로그 함수]
# =============================================================================
log_info()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]    $*"; }
log_ok()      { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [OK]      $*"; }
log_skip()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SKIP]    $*"; }
log_drift()   { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [DRIFT]   $*"; DRIFT_COUNT=$((DRIFT_COUNT + 1)); }
log_restore() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [RESTORE] $*"; RESTORE_COUNT=$((RESTORE_COUNT + 1)); }
log_fail()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [FAIL]    $*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }
log_warn()    { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]    $*"; }

# =============================================================================
# [헬퍼] 복원 전 현재 상태 백업
# =============================================================================
backup_before_restore() {
    local target="$1"
    [[ -e "$target" ]] || return 0
    if [[ ! -d "$RESTORE_BACKUP_DIR" ]]; then
        mkdir -p "$RESTORE_BACKUP_DIR"
    fi
    local dest="${RESTORE_BACKUP_DIR}/$(echo "$target" | tr '/' '_')"
    cp -a "$target" "$dest" 2>/dev/null && \
        log_info "복원 전 백업: $target -> $dest" || true
}

# =============================================================================
# [사전 확인]
# =============================================================================
check_environment() {
    if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
        echo "[ERROR] bash 4.0 이상 필요 (현재: ${BASH_VERSION})"
        exit 1
    fi
    if [[ -f /etc/os-release ]]; then
        local distro version
        distro=$(. /etc/os-release && echo "${ID:-unknown}")
        version=$(. /etc/os-release && echo "${VERSION_ID:-unknown}")
        log_info "배포판: ${distro} ${version} (bash ${BASH_VERSION})"
        case "$distro" in
            ubuntu|debian) ;;
            *) log_warn "이 스크립트는 Ubuntu/Debian 계열에 최적화되어 있습니다" ;;
        esac
    else
        log_warn "/etc/os-release 없음 — 배포판 확인 불가"
    fi
}

check_prerequisites() {
    if [[ $EUID -ne 0 ]]; then
        echo "[ERROR] root 권한이 필요합니다: sudo $SCRIPT_NAME"
        exit 1
    fi

    if [[ ! -d "$BASELINE_DIR" ]]; then
        echo "[ERROR] 베이스라인 스냅샷이 없습니다: $BASELINE_DIR"
        echo "        먼저 01_baseline_hardening_integrated.sh 를 실행하세요."
        exit 1
    fi

    local integrity_file="${BASELINE_DIR}/INTEGRITY.sha256"
    if [[ -f "$integrity_file" ]]; then
        local integrity_errors
        integrity_errors=$(cd / && sha256sum -c "$integrity_file" 2>&1 | grep -c 'FAILED' || true)
        if [[ "$integrity_errors" -gt 0 ]]; then
            echo "[CRITICAL] 베이스라인 파일이 변조되었습니다! (${integrity_errors}개 파일)"
            echo "           01_baseline_hardening_integrated.sh를 재실행하여 베이스라인을 재생성하세요."
            echo "           강제 실행: SKIP_INTEGRITY=true sudo bash $SCRIPT_NAME"
            if [[ "${SKIP_INTEGRITY:-false}" != "true" ]]; then
                exit 2
            fi
            echo "[WARN] SKIP_INTEGRITY=true — 무결성 검증 우회하여 계속 실행"
        else
            log_ok "베이스라인 무결성 검증 통과"
        fi
    else
        log_warn "베이스라인 무결성 해시 없음 (01 재실행 권장)"
    fi
}

# =============================================================================
# [1] sysctl 설정 점검
# =============================================================================
check_sysctl() {
    log_info "===== [1] sysctl 설정 점검 ====="

    local baseline_file="${BASELINE_DIR}/sysctl_baseline.conf"
    if [[ ! -f "$baseline_file" ]]; then
        log_warn "sysctl 베이스라인 파일 없음 — 건너뜀"
        return
    fi

    local -r SYSCTL_SKIP_PATTERN='^(dev\.cdrom\.info|fs\.binfmt_misc\.|kernel\.core_modes|kernel\.ns_last_pid|kernel\.random\.uuid|kernel\.random\.boot_id|kernel\.tainted|kernel\.pty\.nr|fs\.dentry-state|fs\.file-nr|fs\.inode-nr|fs\.inode-state|net\.netfilter\.nf_conntrack_count|kernel\.perf_event_max_sample_rate|vm\.stat_interval)'

    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue

        local key expected_val
        key="${line%%=*}"
        expected_val="${line#*=}"
        [[ -z "$key" ]] && continue

        if echo "$key" | grep -qE "$SYSCTL_SKIP_PATTERN"; then
            continue
        fi

        local current_val
        current_val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")

        if [[ "$current_val" == "$expected_val" ]]; then
            log_ok "sysctl ${key} = ${current_val}"
        else
            log_drift "sysctl ${key}: 기대=${expected_val}, 현재=${current_val}"
            if [[ "$MODE" == "auto-restore" ]]; then
                if sysctl -w "${key}=${expected_val}" >/dev/null 2>&1; then
                    log_restore "sysctl ${key}=${expected_val} 복원 완료"
                else
                    log_fail "sysctl ${key} 복원 실패"
                fi
            fi
        fi
    done < "$baseline_file"
}

# =============================================================================
# [2] 파일 권한 점검
# =============================================================================
check_file_permissions() {
    log_info "===== [2] 파일 권한 점검 ====="

    local baseline_file="${BASELINE_DIR}/file_permissions_baseline.txt"
    if [[ ! -f "$baseline_file" ]]; then
        log_warn "파일 권한 베이스라인 없음 — 건너뜀"
        return
    fi

    while IFS=' ' read -r expected_perm expected_owner filepath; do
        [[ -z "$filepath" ]] && continue
        if [[ ! -e "$filepath" ]]; then
            log_warn "파일 없음 (삭제됨?): $filepath"
            continue
        fi

        local current_perm current_owner
        current_perm=$(stat -c '%a' "$filepath" 2>/dev/null)
        current_owner=$(stat -c '%U:%G' "$filepath" 2>/dev/null)
        local drifted=false

        if [[ "$current_perm" != "$expected_perm" ]]; then
            log_drift "권한 변경: $filepath (기대=${expected_perm}, 현재=${current_perm})"
            drifted=true
            if [[ "$MODE" == "auto-restore" ]]; then
                backup_before_restore "$filepath"
                if chmod "$expected_perm" "$filepath" 2>/dev/null; then
                    log_restore "chmod ${expected_perm} ${filepath}"
                else
                    log_fail "chmod ${expected_perm} ${filepath} 실패"
                fi
            fi
        fi

        if [[ "$current_owner" != "$expected_owner" ]]; then
            log_drift "소유자 변경: $filepath (기대=${expected_owner}, 현재=${current_owner})"
            drifted=true
            if [[ "$MODE" == "auto-restore" ]]; then
                backup_before_restore "$filepath"
                if chown "$expected_owner" "$filepath" 2>/dev/null; then
                    log_restore "chown ${expected_owner} ${filepath}"
                else
                    log_fail "chown ${expected_owner} ${filepath} 실패"
                fi
            fi
        fi

        [[ "$drifted" == "false" ]] && log_ok "정상: $filepath (${current_perm} ${current_owner})"
    done < "$baseline_file"
}

# =============================================================================
# [3] SUID 파일 점검
# =============================================================================
check_suid_files() {
    log_info "===== [3] SUID 파일 점검 ====="

    local baseline_file="${BASELINE_DIR}/suid_files_baseline.txt"
    if [[ ! -f "$baseline_file" ]]; then
        log_warn "SUID 베이스라인 없음 — 건너뜀"
        return
    fi

    local current_suid
    current_suid=$(mktemp)
    find / -xdev -perm -4000 -type f 2>/dev/null | sort > "$current_suid"

    local new_suid
    new_suid=$(comm -13 "$baseline_file" "$current_suid")
    if [[ -n "$new_suid" ]]; then
        while IFS= read -r f; do
            log_drift "새 SUID 파일 발견: $f"
            if [[ "$MODE" == "auto-restore" ]]; then
                if chmod u-s "$f" 2>/dev/null; then
                    log_restore "SUID 제거: $f"
                else
                    log_fail "SUID 제거 실패: $f"
                fi
            fi
        done <<< "$new_suid"
    else
        log_ok "새 SUID 파일 없음"
    fi

    local removed_suid
    removed_suid=$(comm -23 "$baseline_file" "$current_suid")
    if [[ -n "$removed_suid" ]]; then
        while IFS= read -r f; do
            log_info "(참고) 베이스라인 SUID 파일 사라짐: $f"
        done <<< "$removed_suid"
    fi

    rm -f "$current_suid"
}

# =============================================================================
# [4] 비활성화 서비스 점검
# =============================================================================
check_disabled_services() {
    log_info "===== [4] 비활성화 서비스 점검 ====="

    local baseline_file="${BASELINE_DIR}/enabled_services_baseline.txt"

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
                log_drift "베이스라인에 없는 신규 활성 서비스: $svc"
                if [[ "$MODE" == "auto-restore" ]]; then
                    if echo ",${SERVICE_ALLOWLIST}," | grep -q ",${svc},"; then
                        log_skip "allowlist 서비스: ${svc}"
                        continue
                    fi
                    systemctl disable --now "$svc" 2>/dev/null || true
                    log_restore "서비스 비활성화: $svc"
                fi
            done <<< "$new_services"
        else
            log_ok "베이스라인 대비 신규 활성 서비스 없음"
        fi

        local removed_services
        removed_services=$(comm -23 "$baseline_file" "$current_services")
        if [[ -n "$removed_services" ]]; then
            while IFS= read -r svc; do
                [[ -z "$svc" ]] && continue
                log_info "(참고) 베이스라인 서비스 비활성화됨: $svc"
            done <<< "$removed_services"
        fi
        rm -f "$current_services"

        local active_baseline="${BASELINE_DIR}/active_services_baseline.txt"
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
                    log_drift "베이스라인에 없는 신규 active 서비스: $svc (enabled 아닐 수 있음)"
                    if [[ "$MODE" == "auto-restore" ]]; then
                        if echo ",${SERVICE_ALLOWLIST}," | grep -q ",${svc},"; then
                            log_skip "allowlist 서비스: ${svc}"
                            continue
                        fi
                        systemctl stop "$svc" 2>/dev/null || true
                        log_restore "서비스 중지: $svc"
                    fi
                done <<< "$new_active"
            else
                log_ok "베이스라인 대비 신규 active 서비스 없음"
            fi
            rm -f "$current_active"
        fi
    else
        log_warn "서비스 베이스라인 없음 — 기본 서비스 목록으로 점검"
        local target_services=(
            avahi-daemon.service cups.service cups-browsed.service bluetooth.service
        )
        for svc in "${target_services[@]}"; do
            if ! systemctl list-unit-files "$svc" &>/dev/null 2>&1; then
                log_ok "서비스 미설치: $svc"
                continue
            fi
            local is_enabled is_active
            is_enabled=$(systemctl is-enabled "$svc" 2>/dev/null || echo "unknown")
            is_active=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
            if [[ "$is_enabled" == "enabled" ]] || [[ "$is_active" == "active" ]]; then
                log_drift "서비스 재활성화됨: $svc (enabled=${is_enabled}, active=${is_active})"
                if [[ "$MODE" == "auto-restore" ]]; then
                    systemctl disable --now "$svc" 2>/dev/null || true
                    log_restore "서비스 비활성화: $svc"
                fi
            else
                log_ok "비활성 유지: $svc"
            fi
        done
    fi
}

# =============================================================================
# [5] 로그인 가능 계정 점검
# =============================================================================
check_login_accounts() {
    log_info "===== [5] 로그인 가능 계정 점검 ====="

    local baseline_file="${BASELINE_DIR}/login_accounts_baseline.txt"
    if [[ ! -f "$baseline_file" ]]; then
        log_warn "계정 베이스라인 없음 — 건너뜀"
        return
    fi

    local current_accounts
    current_accounts=$(mktemp)
    awk -F: '$7 !~ /(nologin|false)/ {print $1":"$7}' /etc/passwd | sort > "$current_accounts"

    local new_accounts
    new_accounts=$(comm -13 "$baseline_file" "$current_accounts")
    if [[ -n "$new_accounts" ]]; then
        while IFS=: read -r user shell; do
            log_drift "새 로그인 가능 계정: ${user} (셸: ${shell})"
            if [[ "$MODE" == "auto-restore" ]]; then
                if [[ "$user" == "root" ]]; then
                    log_skip "root 계정은 자동 복원하지 않음"
                elif echo ",${ACCOUNT_ALLOWLIST}," | grep -q ",${user},"; then
                    log_skip "allowlist 계정: ${user}"
                else
                    chsh -s /usr/sbin/nologin "$user" 2>/dev/null && \
                        log_restore "${user} -> nologin" || \
                        log_fail "${user} nologin 설정 실패"
                fi
            fi
        done <<< "$new_accounts"
    else
        log_ok "새 로그인 가능 계정 없음"
    fi

    rm -f "$current_accounts"
}

# =============================================================================
# [6] UFW 방화벽 점검
#
# 01 통합본 변경에 따른 추가 점검:
#   (d) after.rules 터널링 방어 블록 존재 여부
#   (e) after.rules 무결성 — 베이스라인 스냅샷과 비교
#   (f) after6.rules 터널링 방어 블록 존재 여부
# =============================================================================
_ufw_rule_cmd() {
    local rule="$1" mode="$2"
    local action to_part from_part

    action=$(echo "$rule" | grep -oiE '\b(ALLOW|DENY|REJECT|LIMIT)\b' | head -1 | tr '[:upper:]' '[:lower:]')
    if [[ -z "$action" ]]; then
        log_warn "UFW 규칙 파싱 실패 (action 불명): ${rule}"
        return 1
    fi

    to_part=$(echo "$rule" | sed -E "s/[[:space:]]+(ALLOW|DENY|REJECT|LIMIT)([[:space:]]+IN)?[[:space:]]+.*//" | sed 's/^[[:space:]]*//')
    from_part=$(echo "$rule" | sed -E "s/.*[[:space:]]+(ALLOW|DENY|REJECT|LIMIT)([[:space:]]+IN)?[[:space:]]+//" \
        | sed 's/[[:space:]]*(v6)[[:space:]]*//' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    if [[ -z "$to_part" ]]; then
        log_warn "UFW 규칙 파싱 실패 (to_part 불명): ${rule}"
        return 1
    fi

    local -a cmd_args=()
    [[ "$mode" == "delete" ]] && cmd_args+=(delete)
    cmd_args+=("$action")

    if [[ "$from_part" == "Anywhere" || -z "$from_part" ]]; then
        cmd_args+=("$to_part")
    elif echo "$to_part" | grep -q '/'; then
        cmd_args+=(from "$from_part" to any port "${to_part%%/*}" proto "${to_part##*/}")
    else
        cmd_args+=(from "$from_part" to any app "$to_part")
    fi

    ufw "${cmd_args[@]}" 2>/dev/null
}

check_ufw() {
    log_info "===== [6] UFW 방화벽 점검 ====="

    if ! command -v ufw >/dev/null 2>&1; then
        log_warn "ufw 미설치"
        return
    fi

    # (a) 활성 상태 점검
    local ufw_status
    ufw_status=$(ufw status 2>/dev/null | head -1)
    if echo "$ufw_status" | grep -qi "inactive"; then
        log_drift "UFW 비활성 상태!"
        if [[ "$MODE" == "auto-restore" ]]; then
            ufw --force enable 2>/dev/null && \
                log_restore "UFW 재활성화" || \
                log_fail "UFW 활성화 실패"
        fi
    else
        log_ok "UFW 활성 상태"
    fi

    # (b) 기본 정책 점검
    if [[ -f /etc/default/ufw ]]; then
        local input_policy
        input_policy=$(grep 'DEFAULT_INPUT_POLICY' /etc/default/ufw 2>/dev/null | cut -d'"' -f2)
        if [[ "$input_policy" != "DROP" ]]; then
            log_drift "UFW 입력 정책 변경: ${input_policy} (기대: DROP)"
            if [[ "$MODE" == "auto-restore" ]]; then
                ufw default deny incoming 2>/dev/null && \
                    log_restore "UFW 입력 정책 DROP 복원" || \
                    log_fail "UFW 정책 복원 실패"
            fi
        else
            log_ok "UFW 입력 정책: DROP"
        fi
    fi

    # (c) 규칙 drift 탐지
    local baseline_rules="${BASELINE_DIR}/ufw_rules_baseline.txt"
    if [[ -f "$baseline_rules" ]]; then
        local current_rules
        current_rules=$(mktemp)
        ufw status 2>/dev/null | grep -iE 'ALLOW|DENY|REJECT|LIMIT' | \
            sed 's/[[:space:]]\+/ /g' | sort > "$current_rules"

        local added_rules
        added_rules=$(comm -13 "$baseline_rules" "$current_rules")
        if [[ -n "$added_rules" ]]; then
            while IFS= read -r rule; do
                log_drift "UFW 신규 규칙 탐지: ${rule}"
                if [[ "$MODE" == "auto-restore" ]]; then
                    if echo "$rule" | grep -q '(v6)'; then
                        log_info "UFW IPv6 규칙 — IPv4 삭제 시 자동 제거"
                    else
                        if _ufw_rule_cmd "$rule" delete; then
                            log_restore "UFW 규칙 삭제: ${rule}"
                        else
                            log_fail "UFW 규칙 삭제 실패: ${rule}"
                        fi
                    fi
                fi
            done <<< "$added_rules"
        else
            log_ok "UFW 규칙: 베이스라인과 동일"
        fi

        local removed_rules
        removed_rules=$(comm -23 "$baseline_rules" "$current_rules")
        if [[ -n "$removed_rules" ]]; then
            while IFS= read -r rule; do
                log_drift "UFW 규칙 삭제됨: ${rule}"
                if [[ "$MODE" == "auto-restore" ]]; then
                    if echo "$rule" | grep -q '(v6)'; then
                        log_info "UFW IPv6 규칙 — IPv4 복원 시 자동 추가"
                    else
                        if _ufw_rule_cmd "$rule" add; then
                            log_restore "UFW 규칙 복원: ${rule}"
                        else
                            log_fail "UFW 규칙 복원 실패: ${rule}"
                        fi
                    fi
                fi
            done <<< "$removed_rules"
        fi
        rm -f "$current_rules"
    else
        log_warn "UFW 규칙 베이스라인 없음 — 규칙 drift 비교 불가"
    fi

    # ── (d) after.rules 터널링 방어 블록 존재 여부 ───────────────────────────
    # 01의 _ufw_write_tunnel_after_rules() 가 삽입한 마커를 기준으로 확인
    local after_rules="/etc/ufw/after.rules"
    local after6_rules="/etc/ufw/after6.rules"

    if [[ ! -f "$after_rules" ]]; then
        log_drift "UFW after.rules 파일 자체가 없음: ${after_rules}"
    elif grep -q "${UFW_TUNNEL_MARKER}" "$after_rules" 2>/dev/null; then
        log_ok "UFW after.rules: 터널링 방어 블록 존재 (마커 확인)"
    else
        log_drift "UFW after.rules: 터널링 방어 블록 누락 (마커 없음)"
        if [[ "$MODE" == "auto-restore" ]]; then
            log_warn "  after.rules 터널링 블록 복원은 01 스크립트 재실행을 권장합니다"
            log_warn "  sudo bash 01_baseline_hardening_integrated.sh"
        fi
    fi

    if [[ ! -f "$after6_rules" ]]; then
        log_drift "UFW after6.rules 파일 자체가 없음: ${after6_rules}"
    elif grep -q "${UFW_TUNNEL_MARKER}" "$after6_rules" 2>/dev/null; then
        log_ok "UFW after6.rules: ICMPv6 터널링 방어 블록 존재"
    else
        log_drift "UFW after6.rules: ICMPv6 터널링 방어 블록 누락"
    fi

    # ── (e) after.rules 무결성 — 베이스라인 스냅샷과 블록 내용 비교 ──────────
    local after_baseline="${BASELINE_DIR}/tunnel_ufw_after_rules_baseline.txt"
    if [[ -f "$after_baseline" ]] && ! grep -q '(없음)' "$after_baseline" 2>/dev/null; then
        # 베이스라인의 블록 내용과 현재 after.rules 블록 내용을 diff
        local current_block baseline_block
        current_block=$(grep -A 9999 "${UFW_TUNNEL_MARKER}" "$after_rules" 2>/dev/null \
                        | grep -B 9999 "TUNNEL_HARDENING_BLOCK_END" 2>/dev/null || true)
        baseline_block=$(grep -A 9999 "${UFW_TUNNEL_MARKER}" "$after_baseline" 2>/dev/null \
                         | grep -B 9999 "TUNNEL_HARDENING_BLOCK_END" 2>/dev/null || true)

        if [[ -z "$current_block" ]]; then
            log_drift "UFW after.rules: 터널링 방어 블록 내용 없음 (마커 있어도 블록 비어있음)"
        elif [[ "$current_block" != "$baseline_block" ]]; then
            log_drift "UFW after.rules: 터널링 방어 블록 내용이 베이스라인과 다름 (변조 가능성)"
            if [[ "$MODE" == "auto-restore" ]]; then
                log_warn "  after.rules 블록 복원: ufw reload 로 재적용 시도"
                # after.rules 자체는 유지하고 reload 만 수행
                # (블록 내용이 잘못됐을 경우 01 재실행 필요)
                if ufw reload 2>/dev/null; then
                    log_restore "UFW reload 완료 (after.rules 재적용)"
                else
                    log_fail "UFW reload 실패 — 01 스크립트 재실행 권장"
                fi
            fi
        else
            log_ok "UFW after.rules: 터널링 방어 블록 무결성 정상"
        fi
    fi
}

# =============================================================================
# [7] sudoers NOPASSWD 점검
# =============================================================================
check_sudoers() {
    log_info "===== [7] sudoers NOPASSWD 점검 ====="

    if [[ -f /etc/sudoers ]]; then
        if grep -q 'NOPASSWD' /etc/sudoers 2>/dev/null; then
            log_drift "sudoers에 NOPASSWD 발견!"
            if [[ "$MODE" == "auto-restore" ]]; then
                backup_before_restore /etc/sudoers
                sed -i 's/^\(%sudo[[:space:]]\+ALL=(ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/' /etc/sudoers
                sed -i 's/^\(%sudo[[:space:]]\+ALL=(ALL:ALL)\)[[:space:]]\+NOPASSWD:[[:space:]]\+ALL/\1 ALL/' /etc/sudoers
                if visudo -c 2>/dev/null; then
                    log_restore "sudoers NOPASSWD 제거"
                else
                    log_fail "sudoers 문법 오류 — 수동 확인 필요"
                fi
            fi
        else
            log_ok "sudoers NOPASSWD 없음"
        fi
    fi

    if [[ -d /etc/sudoers.d ]]; then
        local nopasswd_files
        nopasswd_files=$(grep -rl 'NOPASSWD' /etc/sudoers.d/ 2>/dev/null || true)
        if [[ -n "$nopasswd_files" ]]; then
            while IFS= read -r f; do
                log_drift "sudoers.d에 NOPASSWD 파일 발견: $f"
            done <<< "$nopasswd_files"
        else
            log_ok "sudoers.d NOPASSWD 없음"
        fi
    fi
}

# =============================================================================
# [8] 비밀번호 없는 계정 점검
# =============================================================================
check_empty_passwords() {
    log_info "===== [8] 비밀번호 없는 계정 점검 ====="

    local empty_pw_users
    empty_pw_users=$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null || true)

    if [[ -n "$empty_pw_users" ]]; then
        while IFS= read -r user; do
            log_drift "비밀번호 없는 계정: $user"
            if [[ "$MODE" == "auto-restore" ]]; then
                passwd -l "$user" 2>/dev/null && \
                    log_restore "계정 잠금: $user" || \
                    log_fail "계정 잠금 실패: $user"
            fi
        done <<< "$empty_pw_users"
    else
        log_ok "비밀번호 없는 계정 없음"
    fi
}

# =============================================================================
# [9] 의심스러운 파일 탐지
# =============================================================================
check_suspicious_files() {
    log_info "===== [9] 의심스러운 파일 탐지 ====="

    local suspicious_dirs=(/bin /sbin /usr/bin /usr/sbin /usr/lib/systemd)
    for dir in "${suspicious_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local hidden_files
            hidden_files=$(find "$dir" -maxdepth 2 -name '.*' -type f -executable 2>/dev/null || true)
            if [[ -n "$hidden_files" ]]; then
                while IFS= read -r f; do
                    log_drift "숨겨진 실행 파일: $f"
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
                    log_drift "임시 디렉토리 실행 파일: $f"
                done <<< "$exec_files"
            fi
        fi
    done

    local unusual_authkeys
    unusual_authkeys=$(find /usr/sbin /sbin /bin -name 'authorized_keys' -type f 2>/dev/null || true)
    if [[ -n "$unusual_authkeys" ]]; then
        while IFS= read -r f; do
            log_drift "비정상 위치 authorized_keys: $f"
        done <<< "$unusual_authkeys"
    fi

    log_ok "의심 파일 탐지 완료"
}

# =============================================================================
# [10] auditd 상태 점검
# =============================================================================
check_auditd() {
    log_info "===== [10] auditd 상태 점검 ====="

    if ! command -v auditctl >/dev/null 2>&1; then
        log_warn "auditctl 없음 — auditd 미설치"
        return
    fi

    if systemctl is-active auditd 2>/dev/null | grep -q "active"; then
        log_ok "auditd 서비스 활성"
    else
        log_drift "auditd 서비스 비활성!"
        if [[ "$MODE" == "auto-restore" ]]; then
            systemctl start auditd 2>/dev/null && \
                log_restore "auditd 재시작" || \
                log_fail "auditd 재시작 실패"
        fi
    fi

    local rule_count
    rule_count=$(auditctl -l 2>/dev/null | grep -cv '^No rules' || echo "0")
    local baseline_rule_file="${BASELINE_DIR}/audit_rules_baseline.txt"
    local expected_rules=15
    if [[ -f "$baseline_rule_file" ]]; then
        expected_rules=$(grep -cv '^No rules\|^$' "$baseline_rule_file" 2>/dev/null || echo "15")
        [[ "$expected_rules" -eq 0 ]] && expected_rules=15
    fi
    if [[ "$rule_count" -lt "$expected_rules" ]]; then
        log_drift "auditd 감사 룰 부족 (${rule_count}개, 기대: ${expected_rules}+)"
    else
        log_ok "auditd 감사 룰: ${rule_count}개 (기대: ${expected_rules}+)"
    fi

    local rules_file="/etc/audit/rules.d/99-hardening.rules"
    if [[ ! -f "$rules_file" ]]; then
        log_drift "auditd 하드닝 룰 파일 없음: $rules_file"
    else
        log_ok "auditd 룰 파일 존재: $rules_file"
        # 터널링 방어 auditd 룰 포함 여부 확인 (01 통합본이 추가하는 tunnel_ 키)
        if grep -q 'tunnel_' "$rules_file" 2>/dev/null; then
            log_ok "auditd 터널링 탐지 룰 포함됨 (tunnel_ 키워드 확인)"
        else
            log_drift "auditd 터널링 탐지 룰 누락: $rules_file"
        fi
        # after.rules 변조 감사 룰 포함 여부 (01 통합본 추가 항목)
        if grep -q 'tunnel_ufw_rules' "$rules_file" 2>/dev/null; then
            log_ok "auditd: UFW after.rules 변조 감사 룰 포함됨"
        else
            log_drift "auditd: UFW after.rules 변조 감사 룰 누락 (tunnel_ufw_rules)"
        fi
    fi
}

# =============================================================================
# [11] PAM 패스워드 정책 점검
# =============================================================================
check_pam_policy() {
    log_info "===== [11] PAM 패스워드 정책 점검 ====="

    local passwdqc="/usr/share/pam-configs/passwdqc"
    if [[ -f "$passwdqc" ]]; then
        if grep -q 'pam_passwdqc' "$passwdqc" 2>/dev/null; then
            log_ok "PAM passwdqc 설정 존재"
        else
            log_drift "PAM passwdqc 설정 변조됨"
        fi
    else
        log_drift "PAM passwdqc 설정 파일 없음"
    fi

    local faillock_conf="/etc/security/faillock.conf"
    if [[ -f "$faillock_conf" ]]; then
        if grep -q 'deny' "$faillock_conf" 2>/dev/null; then
            log_ok "faillock deny 설정 존재"
        else
            log_drift "faillock.conf에 deny 설정 없음"
        fi
    else
        log_drift "faillock.conf 파일 없음 — 계정 잠금 정책 미적용"
    fi

    if [[ -f /etc/pam.d/common-auth ]]; then
        if grep -q 'pam_faillock' /etc/pam.d/common-auth 2>/dev/null; then
            log_ok "PAM common-auth에 faillock 적용됨"
        else
            log_drift "PAM common-auth에 faillock 없음"
        fi
    fi
}

# =============================================================================
# [12] cron 디렉토리 권한 점검
# =============================================================================
check_cron_permissions() {
    log_info "===== [12] cron 디렉토리 권한 점검 ====="

    local baseline_file="${BASELINE_DIR}/cron_permissions_baseline.txt"
    if [[ ! -f "$baseline_file" ]]; then
        log_warn "cron 권한 베이스라인 없음 — other 권한 점검으로 폴백"
        for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
                  /etc/cron.monthly /etc/cron.d /etc/crontab; do
            [[ -e "$d" ]] || continue
            local perm
            perm=$(stat -c '%a' "$d" 2>/dev/null)
            if [[ "${perm: -1}" != "0" ]]; then
                log_drift "cron 권한 이상: $d (${perm}) — other 접근 가능"
                if [[ "$MODE" == "auto-restore" ]]; then
                    backup_before_restore "$d"
                    chmod og-rwx "$d" && chown root:root "$d" 2>/dev/null && \
                        log_restore "cron 권한 복원: $d" || \
                        log_fail "cron 권한 복원 실패: $d"
                fi
            else
                log_ok "cron 권한 정상: $d (${perm})"
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
            log_drift "cron 권한 변경: $filepath (기대=${expected_perm}, 현재=${current_perm})"
            if [[ "$MODE" == "auto-restore" ]]; then
                backup_before_restore "$filepath"
                chmod "$expected_perm" "$filepath" 2>/dev/null && \
                    log_restore "cron 권한 복원: $filepath" || \
                    log_fail "cron 권한 복원 실패: $filepath"
            fi
        else
            log_ok "cron 권한 정상: $filepath (${current_perm})"
        fi
    done < "$baseline_file"
}

# =============================================================================
# [13] 커널 모듈 차단 목록 점검
# =============================================================================
check_modprobe_blacklist() {
    log_info "===== [13] 커널 모듈 차단 목록 점검 ====="

    local devsec_conf="/etc/modprobe.d/dev-sec.conf"
    local baseline_file="${BASELINE_DIR}/modprobe_baseline.conf"

    if [[ ! -f "$devsec_conf" ]]; then
        log_drift "커널 모듈 차단 파일 없음: $devsec_conf"
        if [[ "$MODE" == "auto-restore" ]] && [[ -f "$baseline_file" ]]; then
            backup_before_restore "$devsec_conf"
            cp "$baseline_file" "$devsec_conf" && \
                log_restore "modprobe 차단 목록 복원" || \
                log_fail "modprobe 차단 목록 복원 실패"
        fi
        return
    fi

    if [[ -f "$baseline_file" ]]; then
        if ! diff -q "$devsec_conf" "$baseline_file" >/dev/null 2>&1; then
            log_drift "커널 모듈 차단 파일 변조됨"
            if [[ "$MODE" == "auto-restore" ]]; then
                backup_before_restore "$devsec_conf"
                cp "$baseline_file" "$devsec_conf" && \
                    log_restore "modprobe 차단 목록 복원" || \
                    log_fail "modprobe 차단 목록 복원 실패"
            fi
        else
            log_ok "커널 모듈 차단 목록 정상"
        fi
    else
        local required_mods=(cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat usb-storage)
        for mod in "${required_mods[@]}"; do
            if ! grep -q "install ${mod} /bin/true" "$devsec_conf" 2>/dev/null; then
                log_drift "차단 누락 모듈: ${mod}"
            fi
        done
    fi
}

# =============================================================================
# [14] /proc hidepid 점검
#
# 주의: VMware/컨테이너 환경에서는 /proc remount 가 커널 제약으로 실패하는 경우가 있다.
#       이 경우 01 스크립트도 WARN 처리하므로, 여기서도 drift 대신 WARN 으로 격하한다.
#       실제 물리 서버나 KVM 환경에서는 DRIFT 로 정상 탐지된다.
# =============================================================================
check_proc_hidepid() {
    log_info "===== [14] /proc hidepid 점검 ====="

    local hidepid_flag="${BASELINE_DIR}/hidepid_enabled.txt"
    if [[ -f "$hidepid_flag" ]]; then
        local flag_val
        flag_val=$(cat "$hidepid_flag" 2>/dev/null | tr -d '[:space:]')
        if [[ "$flag_val" == "false" ]]; then
            log_skip "/proc hidepid 의도적 비활성 (HIDEPID_ENABLED=false) — 점검 건너뜀"
            return
        fi
    fi

    if mount | grep -q 'hidepid=2'; then
        log_ok "/proc hidepid=2 적용 중"
        return
    fi

    # hidepid 미적용: 가상화/컨테이너 환경 여부를 먼저 판별
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
        # 가상화 환경: remount 가 실패할 수 있으므로 WARN 으로 격하
        log_warn "/proc hidepid=2 미적용 (가상화/컨테이너 환경 — remount 제약 가능)"
        if [[ "$MODE" == "auto-restore" ]]; then
            if mount -o remount,hidepid=2 /proc 2>/dev/null; then
                log_restore "/proc hidepid=2 재적용 성공"
            else
                log_warn "/proc hidepid=2 재적용 실패 — 가상화 환경에서는 재부팅 후 fstab 적용 필요"
            fi
        fi
    else
        # 물리 서버: 실제 drift
        log_drift "/proc hidepid=2 해제됨!"
        if [[ "$MODE" == "auto-restore" ]]; then
            mount -o remount,hidepid=2 /proc 2>/dev/null && \
                log_restore "/proc hidepid=2 재적용" || \
                log_fail "/proc hidepid=2 재적용 실패"
        fi
    fi
}

# =============================================================================
# [15] SSH 설정 점검
# =============================================================================
check_ssh_config() {
    log_info "===== [15] SSH 설정 점검 ====="

    if ! command -v sshd >/dev/null 2>&1; then
        log_warn "sshd 미설치"
        return
    fi

    if ! systemctl is-active sshd 2>/dev/null | grep -q "active" && \
       ! systemctl is-active ssh 2>/dev/null | grep -q "active"; then
        log_warn "SSH 서비스 비활성"
    fi

    if [[ ! -f /etc/ssh/sshd_config.d/99-hardening.conf ]]; then
        log_drift "SSH 하드닝 설정 파일 없음: /etc/ssh/sshd_config.d/99-hardening.conf"
    fi

    local baseline_file="${BASELINE_DIR}/sshd_effective_baseline.txt"
    if [[ ! -f "$baseline_file" ]]; then
        log_warn "SSH 베이스라인 없음 — 건너뜀"
        return
    fi

    local effective
    effective=$(sshd -T 2>/dev/null | sort)
    if [[ -z "$effective" ]]; then
        log_warn "sshd -T 실행 실패"
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
            log_drift "SSH ${key}: 기대=${baseline_val}, 현재=${current_val:-없음}"
            if [[ "$MODE" == "auto-restore" ]]; then
                local hardened_conf="/etc/ssh/sshd_config.d/99-hardening.conf"
                backup_before_restore "$hardened_conf"
                {
                    echo "# === 보안 하드닝 (auto-restore: $(date '+%Y%m%d_%H%M%S')) ==="
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
                    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
                    log_restore "SSH drop-in 재생성 및 reload 완료"
                else
                    rm -f "${hardened_conf}.tmp"
                    local bk_file="${RESTORE_BACKUP_DIR}/$(echo "$hardened_conf" | tr '/' '_')"
                    if [[ -f "$bk_file" ]]; then
                        cp "$bk_file" "$hardened_conf" 2>/dev/null
                        if sshd -t 2>/dev/null; then
                            systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
                            log_warn "SSH drop-in 재생성 실패 — 백업에서 롤백 성공"
                        else
                            log_fail "SSH 롤백 후에도 sshd -t 미통과 — 수동 확인 필요"
                        fi
                    else
                        log_fail "SSH drop-in 재생성 실패 — 백업 파일 없음, 수동 확인 필요"
                    fi
                fi
            fi
        else
            log_ok "SSH ${key}=${current_val}"
        fi
    done
}

# =============================================================================
# [16] 악성 cron/at 작업 탐지
# =============================================================================
check_malicious_cron() {
    log_info "===== [16] 악성 cron/at 작업 탐지 ====="

    local crontab_dir="/var/spool/cron/crontabs"
    if [[ -d "$crontab_dir" ]]; then
        for ct in "$crontab_dir"/*; do
            [[ -f "$ct" ]] || continue
            local user
            user=$(basename "$ct")
            if [[ "$user" != "root" ]]; then
                if echo ",${CRONTAB_ALLOWLIST}," | grep -q ",${user},"; then
                    log_skip "crontab allowlist 계정: ${user}"
                else
                    log_drift "비root 사용자 crontab 발견: ${user}"
                    log_info "  내용: $(head -5 "$ct" 2>/dev/null)"
                fi
            fi
            if grep -qiE '(nc\s+-[elp]|ncat|bash\s+-i|/dev/tcp|python.*socket|wget.*\|.*sh|curl.*\|.*sh|mkfifo|reverse|shell)' "$ct" 2>/dev/null; then
                log_drift "crontab 의심 명령 탐지 (${user}): $(grep -iE '(nc |ncat|bash -i|/dev/tcp|python.*socket|wget.*sh|curl.*sh|mkfifo|reverse|shell)' "$ct" 2>/dev/null | head -3)"
            fi
        done
    fi

    if [[ -d /etc/cron.d ]]; then
        for f in /etc/cron.d/*; do
            [[ -f "$f" ]] || continue
            if grep -qiE '(nc\s+-[elp]|ncat|bash\s+-i|/dev/tcp|python.*socket|wget.*\|.*sh|curl.*\|.*sh|mkfifo)' "$f" 2>/dev/null; then
                log_drift "/etc/cron.d 의심 파일: $f"
            fi
        done
    fi

    if command -v atq >/dev/null 2>&1; then
        local at_count
        at_count=$(atq 2>/dev/null | wc -l)
        if [[ "$at_count" -gt 0 ]]; then
            log_drift "대기 중인 at 작업 ${at_count}건 발견"
            atq 2>/dev/null | while read -r line; do
                log_info "  at: $line"
            done
        else
            log_ok "대기 중인 at 작업 없음"
        fi
    fi

    log_ok "cron/at 점검 완료"
}

# =============================================================================
# [17] 네트워크 리스닝 포트 점검
# =============================================================================
check_network() {
    log_info "===== [17] 네트워크 리스닝 포트 점검 ====="

    local baseline_file="${BASELINE_DIR}/listening_ports_baseline.txt"
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
                log_drift "새 리스닝 포트: ${addr} (${proc_info})"
            done <<< "$new_ports"
        else
            log_ok "베이스라인 대비 새 리스닝 포트 없음"
        fi
    fi

    local suspect_ports=(4444 5555 6666 7777 8888 9999 1234 31337 12345 54321)
    for port in "${suspect_ports[@]}"; do
        if echo ",${WHITELISTED_PORTS}," | grep -q ",${port},"; then
            continue
        fi
        if echo "$current_ports" | grep -q ":${port} " 2>/dev/null; then
            local proc
            proc=$(echo "$current_ports" | grep ":${port} " | awk '{print $NF}')
            log_drift "의심 포트 리스닝: :${port} (${proc})"
        fi
    done

    local ext_conns
    ext_conns=$(ss -tnp state established 2>/dev/null | \
        awk 'NR>1 && $5 !~ /^(127\.|::1|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|169\.254\.)/ {print $4, $5, $NF}' | head -20)
    if [[ -n "$ext_conns" ]]; then
        log_info "외부 ESTABLISHED 연결:"
        while IFS= read -r line; do
            log_info "  $line"
        done <<< "$ext_conns"
    fi
}

# =============================================================================
# [18] 의심 프로세스 점검
# =============================================================================
check_suspicious_processes() {
    log_info "===== [18] 의심 프로세스 점검 ====="

    local deleted_procs
    deleted_procs=$(ls -la /proc/*/exe 2>/dev/null | grep '(deleted)' | grep -v '/memfd:' || true)
    if [[ -n "$deleted_procs" ]]; then
        while IFS= read -r line; do
            log_drift "삭제된 바이너리 실행 중: $line"
        done <<< "$deleted_procs"
    else
        log_ok "삭제된 바이너리 실행 프로세스 없음"
    fi

    local suspect_patterns='(cryptominer|xmrig|kinsing|kdevtmpfsi|kthreaddi|\.hidden|/dev/shm/|/tmp/\.)'
    local suspect_procs
    suspect_procs=$(ps auxww 2>/dev/null | grep -iE "$suspect_patterns" | grep -v grep || true)
    if [[ -n "$suspect_procs" ]]; then
        while IFS= read -r line; do
            log_drift "의심 프로세스: $line"
        done <<< "$suspect_procs"
    fi

    local tmp_procs
    tmp_procs=$(ls -la /proc/*/exe 2>/dev/null | grep -E '(/tmp/|/dev/shm/|/var/tmp/)' || true)
    if [[ -n "$tmp_procs" ]]; then
        while IFS= read -r line; do
            log_drift "임시 경로에서 실행 중: $line"
        done <<< "$tmp_procs"
    else
        log_ok "임시 경로 실행 프로세스 없음"
    fi
}

# =============================================================================
# [19] UID 0 백도어 계정 점검
# =============================================================================
check_uid0_accounts() {
    log_info "===== [19] UID 0 백도어 계정 점검 ====="

    local uid0_users
    uid0_users=$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null)
    local uid0_count=0

    while IFS= read -r user; do
        uid0_count=$((uid0_count + 1))
        if [[ "$user" != "root" ]]; then
            log_drift "root 외 UID 0 계정 발견: ${user} (백도어 가능성!)"
        fi
    done <<< "$uid0_users"

    if [[ "$uid0_count" -le 1 ]]; then
        log_ok "UID 0 계정: root만 존재"
    fi
}

# =============================================================================
# [20] login.defs 패스워드 에이징 점검
# =============================================================================
check_login_defs() {
    log_info "===== [20] login.defs 패스워드 에이징 점검 ====="

    local login_defs="/etc/login.defs"
    if [[ ! -f "$login_defs" ]]; then
        log_warn "login.defs 없음"
        return
    fi

    local baseline_file="${BASELINE_DIR}/login_defs_baseline.txt"
    if [[ ! -f "$baseline_file" ]]; then
        log_warn "login.defs 베이스라인 없음 — 건너뜀"
        return
    fi

    while IFS='=' read -r key expected_val; do
        [[ -z "$key" || "$key" == \#* ]] && continue
        local current_val
        current_val=$(awk -v k="$key" '$1==k {print $2}' "$login_defs" 2>/dev/null)

        if [[ -z "$current_val" ]]; then
            log_drift "login.defs ${key}: 기대=${expected_val}, 현재=미설정"
        elif [[ "$current_val" != "$expected_val" ]]; then
            log_drift "login.defs ${key}: 기대=${expected_val}, 현재=${current_val}"
            if [[ "$MODE" == "auto-restore" ]]; then
                backup_before_restore "$login_defs"
                sed -i "s/^\([[:space:]]*${key}[[:space:]]\+\).*/\1${expected_val}/" "$login_defs" 2>/dev/null && \
                    log_restore "login.defs ${key}=${expected_val} 복원" || \
                    log_fail "login.defs ${key} 복원 실패"
            fi
        else
            log_ok "login.defs ${key}=${current_val}"
        fi
    done < "$baseline_file"
}

# =============================================================================
# [21] 터널링 방어 점검
#
# 01_baseline_hardening_integrated.sh 호환 버전:
#   iptables 규칙은 UFW after.rules 로 관리되므로 점검 구조를 다음과 같이 재편한다.
#
#   (a) UFW after.rules 마커 / 블록 존재 → [6] check_ufw 에서 이미 수행
#       여기서는 "런타임 iptables에 실제 반영됐는가"를 확인한다.
#
#   (b) 런타임 ICMP 터널링 방어 규칙 확인
#       after.rules 가 ufw reload 없이 소실됐을 경우 탐지 → auto-restore: ufw reload
#
#   (c) 런타임 DNS 터널링 방어 규칙 확인 + resolv.conf 잠금
#
#   (d) 런타임 SOCKS5 터널링 방어 규칙 확인
#       string 모듈 없으면 SKIP (after.rules에 기록만 있고 런타임 미반영 가능)
#
#   (e) 터널링 도구 프로세스 탐지 (01의 TUNNEL_TOOL_PROCS 동일 목록)
#
#   (f) auditd 터널링 탐지 룰 확인 (tunnel_ 키워드 기반)
#       → check_auditd 에서도 일부 수행; 여기서는 구체적 키 검증
#
#   [복원 전략]
#   - iptables 규칙 소실 → `ufw reload` 로 after.rules 재적용 (개별 -A 삽입 금지)
#   - after.rules 블록 소실 → 01 스크립트 재실행 안내 (이 스크립트로 복원 불가)
#   - resolv.conf 잠금 해제 → chattr +i 재적용
# =============================================================================
check_tunnel_defense() {
    log_info "===== [21] 터널링 방어 점검 (UFW after.rules 통합 버전) ====="

    local _tunnel_reload_needed=false  # ufw reload 가 필요한 경우 모아서 1회만 실행

    # ── (a) 런타임 ICMP 터널링 방어 규칙 확인 ────────────────────────────────
    log_info "  [21-a] ICMP 터널링 방어 런타임 규칙 확인"

    # 01이 after.rules 에 삽입하는 comment 마커로 확인
    # ufw-before-input / ufw-before-output 체인에 존재해야 함
    local icmp_in_ok=false icmp_out_ok=false icmp_echo_ok=false

    if iptables -S ufw-before-input 2>/dev/null | grep -q 'TUNNEL_ICMP_LARGE_IN'; then
        log_ok "  ICMP 대형 패킷 인바운드 차단 규칙 활성"
        icmp_in_ok=true
    else
        log_drift "  ICMP 대형 패킷 인바운드 차단 규칙 없음 (UFW after.rules 미반영)"
        _tunnel_reload_needed=true
    fi

    if iptables -S ufw-before-output 2>/dev/null | grep -q 'TUNNEL_ICMP_LARGE_OUT'; then
        log_ok "  ICMP 대형 패킷 아웃바운드 차단 규칙 활성"
        icmp_out_ok=true
    else
        log_drift "  ICMP 대형 패킷 아웃바운드 차단 규칙 없음"
        _tunnel_reload_needed=true
    fi

    if iptables -S ufw-before-output 2>/dev/null | grep -q 'TUNNEL_ICMP_ECHO_OUT'; then
        log_ok "  아웃바운드 ICMP echo-request 차단 규칙 활성"
        icmp_echo_ok=true
    else
        log_drift "  아웃바운드 ICMP echo-request 차단 규칙 없음"
        _tunnel_reload_needed=true
    fi

    # ICMPv6 확인
    if command -v ip6tables &>/dev/null; then
        if ip6tables -S ufw6-before-input 2>/dev/null | grep -q 'TUNNEL_ICMP6_LARGE_IN'; then
            log_ok "  ICMPv6 대형 패킷 차단 규칙 활성"
        else
            log_drift "  ICMPv6 대형 패킷 차단 규칙 없음"
            _tunnel_reload_needed=true
        fi
    fi

    # ── (b) 런타임 DNS 터널링 방어 규칙 확인 ─────────────────────────────────
    log_info "  [21-b] DNS 터널링 방어 런타임 규칙 확인"

    if iptables -S ufw-before-output 2>/dev/null | grep -q 'TUNNEL_DNS_TCP_OUT'; then
        log_ok "  DNS over TCP 아웃바운드 차단 규칙 활성"
    else
        log_drift "  DNS over TCP 아웃바운드 차단 규칙 없음"
        _tunnel_reload_needed=true
    fi

    if iptables -S ufw-before-input 2>/dev/null | grep -q 'TUNNEL_DNS_LARGE_RESP'; then
        log_ok "  대형 DNS 응답 로깅 규칙 활성"
    else
        log_drift "  대형 DNS 응답 로깅 규칙 없음"
        _tunnel_reload_needed=true
    fi

    # resolv.conf 불변 잠금 확인
    if command -v lsattr &>/dev/null; then
        if lsattr /etc/resolv.conf 2>/dev/null | grep -q '^....i'; then
            log_ok "  /etc/resolv.conf 불변 잠금(chattr +i) 적용 중"
        else
            # systemd-resolved 심볼릭 링크인 경우 chattr +i 불필요
            if [[ -L /etc/resolv.conf ]]; then
                log_ok "  /etc/resolv.conf 심볼릭 링크 (systemd-resolved 관리 — chattr 불필요)"
            else
                log_drift "  /etc/resolv.conf 불변 잠금 해제됨"
                if [[ "$MODE" == "auto-restore" ]]; then
                    chattr +i /etc/resolv.conf 2>/dev/null && \
                        log_restore "  resolv.conf 불변 잠금 재적용" || \
                        log_fail "  resolv.conf 불변 잠금 재적용 실패"
                fi
            fi
        fi
    fi

    # resolv.conf 스냅샷과 현재 내용 비교 (내용 변조 탐지)
    local resolv_baseline="${BASELINE_DIR}/tunnel_resolv_baseline.txt"
    if [[ -f "$resolv_baseline" ]]; then
        # 스냅샷의 실제 resolv.conf 내용 부분만 추출 (# 주석 이후, "chattr 속성:" 이전)
        local baseline_resolv_content
        baseline_resolv_content=$(awk '/^# chattr 속성:/{exit} /^#/{next} {print}' \
                                   "$resolv_baseline" 2>/dev/null | grep -v '^$' | sort || true)
        local current_resolv_content
        current_resolv_content=$(grep -v '^#' /etc/resolv.conf 2>/dev/null | grep -v '^$' | sort || true)

        if [[ -n "$baseline_resolv_content" ]] && \
           [[ "$baseline_resolv_content" != "$current_resolv_content" ]]; then
            log_drift "  /etc/resolv.conf 내용이 베이스라인과 다름 (DNS 리다이렉트 가능성)"
            log_info "  베이스라인: $(echo "$baseline_resolv_content" | head -3)"
            log_info "  현재:       $(echo "$current_resolv_content" | head -3)"
        else
            log_ok "  /etc/resolv.conf 내용 정상"
        fi
    fi

    # ── (c) 런타임 SOCKS5 터널링 방어 규칙 확인 ──────────────────────────────
    log_info "  [21-c] SOCKS5 터널링 방어 런타임 규칙 확인"

    if iptables -m string --help 2>&1 | grep -q "string"; then
        if iptables -S ufw-before-input 2>/dev/null | grep -q 'TUNNEL_SOCKS5_NOAUTH_IN'; then
            log_ok "  SOCKS5 No-Auth 핸드셰이크 인바운드 차단 규칙 활성"
        else
            log_drift "  SOCKS5 No-Auth 핸드셰이크 인바운드 차단 규칙 없음"
            _tunnel_reload_needed=true
        fi

        if iptables -S ufw-before-output 2>/dev/null | grep -q 'TUNNEL_SOCKS5_CONN_OUT'; then
            log_ok "  SOCKS5 CONNECT 아웃바운드 차단 규칙 활성"
        else
            log_drift "  SOCKS5 CONNECT 아웃바운드 차단 규칙 없음"
            _tunnel_reload_needed=true
        fi
    else
        log_skip "  iptables string 모듈 없음 — SOCKS5 패턴 매칭 규칙 점검 건너뜀"
    fi

    # unprivileged_userns_clone sysctl 확인 (SOCKS5-over-VPN 방지)
    # 주의: Ubuntu 22.04+ 에서는 이 파라미터를 AppArmor 가 관리하며,
    #       재부팅 후 커널 기본값(1)으로 복귀할 수 있다.
    #       sysctl.d 에 설정이 있어도 AppArmor 정책이 우선하는 경우가 있으므로
    #       1 인 경우 DRIFT 대신 WARN 으로 격하한다.
    local userns_val
    userns_val=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo "N/A")
    if [[ "$userns_val" == "0" ]]; then
        log_ok "  kernel.unprivileged_userns_clone=0 (TUN 생성 제한 적용)"
    elif [[ "$userns_val" == "N/A" ]]; then
        log_info "  kernel.unprivileged_userns_clone 없음 (커널 미지원 — 정상)"
    elif [[ "$userns_val" == "1" ]]; then
        # Ubuntu 22.04+ 에서는 AppArmor 로 namespace 격리를 관리하므로
        # 이 값이 1 이어도 실제 보안 수준은 유지될 수 있음
        log_warn "  kernel.unprivileged_userns_clone=1 (Ubuntu AppArmor 관리 환경에서는 정상일 수 있음)"
        log_warn "  sysctl.d 파일에 설정이 있는지 확인: grep -r unprivileged_userns /etc/sysctl.d/"
        if [[ "$MODE" == "auto-restore" ]]; then
            if sysctl -w kernel.unprivileged_userns_clone=0 >/dev/null 2>&1; then
                log_restore "  kernel.unprivileged_userns_clone=0 런타임 적용 (재부팅 후 원복 가능)"
            else
                log_warn "  kernel.unprivileged_userns_clone=0 적용 실패 — AppArmor 정책 확인 필요"
            fi
        fi
    else
        log_drift "  kernel.unprivileged_userns_clone=${userns_val} (기대: 0)"
        if [[ "$MODE" == "auto-restore" ]]; then
            sysctl -w kernel.unprivileged_userns_clone=0 >/dev/null 2>&1 && \
                log_restore "  kernel.unprivileged_userns_clone=0 복원" || \
                log_fail "  kernel.unprivileged_userns_clone 복원 실패"
        fi
    fi

    # ── 런타임 규칙 소실 시 ufw reload 로 일괄 복원 ──────────────────────────
    # 개별 iptables -A 를 직접 삽입하지 않고 after.rules 재적용으로 일원화
    if [[ "$_tunnel_reload_needed" == true ]]; then
        if [[ "$MODE" == "auto-restore" ]]; then
            # after.rules 에 블록이 존재해야만 reload 가 의미있음
            if grep -q "${UFW_TUNNEL_MARKER}" /etc/ufw/after.rules 2>/dev/null; then
                log_info "  런타임 터널링 규칙 소실 탐지 — ufw reload 로 after.rules 재적용"
                if ufw reload 2>/dev/null; then
                    log_restore "  ufw reload 완료 — ICMP/DNS/SOCKS5 터널링 방어 규칙 복원"
                else
                    log_fail "  ufw reload 실패 — UFW 상태 확인 필요"
                fi
            else
                log_fail "  after.rules 터널링 블록 없음 — 01 스크립트 재실행 필요"
                log_fail "  sudo bash 01_baseline_hardening_integrated.sh"
            fi
        else
            log_info "  (check-only 모드) 런타임 규칙 복원: sudo $SCRIPT_NAME --auto-restore"
        fi
    fi

    # ── (d) 터널링 도구 프로세스 탐지 ───────────────────────────────────────
    # 01의 TUNNEL_TOOL_PROCS 와 동일한 목록
    log_info "  [21-d] 터널링 도구 프로세스 탐지"
    local tunnel_procs=(
        # ICMP 터널링
        ptunnel ptunnel-ng icmptunnel icmpsh pingtunnel
        # DNS 터널링
        iodine iodined dns2tcp dnscat dnscat2 dnscapy dnstunnel
        # 범용 터널링
        chisel ligolo frpc ngrok inlets bore gost
        # SSH 기반
        autossh sshuttle
    )
    local _proc_found=false
    for proc in "${tunnel_procs[@]}"; do
        if pgrep -x "$proc" &>/dev/null; then
            local pids
            pids=$(pgrep -x "$proc" | tr '\n' ',' | sed 's/,$//')
            log_drift "  터널링 도구 실행 중: ${proc} (PID: ${pids})"
            _proc_found=true
        fi
    done

    # TUN 디바이스 점유 프로세스 탐지
    if ls /proc/*/fd 2>/dev/null | xargs -I{} readlink {} 2>/dev/null \
       | grep -q "net/tun" 2>/dev/null; then
        log_drift "  TUN 디바이스를 점유한 프로세스 탐지됨 (터널링 가능성)"
        _proc_found=true
    fi

    # 외부 직접 DNS 쿼리 탐지
    local dns_non_std
    dns_non_std=$(ss -unp 2>/dev/null \
                  | awk '$5 ~ /:53$/ && $4 !~ /^(127\.|10\.|172\.|192\.168\.)/ {print}' \
                  || true)
    if [[ -n "$dns_non_std" ]]; then
        log_drift "  비내부망 직접 DNS 쿼리 탐지 (DNS 터널링 가능성):"
        echo "$dns_non_std" | while IFS= read -r line; do
            log_info "    → $line"
        done
        _proc_found=true
    fi

    [[ "$_proc_found" == false ]] && log_ok "  탐지된 터널링 도구/TUN 프로세스 없음"

    # ── (e) auditd 터널링 탐지 룰 구체적 확인 ───────────────────────────────
    # 버그 수정: declare -A + auditctl -l 변수 저장 방식은
    #   · immutable 모드(-e 2)에서 auditctl -l 이 stderr 로만 경고를 내고
    #     stdout 이 비어있으면 전부 DRIFT 오탐 발생
    #   · declare -A 키 순서가 비결정적이라 일부 환경에서 누락 가능
    # → 룰 파일(/etc/audit/rules.d/99-hardening.rules)을 직접 grep 하는 방식으로 교체
    #   파일 기반 확인이 실제 적용 여부와 다를 수 있으나,
    #   auditctl -l 출력이 불안정한 환경에서 오탐을 방지하는 것을 우선한다.
    #   실제 로드 여부는 check_auditd [10] 의 rule_count 비교로 보완한다.
    log_info "  [21-e] auditd 터널링 탐지 룰 확인"
    if command -v auditctl &>/dev/null; then
        local rules_file="/etc/audit/rules.d/99-hardening.rules"

        if [[ ! -f "$rules_file" ]]; then
            log_drift "  auditd 룰 파일 없음: ${rules_file}"
        else
            # 키워드 → 설명 쌍을 배열 2개로 관리 (연관배열 비결정성 회피)
            local audit_keys=(
                tunnel_icmp
                tunnel_dns
                tunnel_dns_config
                tunnel_ufw_rules
                tunnel_tun_create
                tunnel_raw_socket
                tunnel_socks5
                tunnel_net_config
            )
            local audit_descs=(
                "ICMP 터널링 도구 감사"
                "DNS 터널링 도구 감사"
                "resolv.conf 변조 감사"
                "UFW after.rules 변조 감사"
                "TUN/TAP 생성 감사"
                "raw socket 생성 감사"
                "SOCKS5 도구 감사"
                "네트워크 인터페이스 변경 감사"
            )

            local _audit_all_ok=true
            for i in "${!audit_keys[@]}"; do
                local key="${audit_keys[$i]}"
                local desc="${audit_descs[$i]}"
                if grep -q "\-k ${key}" "$rules_file" 2>/dev/null; then
                    log_ok "  auditd 룰 OK: ${desc} (${key})"
                else
                    log_drift "  auditd 룰 누락: ${desc} (${key})"
                    _audit_all_ok=false
                fi
            done

            # 실제 로드 상태도 추가 확인 (auditctl -l 이 신뢰 가능한 경우에만)
            local audit_runtime
            audit_runtime=$(auditctl -l 2>/dev/null || true)
            if [[ -n "$audit_runtime" ]]; then
                local loaded_tunnel_count
                loaded_tunnel_count=$(echo "$audit_runtime" | grep -c '\-k tunnel_' || true)
                if [[ "$loaded_tunnel_count" -gt 0 ]]; then
                    log_ok "  auditd 런타임 터널링 룰 로드 확인: ${loaded_tunnel_count}개"
                else
                    log_warn "  auditd 런타임에 tunnel_ 룰이 없음 — augenrules 재실행 필요할 수 있음"
                fi
            else
                log_warn "  auditd auditctl -l 출력 없음 (immutable 모드 또는 서비스 비활성)"
            fi
        fi
    else
        log_skip "  auditctl 없음 — auditd 터널링 룰 확인 불가"
    fi

    # ── (f) 터널링 도구 실행 파일 잔존 여부 ─────────────────────────────────
    log_info "  [21-f] 터널링 도구 실행 파일 잔존 확인"
    local tunnel_bins=(
        /usr/sbin/iodined /usr/bin/iodine
        /usr/bin/dns2tcp  /usr/bin/dnscat
        /usr/local/bin/chisel   /usr/local/bin/gost
        /usr/local/bin/ligolo   /usr/local/bin/frpc
        /usr/local/bin/bore     /usr/local/bin/inlets
        /usr/local/sbin/ptunnel /usr/local/sbin/ptunnel-ng
        /usr/local/bin/dnscat2
    )
    local _bin_found=false
    for bin in "${tunnel_bins[@]}"; do
        if [[ -f "$bin" ]]; then
            log_drift "  터널링 도구 실행 파일 잔존: $bin"
            _bin_found=true
            if [[ "$MODE" == "auto-restore" ]]; then
                rm -f "$bin" 2>/dev/null && \
                    log_restore "  실행 파일 삭제: $bin" || \
                    { chmod a-x "$bin" 2>/dev/null && \
                      log_restore "  실행 권한 제거 (삭제 실패): $bin" || \
                      log_fail "  삭제/권한 제거 모두 실패: $bin"; }
            fi
        fi
    done
    [[ "$_bin_found" == false ]] && log_ok "  잔존 터널링 도구 실행 파일 없음"
}

# =============================================================================
# [22] 알림 전송
# =============================================================================
send_alert() {
    if [[ $DRIFT_COUNT -gt 0 ]]; then
        logger -t "hardening-check" -p auth.warning \
            "DRIFT DETECTED: host=${HOSTNAME}, drifts=${DRIFT_COUNT}, mode=${MODE}" 2>/dev/null || true
    fi

    local webhook_url="${HARDENING_WEBHOOK_URL:-}"
    if [[ -n "$webhook_url" ]] && [[ $DRIFT_COUNT -gt 0 ]]; then
        local payload
        payload="{\"text\":\"[하드닝 점검 경고] 호스트: ${HOSTNAME}, drift: ${DRIFT_COUNT}건, 모드: ${MODE}, 시각: $(date '+%Y-%m-%d %H:%M:%S')\"}"
        curl -s -X POST -H 'Content-Type: application/json' -d "$payload" "$webhook_url" >/dev/null 2>&1 || true
        log_info "webhook 알림 전송 시도"
    fi
}

# =============================================================================
# [오래된 복원 백업 정리]
# =============================================================================
cleanup_old_backups() {
    log_info "===== 오래된 복원 백업 정리 (30일+) ====="
    local old_dirs
    old_dirs=$(find /var/backups -maxdepth 1 -name 'hardening_restore_*' -type d -mtime +30 2>/dev/null || true)
    if [[ -n "$old_dirs" ]]; then
        while IFS= read -r d; do
            rm -rf "$d"
            log_ok "오래된 복원 백업 삭제: $d"
        done <<< "$old_dirs"
    else
        log_info "정리할 오래된 복원 백업 없음"
    fi
}

# =============================================================================
# [요약 리포트]
# =============================================================================
print_summary() {
    echo ""
    echo "============================================================"
    echo " 점검 결과 요약"
    echo "============================================================"
    echo " 호스트:     ${HOSTNAME}"
    echo " 실행 시각:  $(date '+%Y-%m-%d %H:%M:%S')"
    echo " 동작 모드:  ${MODE}"
    echo " 베이스라인: ${BASELINE_DIR}"
    echo "------------------------------------------------------------"
    echo " 변경(drift) 탐지:  ${DRIFT_COUNT} 건"
    if [[ "$MODE" == "auto-restore" ]]; then
        echo " 자동 복원 성공:    ${RESTORE_COUNT} 건"
        echo " 복원 실패:         ${FAIL_COUNT} 건"
    fi
    echo "------------------------------------------------------------"
    if [[ $DRIFT_COUNT -eq 0 ]]; then
        echo " [결과] 베이스라인 유지 — 이상 없음"
    elif [[ "$MODE" == "check-only" ]]; then
        echo " [결과] ${DRIFT_COUNT}건 변경 탐지됨"
        echo "         복원하려면: sudo $SCRIPT_NAME --auto-restore"
    else
        local remaining=$((DRIFT_COUNT - RESTORE_COUNT))
        echo " [결과] ${RESTORE_COUNT}건 복원, ${remaining}건 수동 확인 필요"
    fi
    echo "============================================================"
    echo " 로그: ${LOGFILE}"
    echo "============================================================"
}

# =============================================================================
# [메인]
# =============================================================================
main() {
    log_info "============================================================"
    log_info "베이스라인 점검 시작: 호스트=${HOSTNAME}, 모드=${MODE}"
    log_info "============================================================"

    check_environment
    check_prerequisites

    check_sysctl               # [1]
    check_file_permissions     # [2]
    check_suid_files           # [3]
    check_disabled_services    # [4]
    check_login_accounts       # [5]
    check_ufw                  # [6] ← after.rules 터널링 블록 점검 포함
    check_sudoers              # [7]
    check_empty_passwords      # [8]
    check_suspicious_files     # [9]
    check_auditd               # [10] ← tunnel_ufw_rules 키 점검 포함
    check_pam_policy           # [11]
    check_cron_permissions     # [12]
    check_modprobe_blacklist   # [13]
    check_proc_hidepid         # [14]
    check_ssh_config           # [15]
    check_malicious_cron       # [16]
    check_network              # [17]
    check_suspicious_processes # [18]
    check_uid0_accounts        # [19]
    check_login_defs           # [20]
    check_tunnel_defense       # [21] ← UFW after.rules 통합 버전

    cleanup_old_backups
    send_alert
    print_summary
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@" 2>&1 | tee -a "$LOGFILE"
fi
