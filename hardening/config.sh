#!/usr/bin/env bash
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║                    시스템 하드닝 설정 파일 (config.sh)                      ║
# ║                                                                           ║
# ║  이 파일은 하드닝 스크립트의 모든 설정을 한곳에서 관리합니다.                    ║
# ║  lib/ 디렉토리의 스크립트는 직접 수정하지 마세요.                              ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
#
# ─────────────────────────────────────────────────────────────────────────────
# 빠른 설정 가이드
# ─────────────────────────────────────────────────────────────────────────────
#
#  [권장] Ansible 2단계 워크플로:
#    1단계(FAM): playbook_discover.yml → host_vars 자동 생성
#    2단계(본훈련): playbook_harden.yml → host_vars 기반 하드닝
#    → 이 경우 CUSTOM_ALLOWED_PORTS가 자동 설정되며 HARDENING_PROFILE은 무시됩니다.
#
#  [수동 실행] CUSTOM_ALLOWED_PORTS 또는 HARDENING_PROFILE 사용:
#    - CUSTOM_ALLOWED_PORTS가 설정되면 해당 포트만 허용 (프로파일 무시)
#    - CUSTOM_ALLOWED_PORTS가 비어있으면 HARDENING_PROFILE 폴백
#
#  1. SSH 키가 없으면 SSH_PASSWORD_AUTH를 "yes"로 유지
#     - "no"로 설정하면 키 없이는 접속 불가!
#
#  2. 라우터/게이트웨이에서는 SYSCTL_DISABLE_IP_FORWARD를 "false"로 설정
#
#  3. 환경변수로 값 오버라이드 가능 (Ansible 등에서 활용)
#     예: CUSTOM_ALLOWED_PORTS="22/tcp 80/tcp 443/tcp" ./01_baseline_hardening.sh
#
#  4. 설정 변경 후 반드시 bash -n config.sh 로 문법 검증
#
# ─────────────────────────────────────────────────────────────────────────────


# ═══════════════════════════════════════════════════════════════════════════
# 인바운드 허용 포트 (주 설정)
# ═══════════════════════════════════════════════════════════════════════════
# 허용할 포트를 공백 구분으로 지정하세요. (예: "22/tcp 80/tcp 443/tcp")
# 이 값이 설정되면 HARDENING_PROFILE은 무시됩니다.
# Ansible host_vars 모드에서는 이 값이 자동으로 채워집니다.
# SSH 포트는 자동 감지되어 추가되므로 생략해도 됩니다.
CUSTOM_ALLOWED_PORTS="${CUSTOM_ALLOWED_PORTS:-}"


# ═══════════════════════════════════════════════════════════════════════════
# 방화벽 프로파일 (폴백, CUSTOM_ALLOWED_PORTS가 비어있을 때만 사용)
# ═══════════════════════════════════════════════════════════════════════════
# [DEPRECATED] host_vars가 있으면 무시됩니다.
# CUSTOM_ALLOWED_PORTS가 비어있을 때만 폴백으로 사용됩니다.
#   base   : SSH(22)만 인바운드 허용
#   web    : SSH + HTTP(80) + HTTPS(443)
#   ad     : SSH + DNS(53) + Kerberos(88) + LDAP(389,636) + GC(3268,3269)
#   log    : SSH + Syslog(514) + Wazuh(1514,1515,1516)
#   full   : 위 전부
HARDENING_PROFILE="${HARDENING_PROFILE:-base}"


# ═══════════════════════════════════════════════════════════════════════════
# Ansible / 자동화 설정
# ═══════════════════════════════════════════════════════════════════════════

# Ansible 등 자동화 도구로 실행할 때 사용하는 계정명
# 이 계정은 하드닝 중 절대 잠기거나 nologin으로 변경되지 않습니다.
# 비워두면 자동 보호 없음 (수동으로 ACCOUNT_ALLOWLIST에 추가 필요)
ANSIBLE_ACCOUNT="${ANSIBLE_ACCOUNT:-}"

# 하드닝 완료 후 다른 SSH 세션 종료 여부
# Ansible로 실행할 때는 반드시 "false"로 설정하세요!
# Ansible의 SSH 연결이 끊어질 수 있습니다.
KILL_OTHER_SESSIONS="${KILL_OTHER_SESSIONS:-true}"


# ═══════════════════════════════════════════════════════════════════════════
# SSH 설정
# ═══════════════════════════════════════════════════════════════════════════

# root 로그인 허용 방식
# "no": 완전 차단 | "prohibit-password": 키 인증만 허용 | "yes": 허용 (비권장)
SSH_PERMIT_ROOT_LOGIN="${SSH_PERMIT_ROOT_LOGIN:-prohibit-password}"

# 패스워드 인증 허용 여부
# 주의: SSH 키가 등록되지 않은 상태에서 "no"로 설정하면 접속 불가!
# 키가 없으면 스크립트가 자동으로 "yes"를 유지합니다.
SSH_PASSWORD_AUTH="${SSH_PASSWORD_AUTH:-no}"

# 인증 최대 시도 횟수
SSH_MAX_AUTH_TRIES="${SSH_MAX_AUTH_TRIES:-4}"

# 클라이언트 생존 확인 주기 (초)
SSH_CLIENT_ALIVE_INTERVAL="${SSH_CLIENT_ALIVE_INTERVAL:-300}"

# 클라이언트 무응답 허용 횟수 (이 횟수 초과 시 연결 종료)
SSH_CLIENT_ALIVE_COUNT_MAX="${SSH_CLIENT_ALIVE_COUNT_MAX:-2}"

# 로그인 유예 시간 (초). 이 시간 내에 인증 완료해야 함
SSH_LOGIN_GRACE_TIME="${SSH_LOGIN_GRACE_TIME:-60}"


# ═══════════════════════════════════════════════════════════════════════════
# 패스워드 정책
# ═══════════════════════════════════════════════════════════════════════════

# 패스워드 최대 사용 기간 (일)
PASS_MAX_DAYS="${PASS_MAX_DAYS:-90}"

# 패스워드 최소 사용 기간 (일). 변경 후 이 기간 동안 재변경 불가
PASS_MIN_DAYS="${PASS_MIN_DAYS:-7}"

# 패스워드 만료 경고 기간 (일). 만료 전 이 일수부터 경고
PASS_WARN_AGE="${PASS_WARN_AGE:-14}"

# 로그인 재시도 허용 횟수
LOGIN_RETRIES="${LOGIN_RETRIES:-3}"

# 기본 umask 값. 027 = 소유자 rwx, 그룹 rx, 기타 없음
DEFAULT_UMASK="${DEFAULT_UMASK:-027}"


# ═══════════════════════════════════════════════════════════════════════════
# 비활성화할 서비스
# ═══════════════════════════════════════════════════════════════════════════
# 여기 지정된 서비스만 비활성화합니다. 나머지는 건드리지 않습니다.
# 그린팀 서비스(gtmon, fscd 등)는 여기 넣어도 자동으로 보호됩니다.
# 공백 구분으로 서비스명을 나열하세요.
DISABLE_SERVICES="${DISABLE_SERVICES:-avahi-daemon cups cups-browsed bluetooth}"


# ═══════════════════════════════════════════════════════════════════════════
# 차단할 커널 모듈 (Linux only)
# ═══════════════════════════════════════════════════════════════════════════
# 불필요한 파일시스템 및 USB 저장장치 커널 모듈을 차단합니다.
# macOS에서는 무시됩니다.
BLOCKED_MODULES="${BLOCKED_MODULES:-cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat usb-storage}"


# ═══════════════════════════════════════════════════════════════════════════
# SUID 제거 대상
# ═══════════════════════════════════════════════════════════════════════════
# SUID 비트를 제거할 바이너리 경로를 공백 구분으로 지정하세요.
# 존재하지 않는 경로는 자동으로 건너뜁니다.
SUID_REMOVE_TARGETS="${SUID_REMOVE_TARGETS:-/usr/bin/nmap /usr/bin/bash /usr/bin/dash /usr/bin/find /usr/bin/less /usr/bin/pkexec /usr/bin/at /usr/bin/newgrp /usr/bin/chfn /usr/bin/chsh}"


# ═══════════════════════════════════════════════════════════════════════════
# sysctl 보안 설정 on/off
# ═══════════════════════════════════════════════════════════════════════════

# 네트워크 보안 설정 (ICMP redirect 차단, source route 차단 등)
SYSCTL_HARDEN_NETWORK="${SYSCTL_HARDEN_NETWORK:-true}"

# 커널 보안 설정 (ASLR 활성화, sysrq 제한 등)
SYSCTL_HARDEN_KERNEL="${SYSCTL_HARDEN_KERNEL:-true}"

# IP 포워딩 비활성화
# 주의: 라우터나 게이트웨이 역할을 하는 서버에서는 반드시 "false"로 설정하세요!
SYSCTL_DISABLE_IP_FORWARD="${SYSCTL_DISABLE_IP_FORWARD:-true}"


# ═══════════════════════════════════════════════════════════════════════════
# 마운트 하드닝
# ═══════════════════════════════════════════════════════════════════════════

# /dev/shm에 noexec 옵션 적용. 공유 메모리에서 실행 파일 차단
SHM_NOEXEC="${SHM_NOEXEC:-true}"

# /proc에 hidepid=2 적용. 다른 사용자의 프로세스 정보 숨김
HIDEPID_ENABLED="${HIDEPID_ENABLED:-true}"


# ═══════════════════════════════════════════════════════════════════════════
# 계정 잠금 정책
# ═══════════════════════════════════════════════════════════════════════════

# 로그인 실패 허용 횟수. 이 횟수 초과 시 계정 잠금
FAILLOCK_DENY="${FAILLOCK_DENY:-5}"

# 잠금 해제까지 대기 시간 (초). 900 = 15분
FAILLOCK_UNLOCK_TIME="${FAILLOCK_UNLOCK_TIME:-900}"

# root 계정도 잠금 정책 적용 여부
# true로 설정하면 root도 잠금될 수 있으니 주의하세요
FAILLOCK_DENY_ROOT="${FAILLOCK_DENY_ROOT:-false}"


# ═══════════════════════════════════════════════════════════════════════════
# 터널링 방어
# ═══════════════════════════════════════════════════════════════════════════

# 터널링 방어 전체 활성화/비활성화
TUNNEL_DEFENSE_ENABLED="${TUNNEL_DEFENSE_ENABLED:-true}"

# ICMP 최대 payload 크기 (바이트). 이 크기 초과 ICMP 패킷 차단
TUNNEL_ICMP_MAX_PAYLOAD="${TUNNEL_ICMP_MAX_PAYLOAD:-128}"

# /etc/resolv.conf 변경 잠금. DNS 터널링 방어용
TUNNEL_LOCK_RESOLV="${TUNNEL_LOCK_RESOLV:-true}"

# 터널링 도구 자동 제거 (iodine, ptunnel, dnscat2 등)
TUNNEL_REMOVE_TOOLS="${TUNNEL_REMOVE_TOOLS:-true}"


# ═══════════════════════════════════════════════════════════════════════════
# 점검/복원 허용 목록
# ═══════════════════════════════════════════════════════════════════════════

# 의심 포트 점검 시 제외할 포트 (쉼표 구분)
# 예: "8080,9090,3000"
WHITELISTED_PORTS="${WHITELISTED_PORTS:-}"

# 자동 계정 잠금에서 제외할 계정 (공백 구분)
# 예: "deploy monitoring"
ACCOUNT_ALLOWLIST="${ACCOUNT_ALLOWLIST:-}"

# crontab 사용을 허용할 사용자 (공백 구분)
# 예: "root deploy"
CRONTAB_ALLOWLIST="${CRONTAB_ALLOWLIST:-}"

# 서비스 자동 중지에서 제외할 서비스 (공백 구분)
# 예: "docker containerd"
SERVICE_ALLOWLIST="${SERVICE_ALLOWLIST:-}"


# ═══════════════════════════════════════════════════════════════════════════
# PAM 패스워드 품질 (Linux only)
# ═══════════════════════════════════════════════════════════════════════════

# Debian 계열: passwdqc의 min 파라미터
# 형식: "disabled,N1,N2,N3,N4" (1종류,2종류,passphrase,3종류,4종류 최소길이)
PAM_PASSWDQC_MIN="${PAM_PASSWDQC_MIN:-disabled,24,12,8,7}"

# RHEL 계열: pwquality 최소 패스워드 길이
PAM_PWQUALITY_MINLEN="${PAM_PWQUALITY_MINLEN:-8}"

# RHEL 계열: 최소 문자 클래스 수 (대문자/소문자/숫자/특수문자 중)
PAM_PWQUALITY_MINCLASS="${PAM_PWQUALITY_MINCLASS:-3}"
