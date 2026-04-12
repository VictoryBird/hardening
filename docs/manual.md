# 시스템 하드닝 스크립트 매뉴얼

> **버전:** v4.0.0  
> **대상:** CDX Blue Team 운용자  
> **최종 수정:** 2026-04-13

---

## 목차

1. [개요](#1-개요)
2. [워크플로](#2-워크플로)
3. [Ansible 실행 가이드](#3-ansible-실행-가이드)
4. [설정 파일 (config.sh) 상세](#4-설정-파일-configsh-상세)
5. [하드닝 항목 상세 (21개)](#5-하드닝-항목-상세-21개)
6. [점검/복원 상세](#6-점검복원-상세)
7. [OS별 차이점](#7-os별-차이점)
8. [로깅](#8-로깅)
9. [트러블슈팅](#9-트러블슈팅)

---

## 1. 개요

### 1.1 목적

사이버 방어 훈련(CDX)에서 Blue Team이 관리하는 서버의 보안을 자동으로 강화하는 스크립트입니다.

- 21개 하드닝 항목을 선택적으로 적용
- 적용 후 baseline 스냅샷을 생성하여 drift(변조) 감지
- 공격자 행위를 탐지하고 자동 복원
- 비보호 계정의 SSH 세션 자동 종료

### 1.2 지원 OS

| OS | 테스트 버전 | 어댑터 | 비고 |
|----|------------|--------|------|
| Ubuntu | 20.04, 22.04, 24.04 | os_debian.sh | 주력 지원 |
| Debian | 12, 13 | os_debian.sh | Ubuntu와 동일 어댑터 |
| Rocky Linux | 9.7, 10.1 | os_rhel.sh | firewalld, pwquality |
| AlmaLinux | 9.7 | os_rhel.sh | Rocky와 동일 |
| FreeBSD | 14.3 | os_freebsd.sh | pf, rc.conf, login.conf |
| macOS | 14+ | os_macos.sh | bash 3.2 호환, 제한적 항목 |

### 1.3 파일 구조

```
playbooks/
├── 4001_hardening_discover.yml    # 사전 수집
├── 4002_hardening_apply.yml       # 하드닝 적용
└── 4003_hardening_check.yml       # 점검/복원

files/scripts/hardening/
├── config.sh                      # 설정 파일 (유일한 편집 대상)
├── 01_baseline_hardening.sh       # 하드닝 오케스트레이터
├── 02_check_and_restore.sh        # 점검/복원 오케스트레이터
└── lib/
    ├── common.sh                  # OS 감지, 로깅, 보호 계정 체크
    ├── os_debian.sh               # Debian/Ubuntu 어댑터
    ├── os_rhel.sh                 # RHEL/Rocky/AlmaLinux 어댑터
    ├── os_freebsd.sh              # FreeBSD 어댑터
    └── os_macos.sh                # macOS 어댑터

artifacts/hardening_discover/      # 4001 수집 결과 (호스트별 YAML)
```

> **주의:** `lib/` 디렉토리의 파일은 직접 수정하지 마세요. 모든 설정은 `config.sh`에서 변경합니다.

### 1.4 사전 조건

하드닝 스크립트를 실행하기 전에 다음이 준비되어야 합니다:

| 항목 | 담당 | 설명 |
|------|------|------|
| operator 계정 | 자동화팀 | SSH 키 인증, NOPASSWD sudo |
| gt 계정 | 훈련 운영팀 | 채점 시스템 계정 |
| Ansible 인벤토리 | 운용자 | hosts.yml 작성 |
| 보안 에이전트 | 별도 플레이북 | Wazuh, CrowdStrike 등 사전 설치 |
| bash | OS 기본 제공 | FreeBSD는 `pkg install bash` 필요 |

---

## 2. 워크플로

### 2.1 전체 흐름

```
FAM (사전 훈련)                         본훈련
──────────────────────                 ──────────────────────────────
① 4001 discover (전체 서버)             ④ 4002 apply (하드닝 적용)
   └→ artifacts/ 생성                     └→ FAM discover 결과 재사용

② 운용자가 결과 검토/수정               ⑤ 4003 check (반복 점검)
   └→ 포트 누락 확인                      └→ --check-only (기본)
                                          └→ --auto-restore (자동 복원)
③ 4002 apply (검증)
   └→ 스냅샷 복원 예정이므로 안전
```

### 2.2 FAM 단계 (사전 훈련)

1. **Discover** — 모든 서버의 리스닝 포트, 보안 에이전트, IP 포워딩 상태, SSH 키 존재 여부를 자동 수집
2. **검토** — 생성된 `artifacts/hardening_discover/<hostname>.yml` 파일을 열어서 내용 확인. 필요 시 포트 추가/제거
3. **검증** — 하드닝을 실행하여 문제가 없는지 확인. FAM 환경은 스냅샷으로 복원되므로 안전하게 테스트 가능

### 2.3 본훈련 단계

4. **Apply** — FAM에서 생성한 discover 결과를 그대로 사용하여 하드닝 적용 (환경이 동일한 스냅샷이므로)
5. **Check** — 주기적으로 점검 실행. 공격자가 설정을 변조하면 drift로 감지하고, `--auto-restore`로 자동 복원

---

## 3. Ansible 실행 가이드

### 3.1 인벤토리 설정

```yaml
# inventories/lab/hosts.yml
all:
  vars:
    ansible_user: operator
    ansible_become: yes
  children:
    ubuntu:
      hosts:
        web01:
          ansible_host: 192.168.1.10
        web02:
          ansible_host: 192.168.1.11

    rhel:
      hosts:
        db01:
          ansible_host: 192.168.1.20

    freebsd:
      hosts:
        fw01:
          ansible_host: 192.168.1.30
          ansible_become_flags: "-H -S -n"    # FreeBSD 필수
```

> **FreeBSD 주의:** `ansible_become_flags: "-H -S -n"` 필수. 없으면 배너 텍스트가 Ansible의 sudo 감지를 방해하여 become 타임아웃이 발생합니다.

### 3.2 4001 Discover 실행

```bash
ansible-playbook playbooks/4001_hardening_discover.yml -i inventories/lab/hosts.yml
```

**결과:** `artifacts/hardening_discover/<hostname>.yml` 파일이 호스트별로 생성됩니다.

**생성 파일 예시:**
```yaml
---
# 자동 수집: 2026-04-13T10:30:00+09:00
# 서버: web01 (Ubuntu 22.04)

hardening_allowed_ports: "22/tcp 80/tcp 443/tcp 1514/tcp"
hardening_service_allowlist: "wazuh-agent"
hardening_account_allowlist: "wazuh ossec"
hardening_ip_forward: "False"
hardening_ssh_password_auth: "no"

# --- 추가 설정 (필요시 주석 해제) ---
# hardening_extra_ports: ""
```

> **반드시 검토하세요.** 포트 누락이 있으면 서비스가 외부에서 접근 불가능해집니다.

**--limit 사용 시 주의:** `--limit`으로 일부 호스트만 실행하면 나머지 호스트의 아티팩트가 에러를 발생시킵니다. 해당 호스트의 아티팩트만 생성되므로 무시해도 됩니다.

### 3.3 4002 Apply 실행

```bash
# 전체 서버 동시 적용 (discover 아티팩트 자동 로드)
ansible-playbook playbooks/4002_hardening_apply.yml -i inventories/lab/hosts.yml

# 특정 서버만
ansible-playbook playbooks/4002_hardening_apply.yml \
  -i inventories/lab/hosts.yml --limit web01

# 특정 항목 비활성화
ansible-playbook playbooks/4002_hardening_apply.yml \
  -i inventories/lab/hosts.yml \
  -e "HARDEN_SSH=false HARDEN_FIREWALL=false"

# 추가 포트 전달
ansible-playbook playbooks/4002_hardening_apply.yml \
  -i inventories/lab/hosts.yml \
  -e "hardening_extra_ports='8443/tcp 9090/tcp'"
```

**플레이북이 자동으로 처리하는 항목:**
- `artifacts/hardening_discover/<hostname>.yml` 자동 로드 (include_vars)
- Ansible 접속 계정 감지 → `PROTECTED_ACCOUNTS`에 자동 추가
- 보안 에이전트 런타임 감지 → 포트/서비스/계정 허용목록 자동 추가
- IP 포워딩 상태 → `SYSCTL_DISABLE_IP_FORWARD` 자동 결정
- SSH 키 존재 여부 → `SSH_PASSWORD_AUTH` 자동 결정
- 비동기 실행 (async) → 서비스 FD 상속으로 인한 멈춤 방지
- 하드닝 완료 후 비보호 계정의 SSH 세션 자동 종료

### 3.4 4003 Check 실행

```bash
# 점검만 (기본)
ansible-playbook playbooks/4003_hardening_check.yml \
  -i inventories/lab/hosts.yml

# 자동 복원
ansible-playbook playbooks/4003_hardening_check.yml \
  -i inventories/lab/hosts.yml \
  -e "auto_restore=true"
```

### 3.5 SSH 컨트롤 소켓 초기화

하드닝 후 Ansible 연결이 안 될 때:

```bash
rm -rf ~/.ansible/cp/*
```

Ansible은 SSH 연결을 재사용(multiplexing)하는데, 하드닝으로 SSH 설정이 변경되면 기존 소켓이 깨질 수 있습니다.

---

## 4. 설정 파일 (config.sh) 상세

`config.sh`는 하드닝 스크립트의 유일한 설정 파일입니다. 모든 변수는 `${VAR:-default}` 패턴으로 환경변수 오버라이드를 지원합니다.

### 4.1 보호 계정 (PROTECTED_ACCOUNTS)

```bash
PROTECTED_ACCOUNTS="${PROTECTED_ACCOUNTS:-gt}"
```

이 목록에 포함된 계정은 하드닝 중:
- 잠금/nologin 변경에서 제외
- sudoers NOPASSWD 제거에서 제외 (zz-<계정>-nopasswd 파일 자동 생성)
- SSH 세션 종료에서 제외

Ansible 플레이북은 자동으로 접속 계정을 추가합니다 (`"gt operator"` 형태).

### 4.2 하드닝 토글 (21개)

모든 토글은 `true`(실행) 또는 `false`(건너뜀)으로 설정합니다.

| # | 변수 | 기본값 | 항목 |
|---|------|--------|------|
| 1 | `HARDEN_FIREWALL` | `true` | 방화벽 설정 (UFW/firewalld/pf) |
| 2 | `HARDEN_SSH` | `true` | SSH 하드닝 (sshd_config) |
| 3 | `HARDEN_PAM` | `true` | PAM 패스워드 정책 |
| 4 | `HARDEN_FAILLOCK` | `true` | 계정 잠금 정책 |
| 5 | `HARDEN_SYSCTL` | `true` | sysctl 커널 보안 |
| 6 | `HARDEN_ACCOUNTS` | `true` | 시스템 계정 nologin |
| 7 | `HARDEN_SUDOERS` | `true` | NOPASSWD 제거 |
| 8 | `HARDEN_SERVICES` | `true` | 불필요 서비스 비활성화 |
| 9 | `HARDEN_FILE_PERMISSIONS` | `true` | 민감 파일 권한 |
| 10 | `HARDEN_SUID` | `true` | SUID 비트 제거 |
| 11 | `HARDEN_EMPTY_PASSWORDS` | `true` | 빈 패스워드 잠금 |
| 12 | `HARDEN_KERNEL_MODULES` | `true` | 커널 모듈 차단 (Linux) |
| 13 | `HARDEN_MOUNT` | `true` | /tmp 마운트 하드닝 |
| 14 | `HARDEN_HIDEPID` | `true` | /proc hidepid |
| 15 | `HARDEN_CORE_DUMP` | `true` | core dump 제한 |
| 16 | `HARDEN_UMASK` | `true` | umask 설정 |
| 17 | `HARDEN_BANNER` | `true` | 경고 배너 |
| 18 | `HARDEN_TUNNEL_DEFENSE` | `true` | 터널링 방어 |
| 19 | `HARDEN_LOGIN_DEFS` | `true` | 패스워드 에이징 |
| 20 | `HARDEN_CRON` | `true` | cron 디렉토리 권한 |
| 21 | `HARDEN_OTHER_PERMS` | `true` | other 권한 제거 |

### 4.3 인바운드 방화벽

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `CUSTOM_ALLOWED_PORTS` | *(비어있음)* | 허용 포트 (예: `"22/tcp 80/tcp 443/tcp"`) |
| `HARDENING_PROFILE` | `base` | 폴백 프로파일. CUSTOM_ALLOWED_PORTS 비어있을 때만 사용 |

**프로파일 종류:**
- `base` — SSH(22)만
- `web` — SSH + HTTP(80) + HTTPS(443)
- `ad` — SSH + DNS(53) + Kerberos(88) + LDAP(389,636) + GC(3268,3269)
- `log` — SSH + Syslog(514) + Wazuh(1514,1515,1516)
- `full` — 위 전부

> **권장:** 4001 discover를 사용하면 `CUSTOM_ALLOWED_PORTS`가 자동 설정되므로 프로파일을 사용할 필요가 없습니다.

### 4.4 아웃바운드 정책

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `OUTBOUND_POLICY` | `restrict` | `restrict`: 지정 포트만 허용 / `allow`: 전체 허용 |
| `OUTBOUND_ALLOWED_PORTS` | `22/tcp 53/udp 80/tcp 443/tcp 123/udp 8080/tcp 110/tcp 143/tcp 993/tcp 995/tcp 21/tcp` | restrict 모드 허용 포트 |
| `OUTBOUND_ALLOW_ICMP` | `true` | 아웃바운드 ping 허용 |

> **`restrict`를 권장합니다.** 공격자의 리버스 셸을 차단합니다.

### 4.5 SSH 설정

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `SSH_PERMIT_ROOT_LOGIN` | `prohibit-password` | `no`=차단, `prohibit-password`=키만, `yes`=허용 |
| `SSH_PASSWORD_AUTH` | `no` | SSH 키 없으면 자동으로 `yes` 유지 |
| `SSH_MAX_AUTH_TRIES` | `4` | 인증 최대 시도 |
| `SSH_CLIENT_ALIVE_INTERVAL` | `300` | keepalive 주기 (초) |
| `SSH_CLIENT_ALIVE_COUNT_MAX` | `2` | 무응답 허용 횟수 |
| `SSH_LOGIN_GRACE_TIME` | `60` | 인증 유예 시간 (초) |

> **주의:** `SSH_PASSWORD_AUTH=no`인데 SSH 키가 없으면 접속 불가. 스크립트가 자동 감지하여 보호하지만, config.sh 직접 수정 시 주의.

### 4.6 패스워드/계정 잠금 정책

**패스워드 에이징:**

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `PASS_MAX_DAYS` | `90` | 최대 사용기간 (일) |
| `PASS_MIN_DAYS` | `7` | 최소 사용기간 (일) |
| `PASS_WARN_AGE` | `14` | 만료 경고 (일) |
| `DEFAULT_UMASK` | `027` | 기본 umask |

**계정 잠금 (faillock):**

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `FAILLOCK_DENY` | `5` | 잠금까지 실패 횟수 |
| `FAILLOCK_UNLOCK_TIME` | `300` | 잠금 해제 대기 (초, 5분) |
| `FAILLOCK_DENY_ROOT` | `false` | root 잠금 적용 여부 |

**PAM 패스워드 품질:**

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `PAM_PASSWDQC_MIN` | `disabled,24,12,8,7` | Debian: passwdqc 최소 길이 |
| `PAM_PWQUALITY_MINLEN` | `8` | RHEL: 최소 길이 |
| `PAM_PWQUALITY_MINCLASS` | `3` | RHEL: 최소 문자 클래스 수 |

### 4.7 터널링 방어

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `TUNNEL_ICMP_MAX_PAYLOAD` | `128` | ICMP 최대 payload (바이트) |
| `TUNNEL_LOCK_RESOLV` | `true` | /etc/resolv.conf 변경 잠금 |
| `TUNNEL_REMOVE_TOOLS` | `true` | 터널링 도구 자동 제거 |

**제거 대상:** ptunnel, iodine, dns2tcp, dnscat2, chisel, sshuttle, autossh, ligolo, frpc, ngrok, gost, bore, inlets

### 4.8 허용 목록 (allowlist)

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `WHITELISTED_PORTS` | *(비어있음)* | 의심 포트 점검 제외 (쉼표 구분) |
| `ACCOUNT_ALLOWLIST` | *(비어있음)* | 계정 잠금 제외 (공백 구분) |
| `CRONTAB_ALLOWLIST` | *(비어있음)* | crontab 허용 사용자 (공백 구분) |
| `SERVICE_ALLOWLIST` | *(비어있음)* | 서비스 자동 중지 제외 (공백 구분) |

### 4.9 기타 설정

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `DISABLE_SERVICES` | `avahi-daemon cups cups-browsed bluetooth` | 비활성화할 서비스 |
| `BLOCKED_MODULES` | `cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat usb-storage` | 차단 커널 모듈 |
| `SUID_REMOVE_TARGETS` | nmap, bash, dash, find, less, pkexec, at, newgrp, chfn, chsh | SUID 제거 대상 |
| `SYSCTL_HARDEN_NETWORK` | `true` | 네트워크 sysctl 보안 |
| `SYSCTL_HARDEN_KERNEL` | `true` | 커널 sysctl 보안 |
| `SYSCTL_DISABLE_IP_FORWARD` | `true` | IP 포워딩 비활성화 (라우터는 false) |
| `SHM_NOEXEC` | `true` | /dev/shm noexec |
| `HIDEPID_ENABLED` | `true` | /proc hidepid=2 |

---

## 5. 하드닝 항목 상세 (21개)

### 5.1 방화벽 (HARDEN_FIREWALL)

| 항목 | 내용 |
|------|------|
| **적용 OS** | Debian (UFW), RHEL (firewalld), FreeBSD (pf), macOS (pf+socketfilterfw) |

**동작:**
- 인바운드: `CUSTOM_ALLOWED_PORTS`에 지정된 포트만 허용. SSH 포트는 자동 감지
- 아웃바운드: `OUTBOUND_POLICY=restrict`면 `OUTBOUND_ALLOWED_PORTS`만 허용
- 터널 방어: DNS over TCP(53) 아웃바운드 차단, 대형 ICMP 패킷 차단 (Linux)
- 기존 방화벽 규칙은 초기화됨

**false 시:** 방화벽 설정 미변경

**변경 영향:**
- `OUTBOUND_POLICY=allow`로 변경하면 리버스 셸 가능
- 포트 누락 시 해당 서비스 접근 불가

---

### 5.2 SSH 하드닝 (HARDEN_SSH)

| 항목 | 내용 |
|------|------|
| **적용 OS** | 전체 |

**동작:**
- `PermitRootLogin`, `PasswordAuthentication` 설정
- `AllowTcpForwarding=no` — SSH 터널 차단
- `X11Forwarding=no`
- keepalive, 인증 시도 제한, 유예 시간 설정
- `Banner /etc/issue.net`
- sshd 재시작

**주의:** SSH 키 없이 `SSH_PASSWORD_AUTH=no` 설정 시 접속 불가

---

### 5.3 PAM 패스워드 정책 (HARDEN_PAM)

| 항목 | 내용 |
|------|------|
| **적용 OS** | Debian (passwdqc), RHEL (pwquality), FreeBSD (login.conf) |

**동작:**
- Debian: passwdqc 모듈로 패스워드 복잡도 설정
- RHEL: pwquality 모듈로 최소 길이/문자 클래스 설정
- FreeBSD: login.conf의 passwd_format, minpasswordlen 설정

---

### 5.4 계정 잠금 (HARDEN_FAILLOCK)

| 항목 | 내용 |
|------|------|
| **적용 OS** | Debian (faillock/pam_tally2), RHEL (faillock), FreeBSD (login.conf) |

**동작:**
- 5회 실패 시 계정 잠금, 5분 후 자동 해제
- root는 잠금 대상에서 제외 (기본)
- FreeBSD: login.conf의 auth-retries, login_timeout으로 구현

**변경 영향:**
- `FAILLOCK_DENY_ROOT=true` → root도 잠김 (콘솔 접근 없으면 위험)
- `FAILLOCK_UNLOCK_TIME=0` → 수동 해제 전까지 영구 잠금

---

### 5.5 sysctl 커널 보안 (HARDEN_SYSCTL)

| 항목 | 내용 |
|------|------|
| **적용 OS** | Debian, RHEL, FreeBSD (일부), macOS (제한적) |

**동작:**
- ICMP redirect/source routing 차단
- SYN flood 방어 (tcp_syncookies)
- ASLR 활성화, SysRq 제한
- SUID core dump 방지
- IP 포워딩 비활성화 (SYSCTL_DISABLE_IP_FORWARD)
- IPv6 비활성화는 하지 않음

**주의:** `SYSCTL_DISABLE_IP_FORWARD=true`인데 라우터/게이트웨이 서버이면 네트워크 중단

---

### 5.6 시스템 계정 nologin (HARDEN_ACCOUNTS)

| 항목 | 내용 |
|------|------|
| **적용 OS** | 전체 |

**동작:** 시스템 계정(www-data, nobody, daemon 등)의 셸을 nologin으로 변경. PROTECTED_ACCOUNTS와 ACCOUNT_ALLOWLIST 계정은 제외.

---

### 5.7 sudoers NOPASSWD 제거 (HARDEN_SUDOERS)

| 항목 | 내용 |
|------|------|
| **적용 OS** | 전체 |

**동작:**
- sudoers 및 sudoers.d에서 NOPASSWD 지시문 제거
- PROTECTED_ACCOUNTS의 각 계정에 대해 `zz-<계정>-nopasswd` 파일 생성 (NOPASSWD 유지)
- sudoers.d 파일 순서: `zz-` 접두사가 알파벳 순서상 마지막이므로 NOPASSWD가 최종 적용됨

---

### 5.8 서비스 비활성화 (HARDEN_SERVICES)

| 항목 | 내용 |
|------|------|
| **적용 OS** | 전체 |

**기본 대상:** avahi-daemon, cups, cups-browsed, bluetooth

**동작:** 대상 서비스 stop + disable. `SERVICE_ALLOWLIST`에 있는 서비스는 건너뜀.

---

### 5.9 파일 권한 최소화 (HARDEN_FILE_PERMISSIONS)

| 항목 | 내용 |
|------|------|
| **적용 OS** | 전체 |

**동작:** /etc/shadow(600), /etc/passwd(644), /etc/sudoers(440) 등 민감 파일 권한 설정.

---

### 5.10 SUID 비트 제거 (HARDEN_SUID)

| 항목 | 내용 |
|------|------|
| **적용 OS** | Debian, RHEL, FreeBSD (macOS는 SIP 관리) |

**대상:** nmap, bash, dash, find, less, pkexec, at, newgrp, chfn, chsh

**동작:** `chmod u-s`로 SUID 비트 제거. 파일 미존재 시 건너뜀. baseline에 현재 SUID 파일 목록 저장하여 02에서 새 SUID 파일 감지.

**주의:** `SUID_REMOVE_TARGETS`에 su, sudo, passwd 등 시스템 필수 바이너리를 추가하면 안 됩니다.

---

### 5.11 빈 패스워드 잠금 (HARDEN_EMPTY_PASSWORDS)

| 항목 | 내용 |
|------|------|
| **적용 OS** | Debian, RHEL, FreeBSD |

**동작:** /etc/shadow에서 패스워드 필드가 빈 계정을 `passwd -l`로 잠금. PROTECTED_ACCOUNTS 계정 제외.

---

### 5.12 커널 모듈 차단 (HARDEN_KERNEL_MODULES)

| 항목 | 내용 |
|------|------|
| **적용 OS** | Debian, RHEL (Linux 전용) |

**동작:** `/etc/modprobe.d/dev-sec.conf`에 `blacklist` + `install /bin/true` 작성.

**기본 차단:** cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf, vfat, usb-storage

---

### 5.13 /tmp 마운트 하드닝 (HARDEN_MOUNT)

| 항목 | 내용 |
|------|------|
| **적용 OS** | Debian, RHEL, FreeBSD |

**동작:** /tmp, /var/tmp에 noexec,nosuid,nodev 적용. /dev/shm은 `SHM_NOEXEC=true`일 때 적용. fstab에 영구 등록.

---

### 5.14 /proc hidepid (HARDEN_HIDEPID)

| 항목 | 내용 |
|------|------|
| **적용 OS** | Debian, RHEL |

**동작:** /proc에 hidepid=2 마운트. 일반 사용자는 다른 사용자의 프로세스를 볼 수 없음. root는 영향 없음.

**참고:** 일반 사용자가 `ps aux` 시 자기 프로세스만 보임. `sudo ps aux`로 전체 확인 가능.

---

### 5.15 core dump 제한 (HARDEN_CORE_DUMP)

| 항목 | 내용 |
|------|------|
| **적용 OS** | Debian, RHEL, FreeBSD |

**동작:** limits.conf `* hard core 0`, systemd `Storage=none`, sysctl `fs.suid_dumpable=0`

---

### 5.16 umask (HARDEN_UMASK)

| 항목 | 내용 |
|------|------|
| **적용 OS** | Debian, RHEL, FreeBSD |

**동작:** /etc/profile, /etc/bash.bashrc(또는 /etc/bashrc), /etc/login.defs(또는 login.conf)에 umask 설정. 기본 027.

---

### 5.17 경고 배너 (HARDEN_BANNER)

| 항목 | 내용 |
|------|------|
| **적용 OS** | 전체 |

**동작:** /etc/issue, /etc/issue.net에 "AUTHORIZED ACCESS ONLY" 배너 설정. MOTD 스크립트 실행 권한 제거. sshd_config에 Banner 설정.

---

### 5.18 터널링 방어 (HARDEN_TUNNEL_DEFENSE)

| 항목 | 내용 |
|------|------|
| **적용 OS** | Debian, RHEL, FreeBSD |

**동작:**
1. 터널 프로세스 탐지 (chisel, ligolo, frpc, iodine, dns2tcp 등)
2. TUN 디바이스 사용 감지, 비내부 DNS 쿼리 감지
3. 터널링 도구 패키지 제거
4. 터널링 바이너리 직접 삭제

---

### 5.19 패스워드 에이징 (HARDEN_LOGIN_DEFS)

| 항목 | 내용 |
|------|------|
| **적용 OS** | Debian, RHEL, FreeBSD |

**동작:** login.defs(또는 login.conf)에 PASS_MAX_DAYS=90, PASS_MIN_DAYS=7, PASS_WARN_AGE=14, UMASK=027 설정.

---

### 5.20 cron 권한 (HARDEN_CRON)

| 항목 | 내용 |
|------|------|
| **적용 OS** | Debian, RHEL, FreeBSD |

**동작:** /etc/cron.d, /etc/cron.daily 등 디렉토리와 /etc/crontab을 root만 접근 가능하게 설정 (og-rwx).

---

### 5.21 other 권한 제거 (HARDEN_OTHER_PERMS)

| 항목 | 내용 |
|------|------|
| **적용 OS** | Debian, RHEL, FreeBSD |

**동작:** /var/log 등 디렉토리에서 other(제3자) 읽기/쓰기/실행 권한 제거 (o-rwx).

---

## 6. 점검/복원 상세

### 6.1 baseline 스냅샷 구조

01 스크립트 실행 시 `/var/backups/hardening/baseline/` (Linux/FreeBSD) 또는 `/Library/Caches/hardening/baseline/` (macOS)에 생성:

```
baseline/
├── INTEGRITY.sha256              # 무결성 해시
├── auditd/                       # auditd 설정 스냅샷
├── sysctl_baseline.txt           # sysctl 전체 스냅샷
├── sysctl_baseline.conf          # 하드닝 키만 (FreeBSD)
├── sshd_baseline.txt             # sshd -T 출력
├── passwd_baseline.txt           # /etc/passwd 스냅샷
├── ports_baseline.txt            # 리스닝 포트 스냅샷
├── services_baseline.txt         # 서비스 상태 스냅샷
├── suid_files_baseline.txt       # SUID 파일 목록
├── cron_permissions_baseline.txt # cron 디렉토리 권한
├── file_permissions_baseline.txt # 민감 파일 권한
└── (OS별 추가 스냅샷)
```

### 6.2 drift 감지 항목

| 점검 대상 | 감지 방법 |
|-----------|-----------|
| 방화벽 규칙 | 규칙 수 비교, 핵심 규칙 존재 확인 |
| SSH 설정 | sshd_config 파라미터 비교 |
| sysctl 값 | 현재 값 vs baseline 값 |
| 파일 권한 | stat 권한 비교 |
| SUID 파일 | 새로 등장한 SUID 바이너리 탐지 |
| cron 권한 | 권한 변경 감지 |
| /proc hidepid | hidepid=2 유지 확인 |
| auditd | 설정 파일 diff |
| sudoers | NOPASSWD 재출현 감지 (보호 계정 제외) |

### 6.3 의심 활동 탐지

drift 감지와 별도로 공격 징후를 탐지합니다:

- **의심 리스닝 포트:** 4444, 5555, 6666, 7777, 8888, 9999, 31337 등
- **의심 crontab 명령어:** `nc`, `ncat`, `bash -i`, `/dev/tcp`, `python.*socket`, `curl.*sh`, `mkfifo`
- **터널 프로세스:** chisel, ligolo, frpc, iodine 등 재실행 감지
- **UID 0 계정:** root 외에 UID 0인 계정 감지
- **의심 파일:** /tmp, /var/tmp, /dev/shm의 숨김 파일, 실행 파일

### 6.4 auto-restore 동작

`--auto-restore` 모드에서는:
- drift 감지 시 baseline 값으로 자동 복원
- 복원 전 현재 상태를 `/var/backups/hardening/hardening_restore_<timestamp>/`에 백업
- 성공: `log_restore`, 실패: `log_fail`
- 30일 이상 된 복원 백업은 자동 정리

### 6.5 알림

- **syslog:** `logger -t "hardening-check"` 메시지 전송
- **webhook:** `HARDENING_WEBHOOK_URL` 설정 시 JSON payload POST

---

## 7. OS별 차이점

### 7.1 Debian / Ubuntu

| 항목 | 구현 |
|------|------|
| 방화벽 | UFW |
| PAM | passwdqc |
| 패키지 | apt-get |
| 서비스 | systemd (systemctl) |
| 계정 잠금 | faillock (구버전: pam_tally2) |
| nologin | /usr/sbin/nologin |

### 7.2 RHEL / Rocky / AlmaLinux

| 항목 | 구현 |
|------|------|
| 방화벽 | firewalld (direct rules) |
| PAM | pwquality |
| 패키지 | dnf (RHEL 8+) / yum (RHEL 7) |
| 서비스 | systemd (systemctl) |
| sudo 그룹 | wheel |
| SELinux | 변경 안 함 (상태만 로그) |

### 7.3 FreeBSD

| 항목 | 구현 |
|------|------|
| 방화벽 | pf (`/etc/pf.conf`) |
| 패키지 | pkg |
| 서비스 | rc.conf (sysrc) |
| 계정 관리 | pw |
| 패스워드 정책 | /etc/login.conf |
| sudo 그룹 | wheel |
| sudoers | /usr/local/etc/sudoers.d/ |
| stat | `stat -f '%Lp'` (BSD 형식) |
| sed | `sed -i ''` (BSD 형식) |

**FreeBSD 특수 사항:**
- pf 사용 시 커널 모듈 자동 로드 (`kldload pf pflog`)
- operator 시스템 계정(UID 2)이 기본 존재 — 홈 디렉토리 확인 필요
- bash 미설치 시 `pkg install bash` 필요
- Ansible 인벤토리에 `ansible_become_flags: "-H -S -n"` 필수
- sysctl baseline은 하드닝 키만 저장 (동적 값 제외)
- pf 규칙 확인 시 포트 번호 대신 서비스 이름 표시 (53 → domain)

### 7.4 macOS

| 항목 | 구현 |
|------|------|
| 방화벽 | pf + socketfilterfw |
| 서비스 | launchd (plist) |
| 계정 관리 | dscl |
| bash 호환성 | 3.2+ (연관 배열 불가) |
| sudo 그룹 | admin |
| PermitRootLogin | 강제 no |

**macOS 미적용 항목:** 커널 모듈 차단, PAM faillock, /proc hidepid, SUID 제거, core dump 제한, umask

---

## 8. 로깅

### 8.1 로그 파일 위치

| 스크립트 | 파일명 |
|----------|--------|
| 01 (하드닝) | `/var/log/hardening/<timestamp>_<hostname>_baseline_hardening.log` |
| 02 (점검) | `/var/log/hardening/<timestamp>_<hostname>_check_result.log` |

`/var/log/hardening/`이 쓰기 불가능하면 `/tmp/`에 저장됩니다.

### 8.2 로그 레벨

| 레벨 | 의미 |
|------|------|
| `INFO` | 일반 정보 |
| `OK` | 성공 |
| `SKIP` | 건너뜀 (이미 적용 또는 토글 비활성화) |
| `WARN` | 경고 (비치명적) |
| `ERROR` | 오류 (치명적, stderr) |
| `DRIFT` | 변조 감지 |
| `RESTORE` | 복원 완료 |
| `FAIL` | 복원 실패 |

### 8.3 요약 출력 해석

```
============================================================
  Check & Restore Summary
  Mode: check-only  Host: web01  OS: debian/ubuntu 22.04
  Drifts: 3  Restores: 0  Failures: 0
============================================================
[WARN]    Drifts detected: 3 — re-run with --auto-restore to fix
```

| 상태 | 의미 |
|------|------|
| Drifts=0, Failures=0 | 정상 — baseline과 일치 |
| Drifts>0, Mode=check-only | 변조 감지됨 — auto-restore 필요 |
| Drifts>0, Mode=auto-restore, Restores>0 | 변조 감지 후 복원 완료 |
| Failures>0 | 복원 실패 항목 있음 — 수동 확인 필요 |

---

## 9. 트러블슈팅

### 9.1 SSH 접속 불가

| 원인 | 해결 |
|------|------|
| `SSH_PASSWORD_AUTH=no`인데 키 없음 | 콘솔에서 sshd_config `PasswordAuthentication yes`로 변경 |
| 방화벽이 SSH 차단 | `ufw allow 22/tcp` 또는 `firewall-cmd --add-service=ssh --permanent` |
| SSH 포트가 22가 아님 | `CUSTOM_ALLOWED_PORTS`에 실제 포트 포함 |

### 9.2 방화벽 포트 누락

1. discover 파일에서 포트 확인: `cat artifacts/hardening_discover/<hostname>.yml`
2. 포트 추가: discover 파일 수정 후 4002 재실행, 또는 `hardening_extra_ports` 사용
3. 긴급: `ufw allow <port>/tcp` 또는 `firewall-cmd --add-port=<port>/tcp --permanent && firewall-cmd --reload`

### 9.3 서비스 장애

| 원인 | 해결 |
|------|------|
| `DISABLE_SERVICES`에 포함됨 | 목록에서 제거 또는 `SERVICE_ALLOWLIST` 추가 |
| 서비스 계정이 nologin 처리됨 | `ACCOUNT_ALLOWLIST`에 추가 |
| /tmp noexec | `HARDEN_MOUNT=false` 또는 서비스 경로 변경 |

### 9.4 Ansible 연결 문제

**become 타임아웃:**
```
Timeout (12s) waiting for privilege escalation prompt
```
→ SSH 컨트롤 소켓 초기화: `rm -rf ~/.ansible/cp/*`

**FreeBSD become 실패:**
→ 인벤토리에 `ansible_become_flags: "-H -S -n"` 추가

**async 완료 대기:**
→ 하드닝 스크립트가 시작한 서비스의 FD 상속으로 폴링이 느릴 수 있음. 5분 이내에 감지되지 않으면 Ctrl+C 후 4003으로 점검

### 9.5 sudo 패스워드 요구됨

하드닝이 sudoers NOPASSWD를 제거했지만 보호 파일이 제대로 적용 안 된 경우:
1. `ls /etc/sudoers.d/` (또는 `/usr/local/etc/sudoers.d/`)에서 `zz-operator-nopasswd` 확인
2. 없으면 수동 생성: `echo "operator ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/zz-operator-nopasswd && chmod 440 /etc/sudoers.d/zz-operator-nopasswd`
3. sudoers.d 파일 순서 확인: `zz-` 접두사가 다른 파일보다 뒤에 와야 함

### 9.6 FreeBSD 특수 사항

**pf 방화벽 미활성화:**
```bash
kldload pf pflog        # 커널 모듈 로드
pfctl -e                # pf 활성화
pfctl -f /etc/pf.conf   # 규칙 적용
```

**login.conf 설정 미적용:**
→ login.conf 형식이 capability database 형식이므로 수동 확인: `grep -E 'auth-retries|login_timeout|minpasswordlen' /etc/login.conf`

**operator 시스템 계정:**
→ FreeBSD에 UID 2인 `operator` 계정이 기본 존재. 홈 디렉토리가 `/`로 설정되어 있으면 `pw usermod operator -d /home/operator` 필요

**bash 미설치:**
→ `pkg install -y bash` (하드닝 스크립트는 bash 필수)

### 9.7 설정 파일 문법 검증

설정 변경 후 반드시:
```bash
bash -n config.sh
```

### 9.8 로그 확인

```bash
# 에러/실패 확인
grep -E '\[(FAIL|ERROR)\]' /var/log/hardening/*_baseline_hardening.log

# drift 확인
grep '\[DRIFT\]' /var/log/hardening/*_check_result.log

# 최신 로그만
ls -t /var/log/hardening/*_check_result.log | head -1 | xargs grep '\[DRIFT\]'
```
