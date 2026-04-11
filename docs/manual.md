# 시스템 하드닝 스크립트 매뉴얼

> **버전:** v4.0.0  
> **대상:** CDX Blue Team 운용자  
> **최종 수정:** 2026-04-11

---

## 목차

1. [개요](#1-개요)
2. [워크플로](#2-워크플로)
3. [실행 방법](#3-실행-방법)
4. [설정 파일 (config.sh) 가이드](#4-설정-파일-configsh-가이드)
5. [하드닝 항목 상세 (21개)](#5-하드닝-항목-상세-21개)
6. [안전장치](#6-안전장치)
7. [점검/복원 (02 스크립트)](#7-점검복원-02-스크립트)
8. [OS별 차이점](#8-os별-차이점)
9. [로깅](#9-로깅)
10. [트러블슈팅](#10-트러블슈팅)

---

## 1. 개요

### 1.1 목적

사이버 방어 훈련(CDX)에서 Blue Team이 관리하는 서버의 보안을 자동으로 강화하는 스크립트입니다.

- 21개 하드닝 항목을 선택적으로 적용
- 적용 후 baseline 스냅샷을 생성하여 drift(변조) 감지
- 공격자 행위를 탐지하고 자동 복원

### 1.2 지원 OS

| OS | 버전 | 비고 |
|----|------|------|
| Debian / Ubuntu | 20.04+ | 주력 지원 |
| RHEL / Rocky / AlmaLinux | 8, 9 | firewalld, pwquality |
| FreeBSD | 13, 14 | pf, rc.conf |
| macOS | 14+ | bash 3.2 호환, 제한적 항목 |

### 1.3 파일 구조

```
playbooks/
├── 4001_hardening_discover.yml    # 사전 수집 (FAM)
├── 4002_hardening_apply.yml       # 하드닝 적용 (본훈련)
└── 4003_hardening_check.yml       # 점검/복원 (본훈련)

files/scripts/hardening/
├── config.sh                      # 설정 파일 (유일한 편집 대상)
├── 01_baseline_hardening.sh       # 하드닝 오케스트레이터
├── 02_check_and_restore.sh        # 점검/복원 오케스트레이터
└── lib/
    ├── common.sh                  # OS 감지, 로깅, 백업 유틸리티
    ├── safety_guards.sh           # 안전장치 (계정/네트워크/에이전트 보호)
    ├── os_debian.sh               # Debian/Ubuntu 어댑터
    ├── os_rhel.sh                 # RHEL 어댑터
    ├── os_freebsd.sh              # FreeBSD 어댑터
    └── os_macos.sh                # macOS 어댑터

artifacts/
└── hardening_discover/            # 4001 수집 결과 (호스트별 YAML)
    └── <hostname>.yml
```

> **주의:** `lib/` 디렉토리의 파일은 직접 수정하지 마세요. 모든 설정은 `config.sh`에서 변경합니다.

---

## 2. 워크플로

### 2.1 전체 흐름

```
FAM (사전 훈련)                     본훈련
─────────────────                  ─────────────────────────────
① 4001 discover                    ④ 4002 apply (하드닝 적용)
   └→ artifacts/ 생성                  └→ FAM discover 결과 재사용
② 결과 검토/수정                    ⑤ 4003 check (반복 점검)
③ 4002 apply (검증)                    └→ --auto-restore로 복원
   └→ 스냅샷 버림
```

### 2.2 FAM 단계 (사전 훈련)

1. **Discover** — 모든 서버의 리스닝 포트, 보안 에이전트, IP 포워딩 상태, SSH 키 존재 여부를 자동 수집
2. **검토** — 생성된 `artifacts/hardening_discover/<hostname>.yml` 파일을 열어서 내용 확인. 필요 시 포트 추가/제거
3. **검증** — 하드닝을 실행하여 문제가 없는지 확인. FAM 환경은 스냅샷으로 복원되므로 안전하게 테스트 가능

### 2.3 본훈련 단계

4. **Apply** — FAM에서 생성한 discover 결과를 그대로 사용하여 하드닝 적용 (환경이 동일한 스냅샷이므로)
5. **Check** — 주기적으로 점검 실행. 공격자가 설정을 변조하면 drift로 감지하고, `--auto-restore`로 자동 복원

---

## 3. 실행 방법

### 3.1 Ansible 실행 (권장)

#### 3.1.1 사전 수집 (4001)

```bash
ansible-playbook playbooks/4001_hardening_discover.yml \
  -i inventories/lab/hosts.yml
```

모든 호스트에 대해 `artifacts/hardening_discover/<hostname>.yml`이 생성됩니다.

**생성 파일 예시:**
```yaml
---
# 자동 수집: 2026-04-11T10:30:00+09:00
# 서버: bps_dmz_web (Ubuntu 22.04)

hardening_allowed_ports: "22/tcp 80/tcp 443/tcp 1514/tcp 1515/tcp"
hardening_service_allowlist: "wazuh-agent"
hardening_account_allowlist: "wazuh ossec"
hardening_ip_forward: false
hardening_ssh_password_auth: "no"

# --- 추가 설정 (필요시 주석 해제) ---
# hardening_extra_ports: ""
# hardening_extra_services: ""
```

> **반드시 검토하세요.** 포트 누락이 있으면 서비스 장애가 발생합니다.

#### 3.1.2 하드닝 적용 (4002)

```bash
# 단일 서버
ansible-playbook playbooks/4002_hardening_apply.yml \
  -i inventories/lab/hosts.yml \
  -e "@artifacts/hardening_discover/bps_dmz_web.yml" \
  --limit bps_dmz_web

# 전체 서버 (discover 파일을 host_vars에 복사한 경우)
ansible-playbook playbooks/4002_hardening_apply.yml \
  -i inventories/lab/hosts.yml
```

**플레이북이 자동으로 처리하는 항목:**
- Ansible 접속 계정 감지 → `ANSIBLE_ACCOUNT`에 자동 설정
- 보안 에이전트 런타임 감지 → 포트/서비스/계정 허용목록에 자동 추가
- IP 포워딩 상태 감지 → `SYSCTL_DISABLE_IP_FORWARD` 자동 결정
- SSH 키 존재 여부 → `SSH_PASSWORD_AUTH` 자동 결정

#### 3.1.3 점검/복원 (4003)

```bash
# 점검만 (기본)
ansible-playbook playbooks/4003_hardening_check.yml \
  -i inventories/lab/hosts.yml \
  -e "@artifacts/hardening_discover/bps_dmz_web.yml" \
  --limit bps_dmz_web

# 자동 복원
ansible-playbook playbooks/4003_hardening_check.yml \
  -i inventories/lab/hosts.yml \
  -e "@artifacts/hardening_discover/bps_dmz_web.yml" \
  -e "auto_restore=true" \
  --limit bps_dmz_web
```

#### 3.1.4 특정 항목만 비활성화

```bash
# SSH 하드닝과 방화벽을 건너뛰고 적용
ansible-playbook playbooks/4002_hardening_apply.yml \
  -i inventories/lab/hosts.yml \
  -e "@artifacts/hardening_discover/bps_dmz_web.yml" \
  -e "HARDEN_SSH=false HARDEN_FIREWALL=false" \
  --limit bps_dmz_web
```

#### 3.1.5 추가 포트가 필요한 경우

discover 이후 새로운 서비스가 추가되었다면:

**방법 1:** discover 파일을 직접 수정
```yaml
# artifacts/hardening_discover/bps_dmz_web.yml
hardening_allowed_ports: "22/tcp 80/tcp 443/tcp 1514/tcp 1515/tcp 8443/tcp"
```

**방법 2:** extra_ports로 추가 전달
```bash
ansible-playbook playbooks/4002_hardening_apply.yml \
  -e "@artifacts/hardening_discover/bps_dmz_web.yml" \
  -e "hardening_extra_ports='8443/tcp 9090/tcp'" \
  --limit bps_dmz_web
```

### 3.2 수동 실행 (단독 서버)

Ansible 없이 서버에서 직접 실행할 수 있습니다.

#### 3.2.1 하드닝 적용

```bash
# 기본 실행 (SSH 포트만 허용)
sudo ./01_baseline_hardening.sh

# 허용 포트 지정
sudo CUSTOM_ALLOWED_PORTS="22/tcp 80/tcp 443/tcp" ./01_baseline_hardening.sh

# 특정 항목 비활성화
sudo HARDEN_FIREWALL=false HARDEN_SSH=false ./01_baseline_hardening.sh
```

#### 3.2.2 점검/복원

```bash
# 점검만
sudo ./02_check_and_restore.sh

# 자동 복원
sudo ./02_check_and_restore.sh --auto-restore
```

#### 3.2.3 환경변수 오버라이드

`config.sh`의 모든 변수는 환경변수로 오버라이드할 수 있습니다. `${VAR:-default}` 패턴을 사용하므로 환경변수가 설정되어 있으면 config.sh의 기본값보다 우선합니다.

```bash
# 예: 아웃바운드 전체 허용, faillock 잠금 횟수 변경
sudo OUTBOUND_POLICY=allow FAILLOCK_DENY=3 ./01_baseline_hardening.sh
```

---

## 4. 설정 파일 (config.sh) 가이드

`config.sh`는 하드닝 스크립트의 유일한 설정 파일입니다. `lib/` 디렉토리는 수정하지 마세요.

### 4.1 하드닝 항목 토글 (21개)

각 항목은 `true`(실행) 또는 `false`(건너뜀)로 설정합니다.

| 변수 | 기본값 | 항목 |
|------|--------|------|
| `HARDEN_FIREWALL` | `true` | 방화벽 설정 |
| `HARDEN_SSH` | `true` | SSH 하드닝 |
| `HARDEN_PAM` | `true` | PAM 패스워드 정책 |
| `HARDEN_FAILLOCK` | `true` | 계정 잠금 정책 |
| `HARDEN_SYSCTL` | `true` | sysctl 커널 보안 |
| `HARDEN_ACCOUNTS` | `true` | 시스템 계정 nologin |
| `HARDEN_SUDOERS` | `true` | sudoers NOPASSWD 제거 |
| `HARDEN_SERVICES` | `true` | 불필요 서비스 비활성화 |
| `HARDEN_FILE_PERMISSIONS` | `true` | 파일 권한 최소화 |
| `HARDEN_SUID` | `true` | SUID 비트 제거 |
| `HARDEN_EMPTY_PASSWORDS` | `true` | 빈 패스워드 계정 잠금 |
| `HARDEN_KERNEL_MODULES` | `true` | 커널 모듈 차단 (Linux) |
| `HARDEN_MOUNT` | `true` | /tmp 마운트 하드닝 |
| `HARDEN_HIDEPID` | `true` | /proc hidepid |
| `HARDEN_CORE_DUMP` | `true` | core dump 제한 |
| `HARDEN_UMASK` | `true` | umask 설정 |
| `HARDEN_BANNER` | `true` | 경고 배너 |
| `HARDEN_TUNNEL_DEFENSE` | `true` | 터널링 방어 |
| `HARDEN_LOGIN_DEFS` | `true` | 패스워드 에이징 |
| `HARDEN_CRON` | `true` | cron 디렉토리 권한 |
| `HARDEN_OTHER_PERMS` | `true` | other 권한 제거 |

### 4.2 방화벽 설정

#### 인바운드

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `CUSTOM_ALLOWED_PORTS` | *(비어있음)* | 허용할 인바운드 포트 (예: `"22/tcp 80/tcp 443/tcp"`) |
| `HARDENING_PROFILE` | `base` | 폴백 프로파일. `CUSTOM_ALLOWED_PORTS`가 비어있을 때만 사용 |

**프로파일 종류** (CUSTOM_ALLOWED_PORTS가 비어있을 때만 적용):
- `base` — SSH(22)만
- `web` — SSH + HTTP(80) + HTTPS(443)
- `ad` — SSH + DNS(53) + Kerberos(88) + LDAP(389,636) + GC(3268,3269)
- `log` — SSH + Syslog(514) + Wazuh(1514,1515,1516)
- `full` — 위 전부

> **권장:** Ansible 4001 discover를 사용하면 `CUSTOM_ALLOWED_PORTS`가 자동 설정되므로 프로파일을 사용할 필요가 없습니다.

#### 아웃바운드

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `OUTBOUND_POLICY` | `restrict` | `restrict`: 지정 포트만 허용 / `allow`: 전체 허용 |
| `OUTBOUND_ALLOWED_PORTS` | `22/tcp 53/udp 80/tcp 443/tcp 123/udp 8080/tcp 110/tcp 143/tcp 993/tcp 995/tcp 21/tcp` | restrict 모드에서 허용할 아웃바운드 포트 |
| `OUTBOUND_ALLOW_ICMP` | `true` | 아웃바운드 ICMP ping 허용 |

> **`restrict`를 권장합니다.** 공격자가 리버스 셸을 열 수 없게 됩니다. `allow`는 워크스테이션 등 특수한 경우에만 사용하세요.

### 4.3 SSH 설정

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `SSH_PERMIT_ROOT_LOGIN` | `prohibit-password` | root 로그인. `no`=차단, `prohibit-password`=키만, `yes`=허용 |
| `SSH_PASSWORD_AUTH` | `no` | 패스워드 인증. SSH 키가 없으면 자동으로 `yes` 유지 |
| `SSH_MAX_AUTH_TRIES` | `4` | 인증 최대 시도 횟수 |
| `SSH_CLIENT_ALIVE_INTERVAL` | `300` | keepalive 주기 (초) |
| `SSH_CLIENT_ALIVE_COUNT_MAX` | `2` | 무응답 허용 횟수 |
| `SSH_LOGIN_GRACE_TIME` | `60` | 인증 유예 시간 (초) |

> **주의:** `SSH_PASSWORD_AUTH=no`로 설정했는데 SSH 키가 없으면 접속이 불가능합니다. 스크립트는 키가 없는 경우 자동으로 `yes`를 유지하지만, config.sh를 직접 수정할 때는 주의하세요.

### 4.4 패스워드 정책

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `PASS_MAX_DAYS` | `90` | 패스워드 최대 사용기간 (일) |
| `PASS_MIN_DAYS` | `7` | 패스워드 최소 사용기간 (일) |
| `PASS_WARN_AGE` | `14` | 만료 경고 시작 일수 |
| `LOGIN_RETRIES` | `3` | 로그인 재시도 횟수 |
| `DEFAULT_UMASK` | `027` | 기본 umask (027 = 소유자 rwx, 그룹 rx, 기타 없음) |
| `PAM_PASSWDQC_MIN` | `disabled,24,12,8,7` | Debian: passwdqc 최소 길이 설정 |
| `PAM_PWQUALITY_MINLEN` | `8` | RHEL: 최소 패스워드 길이 |
| `PAM_PWQUALITY_MINCLASS` | `3` | RHEL: 최소 문자 클래스 수 |

### 4.5 계정 잠금 (faillock)

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `FAILLOCK_DENY` | `5` | 잠금까지 실패 허용 횟수 |
| `FAILLOCK_UNLOCK_TIME` | `300` | 잠금 해제 대기 시간 (초, 300=5분) |
| `FAILLOCK_DENY_ROOT` | `false` | root 계정 잠금 적용 여부 |

> **`FAILLOCK_DENY_ROOT=true` 주의:** root도 잠길 수 있습니다. 콘솔 접근이 없는 원격 서버에서는 `false`를 유지하세요.

### 4.6 터널링 방어

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `TUNNEL_DEFENSE_ENABLED` | `true` | 터널링 방어 전체 ON/OFF |
| `TUNNEL_ICMP_MAX_PAYLOAD` | `128` | ICMP 최대 payload (바이트). 초과 시 차단 |
| `TUNNEL_LOCK_RESOLV` | `true` | /etc/resolv.conf 변경 잠금 (DNS 터널 방어) |
| `TUNNEL_REMOVE_TOOLS` | `true` | 터널링 도구 패키지 자동 제거 |

**제거 대상 도구:** ptunnel, iodine, dns2tcp, dnscat2, chisel, sshuttle, autossh 등

### 4.7 허용 목록 (allowlist)

점검(02) 스크립트에서 오탐을 방지하기 위한 화이트리스트입니다.

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `WHITELISTED_PORTS` | *(비어있음)* | 의심 포트 점검 제외 (쉼표 구분, 예: `"8080,9090"`) |
| `ACCOUNT_ALLOWLIST` | *(비어있음)* | 계정 잠금 제외 (공백 구분, 예: `"deploy monitoring"`) |
| `CRONTAB_ALLOWLIST` | *(비어있음)* | crontab 허용 사용자 (공백 구분) |
| `SERVICE_ALLOWLIST` | *(비어있음)* | 서비스 자동 중지 제외 (공백 구분, 예: `"docker containerd"`) |

### 4.8 기타 설정

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `ANSIBLE_ACCOUNT` | *(비어있음)* | 자동화 접속 계정. 잠금/nologin에서 자동 보호 |
| `KILL_OTHER_SESSIONS` | `true` | 하드닝 후 다른 SSH 세션 종료 |
| `DISABLE_SERVICES` | `avahi-daemon cups cups-browsed bluetooth` | 비활성화할 서비스 목록 |
| `BLOCKED_MODULES` | `cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat usb-storage` | 차단할 커널 모듈 |
| `SUID_REMOVE_TARGETS` | `/usr/bin/nmap /usr/bin/bash ...` (10개) | SUID 제거 대상 바이너리 |
| `SYSCTL_HARDEN_NETWORK` | `true` | 네트워크 sysctl 보안 설정 |
| `SYSCTL_HARDEN_KERNEL` | `true` | 커널 sysctl 보안 설정 |
| `SYSCTL_DISABLE_IP_FORWARD` | `true` | IP 포워딩 비활성화 |
| `SHM_NOEXEC` | `true` | /dev/shm noexec 적용 |
| `HIDEPID_ENABLED` | `true` | /proc hidepid=2 적용 |

> **`SYSCTL_DISABLE_IP_FORWARD` 주의:** 라우터/게이트웨이 서버에서는 반드시 `false`로 설정하세요.

---

## 5. 하드닝 항목 상세 (21개)

### 5.1 방화벽 설정 (HARDEN_FIREWALL)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_FIREWALL=true` |
| **적용 OS** | Debian (UFW), RHEL (firewalld), FreeBSD (pf), macOS (pf) |
| **동작** | 인바운드: 지정 포트만 허용, 나머지 차단. 아웃바운드: 정책에 따라 restrict/allow |

**`true` 시:**
- 인바운드: `CUSTOM_ALLOWED_PORTS`에 지정된 포트만 허용. SSH 포트는 자동 감지
- 아웃바운드: `OUTBOUND_POLICY=restrict`면 `OUTBOUND_ALLOWED_PORTS`만 허용
- 기존 방화벽 규칙은 초기화(reset)됨

**`false` 시:**
- 방화벽 설정을 건드리지 않음. 기존 규칙이 그대로 유지

**설정 변경 시 영향:**
- `OUTBOUND_POLICY`를 `allow`로 변경하면 공격자가 리버스 셸을 열 수 있음
- `CUSTOM_ALLOWED_PORTS`에 포트를 빠뜨리면 해당 서비스가 외부에서 접근 불가
- `OUTBOUND_ALLOW_ICMP=false`로 변경하면 ping이 안 됨

**주의:** 방화벽을 끄더라도 터널링 방어(HARDEN_TUNNEL_DEFENSE)는 별도로 동작합니다.

---

### 5.2 SSH 하드닝 (HARDEN_SSH)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_SSH=true` |
| **적용 OS** | 전체 |
| **동작** | sshd_config 변경: 인증 방식, 타임아웃, 포워딩 제한 등 |

**`true` 시:**
- `PermitRootLogin`을 설정값으로 변경 (기본: `prohibit-password`)
- `PasswordAuthentication`을 설정값으로 변경 (기본: `no`, SSH 키 없으면 자동 `yes`)
- `AllowTcpForwarding=no` — SSH 터널 차단
- `X11Forwarding=no`
- `MaxAuthTries`, `ClientAliveInterval`, `LoginGraceTime` 적용
- `Banner /etc/issue.net` 설정
- sshd 재시작

**`false` 시:**
- sshd_config를 건드리지 않음

**설정 변경 시 영향:**
- `SSH_PASSWORD_AUTH=no`인데 키가 없으면 접속 불가 (스크립트가 자동 감지하여 보호하지만, config.sh 직접 수정 시 주의)
- `SSH_PERMIT_ROOT_LOGIN=no`로 변경하면 root로 직접 SSH 접속 불가
- `SSH_CLIENT_ALIVE_INTERVAL`을 너무 짧게 하면 네트워크 지연 시 연결이 끊길 수 있음

---

### 5.3 PAM 패스워드 정책 (HARDEN_PAM)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_PAM=true` |
| **적용 OS** | Debian (passwdqc), RHEL (pwquality) |
| **동작** | 패스워드 복잡도 정책 설정 |

**`true` 시:**
- Debian: `pam_passwdqc` 모듈 설정. 기본 min=`disabled,24,12,8,7` (1종류 비활성, 2종류 24자, passphrase 12자, 3종류 8자, 4종류 7자)
- RHEL: `pam_pwquality` 설정. 최소 길이 8자, 최소 문자 클래스 3종

**`false` 시:**
- PAM 패스워드 정책을 변경하지 않음. OS 기본 정책 유지

**설정 변경 시 영향:**
- `PAM_PWQUALITY_MINLEN`을 늘리면 기존 패스워드가 다음 변경 시 거부될 수 있음
- CDX 훈련 중에는 기본값으로 충분함

---

### 5.4 계정 잠금 정책 (HARDEN_FAILLOCK)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_FAILLOCK=true` |
| **적용 OS** | Debian (faillock/pam_tally2), RHEL (faillock) |
| **동작** | 로그인 N회 실패 시 계정 자동 잠금 |

**`true` 시:**
- 5회 실패 시 계정 잠금 (FAILLOCK_DENY)
- 5분 후 자동 해제 (FAILLOCK_UNLOCK_TIME=300)
- root는 잠금 대상에서 제외 (FAILLOCK_DENY_ROOT=false)

**`false` 시:**
- 계정 잠금 정책 미적용. 무한 brute-force 가능

**설정 변경 시 영향:**
- `FAILLOCK_DENY`를 낮추면 정상 사용자도 잠길 수 있음
- `FAILLOCK_DENY_ROOT=true`로 변경하면 root도 잠김. 콘솔 접근 없으면 위험
- `FAILLOCK_UNLOCK_TIME`을 0으로 설정하면 수동 해제 전까지 영구 잠금

---

### 5.5 sysctl 커널 보안 (HARDEN_SYSCTL)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_SYSCTL=true` |
| **적용 OS** | Debian, RHEL, FreeBSD (일부), macOS (제한적) |
| **동작** | `/etc/sysctl.d/99-hardening.conf`에 보안 커널 파라미터 설정 |

**`true` 시:**
- ICMP redirect 차단 (`net.ipv4.conf.all.accept_redirects=0`)
- Source routing 차단 (`net.ipv4.conf.all.accept_source_route=0`)
- SYN flood 방어 (`net.ipv4.tcp_syncookies=1`)
- ASLR 활성화 (`kernel.randomize_va_space=2`)
- SysRq 제한 (`kernel.sysrq=0`)
- SUID core dump 방지 (`fs.suid_dumpable=0`)
- IP 포워딩 비활성화 (SYSCTL_DISABLE_IP_FORWARD=true일 때)

**`false` 시:**
- sysctl 설정을 변경하지 않음

**설정 변경 시 영향:**
- `SYSCTL_DISABLE_IP_FORWARD=true`인데 라우터/게이트웨이 서버이면 네트워크 중단
- `SYSCTL_HARDEN_NETWORK=false`로 개별 비활성화 가능
- IPv6 비활성화는 하지 않음 (안전장치로 보호)

---

### 5.6 시스템 계정 nologin (HARDEN_ACCOUNTS)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_ACCOUNTS=true` |
| **적용 OS** | 전체 |
| **동작** | 시스템 계정(www-data, nobody, daemon 등)의 셸을 `/usr/sbin/nologin`으로 변경 |

**`true` 시:**
- 서비스 계정들이 로그인 불가능하게 변경
- 보호 계정(gt, ANSIBLE_ACCOUNT)은 자동 제외

**`false` 시:**
- 시스템 계정 셸을 변경하지 않음

**설정 변경 시 영향:**
- 정상적인 서비스 계정은 보통 로그인이 필요 없으므로 부작용 없음
- 특정 서비스가 해당 계정으로 로그인이 필요하면 `ACCOUNT_ALLOWLIST`에 추가

---

### 5.7 sudoers NOPASSWD 제거 (HARDEN_SUDOERS)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_SUDOERS=true` |
| **적용 OS** | 전체 |
| **동작** | `/etc/sudoers.d/` 파일에서 NOPASSWD 항목 제거. gt와 ANSIBLE_ACCOUNT는 보호 |

**`true` 시:**
- NOPASSWD sudo 권한 제거 → sudo 시 패스워드 입력 필요
- gt 계정: `/etc/sudoers.d/00-gt-nopasswd` (NOPASSWD 유지)
- ANSIBLE_ACCOUNT: `/etc/sudoers.d/01-ansible-nopasswd` (NOPASSWD 유지)

**`false` 시:**
- sudoers 파일을 변경하지 않음

**설정 변경 시 영향:**
- 기존에 NOPASSWD로 sudo를 사용하던 사용자가 패스워드를 입력해야 함
- 자동화 스크립트가 NOPASSWD에 의존하면 실패할 수 있음 → `ACCOUNT_ALLOWLIST` 활용

---

### 5.8 불필요 서비스 비활성화 (HARDEN_SERVICES)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_SERVICES=true` |
| **적용 OS** | 전체 |
| **동작** | 지정된 서비스를 stop + disable |

**기본 대상:** `avahi-daemon`, `cups`, `cups-browsed`, `bluetooth`

**`true` 시:**
- 대상 서비스가 존재하면 중지 + 부팅 시 자동 시작 비활성화
- gtmon, fscd 등 보안 에이전트 서비스는 자동 보호 (목록에 넣어도 건너뜀)

**`false` 시:**
- 서비스를 건드리지 않음

**설정 변경 시 영향:**
- `DISABLE_SERVICES`에 필요한 서비스를 넣으면 해당 서비스 중단
- `SERVICE_ALLOWLIST`로 특정 서비스를 보호할 수 있음

---

### 5.9 파일 권한 최소화 (HARDEN_FILE_PERMISSIONS)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_FILE_PERMISSIONS=true` |
| **적용 OS** | 전체 |
| **동작** | 민감 파일(sshd_config, shadow, sudoers 등)의 권한을 644/600으로 설정 |

**`true` 시:**
- `/etc/ssh/sshd_config` → 600
- `/etc/shadow` → 600
- `/etc/gshadow` → 600
- `/etc/sudoers` → 440
- 기타 민감 설정 파일 → 644

**`false` 시:**
- 파일 권한을 변경하지 않음

---

### 5.10 other 권한 제거 (HARDEN_OTHER_PERMS)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_OTHER_PERMS=true` |
| **적용 OS** | Debian, RHEL, FreeBSD |
| **동작** | 주요 디렉토리/파일에서 other(제3자) 읽기/쓰기/실행 권한 제거 (`o-rwx`) |

**`true` 시:**
- `/var/log` 등 디렉토리에서 other 권한 제거
- 다른 사용자가 로그 파일 등을 읽을 수 없음

**`false` 시:**
- other 권한을 변경하지 않음

---

### 5.11 SUID 비트 제거 (HARDEN_SUID)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_SUID=true` |
| **적용 OS** | Debian, RHEL, FreeBSD (macOS는 SIP가 관리) |
| **동작** | 위험한 바이너리에서 SUID 비트 제거 |

**기본 대상:** nmap, bash, dash, find, less, pkexec, at, newgrp, chfn, chsh

**`true` 시:**
- 대상 바이너리에서 SUID 비트 제거 (`chmod u-s`)
- 파일이 없으면 건너뜀
- baseline에 현재 SUID 파일 목록 저장 → 02에서 새 SUID 파일 출현 감지

**`false` 시:**
- SUID 비트를 건드리지 않음

**설정 변경 시 영향:**
- `SUID_REMOVE_TARGETS`에 시스템 필수 바이너리(su, sudo, passwd 등)를 추가하면 시스템 장애 발생
- 기본 목록은 안전하게 선별된 것이므로 변경 시 주의

---

### 5.12 빈 패스워드 계정 잠금 (HARDEN_EMPTY_PASSWORDS)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_EMPTY_PASSWORDS=true` |
| **적용 OS** | Debian, RHEL, FreeBSD |
| **동작** | `/etc/shadow`에서 패스워드가 비어있는 계정을 `passwd -l`로 잠금 |

**`true` 시:**
- 빈 패스워드 계정 잠금
- 보호 계정(gt, ANSIBLE_ACCOUNT)은 자동 제외

**`false` 시:**
- 빈 패스워드 계정을 건드리지 않음

---

### 5.13 커널 모듈 차단 (HARDEN_KERNEL_MODULES)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_KERNEL_MODULES=true` |
| **적용 OS** | Debian, RHEL (Linux 전용) |
| **동작** | `/etc/modprobe.d/dev-sec.conf`에 커널 모듈 블랙리스트 작성 |

**기본 차단:** cramfs, freevxfs, jffs2, hfs, hfsplus, squashfs, udf, vfat, usb-storage

**`true` 시:**
- 불필요 파일시스템 모듈과 USB 스토리지 모듈 차단
- `blacklist` + `install /bin/true` 방식

**`false` 시:**
- 커널 모듈 차단 미적용

**설정 변경 시 영향:**
- `BLOCKED_MODULES`에서 `vfat`를 제거하면 FAT 파일시스템 마운트 가능
- `usb-storage`를 제거하면 USB 드라이브 사용 가능
- 훈련 환경에서는 기본 목록 유지 권장

---

### 5.14 /tmp 마운트 하드닝 (HARDEN_MOUNT)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_MOUNT=true` |
| **적용 OS** | Debian, RHEL, FreeBSD |
| **동작** | /tmp, /var/tmp, /dev/shm에 noexec,nosuid,nodev 적용 |

**`true` 시:**
- 임시 디렉토리에서 실행 파일 차단 (noexec)
- SUID 바이너리 차단 (nosuid)
- 디바이스 파일 차단 (nodev)
- fstab에 영구 등록

**`false` 시:**
- 마운트 옵션 변경 안 함

**설정 변경 시 영향:**
- `SHM_NOEXEC=false`로 변경하면 /dev/shm에서 실행 허용 (일부 앱이 필요로 할 수 있음)
- noexec가 적용되면 /tmp에서 컴파일러 실행 등이 불가

---

### 5.15 /proc hidepid (HARDEN_HIDEPID)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_HIDEPID=true` |
| **적용 OS** | Debian, RHEL |
| **동작** | `/proc`에 `hidepid=2` 마운트 |

**`true` 시:**
- 일반 사용자가 다른 사용자의 프로세스를 볼 수 없음 (`ps aux`에 자기 프로세스만 표시)
- root는 영향 없음 (모든 프로세스 볼 수 있음)
- fstab에 영구 등록

**`false` 시:**
- /proc 마운트 옵션 변경 안 함

**설정 변경 시 영향:**
- 공격자(non-root)가 프로세스 정찰 불가 → 방어 효과
- Blue Team도 `sudo ps aux` 필요 (`sudo` 없이는 자기 프로세스만 보임)
- `HIDEPID_ENABLED=false`로 세부 제어 가능

---

### 5.16 core dump 제한 (HARDEN_CORE_DUMP)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_CORE_DUMP=true` |
| **적용 OS** | Debian, RHEL, FreeBSD |
| **동작** | 프로세스 크래시 시 메모리 덤프 생성 방지 |

**`true` 시:**
- `limits.conf`: `* hard core 0`
- systemd `coredump.conf`: `Storage=none`
- sysctl: `fs.suid_dumpable=0`

**`false` 시:**
- core dump 설정 변경 안 함

**설정 변경 시 영향:**
- 디버깅이 필요한 서비스가 있으면 core dump를 생성할 수 없음
- 훈련 환경에서는 디버깅보다 보안이 우선이므로 기본값 유지 권장

---

### 5.17 umask 설정 (HARDEN_UMASK)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_UMASK=true` |
| **적용 OS** | Debian, RHEL |
| **동작** | 시스템 기본 umask를 027로 변경 |

**`true` 시:**
- `/etc/profile`, `/etc/bash.bashrc`(또는 `/etc/bashrc`), `/etc/login.defs`에 umask 설정
- 새로 생성되는 파일에 other 읽기/실행 권한이 자동으로 제거됨

**`false` 시:**
- umask를 변경하지 않음 (OS 기본값 022 유지)

**설정 변경 시 영향:**
- `DEFAULT_UMASK=077`로 강화하면 그룹 읽기도 차단 (서비스 간 파일 공유 문제 가능)
- `DEFAULT_UMASK=022`로 완화하면 모든 사용자가 새 파일을 읽을 수 있음

---

### 5.18 경고 배너 (HARDEN_BANNER)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_BANNER=true` |
| **적용 OS** | 전체 |
| **동작** | SSH 접속 시 법적 경고문 표시 |

**`true` 시:**
- `/etc/issue`, `/etc/issue.net`에 "AUTHORIZED ACCESS ONLY" 배너 설정
- MOTD 스크립트 실행 권한 제거 (OS 정보 노출 방지)
- sshd_config에 `Banner /etc/issue.net` 설정

**`false` 시:**
- 배너를 변경하지 않음

---

### 5.19 터널링 방어 (HARDEN_TUNNEL_DEFENSE)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_TUNNEL_DEFENSE=true` |
| **적용 OS** | Debian, RHEL, FreeBSD |
| **동작** | 3단계 방어: 프로세스 탐지 → 패키지 제거 → 바이너리 삭제 |

**`true` 시:**
1. **프로세스 탐지:** chisel, ligolo, frpc, ngrok, iodine, dns2tcp, dnscat, ptunnel 등 실행 중인 터널 도구 감지
2. **추가 탐지:** TUN 디바이스 사용, 비내부 DNS 쿼리 (DNS 터널링 징후)
3. **패키지 제거:** 터널링 도구 패키지 purge
4. **바이너리 삭제:** 패키지 외 바이너리 직접 삭제

**`false` 시:**
- 터널 관련 탐지/제거를 하지 않음

**설정 변경 시 영향:**
- `TUNNEL_LOCK_RESOLV=true`이면 /etc/resolv.conf가 immutable로 설정됨 → DNS 설정 변경 불가
- `TUNNEL_REMOVE_TOOLS=false`로 변경하면 도구 제거 없이 탐지만 수행

---

### 5.20 패스워드 에이징 (HARDEN_LOGIN_DEFS)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_LOGIN_DEFS=true` |
| **적용 OS** | Debian, RHEL, FreeBSD |
| **동작** | `/etc/login.defs` 패스워드 정책 설정 |

**`true` 시:**
- `PASS_MAX_DAYS=90` — 패스워드 최대 사용기간
- `PASS_MIN_DAYS=7` — 최소 사용기간
- `PASS_WARN_AGE=14` — 만료 경고
- `UMASK=027` — login.defs의 umask도 동기화

**`false` 시:**
- login.defs를 변경하지 않음

**설정 변경 시 영향:**
- CDX는 보통 1~2주이므로 90일 제한이 실제 만료를 유발하지 않음
- `PASS_MAX_DAYS`를 너무 짧게 하면(예: 7) 기존 계정이 만료될 수 있음

---

### 5.21 cron 디렉토리 권한 (HARDEN_CRON)

| 항목 | 내용 |
|------|------|
| **토글** | `HARDEN_CRON=true` |
| **적용 OS** | Debian, RHEL, FreeBSD |
| **동작** | cron 디렉토리/파일 권한을 root만 접근 가능하게 설정 |

**`true` 시:**
- `/etc/cron.d`, `/etc/cron.daily`, `/etc/cron.hourly` 등 → `og-rwx`
- `/etc/crontab` → `og-rwx`, root:root
- 비root 사용자가 cron 설정 변경 불가

**`false` 시:**
- cron 권한을 변경하지 않음

**설정 변경 시 영향:**
- 정상 서비스 계정이 crontab을 사용하면 `CRONTAB_ALLOWLIST`에 추가 필요
- 02 점검 시 비root crontab과 의심 명령어(nc, bash -i, /dev/tcp 등) 패턴도 감지

---

## 6. 안전장치

하드닝 스크립트는 훈련 인프라를 보호하기 위한 안전장치를 내장하고 있습니다. 이 안전장치는 하드닝 전(pre-flight)과 후(post-flight)에 자동 실행됩니다.

### 6.1 gt 계정 보호

Green Team 계정(`gt`)은 훈련 채점 시스템에 필수적입니다.

**보호 내용:**
- 삭제/잠금/nologin 변경 금지
- sudo 그룹 멤버십 보장 (Debian: sudo, RHEL/FreeBSD: wheel, macOS: admin)
- NOPASSWD sudo 보장 (`/etc/sudoers.d/00-gt-nopasswd`)
- 하드닝 스크립트가 실행될 때마다 자동 확인/복원

**이 보호는 비활성화할 수 없습니다.**

### 6.2 ANSIBLE_ACCOUNT 보호

자동화팀 접속 계정은 하드닝 중 보호됩니다.

**보호 내용:**
- nologin 변경에서 제외
- 빈 패스워드 잠금에서 제외
- NOPASSWD sudo 보장 (`/etc/sudoers.d/01-ansible-nopasswd`)
- SSH 세션 종료에서 제외

**설정:** `ANSIBLE_ACCOUNT` 변수에 계정명 지정. Ansible 플레이북은 자동 감지합니다.

### 6.3 gtmon 에이전트 보호

채점 에이전트(gtmon)가 정상 동작하도록 보호합니다.

**보호 내용:**
- 바이너리 실행 권한 확인 (Linux: `/opt/gtmon`, macOS: `/Users/gt/scoringbot/scoringbot`)
- 서비스 활성화/실행 확인 (systemd/rc.d/launchd)
- 비활성화된 경우 자동 복원
- FreeBSD: fscd 헬퍼 서비스도 보호

### 6.4 네트워크 보호

| 보호 항목 | 동작 |
|-----------|------|
| IPv6 | 비활성화 금지. IPv6가 꺼진 것이 감지되면 자동 복원 |
| DNS | 호스트명 변경 감지 시 자동 복원 |
| 아웃바운드 | 필수 포트(22, 80, 443 등) 차단 방지. 차단 규칙이 있으면 자동 제거 |
| ICMP | 아웃바운드 ICMP 차단 시 경고 |

### 6.5 auditd 보호

- 01 스크립트: auditd 설정을 **읽기만** 함 (스냅샷 저장). 변경 없음
- 02 스크립트: 스냅샷 대비 변경 감지 + auto-restore 시 복원

---

## 7. 점검/복원 (02 스크립트)

### 7.1 baseline 스냅샷 구조

01 스크립트 실행 시 생성되는 baseline 스냅샷:

```
/var/backups/hardening/baseline/          # Linux/FreeBSD
/Library/Caches/hardening/baseline/       # macOS
├── INTEGRITY.sha256                      # 무결성 해시
├── auditd/
│   ├── auditd.conf
│   ├── audit_rules_loaded.txt
│   └── rules.d/
├── sshd_config
├── sysctl.d/
├── network_config/
├── suid_files_baseline.txt
├── cron_permissions_baseline.txt
├── hidepid_enabled.txt
└── (OS별 추가 스냅샷)
```

### 7.2 drift 감지 방식

02 스크립트는 baseline과 현재 상태를 비교합니다:

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
| 의심 포트 | 새로운 리스닝 포트 탐지 |
| 의심 crontab | 비root 사용자 crontab + 리버스 셸 패턴 감지 |
| 터널 프로세스 | 터널링 도구 재출현 감지 |

### 7.3 실행 모드

| 모드 | 옵션 | 동작 |
|------|------|------|
| 점검만 | `--check-only` (기본) | drift 보고만, 변경 없음 |
| 자동 복원 | `--auto-restore` | drift 감지 시 자동으로 원상복구 |

auto-restore 시 복원 전 현재 상태를 백업합니다:
```
/var/backups/hardening/hardening_restore_<timestamp>/
```

### 7.4 의심 활동 탐지

02 스크립트는 하드닝 항목 점검 외에도 공격 징후를 탐지합니다:

- **의심 리스닝 포트:** 4444, 5555, 6666, 7777, 8888, 9999, 31337 등
- **의심 crontab 명령어:** `nc`, `ncat`, `bash -i`, `/dev/tcp`, `python.*socket`, `curl.*sh`, `mkfifo` 패턴
- **터널 프로세스:** chisel, ligolo, frpc, iodine 등 재실행 감지
- **비내부 DNS 쿼리:** DNS 터널링 징후

### 7.5 알림

점검 완료 시:
- **syslog:** `logger -t "hardening-check"` 메시지 전송
- **webhook:** `HARDENING_WEBHOOK_URL`이 설정되어 있으면 JSON payload 전송

---

## 8. OS별 차이점

### 8.1 Debian / Ubuntu

| 항목 | 구현 |
|------|------|
| 방화벽 | UFW |
| PAM | passwdqc |
| 패키지 | apt-get |
| 서비스 | systemd (systemctl) |
| 계정 잠금 | faillock (구버전: pam_tally2) |
| sudoers | `/etc/sudoers.d/` |
| 로그인 설정 | `/etc/login.defs` |
| nologin | `/usr/sbin/nologin` |

### 8.2 RHEL / Rocky / AlmaLinux

| 항목 | 구현 |
|------|------|
| 방화벽 | firewalld (direct rules) |
| PAM | pwquality |
| 패키지 | dnf (RHEL 8+) / yum (RHEL 7) |
| 서비스 | systemd (systemctl) |
| 계정 잠금 | faillock (authselect → authconfig → 수동 fallback) |
| sudo 그룹 | wheel |
| SELinux | 변경 안 함 (상태만 로그) |

### 8.3 FreeBSD

| 항목 | 구현 |
|------|------|
| 방화벽 | pf (`/etc/pf.conf`) |
| 패키지 | pkg |
| 서비스 | rc.conf (sysrc) |
| 계정 관리 | pw |
| 패스워드 정책 | `/etc/login.conf` |
| sudo 그룹 | wheel |
| 호스트명 | `/etc/rc.conf` |
| stat 명령어 | `stat -f '%Lp'` (BSD 형식) |
| sed | `sed -i ''` (BSD 형식) |
| gtmon 헬퍼 | fscd 서비스 보호 |

### 8.4 macOS

| 항목 | 구현 |
|------|------|
| 방화벽 | pf (제한적) + socketfilterfw |
| 서비스 | launchd (plist) |
| 계정 관리 | dscl |
| bash 호환성 | 3.2+ (연관 배열 사용 불가) |
| sudo 그룹 | admin |
| PermitRootLogin | 강제 `no` |
| gtmon 경로 | `/Users/gt/scoringbot/scoringbot` |
| gtmon 서비스 | `net.cr14.gtmon.plist` (launchd) |

**macOS에서 미적용 항목:**
- 커널 모듈 차단 (SIP가 관리)
- PAM 패스워드 정책 (macOS 자체 인증 사용)
- /proc hidepid (macOS에 /proc 없음)
- SUID 비트 제거 (SIP가 관리)
- faillock 계정 잠금

---

## 9. 로깅

### 9.1 로그 파일 위치

| 스크립트 | 로그 파일명 |
|----------|------------|
| 01 (하드닝) | `/var/log/hardening/<timestamp>_<hostname>_baseline_hardening.log` |
| 02 (점검) | `/var/log/hardening/<timestamp>_<hostname>_check_result.log` |

`/var/log/hardening/`이 쓰기 불가능하면 `/tmp/`에 저장됩니다.

### 9.2 로그 레벨

| 레벨 | 의미 | 예시 |
|------|------|------|
| `INFO` | 일반 정보 | 작업 시작, 설정 로드 |
| `OK` | 성공 | 하드닝 항목 적용 완료 |
| `SKIP` | 건너뜀 | 이미 적용됨, 토글 비활성화 |
| `WARN` | 경고 | 비치명적 문제 |
| `ERROR` | 오류 | 치명적 실패 (stderr 출력) |
| `DRIFT` | 변조 감지 | baseline과 다른 설정 발견 |
| `RESTORE` | 복원 완료 | auto-restore로 설정 복구 |
| `FAIL` | 복원 실패 | 자동 복원 시도 실패 |

### 9.3 요약 출력

각 스크립트 종료 시 요약이 출력됩니다:

```
============================================================
  Check & Restore Summary
  Mode: auto-restore  Host: bps_dmz_web  OS: debian/ubuntu 22.04
  Drifts: 3  Restores: 3  Failures: 0
============================================================
[OK]     System is in compliance with baseline.
```

| 카운터 | 의미 |
|--------|------|
| Drifts | 변조가 감지된 항목 수 |
| Restores | 성공적으로 복원된 항목 수 |
| Failures | 복원에 실패한 항목 수 |

---

## 10. 트러블슈팅

### 10.1 SSH 접속 불가

**증상:** 하드닝 후 SSH 접속이 안 됨

**원인 및 해결:**

| 원인 | 해결 |
|------|------|
| `SSH_PASSWORD_AUTH=no`인데 키가 없음 | 콘솔에서 `/etc/ssh/sshd_config`의 `PasswordAuthentication`을 `yes`로 변경 후 `systemctl restart sshd` |
| 방화벽이 SSH 포트를 차단 | 콘솔에서 `ufw allow 22/tcp` (Debian) 또는 `firewall-cmd --add-service=ssh --permanent && firewall-cmd --reload` (RHEL) |
| SSH 포트가 기본(22)이 아님 | `CUSTOM_ALLOWED_PORTS`에 실제 SSH 포트 포함 필요 (스크립트는 `ss`/`sshd_config`에서 자동 감지하지만 누락 가능) |

### 10.2 방화벽 문제

**증상:** 특정 서비스에 접근 불가

**해결:**
1. 해당 포트가 `CUSTOM_ALLOWED_PORTS`에 포함되어 있는지 확인
2. 포트 추가: discover 파일 수정 후 4002 재실행, 또는 `hardening_extra_ports` 사용
3. 긴급 시: `ufw allow <port>/tcp` (Debian) 또는 `firewall-cmd --add-port=<port>/tcp --permanent && firewall-cmd --reload` (RHEL)

**아웃바운드 문제:**
- `OUTBOUND_POLICY=restrict`에서 특정 아웃바운드 포트가 필요하면 `OUTBOUND_ALLOWED_PORTS`에 추가
- 긴급 시: `OUTBOUND_POLICY=allow`로 변경 후 재실행

### 10.3 서비스 장애

**증상:** 하드닝 후 특정 서비스가 중지됨

**원인 및 해결:**

| 원인 | 해결 |
|------|------|
| `DISABLE_SERVICES`에 포함됨 | 해당 서비스를 목록에서 제거하거나 `SERVICE_ALLOWLIST`에 추가 |
| 서비스 계정이 nologin 처리됨 | `ACCOUNT_ALLOWLIST`에 해당 계정 추가 |
| 서비스가 /tmp에서 실행 파일 사용 | `HARDEN_MOUNT=false`로 비활성화하거나 서비스 경로 변경 |
| SUID 바이너리 의존 | `SUID_REMOVE_TARGETS`에서 해당 바이너리 제거 |

### 10.4 Ansible 연결 끊김

**증상:** 4002 실행 중 Ansible 연결이 끊김

**원인 및 해결:**

| 원인 | 해결 |
|------|------|
| SSH 패스워드 인증 비활성화 | discover 파일에서 `hardening_ssh_password_auth: "yes"` 확인 |
| ANSIBLE_ACCOUNT 감지 실패 | `-e "ANSIBLE_ACCOUNT=<계정명>"` 명시 |
| sshd 재시작 시 일시 끊김 | 플레이북의 `wait_for_connection` (30초 대기)이 처리하지만, 네트워크가 느리면 timeout 증가 |

> **참고:** 4002/4003 플레이북은 `KILL_OTHER_SESSIONS=true`로 설정되어 있지만, Ansible 접속 계정의 세션은 자동 보호됩니다.

### 10.5 baseline 손상

**증상:** 02 스크립트가 "Baseline snapshot not found" 또는 "integrity check failed" 출력

**해결:**
1. baseline 디렉토리 확인: `ls -la /var/backups/hardening/baseline/`
2. 없으면 01 스크립트 재실행 필요
3. 무결성 실패: baseline 파일이 변조되었을 수 있음. 01 스크립트를 재실행하여 새 baseline 생성

> **주의:** 공격자가 baseline을 변조하면 02 스크립트가 변조된 상태를 "정상"으로 인식합니다. INTEGRITY.sha256이 이를 방지하지만, 공격자가 sha256 파일도 변조하면 탐지가 어렵습니다. 주기적으로 01 스크립트를 재실행하여 baseline을 갱신하세요.

### 10.6 기타

**문법 검증:**
설정 파일 수정 후 반드시 문법 검증을 하세요:
```bash
bash -n config.sh
```

**로그 확인:**
문제 발생 시 로그 파일에서 `[FAIL]`, `[ERROR]`, `[WARN]` 메시지를 확인하세요:
```bash
grep -E '\[(FAIL|ERROR|WARN)\]' /var/log/hardening/*_baseline_hardening.log
```
