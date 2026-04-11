# 시스템 하드닝 스크립트 사용 매뉴얼

## 1. 개요

이 문서는 다중 OS 환경(Debian/Ubuntu, RHEL/CentOS, FreeBSD, macOS)을 지원하는 ��스템 하드닝 스크립트 프레임워크의 사용 매뉴얼입니다. 비하드닝 전문가 및 자동화 팀을 대상으로 작성되었습니다.

### 1.1 시스템 구성도

**하드닝 실행 흐름 (01 스크립트)**

```
config.sh (설정값)
    │
    ▼
01_baseline_hardening.sh (오케스트레이터)
    │
    ├── lib/common.sh         (OS 감지, 로깅, 백업)
    ├���─ lib/safety_guards.sh  (보호 계정, 네트워크, gtmon 가드)
    └── lib/os_<family>.sh    (OS별 어댑터)
            │
            ├── setup_pam()                [1] PAM 패스워드 정책
            ├── setup_ufw()                [2] 방화벽 + 터널 방어
            ├── setup_cron_permissions()   [3] cron 권한
            ├── setup_modprobe()           [4] 커널 모듈 차단
            ├── setup_sysctl()             [5] sysctl 보안
            ├── setup_proc_hidepid()       [6] /proc hidepid
            ├── setup_sensitive_file_permissions() [7] 민감 파일 권한
            ├── ... (총 21개 하드닝 함수)
            └── create_baseline_snapshot() → /var/backups/hardening/baseline/
```

**점검/복원 흐�� (02 스크립트)**

```
config.sh (설정값)
    │
    ▼
02_check_and_restore.sh (오케스트레이터)
    │
    ├── lib/common.sh
    ├── lib/safety_guards.sh
    └── lib/os_<family>.sh
            │
            ├── check_sysctl()            [C1]
            ├── check_file_permissions()  [C2]
            ├── ... (총 21개 점검 함수)
            └── 비교 대상: /var/backups/hardening/baseline/*
                    │
                    ├── --check-only  → drift 리포트 출력
                    └── --auto-restore → drift 자동 복원
```

### 1.2 파일 구조

```
hardening/
├── config.sh                          # 모든 하드닝 설정 (유일하게 수정할 파일)
├── 01_baseline_hardening.sh           # 초기 하드닝 오케스트레이터
├── 02_check_and_restore.sh            # 점검/복원 오케스트레이터
├── lib/
│   ├���─ common.sh                      # 공통 라이브러리 (OS 감지, 로깅, 백업)
│   ├── safety_guards.sh               # 보호 계정/네트워크/에이전트 가드
│   ├── os_debian.sh                   # Debian/Ubuntu 어댑터
│   ├── os_rhel.sh                     # RHEL/CentOS/Rocky 어댑터
│   ├─�� os_freebsd.sh                  # FreeBSD ��댑터
│   └── os_macos.sh                    # macOS 어댑터
├── ansible/
│   ├── playbook_harden.yml            # 하드닝 실행 플레이북
│   ├── playbook_check.yml             # 점검/복원 플레이북
│   ├── README.md                      # Ansible 사용 가이드
│   ├── host_vars/
│   │   └── _template.yml              # 호스트별 설정 오버라이드 템플릿
│   ���── roles/hardening/
│       ��── tasks/
│       │   ├── main.yml               # 역할 진입점
│       │   ├── discover.yml           # 서버 자동 탐색 (포트, 에이전트, SSH 키)
│       │   ├── deploy.yml             # 스크립트 배포
│       │   └── execute.yml            # 하드닝 실행
│       ├── defaults/main.yml          # 기본 변수 (에이전트 정의 포함)
│       └── files/                     # 하드닝 스크립트 배치 위치
└── docs/
    └── manual.md                      # 이 문서
```

### 1.3 실행 흐름

#### 01_baseline_hardening.sh 실행 흐름

1. `lib/common.sh` 로드 -- 전역 상수, 로깅 함수, OS 감지 함수 초기화
2. `detect_os()` -- OS_FAMILY, OS_ID, OS_VERSION 결정
3. `config.sh` 로드 -- 환경변수 오버라이드 적용
4. `lib/safety_guards.sh` 로드 -- 보호 계정/네트워크/에이전트 가드
5. `load_os_adapter()` -- `lib/os_${OS_FAMILY}.sh` 로드
6. 커맨드라인 파싱 (`--check`, `--profile=X`)
7. `require_privileged()` -- root 권한 확인
8. `create_backup_dir()` -- 백업 디렉토리 생성
9. `run_all_guards()` -- 사전 안전 점검 (gt/usr 계정, 네트워크, 호스트명, IPv6, gtmon)
10. `guard_auditd_snapshot_only()` -- auditd 설정 스냅샷 (변경 없음)
11. `run_hardening()` -- OS 어댑터의 21개 하드닝 함수 순차 실행
12. `run_all_guards()` -- 사후 안전 재점검
13. `create_baseline_snapshot()` -- 베이스라인 스냅샷 저장
14. `kill_other_ssh_sessions()` -- 다른 SSH 세션 종료 (설정에 따라)
15. 로그 파일 저장

#### 02_check_and_restore.sh 실행 흐름

1. 라이브러리 로드 (common.sh, config.sh, safety_guards.sh, OS 어댑터)
2. 커맨드라인 파싱 (`--check-only` 또는 `--auto-restore`)
3. `require_privileged()` -- root 권한 확인
4. `create_backup_dir()` -- 백업 디렉토리 생성
5. 베이스라인 스냅샷 존재 확인 (`/var/backups/hardening/baseline/`)
6. `INTEGRITY.sha256` 파일로 베이스라인 무결성 검증
7. `run_all_guards()` -- 사전 안전 점검
8. `run_checks()` -- OS 어댑터의 21개 점검 함수 실행 (MODE에 따라 복원 수행)
9. `check_auditd()` -- auditd 설정 변경 감지 및 복원
10. `run_all_guards()` -- 사후 안전 점검
11. `cleanup_old_backups()` -- 30일 이상 된 복원 백업 삭제
12. `send_alert()` -- syslog 및 웹훅 알림 발송
13. `print_summary()` -- 결과 요약 출력

---

## 2. 사전 준비

### 2.1 필수 조건

| 항목 | 요구사항 |
|------|----------|
| OS | Debian/Ubuntu, RHEL/CentOS/Rocky/Alma, FreeBSD, macOS |
| Bash 버전 | 3.2+ (macOS), 4.0+ (Linux/FreeBSD) |
| 실행 권한 | root 또는 sudo (macOS는 admin 그룹 허용) |
| 디스크 공간 | /var/backups/ (또는 macOS: /Library/Caches/) 에 최소 50MB |
| 네트워크 | apt/yum 패키지 설치를 위한 인터넷 접속 (첫 실행 시) |

### 2.2 실행 순서

```
1. 보안 에이전트 설치 (Wazuh, CrowdStrike 등)
        ↓
2. config.sh 편집 (프로파일, SSH, 터널 방어 등)
        ↓
3. sudo ./01_baseline_hardening.sh 실행
        ↓
4. 주기적 점검: sudo ./02_check_and_restore.sh
        ↓
5. (선택) crontab에 02 스크립트 등록
```

### 2.3 사전 확인 사항

실행 전 반드시 확인해야 할 사항:

- [ ] `gt` 계정이 존재하는가? (보호 계정 -- 없으면 가드 실패)
- [ ] `usr` 계정이 존재하는가? (보호 계정)
- [ ] SSH 키가 등록되어 있는가? (없으면 `SSH_PASSWORD_AUTH=yes` 유지)
- [ ] 서버 용도에 맞는 `HARDENING_PROFILE` 선택했는가?
- [ ] 라우터/게이트웨이인 경우 `SYSCTL_DISABLE_IP_FORWARD=false` 설정했는가?
- [ ] Ansible로 실행하는 경우 `KILL_OTHER_SESSIONS=false` 설정했는가?
- [ ] 보안 에이전트(Wazuh, CrowdStrike, Velociraptor)가 이미 설치되어 있는가?
- [ ] `config.sh` 편집 후 `bash -n config.sh` 로 문법 검증했는가?

---

## 3. Ansible 플레이북 사용법

### 3.1 하드닝 실행

사전 준비: 스크립트를 `roles/hardening/files/hardening/` 디렉토리로 복사합니다.

```bash
cd ansible/
mkdir -p roles/hardening/files/hardening
cp -r ../config.sh ../01_baseline_hardening.sh ../02_check_and_restore.sh ../lib \
    roles/hardening/files/hardening/
```

인벤토리 파일을 준비합니다:

```ini
# inventory.ini
[webservers]
web01 ansible_host=10.0.1.10
web02 ansible_host=10.0.1.11

[dbservers]
db01 ansible_host=10.0.2.10

[all:vars]
ansible_user=deploy
ansible_become=yes
```

하드닝 실행 명령어:

```bash
# 전체 서버 하드닝
ansible-playbook playbook_harden.yml -i inventory.ini

# 특정 서버만 하드닝
ansible-playbook playbook_harden.yml -i inventory.ini --limit web01

# SSH 패스워드 인증 허용으로 하드닝
ansible-playbook playbook_harden.yml -i inventory.ini -e "ssh_password_auth=yes"

# 웹서버 프로파일 강제 지정
ansible-playbook playbook_harden.yml -i inventory.ini -e "hardening_profile=web"
```

### 3.2 점검/복원

기본 실행은 점검만 수행합니다 (`--check-only`). 자동 복원을 원하면 `-e "auto_restore=true"`를 추가합니다.

```bash
# 하드닝 상태 점검만 (기본)
ansible-playbook playbook_check.yml -i inventory.ini

# 자동 복원 포함
ansible-playbook playbook_check.yml -i inventory.ini -e "auto_restore=true"

# 특정 서버만 점검
ansible-playbook playbook_check.yml -i inventory.ini --limit db01
```

### 3.3 호스트별 예외 설정

특정 호스트에 맞춤 설정이 필요한 경우 `host_vars/` 디렉토리에 `<호스트명>.yml` 파일을 생성합니다.

```bash
# 템플릿 복사
cp host_vars/_template.yml host_vars/web01.yml
```

`host_vars/web01.yml` 편집 예시:

```yaml
# 웹서버: 추가 포트 허용 및 프로파일 강제 지정
extra_allowed_ports: "8443/tcp 3306/tcp"
hardening_profile: "web"
ssh_password_auth: "yes"

# Docker 서비스 보호
extra_service_allowlist: "docker containerd"
```

사용 가능한 오버라이드 항목:

| 항목 | 설명 | 예시 |
|------|------|------|
| `extra_allowed_ports` | 자동 감지 외 추가 허용 포트 | `"3306/tcp 8443/tcp"` |
| `hardening_profile` | 방화벽 프로파일 강제 지정 | `"web"` |
| `ssh_password_auth` | SSH 패스워드 인증 허용 | `"yes"` |
| `ssh_permit_root_login` | root SSH 로그인 방식 | `"no"` |
| `sysctl_disable_ip_forward` | IP 포워딩 비활성화 | `"false"` |
| `extra_service_allowlist` | 추가 보호 서비스 | `"docker containerd"` |
| `extra_account_allowlist` | 추가 보호 계정 | `"deploy monitoring"` |
| `disable_services` | 비활성화 서비스 오버라이드 | `"avahi-daemon cups"` |
| `tunnel_defense_enabled` | 터널링 방어 비활성화 | `"false"` |

설정 우선순위: `host_vars 오버라이드 > 자동 감지값 > config.sh 기본값`

### 3.4 자동 탐색 항목

`discover.yml`이 각 서버에서 자동으로 감지하는 항목:

| 탐색 항목 | 감지 방법 | 결과 활용 |
|-----------|-----------|-----------|
| Ansible 접속 계정 | `ansible_user` 변수 | `ANSIBLE_ACCOUNT`에 설정, 자동 보호 |
| 리스닝 포트 | Linux: `ss -tlnp`, FreeBSD: `sockstat`, macOS: `lsof` | 프로파일 자동 결정 (80/443=web, 53=dns, 88/389=ad, 514/1514=log) |
| 방화벽 프로파일 | 포트 조합 분석 | 복수 카테고리 = `full`, 단일 = 해당 프로파일, 없으면 = `base` |
| 보안 에이전트 | 프로세스 감지 (pgrep) | 포트/서비스/계정을 allowlist에 자동 추가 |
| IP 포워딩 상태 | `sysctl -n net.ipv4.ip_forward` | 이미 활성화되어 있으면 `SYSCTL_DISABLE_IP_FORWARD=false` |
| SSH 키 존재 여부 | `~/.ssh/authorized_keys` 확인 | 키 없으면 `SSH_PASSWORD_AUTH=yes` 자동 설정 |

감지 대상 보안 에이전트 정의 (`defaults/main.yml`):

| 에이전트 | 프로세스 | 서비스 | 포트 | 계정 |
|----------|---------|--------|------|------|
| Wazuh | `wazuh-agentd`, `wazuh-modulesd`, `ossec-agentd` | `wazuh-agent` | `1514/tcp`, `1515/tcp` | `wazuh`, `ossec` |
| CrowdStrike | `falcon-sensor` | `falcon-sensor` | - | - |
| Velociraptor | `velociraptor_client`, `velociraptor` | `velociraptor_client` | `8000/tcp` | - |

---

## 4. 설정 파일 (config.sh) 가이드

### 4.1 설정 우선순위

```
host_vars 오버라이드 (Ansible)  >  환경변수  >  config.sh 기본값
```

환경변수 오버라이드 예시:

```bash
# 환경변수로 프로파일과 SSH 인증 방식을 오버라이드
HARDENING_PROFILE=web SSH_PASSWORD_AUTH=yes sudo ./01_baseline_hardening.sh
```

### 4.2 설정 항목 전체 목록

#### 방화벽 설정

| 항목명 | 기본값 | 설명 | 변경 시 영향 |
|--------|--------|------|--------------|
| `HARDENING_PROFILE` | `base` | 방화벽 프로파일 (base/web/ad/log/full/custom) | 인바운드 허용 포트가 변경됨 |
| `CUSTOM_ALLOWED_PORTS` | (비어 있음) | 프로파일 외 추가 허용 포트 (공백 구분, 예: `"3306/tcp 5432/tcp"`) | 지정한 포트가 추가로 인바운드 허용됨 |

#### Ansible / 자동화 설정

| 항목명 | 기본�� | 설�� | 변경 시 영향 |
|--------|--------|------|--------------|
| `ANSIBLE_ACCOUNT` | (비어 있음) | 자동화 도구 접속 계정명 | 이 계정은 nologin 변환/잠금에서 제외됨 |
| `KILL_OTHER_SESSIONS` | `true` | 하드닝 후 다른 SSH 세션 종료 여부 | `false`로 설정하면 다른 SSH 세션 유지 (Ansible 실행 시 필수) |

#### SSH 설정

| 항목명 | ���본값 | 설명 | 변경 시 영향 |
|--------|--------|------|--------------|
| `SSH_PERMIT_ROOT_LOGIN` | `prohibit-password` | root SSH 로그인 방식 | `no`: 완전 차단, `prohibit-password`: 키만 허용, `yes`: 모두 허용 |
| `SSH_PASSWORD_AUTH` | `no` | 패스워드 인증 허용 | `no`로 설정 시 SSH 키 없으면 접속 불가 (스크립트가 키 없으면 자동으로 `yes` 유지) |
| `SSH_MAX_AUTH_TRIES` | `4` | 인증 최대 시도 횟수 | 낮추면 brute-force 방어 강화, 너무 낮으면 정상 사용자 불편 |
| `SSH_CLIENT_ALIVE_INTERVAL` | `300` | 클라이언트 생존 확인 주기 (초) | 낮추면 유휴 세션이 빨리 종료됨 |
| `SSH_CLIENT_ALIVE_COUNT_MAX` | `2` | 클라이언트 무응답 허용 횟수 | `INTERVAL * COUNT_MAX` 초 후 자동 종료 (기본: 600초=10분) |
| `SSH_LOGIN_GRACE_TIME` | `60` | 로그인 유예 시간 (초) | 이 시간 내에 인증을 완료하지 못하면 연결 종료 |

#### 패스워드 정책

| 항목명 | 기본값 | ���명 | 변경 시 영향 |
|--------|--------|------|--------------|
| `PASS_MAX_DAYS` | `90` | 패스워드 최대 사용 기간 (일) | 낮추면 패스워드 변경 주기가 ���아짐 |
| `PASS_MIN_DAYS` | `7` | 패스워드 최소 사용 기간 (일) | 변경 후 이 기간 동안 재변경 불가 |
| `PASS_WARN_AGE` | `14` | 패스워드 만료 경고 기간 (일) | 만료 전 이 일수부터 경고 표시 |
| `LOGIN_RETRIES` | `3` | 로그인 재시도 허용 횟수 | 이 횟수 초과 시 세션 종료 |
| `DEFAULT_UMASK` | `027` | 기본 umask 값 | `027`: 소유자 rwx, 그룹 rx, 기타 없음 |

#### 서비스 비활성화

| 항목명 | 기본값 | 설명 | 변경 시 영향 |
|--------|--------|------|--------------|
| `DISABLE_SERVICES` | `avahi-daemon cups cups-browsed bluetooth` | 비활성화할 서비스 (공백 구분) | 지정된 서비스가 중지 및 비활성화됨. gtmon/fscd는 자동 보호 |

#### 커널 모듈 차단

| 항목명 | 기본값 | ���명 | 변경 시 영�� |
|--------|--------|------|--------------|
| `BLOCKED_MODULES` | `cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat usb-storage` | 차단할 커널 모듈 | 해당 파일시스템/USB 저장장치 사용 불가 (macOS에서는 무시) |

#### SUID 제거

| 항목명 | 기본값 | 설명 | 변경 시 영향 |
|--------|--------|------|--------------|
| `SUID_REMOVE_TARGETS` | `/usr/bin/nmap /usr/bin/bash /usr/bin/dash /usr/bin/find /usr/bin/less /usr/bin/pkexec /usr/bin/at /usr/bin/newgrp /usr/bin/chfn /usr/bin/chsh` | SUID 비트 제거 대상 | 해당 바이너리가 root 권한으로 실행되지 않음 |

#### sysctl 보안 설정

| 항목명 | 기본값 | 설명 | 변경 시 영향 |
|--------|--------|------|--------------|
| `SYSCTL_HARDEN_NETWORK` | `true` | 네트워크 보안 (ICMP redirect/source route 차단 등) | `false`로 설정하면 네트워크 관련 sysctl 미적용 |
| `SYSCTL_HARDEN_KERNEL` | `true` | 커널 보안 (ASLR, sysrq 제한 등) | `false`로 설정하면 커널 보안 sysctl 미적용 |
| `SYSCTL_DISABLE_IP_FORWARD` | `true` | IP 포워딩 비활성화 | **주의: 라우터/게이트웨이에서는 반드시 `false`로 설정** |

#### 마운트 하드닝

| 항목명 | 기본값 | ���명 | 변경 시 영향 |
|--------|--------|------|--------------|
| `SHM_NOEXEC` | `true` | /dev/shm에 noexec 적용 | `false`로 설정하면 공유 메모리에서 실행 파일 허용 |
| `HIDEPID_ENABLED` | `true` | /proc에 hidepid=2 적용 | `false`로 설정하면 다른 사용자의 프로세스 정보 노출 |

#### 계정 잠금 정책

| 항목명 | 기���값 | 설명 | 변경 시 영향 |
|--------|--------|------|--------------|
| `FAILLOCK_DENY` | `5` | 로그인 실패 허용 횟수 | 이 횟수 초과 시 계정 잠금 |
| `FAILLOCK_UNLOCK_TIME` | `900` | 잠금 해제 대기 시간 (초) | 900초 = 15분 후 자동 잠금 해제 |
| `FAILLOCK_DENY_ROOT` | `false` | root 계정 잠금 정책 적용 여부 | `true`로 설정하면 root도 잠금될 수 있음 -- 주의 |

#### 터널링 방어

| 항목명 | 기본값 | 설명 | 변경 시 영향 |
|--------|--------|------|--------------|
| `TUNNEL_DEFENSE_ENABLED` | `true` | 터널링 방어 전체 활성화/비활성화 | `false`로 설정하면 모든 터널 방어 미적용 |
| `TUNNEL_ICMP_MAX_PAYLOAD` | `128` | ICMP 최대 payload 크기 (바이트) | 이 크기 초과 ICMP 패킷 차단. 낮추면 오탐 가능성 증가 |
| `TUNNEL_LOCK_RESOLV` | `true` | /etc/resolv.conf 변경 잠금 | DNS 서버 변경을 방지. DNS 터널링 방어용 |
| `TUNNEL_REMOVE_TOOLS` | `true` | 터널링 도구 자동 제거 | iodine, ptunnel, dnscat2 등 터널링 도구 패키지/바이너리 삭제 |

#### 점검/복원 허용 목록

| 항목명 | 기본값 | 설명 | 변경 시 영향 |
|--------|--------|------|--------------|
| `WHITELISTED_PORTS` | (비어 있음) | 의심 포트 점검 제외 (쉼표 구분, 예: `"8080,9090"`) | 해당 포트가 의심 포트 목록에서 제외됨 |
| `ACCOUNT_ALLOWLIST` | (비어 있음) | 자동 계정 잠금 제외 (공백 구분) | 해당 계정이 nologin 변환 대상에서 제외됨 |
| `CRONTAB_ALLOWLIST` | (비어 있음) | crontab 사용 허용 사용자 (공백 구분) | 해당 사용자의 crontab이 의심 대상에서 제외됨 |
| `SERVICE_ALLOWLIST` | (비어 있음) | 서비스 자동 중지 제외 (공백 구분) | 해당 서비스가 비활성화/중지 대상에서 제외됨 |

#### PAM 패스워드 품질

| 항목명 | 기본값 | 설��� | 변경 시 영��� |
|--------|--------|------|--------------|
| `PAM_PASSWDQC_MIN` | `disabled,24,12,8,7` | Debian: passwdqc min 파라미터 | 형식: `disabled,1종류,2종류,passphrase,3종류,4종류` 최소 길이 |
| `PAM_PWQUALITY_MINLEN` | `8` | RHEL: pwquality 최소 패스워드 길이 | RHEL 계열에서 패스워드 최소 길이 |
| `PAM_PWQUALITY_MINCLASS` | `3` | RHEL: 최소 문자 클래스 수 | 대문자/소문자/숫자/특수문자 중 최소 조합 수 |

### 4.3 설정 변경 예시

#### 웹서버 설정

```bash
# config.sh 수정
HARDENING_PROFILE="web"             # SSH + HTTP + HTTPS 허용
SSH_PASSWORD_AUTH="yes"             # 키 미배포 시 패스워드 허용
CUSTOM_ALLOWED_PORTS="8443/tcp"     # HTTPS 대체 포트 추가
DISABLE_SERVICES="avahi-daemon cups cups-browsed bluetooth postfix"
```

이렇게 설정하면: 인바운드 22/tcp, 80/tcp, 443/tcp, 8443/tcp만 허용되고, SSH 패스워드 인증이 가능하며, postfix를 포함한 불필요 서비스가 비활성화됩니다.

#### 라우터/게이트웨이 ��정

```bash
# config.sh ���정
HARDENING_PROFILE="base"
SYSCTL_DISABLE_IP_FORWARD="false"   # IP 포워딩 유지 (필수!)
TUNNEL_DEFENSE_ENABLED="false"      # 라우터에서는 터널 방어 비활성화
SHM_NOEXEC="false"                  # 라우팅 소프트웨어가 사용할 수 있음
```

이렇게 설정하면: IP 포워딩이 유지되고, 터널 방어 규칙이 적용되지 않으며, /dev/shm에서 실행 파일이 허용됩니다.

#### DB 서버 설정

```bash
# config.sh 수정
HARDENING_PROFILE="base"
CUSTOM_ALLOWED_PORTS="3306/tcp 5432/tcp"   # MySQL + PostgreSQL
SERVICE_ALLOWLIST="mysql mysqld postgresql"  # DB 서비스 보호
ACCOUNT_ALLOWLIST="mysql postgres"           # DB 계정 보호
```

이렇게 설정하면: SSH와 DB 포트만 허용되고, DB 서비스와 계정이 하드닝 중 비활성화/잠금되지 않습니다.

#### Ansible 자동화 환경 설정

```bash
# config.sh 수정
ANSIBLE_ACCOUNT="deploy"            # Ansible 접속 계정
KILL_OTHER_SESSIONS="false"         # Ansible SSH 연결 보호 (필수!)
```

이렇게 설정하면: `deploy` 계정이 nologin 변환 및 잠금 대상에서 제외되고, 하드닝 후 Ansible의 SSH 연결이 유지됩니다.

### 4.4 특정 하드닝 항목 비활성화 방법

#### 터널 방어 비활성화

```bash
TUNNEL_DEFENSE_ENABLED="false"      # 모든 터널 방어 비활성화
```

또는 부분 비활성화:

```bash
TUNNEL_LOCK_RESOLV="false"          # resolv.conf 잠금만 비활성화
TUNNEL_REMOVE_TOOLS="false"         # 터널 도구 삭제만 비활성화
```

#### /proc hidepid 비활성화

```bash
HIDEPID_ENABLED="false"             # /proc hidepid=2 미적용
```

모니터링 도구가 다른 프로세스를 확인해야 하는 환경에서 필요합니다.

#### /dev/shm noexec 비활성화

```bash
SHM_NOEXEC="false"                  # /dev/shm noexec 미적용
```

Oracle DB 등 공유 메모리에서 실행 파일이 필요한 환경에서 사용합니다.

#### 특정 서비스 비활성화에서 제외

```bash
# 방법 1: DISABLE_SERVICES에서 제거
DISABLE_SERVICES="avahi-daemon cups"    # bluetooth 제거

# 방법 2: SERVICE_ALLOWLIST에 추가
SERVICE_ALLOWLIST="docker containerd"    # 이 서비스는 중지하지 않음
```

#### IP 포워딩 유지

```bash
SYSCTL_DISABLE_IP_FORWARD="false"   # IP 포워딩 비활성화하지 않음
```

---

## 5. 하드닝 항목 상세

### 5.1 방화벽

#### 프로파일별 허용 포트

| 프로파일 | 허용 포트 | 용도 |
|----------|-----------|------|
| `base` | `22/tcp` | SSH만 |
| `web` | `22/tcp 80/tcp 443/tcp` | 웹서버 |
| `ad` | `22/tcp 53/tcp 53/udp 88/tcp 389/tcp 389/udp 636/tcp 3268/tcp 3269/tcp` | AD/LDAP 서버 |
| `log` | `22/tcp 514/udp 1514/tcp 1515/tcp 1516/tcp` | 로그/Wazuh 서버 |
| `full` | 위 전부 + `953/tcp` | 복합 서버 |
| `custom` | `CUSTOM_ALLOWED_PORTS`에 직접 지정 | 맞춤 설정 |

#### OS별 방화벽 도구

| OS | 방화벽 도구 | 설정 방법 |
|----|------------|-----------|
| Debian/Ubuntu | UFW (iptables 기반) | `ufw allow`, `ufw default deny incoming` |
| RHEL/CentOS | firewalld | `firewall-cmd --add-port`, `firewall-cmd --set-default-zone` |
| FreeBSD | pf | `/etc/pf.conf` 편집 |
| macOS | pf | `/etc/pf.conf` 편집, `pfctl` 명령 |

#### 기본 정책

- 인바운드: **전체 거부** (프로파일 포트만 허용)
- 아웃바운드: **전체 허용** (보호 포트는 가드가 확인)

#### 터널 방어 규칙 (UFW after.rules)

UFW에서는 `/etc/ufw/after.rules` 및 `/etc/ufw/after6.rules`에 터널 방어 블록이 삽입됩니다. 상세는 5.9절을 참조하세요.

#### 사용 명령

```bash
# UFW 상태 확인
ufw status verbose

# UFW 규칙 추가/삭제
ufw allow 8080/tcp
ufw delete allow 8080/tcp

# UFW 리로드 (after.rules 적용)
ufw reload
```

### 5.2 SSH 하드닝

하드닝 스크립트는 `/etc/ssh/sshd_config.d/99-hardening.conf` 드롭인 파일을 생성합니다.

#### SSH 설정 항목

| sshd_config 설정 | 기본값 | 의미 | 효과 |
|------------------|--------|------|------|
| `PermitRootLogin` | `prohibit-password` | root 로그인 방식 | 키 인증만 허용 (패스워드 로그인 차단) |
| `PasswordAuthentication` | `no` | 패스워드 인증 | SSH 키 필수 (키 없으면 자동 `yes` 유지) |
| `MaxAuthTries` | `4` | 인증 최대 시도 | 4회 실패 시 연결 종료 |
| `PermitEmptyPasswords` | `no` | 빈 패스워드 허용 | 빈 패스워드로 로그인 불가 |
| `X11Forwarding` | `no` | X11 포워딩 | GUI 포워딩 차단 |
| `AllowTcpForwarding` | `no` | TCP 포워딩 | 포트 포워딩 차단 |
| `AllowAgentForwarding` | `no` | SSH 에이전트 포워딩 | 에이전트 포워딩 차단 |
| `AllowStreamLocalForwarding` | `no` | Unix 소켓 포워딩 | 로컬 소켓 포워딩 차단 |
| `PermitTunnel` | `no` | 터널 디바이스 사용 | SSH 터널 차단 |
| `GatewayPorts` | `no` | 게이트웨이 포트 | 원격 포트 포워딩 차단 |
| `ClientAliveInterval` | `300` | 생존 확인 주기 (초) | 5분마다 클라이언트 생존 확인 |
| `ClientAliveCountMax` | `2` | 무응답 허용 횟수 | 2회 무응답 시 연결 종료 (총 10분) |
| `LoginGraceTime` | `60` | 로그인 유예 (초) | 60초 내 인증 미완료 시 종료 |
| `Banner` | `/etc/issue.net` | 로그인 배너 | 법적 경고 배너 표시 |
| `UsePAM` | `yes` | PAM 사용 | PAM 인증 모듈 활성��� |
| `HostbasedAuthentication` | `no` | 호스트 기반 인증 | 비활성화 (보안 취약) |
| `IgnoreRhosts` | `yes` | .rhosts 무시 | .rhosts 파일 무시 |
| `MaxSessions` | `4` | 최대 세션 수 | 연결당 최대 4개 세션 |
| `MaxStartups` | `10:30:60` | 최대 동시 인증 | 10개 이후 30% 확률로 거부, 60개에서 전부 거부 |

#### 잠금 방지 로직

스크립트는 SSH 키가 등록되어 있는지 자동으로 확인합니다:
1. `/etc/passwd`에서 로그인 가능한 계정을 순회
2. `~/.ssh/authorized_keys` 파일이 존재하고 비어있지 않은지 확인
3. 키가 하나도 없으면 `PasswordAuthentication=yes`를 자동 유지
4. `ANSIBLE_ACCOUNT`에 지정된 계정도 동일하게 보호

#### 검증 명령

```bash
# SSH 설정 유효성 검사
sshd -t

# 현재 적용된 SSH 설정 확인
sshd -T

# SSH 서비스 리로드
systemctl reload sshd
```

### 5.3 계정 보안

#### nologin 계정 변환

다음 시스템 계정의 셸을 `/usr/sbin/nologin`으로 변경합니다:

`daemon`, `bin`, `sys`, `games`, `man`, `lp`, `mail`, `news`, `uucp`, `proxy`, `www-data`, `backup`, `list`, `irc`, `gnats`, `nobody`, `_apt`, `systemd-network`, `systemd-resolve`, `messagebus`, `systemd-timesync`, `sshd`, `syslog`, `uuidd`, `tcpdump`, `landscape`, `fwupd-refresh`, `usbmux`, `dnsmasq`, `rtkit`, `kernoops`, `systemd-oom`, `avahi-autoipd`, `nm-openvpn`, `avahi`, `cups-pk-helper`, `saned`, `colord`, `sssd`, `geoclue`, `pulse`, `ntp`, `postfix`, `xrdp`

다음 계정은 `/bin/false`로 변경합니다:

`pollinate`, `tss`, `lxd`, `whoopsie`, `speech-dispatcher`, `gnome-initial-setup`, `hplip`, `gdm`

#### 빈 패스워드 계정 잠금

`/etc/shadow`에서 패스워드 필드가 비어 있는 계정을 `passwd -l`로 잠급니다.

#### SUID 비트 제거

다음 바이너리에서 SUID 비트를 제거합니다:

| 바이너리 | 제거 이유 |
|----------|-----------|
| `/usr/bin/nmap` | 네트워크 스캔 도구 |
| `/usr/bin/bash`, `/usr/bin/dash` | 셸 -- root SUID 위험 |
| `/usr/bin/find` | 명령 실행 가능 (`-exec`) |
| `/usr/bin/less` | 셸 이스케이프 가�� |
| `/usr/bin/pkexec` | 권한 상승 도구 |
| `/usr/bin/at` | 예약 실행 |
| `/usr/bin/newgrp` | 그룹 변경 |
| `/usr/bin/chfn`, `/usr/bin/chsh` | 사용자 정보/셸 변경 |

#### 보호 계정

다음 계정은 하드닝 중 **절대 수정되지 않습니다**:

| 계정 | 보호 내용 |
|------|-----------|
| `gt` | nologin 변환/잠금/삭제 대상에서 제외. sudo 그룹 유지. `/etc/sudoers.d/00-gt-nopasswd`로 NOPASSWD 보장 |
| `usr` | 존재 확인만 수행. 삭제 금지 |
| `ANSIBLE_ACCOUNT` 설정 계정 | nologin 변환/잠금/SSH 세션 종료 대상에서 제외 |
| `ACCOUNT_ALLOWLIST` 계정 | nologin 변환/잠금 대상에서 제외 |

#### kill_other_ssh_sessions 동작

`KILL_OTHER_SESSIONS=true`(기본)일 때 하드닝 완료 후 실행됩니다:

1. 현재 스크립트를 실행 중인 SSH 세션의 sshd PID를 추적
2. `pgrep -x sshd`로 모든 sshd 프로세스를 나열
3. 현재 세션, 마스터 sshd(PPID=1), `gt` 계정, `ANSIBLE_ACCOUNT` ��션은 **제외**
4. 나머지 세션에 `kill -HUP` 전송
5. macOS에서는 **실행하지 않음**

### 5.4 PAM / 패스워드 정책

#### Debian 계열: passwdqc

`/usr/share/pam-configs/passwdqc` 파일을 생성하여 `pam-auth-update`로 적용합니다.

기본 설정: `min=disabled,24,12,8,7`

| 위치 | 의미 | 기본값 |
|------|------|--------|
| 1번째 (disabled) | 1종류 문자만 사용한 패스워드 | 사용 불가 |
| 2번째 | 2종류 문자 사용 시 최소 길이 | 24자 |
| 3번째 | passphrase 최소 길이 | 12자 |
| 4번째 | 3종류 문자 사용 시 최소 길이 | 8자 |
| 5번째 | 4종류 문자 사용 시 최소 길이 | 7자 |

#### RHEL 계열: pwquality

`/etc/security/pwquality.conf`에 설정:
- `minlen` = `PAM_PWQUALITY_MINLEN` (기본: 8)
- `minclass` = `PAM_PWQUALITY_MINCLASS` (기본: 3)

#### faillock 계정 잠금 (공통)

`/etc/security/faillock.conf`에 설정:

| 항목 | 기본값 | 의미 |
|------|--------|------|
| `deny` | 5 | 연속 실패 허용 횟수 |
| `unlock_time` | 900 | 잠금 해제 대기 시간 (초) |
| `fail_interval` | 900 | 실패 횟수 카운트 기간 (초) |
| `even_deny_root` | (미설정) | `FAILLOCK_DENY_ROOT=true` 시 활성화 |

Debian에서는 `/usr/share/pam-configs/faillock`을 생성하고 `pam-auth-update --package`로 PAM 스택에 반영합니다. PAM 스택 검증에 실패하면 자동 롤백합니다.

#### login.defs 설정

| 항목 | 기본값 | 의미 |
|------|--------|------|
| `PASS_MAX_DAYS` | 90 | 패스워드 최대 사용 기간 |
| `PASS_MIN_DAYS` | 7 | 패스워드 최소 사용 기간 |
| `PASS_WARN_AGE` | 14 | 만료 경고 기간 |
| `LOGIN_RETRIES` | 3 | 로그인 재시도 허용 횟수 |
| `UMASK` | 027 | 기본 파일 생성 마스크 |
| `LOG_OK_LOGINS` | yes | 정상 로그인도 로깅 |
| `ENCRYPT_METHOD` | SHA512 | 패스워드 해시 방식 |
| `SHA_CRYPT_MIN_ROUNDS` | 5000 | 해시 라운드 최소 횟수 |

### 5.5 커널 보안 (sysctl)

`/etc/sysctl.d/99-hardening.conf`에 다음 설정을 적용합니다:

| sysctl 키 | 값 | 의미 |
|-----------|----|----- |
| `net.ipv4.conf.all.send_redirects` | `0` | ICMP redirect 전송 차단 |
| `net.ipv4.conf.default.send_redirects` | `0` | ICMP redirect 전송 차단 (기본) |
| `net.ipv4.conf.all.accept_source_route` | `0` | source route 패킷 거부 |
| `net.ipv4.conf.default.accept_source_route` | `0` | source route 패킷 거부 (기본) |
| `net.ipv4.conf.all.accept_redirects` | `0` | ICMP redirect 수신 거부 |
| `net.ipv4.conf.default.accept_redirects` | `0` | ICMP redirect 수신 거부 (기본) |
| `net.ipv4.conf.all.secure_redirects` | `0` | 게이트웨이 ICMP redirect 거부 |
| `net.ipv4.conf.default.secure_redirects` | `0` | 게이트웨이 ICMP redirect 거부 (기본) |
| `net.ipv4.icmp_echo_ignore_broadcasts` | `1` | 브로드캐스트 ICMP 무시 (Smurf 공격 방지) |
| `net.ipv4.icmp_ignore_bogus_error_responses` | `1` | 잘못된 ICMP 에러 무시 |
| `net.ipv4.conf.all.log_martians` | `1` | 비정상 소스 IP 패킷 로깅 |
| `net.ipv4.conf.default.log_martians` | `1` | 비정상 소스 IP 패킷 로깅 (기본) |
| `net.ipv4.tcp_syncookies` | `1` | SYN flood 방지 |
| `kernel.randomize_va_space` | `2` | ASLR 전체 활성화 |
| `kernel.sysrq` | `0` | SysRq 키 비활성화 |
| `fs.suid_dumpable` | `0` | SUID 프로세스 코어 덤프 금지 |
| `fs.protected_hardlinks` | `1` | 하드링크 보호 |
| `fs.protected_symlinks` | `1` | 심볼릭링크 보호 |
| `net.ipv6.conf.all.accept_redirects` | `0` | IPv6 redirect 거부 |
| `net.ipv6.conf.default.accept_redirects` | `0` | IPv6 redirect 거부 (기본) |
| `net.ipv6.conf.all.accept_source_route` | `0` | IPv6 source route 거부 |
| `net.ipv6.conf.default.accept_source_route` | `0` | IPv6 source route 거부 (기본) |
| `net.ipv6.conf.all.accept_ra` | `0` | IPv6 Router Advertisement 거부 |
| `net.ipv6.conf.default.accept_ra` | `0` | IPv6 RA 거부 (기본) |
| `net.ipv6.conf.all.forwarding` | `0` | IPv6 포워딩 비활성화 |
| `net.ipv4.ip_forward` | `0` | IPv4 포워딩 비활성화 (`SYSCTL_DISABLE_IP_FORWARD=true`일 때만) |

**주의**: IPv6 자체는 **비활성화하지 않습니다**. IPv6 redirect/source-route/RA만 차단합니다. `guard_ipv6_preserved()`가 IPv6 비활성화를 감지하면 자동으로 재활성화합니다.

**주의**: `net.ipv4.ip_forward=0`은 `SYSCTL_DISABLE_IP_FORWARD=true`(기본)일 때만 적용됩니다. 라우터/게이트웨이에서는 반드시 `false`로 설정하세요.

### 5.6 파일 권한

#### chmod 0644 대상

| 파일 | 설명 |
|------|------|
| `/etc/passwd` | 사용자 계정 정보 |
| `/etc/group` | 그룹 정보 |
| `/etc/passwd-` | passwd 백업 |
| `/etc/group-` | group 백업 |

#### chmod 0600 대상

| 파일 | 설명 |
|------|------|
| `/etc/shadow` | 패스워드 해시 |
| `/etc/gshadow` | 그룹 패스워드 해시 |
| `/etc/shadow-` | shadow 백업 |
| `/etc/gshadow-` | gshadow 백업 |

#### chown root:root 대상

위의 644/600 대상 파일 모두 (`/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` 및 백업 파일)

#### o-rwx (기타 사용자 권한 제거) 대상

`/etc/fstab`, `/etc/ftpusers`, `/etc/group`, `/etc/hosts`, `/etc/hosts.allow`, `/etc/hosts.equiv`, `/etc/ssh`, `/etc/hosts.lpd`, `/etc/inetd.conf`, `/etc/login.access`, `/etc/login.defs`, `/etc/ssh/sshd_config`, `/etc/sysctl.conf`, `/etc/crontab`, `/usr/bin/crontab`, `/usr/bin/at`, `/usr/bin/atq`, `/usr/bin/atrm`, `/usr/bin/batch`, `/var/log`, `/var/spool/cron/crontabs`

### 5.7 서비스 비활성화

#### 기본 비활성화 서비스

`DISABLE_SERVICES` 기본값으로 다음 서비스가 비활성화됩니다:

| 서비스 | 비활성화 이유 |
|--------|-------------|
| `avahi-daemon.service` | mDNS/DNS-SD -- 네트워크 검색 서비스 |
| `cups.service` | 인쇄 서비스 |
| `cups-browsed.service` | 인쇄 탐색 서비스 |
| `bluetooth.service` | 블루투스 서비스 |

#### 보호 서비스 (절대 비활성화되지 않음)

다음 서비스는 `is_protected_service()` 함수가 보호합니다:

| 서비스 | 설명 |
|--------|------|
| `gtmon` / `gtmon.service` | 그린팀 모니터링 에이전트 (Linux) |
| `fscd` / `fscd.service` | 파일 시스템 무결성 모니터 (FreeBSD) |
| `net.cr14.gtmon` / `net.cr14.gtmon.plist` | gtmon LaunchDaemon (macOS) |

#### SERVICE_ALLOWLIST 사용법

`SERVICE_ALLOWLIST`에 공백으로 구분하여 서비스명을 지정하면, 해당 서비스는 점검/복원 시 자동 중지 대상에서 제외됩니다.

```bash
SERVICE_ALLOWLIST="docker containerd mysql"
```

### 5.8 마운트 하드닝

#### /tmp, /var/tmp, /dev/shm noexec

| 마운트 포인트 | 옵션 | 조건 |
|--------------|------|------|
| `/tmp` | `defaults,rw,nosuid,nodev,noexec,relatime` | 항상 적용 |
| `/var/tmp` | `defaults,rw,nosuid,nodev,noexec,relatime` | 항상 적용 |
| `/dev/shm` | `defaults,rw,nosuid,nodev,noexec,relatime` | `SHM_NOEXEC=true`일 때만 |

fstab에 엔트리를 추가하고, `mount -o remount`로 즉시 적용합니다.

#### /proc hidepid

`HIDEPID_ENABLED=true`(기본)일 때:
- `mount -o remount,hidepid=2 /proc` 실행
- fstab에 `proc /proc proc defaults,hidepid=2 0 0` 추가
- 효과: 일반 사용자가 다른 사용자의 프로세스 정보를 볼 수 없음

컨테이너/가상 환경에서는 remount가 실패할 수 있으며, 이 경우 경고만 표시합니다.

### 5.9 터널링 방어

`TUNNEL_DEFENSE_ENABLED=true`(기본)일 때 적용됩니다.

#### ICMP 터널 방어

`/etc/ufw/after.rules`에 다음 규칙 삽입:

| 규칙 | 방향 | 설명 |
|------|------|------|
| `TUNNEL_ICMP_LARGE_IN` | 인바운드 | ICMP payload > `TUNNEL_ICMP_MAX_PAYLOAD`(128) 바이트 차��� |
| `TUNNEL_ICMP_LARGE_OUT` | 아웃바운드 | 대형 ICMP 아웃바운드 차단 |
| `TUNNEL_ICMP6_LARGE_IN` | 인바운드 | ICMPv6 echo-request 대형 패킷 차단 |
| `TUNNEL_ICMP6_LARGE_OUT` | 아웃바운드 | ICMPv6 echo-request 대형 패킷 차단 |

실제 차단 크기: `20(IP 헤더) + 8(ICMP 헤더) + 128(payload) = 156` 바이트 이상

**참고**: 일반 ping(echo-request)은 차단하지 않습니다. 워크스테이션에서 진단용 ping이 필요하기 ���문입니다.

#### DNS over TCP 터널 방어

| 규칙 | 방향 | 설명 |
|------|------|------|
| `TUNNEL_DNS_TCP_OUT` | 아웃바운드 | TCP 포트 53 아웃바운드 차단 (DNS 터널은 TCP 사용) |
| `TUNNEL_DNS_LARGE_RESP` | 인바운드 | UDP 포트 53, 1024바이트 이상 응답 로깅 (차단하지 않음 -- DNSSEC 오탐 방지) |

#### SOCKS5 패턴 탐지

| 규칙 | 방향 | 설명 |
|------|------|------|
| `TUNNEL_SOCKS5_NOAUTH_IN` | 인바운드 | SOCKS5 No-Auth 핸드셰이크 패턴 (`|050100|`) 차단 |
| `TUNNEL_SOCKS5_CONN_OUT` | 아웃바운드 | SOCKS5 CONNECT 패턴 차단 |

iptables의 `string` 모듈을 사용하여 패킷 payload에서 hex 패턴 `|050100|` (VER=5, NMETHODS=1, METHOD=NO_AUTH)을 탐지합니다.

#### 터널 도구 제거

제거 대상 패키지: `ptunnel`, `ptunnel-ng`, `iodine`, `dns2tcp`, `dnscat2`, `chisel`, `sshuttle`, `autossh`

제거 대상 바이너리:

| 경로 | 도구 |
|------|------|
| `/usr/sbin/iodined`, `/usr/bin/iodine` | DNS 터널 |
| `/usr/bin/dns2tcp`, `/usr/bin/dnscat` | DNS 터널 |
| `/usr/local/bin/chisel` | HTTP/SOCKS5 터널 |
| `/usr/local/bin/gost` | 프록시/터널 |
| `/usr/local/bin/ligolo`, `/usr/local/bin/frpc` | 리버스 터널 |
| `/usr/local/bin/bore`, `/usr/local/bin/inlets` | 포트 포워딩 |
| `/usr/local/sbin/ptunnel`, `/usr/local/sbin/ptunnel-ng` | ICMP 터널 |
| `/usr/local/bin/dnscat2` | DNS 터널 |

프로세스 탐지 대상: `ptunnel`, `ptunnel-ng`, `icmptunnel`, `icmpsh`, `pingtunnel`, `iodine`, `iodined`, `dns2tcp`, `dnscat`, `dnscat2`, `dnscapy`, `dnstunnel`, `chisel`, `ligolo`, `frpc`, `ngrok`, `inlets`, `bore`, `gost`, `autossh`, `sshuttle`

#### resolv.conf 잠금

`TUNNEL_LOCK_RESOLV=true`(기본)일 때:
- systemd-resolved 관리 환경: `/etc/systemd/resolved.conf.d/99-tunnel-hardening.conf` 생성
- 직접 관리 환경: `/etc/resolv.conf`에 `chattr +i` 적용 (immutable 속성)

### 5.10 기타

#### umask 설정

`/etc/profile`, `/etc/bash.bashrc`, `/etc/login.defs`에서 umask 값을 `DEFAULT_UMASK`(기본: `027`)으로 변경합니다.

- `027` = 소유자 rwx, 그룹 rx, 기타 사용자 접근 불가

#### 코어 덤프 제한

- `/etc/security/limits.conf`에 `* hard core 0` 추가
- `/etc/systemd/coredump.conf`에서 `Storage=none`, `ProcessSizeMax=0` 설정

#### 법적 경고 배너

`/etc/issue`와 `/etc/issue.net`에 경고 배너를 설정합니다:

```
====================================================================
                    AUTHORIZED ACCESS ONLY
====================================================================
This system is for authorized use only. All activities are monitored
and logged. Unauthorized access is prohibited and will be prosecuted
to the fullest extent of the law.
====================================================================
```

MOTD 스크립트(`/etc/update-motd.d/*`)의 실행 권한을 제거합니다.

#### 커널 모듈 차단

`/etc/modprobe.d/dev-sec.conf`에 차단 규칙을 작성합니다:

| 모듈 | 설명 |
|------|------|
| `cramfs` | 읽기 전용 압축 파일시스템 |
| `freevxfs` | Veritas VxFS 파일시스템 |
| `jffs2` | Journalling Flash 파일시스템 |
| `hfs` | Apple HFS 파일시스템 |
| `hfsplus` | Apple HFS+ 파일시스템 |
| `squashfs` | 읽기 전용 압축 파일시스템 |
| `udf` | Universal Disk Format |
| `vfat` | FAT 파일시스템 |
| `usb-storage` | USB 저장장치 |

각 모듈에 대해 `blacklist <module>`과 `install <module> /bin/true` 두 줄을 작성합니다.

#### cron 디렉토리 권한

`/etc/cron.hourly`, `/etc/cron.daily`, `/etc/cron.weekly`, `/etc/cron.monthly`, `/etc/cron.d`, `/etc/crontab`에 `chmod og-rwx`, `chown root:root`를 적용합니다.

---

## 6. 점검/복원 (02 스크립트) 상세

### 6.1 동작 모드

| 모드 | 커맨드라인 | 동작 |
|------|-----------|------|
| 점검만 | `--check-only` (기본) | drift만 탐지하고 리포트 출력. 변경 사항 없음 |
| 자동 복원 | `--auto-restore` | drift 탐지 후 자동으로 베이스라인 상태로 복원 |

```bash
# 점검만
sudo ./02_check_and_restore.sh
sudo ./02_check_and_restore.sh --check-only

# 자동 복원
sudo ./02_check_and_restore.sh --auto-restore
```

### 6.2 베이스라인 스냅샷 구조

베이스라인 스냅샷은 `/var/backups/hardening/baseline/` (macOS: `/Library/Caches/hardening/baseline/`)에 저장됩니다.

| 파일 | 내용 |
|------|------|
| `packages_baseline.txt` | `dpkg -l` 패키지 목록 |
| `services_baseline.txt` | 실행 중인 서비스 목록 |
| `ports_baseline.txt` | 리스닝 포트 (`ss -tlnup`) |
| `iptables_baseline.txt` | iptables/ip6tables 규칙 (`iptables -S`) |
| `tunnel_ufw_after_rules_baseline.txt` | UFW after.rules 터널 방어 블록 |
| `sysctl_baseline.txt` | `sysctl -a` 전체 출력 |
| `sysctl_baseline.conf` | sysctl 설정 (key=value 형식, 비교용) |
| `passwd_baseline.txt` | `/etc/passwd` 내용 |
| `sshd_baseline.txt` | `sshd -T` SSH 설정 |
| `sshd_effective_baseline.txt` | `sshd -T` 정렬된 버전 (비교용) |
| `auditd_baseline.txt` | `auditctl -l` 감사 규칙 |
| `tunnel_icmp_iptables_baseline.txt` | ICMP 터널 방어 iptables 규칙 |
| `tunnel_dns_iptables_baseline.txt` | DNS 터널 방어 iptables 규칙 |
| `tunnel_resolv_baseline.txt` | `/etc/resolv.conf` 내용 + chattr 속성 |
| `tunnel_processes_baseline.txt` | 터널 도구 프로세스 존재 여부 |
| `file_permissions_baseline.txt` | 민감 파일 권한/소유자 (`<perm> <owner> <path>`) |
| `suid_files_baseline.txt` | SUID 비트 설정된 파일 목록 |
| `enabled_services_baseline.txt` | 활성화된 서비스 유닛 목록 |
| `active_services_baseline.txt` | 실행 중인 서비스 유닛 목록 |
| `login_accounts_baseline.txt` | 로그인 가능 계정 (`<user>:<shell>`) |
| `ufw_rules_baseline.txt` | UFW 규칙 목록 |
| `audit_rules_baseline.txt` | 감사 규칙 (정렬) |
| `cron_permissions_baseline.txt` | cron 디렉토리 권한 |
| `modprobe_baseline.conf` | `/etc/modprobe.d/dev-sec.conf` 복사본 |
| `hidepid_enabled.txt` | `HIDEPID_ENABLED` 설정값 |
| `listening_ports_baseline.txt` | `ss -tlnp` 출력 (비교용) |
| `login_defs_baseline.txt` | login.defs 주요 설정값 |
| `INTEGRITY.sha256` | 모든 스냅샷 및 주요 설정 파일의 SHA256 해시 |
| `integrity_hashes.txt` | INTEGRITY.sha256 복사본 |
| `auditd/` | auditd 설정 디렉토리 (auditd.conf, rules.d/ 등) |

### 6.3 drift 판단 기준

| # | 점검 항목 | 베이스라인 파일 | 비교 방법 | DRIFT 조건 | 자동 복원 동작 |
|---|---------|---------------|-----------|------------|---------------|
| C1 | sysctl 설정 | `sysctl_baseline.conf` | key=value 행별 비교, `sysctl -n <key>`로 현재값 확인 | 현재값이 베이스라인과 다름 | `sysctl -w <key>=<value>` |
| C2 | 파일 권한 | `file_permissions_baseline.txt` | `stat -c '%a'`와 `stat -c '%U:%G'` 비교 | 권한 또는 소유자 변경됨 | `chmod`/`chown` 복원 |
| C3 | SUID 파일 | `suid_files_baseline.txt` | `find / -perm -4000` 결과와 `comm -13` 비교 | 베이스라인에 없는 새 SUID 파일 발견 | `chmod u-s` |
| C4 | 서비스 상��� | `enabled_services_baseline.txt`, `active_services_baseline.txt` | `systemctl list-unit-files`와 `comm -13` 비교 | 베이스라인에 없는 새 활성/실행 서비스 | `systemctl disable --now` / `systemctl stop` |
| C5 | 로그인 계정 | `login_accounts_baseline.txt` | `/etc/passwd`에서 로그인 가능 계정 추출 후 `comm -13` | 베이스라인에 없는 새 로그인 가능 계정 | `chsh -s /usr/sbin/nologin` |
| C6 | UFW 방화벽 | `ufw_rules_baseline.txt` | `ufw status` 출력 비교 | UFW 비활성화, 정책 변경, 규칙 추가/삭제, 터널 블록 누락 | UFW 재활성화, 규칙 복원, `ufw reload` |
| C7 | sudoers NOPASSWD | - | `grep NOPASSWD` (gt 라인 제외) | gt 이외의 NOPASSWD 발견 | `sed`로 NOPASSWD 제거 |
| C8 | 빈 패스워드 | - | `/etc/shadow`에서 빈 패스워드 필드 확인 | 빈 패스워드 계정 존재 | `passwd -l` |
| C9 | 의심 파일 | - | `/bin`, `/sbin` 등에서 숨겨진 실행파일 탐색, `/tmp` 등에서 실행파일 탐색 | 숨겨진/temp 실행파일 발견 | 리포트만 (자동 삭제 안 함) |
| C10 | auditd | `auditd/` 디렉토리 | `diff` 명령으로 auditd.conf, rules.d 파일 비교 | 설정 파일이 베이스라인과 다름 | 스냅샷에서 복원 후 `augenrules --load` |
| C11 | PAM 정책 | - | passwdqc 파일 존재/내용, faillock.conf deny 설정, common-auth에 faillock 존재 확인 | 설정 파일 누락 또는 내용 변조 | 리포트만 |
| C12 | cron 권한 | `cron_permissions_baseline.txt` | `stat` 비교 | 권한 변경됨 | `chmod`/`chown` 복원 |
| C13 | 커널 모듈 | `modprobe_baseline.conf` | `diff -q` 비교 | 블랙리스트 파일이 삭제/변조됨 | 베이스라인에서 복원 |
| C14 | /proc hidepid | `hidepid_enabled.txt` | `mount` 명령으로 hidepid=2 확인 | hidepid=2가 해제됨 | `mount -o remount,hidepid=2 /proc` |
| C15 | SSH 설정 | `sshd_effective_baseline.txt` | `sshd -T`로 현재 설정 확인, 키별 비교 | SSH 설정이 베이스라인과 다름 | 드롭인 파일 재생성 후 `systemctl reload sshd` |
| C16 | 악성 cron/at | - | crontab 내용에서 의심 패턴(nc, bash -i, /dev/tcp 등) 탐색 | 의심 패턴 발견 또는 비root crontab 존재 | 리포트만 |
| C17 | 네트워크 포트 | `listening_ports_baseline.txt` | `ss -tlnp` 비교 | 새로운 리스닝 포트 또는 의심 포트(4444, 31337 등) 발견 | 리포트만 |
| C18 | 의심 프로세스 | - | 삭제된 바이너리 실행, 의심 패턴, /tmp 경로 실행 탐색 | 의심 프로세스 발견 | ���포트만 |
| C19 | UID 0 백도어 | - | `/etc/passwd`에서 UID 0 계정 확인 | root 이외의 UID 0 계정 존재 | 리포���만 |
| C20 | login.defs | `login_defs_baseline.txt` | key=value 비교 | 설정값 변경됨 | `sed`로 복원 |
| C21 | 터널 방어 | `tunnel_ufw_after_rules_baseline.txt`, `tunnel_resolv_baseline.txt` | iptables 규칙 존재 확인, resolv.conf chattr 확인, 프로세스 탐지, 바이너리 잔류 확인 | 터널 규칙 누락, resolv 잠금 해제, 터널 도구 발견 | `ufw reload`, `chattr +i`, 바이너리 삭제 |

### 6.4 자동 복원이 하는 일

`--auto-restore` 모드에서 수행하는 주요 복원 작업:

1. **sysctl 설정**: 변경된 sysctl 값을 `sysctl -w`로 런타임 복원
2. **파일 권한**: `chmod`/`chown`으로 원래 권한/소유자 복원
3. **SUID 제거**: 새로 나타난 SUID 파일에서 `chmod u-s`
4. **서비스 비활성화**: 새로 활성화된 서비스를 `systemctl disable --now`
5. **계정 잠금**: 새 로그인 계정을 `chsh -s /usr/sbin/nologin`
6. **UFW 복원**: 비활성화된 UFW 재활성화, 규칙 추가/삭제, `ufw reload`
7. **sudoers 정리**: 비인가 NOPASSWD 제거
8. **빈 패스워드 잠금**: `passwd -l`
9. **auditd 복원**: 스냅샷에서 auditd.conf/rules 복원, `augenrules --load`
10. **cron 권한**: 변경된 cron 디렉토리 권한 복원
11. **커널 모듈**: 변조/삭제된 블랙리스트 파일 복원
12. **hidepid**: `mount -o remount,hidepid=2 /proc`
13. **SSH 설정**: 드롭인 파일 재생성 후 `systemctl reload sshd`
14. **login.defs**: 변경된 설정값 `sed`로 복원
15. **터널 방어**: UFW 리로드, resolv.conf chattr 복원, 터널 바이너리 삭제

복원 전에는 반드시 현재 파일을 `/var/backups/hardening/hardening_restore_<timestamp>/`에 백업합니다.

### 6.5 복원 불가 항목

다음 항목은 자동 복원이 불가능하며 수동 개입이 필요합니다:

| 항목 | 이유 | 수동 조치 |
|------|------|-----------|
| 의심 파일 (C9) | 정상 파일과 악성 파일 구별 불가 | 수동으로 파일 확인 후 삭제 |
| PAM 정책 (C11) | PAM 스택 변경은 위험 | `01_baseline_hardening.sh` 재실행 |
| 악성 cron/at (C16) | 정상 작업과 구별 불가 | 수동으로 crontab 확인 후 삭제 |
| 네트워크 포트 (C17) | 프로세스 종료는 서비스 영향 | 수동으로 프로세스 확인 후 조치 |
| 의심 프로세스 (C18) | 정상 프로세스 종료 위험 | 수동으로 프로세스 확인 후 조치 |
| UID 0 백도어 (C19) | 계정 삭제는 위험 | 수동으로 계정 확인 후 제거 |
| UFW after.rules 터널 블록 누락 | 단순 복원 불가 | `01_baseline_hardening.sh` 재실행 |
| auditd 규칙 키 누락 | 개별 규칙 재생성 불가 | `01_baseline_hardening.sh` 재실행 |

---

## 7. 로그

### 7.1 로그 위치

| 환경 | 로그 디렉토리 |
|------|-------------|
| 쓰기 권한이 있는 경우 | `/var/log/hardening/` |
| 쓰기 권한이 없는 경우 (fallback) | `/tmp/` |

로그 파일명 형식:

| 스크립트 | 파일명 |
|----------|--------|
| 01 하드닝 | `<YYYYMMDD_HHMMSS>_<hostname>_baseline_hardening.log` |
| 02 점검/복��� | `<YYYYMMDD_HHMMSS>_<hostname>_check_result.log` |

예: `20260407_143022_webserver01_baseline_hardening.log`

### 7.2 로그 형식

```
[YYYY-MM-DD HH:MM:SS] [LEVEL]   메시지
```

예:

```
[2026-04-07 14:30:22] [INFO]    OS detected: family=debian id=ubuntu version=22.04
```

### 7.3 로그 레벨

| 레벨 | 출력 | 의미 | 카운터 |
|------|------|------|--------|
| `INFO` | stdout | 일반 정보 메시지 | - |
| `OK` | stdout | 점검 통과 또는 작업 성공 | - |
| `SKIP` | stdout | 항목 건너뜀 (이미 적용됨 또는 해당 없음) | - |
| `WARN` | stdout | 경고 (주의 필요하지만 진행 가능) | - |
| `ERROR` | stderr | 오류 (실패했지만 중단하지 않음) | - |
| `DRIFT` | stdout | 베이스라인과 다른 설정 감지 | `DRIFT_COUNT++` |
| `RESTORE` | stdout | drift를 자동으로 복원함 | `RESTORE_COUNT++` |
| `FAIL` | stderr | 복원 시도 실패 또는 심각한 오류 | `FAIL_COUNT++` |

### 7.4 로그 해석 예시

```
[2026-04-07 15:00:01] [INFO]    ============================================================
[2026-04-07 15:00:01] [INFO]      Check & Restore v4.0.0 — START
[2026-04-07 15:00:01] [INFO]      Host: webserver01  OS: debian/ubuntu 22.04
[2026-04-07 15:00:01] [INFO]      Mode: auto-restore  Timestamp: 20260407_150001
[2026-04-07 15:00:01] [INFO]    ============================================================
[2026-04-07 15:00:02] [OK]      Account 'gt' exists
[2026-04-07 15:00:02] [OK]      Account 'gt' is in group 'sudo'
[2026-04-07 15:00:02] [OK]      Sudoers drop-in '/etc/sudoers.d/00-gt-nopasswd' is correct
[2026-04-07 15:00:03] [DRIFT]   sysctl net.ipv4.conf.all.accept_redirects: expected=0, current=1
[2026-04-07 15:00:03] [RESTORE] sysctl net.ipv4.conf.all.accept_redirects=0 restored
[2026-04-07 15:00:04] [OK]      sysctl kernel.randomize_va_space = 2
[2026-04-07 15:00:05] [DRIFT]   New SUID file: /usr/local/bin/suspicious
[2026-04-07 15:00:05] [RESTORE] SUID removed: /usr/local/bin/suspicious
[2026-04-07 15:00:06] [SKIP]    Protected service — skipping disable: gtmon.service
[2026-04-07 15:00:10] [OK]      UFW active
[2026-04-07 15:00:10] [OK]      UFW input policy: DROP
[2026-04-07 15:00:12] [DRIFT]   SSH passwordauthentication: expected=no, current=yes
[2026-04-07 15:00:12] [RESTORE] SSH drop-in regenerated and reloaded
[2026-04-07 15:00:15] [INFO]    ============================================================
[2026-04-07 15:00:15] [INFO]      Check & Restore Summary
[2026-04-07 15:00:15] [INFO]      Mode: auto-restore  Host: webserver01  OS: debian/ubuntu 22.04
[2026-04-07 15:00:15] [INFO]      Drifts: 3  Restores: 3  Failures: 0
[2026-04-07 15:00:15] [INFO]    ============================================================
[2026-04-07 15:00:15] [INFO]    Drifts detected and restored: 3
```

해석:
- `[DRIFT]` 3건 감지: sysctl 변경, 새 SUID 파일, SSH 설정 변경
- `[RESTORE]` 3건 복원: sysctl 복원, SUID 제거, SSH 드롭인 재생성
- `[SKIP]` gtmon.service는 보호 서비스이므로 건너뜀
- `[OK]` gt 계정, UFW 상태 등은 정상
- 최종 결과: Drifts 3, Restores 3, Failures 0 -- 모든 drift 복원 성공

---

## 8. OS별 차이점

| 항목 | Debian/Ubuntu | RHEL/CentOS/Rocky | FreeBSD | macOS |
|------|--------------|-------------------|---------|-------|
| 패키지 관리자 | `apt-get` | `dnf` / `yum` | `pkg` | - |
| 방화벽 | UFW (iptables) | firewalld | pf | pf |
| 서비스 관리자 | systemd (`systemctl`) | systemd (`systemctl`) | rc (`service`, `sysrc`) | launchd (`launchctl`) |
| 사용자 관리 | `useradd`, `usermod`, `chsh` | `useradd`, `usermod`, `chsh` | `pw`, `chpass` | `dscl`, `dseditgroup` |
| sudo 그룹 | `sudo` | `wheel` | `wheel` | `admin` |
| sudoers 디렉토리 | `/etc/sudoers.d/` | `/etc/sudoers.d/` | `/usr/local/etc/sudoers.d/` | `/etc/sudoers.d/` |
| PAM 패스워드 정책 | passwdqc | pwquality | - | - |
| sysctl 설정 파일 | `/etc/sysctl.d/99-hardening.conf` | `/etc/sysctl.d/99-hardening.conf` | `/etc/sysctl.conf` | `sysctl` 명령 |
| SSH 설정 경로 | `/etc/ssh/sshd_config` | `/etc/ssh/sshd_config` | `/etc/ssh/sshd_config` | `/etc/ssh/sshd_config` |
| gtmon 바이너리 경로 | `/opt/gtmon` 또는 `/usr/bin/gtmon` | `/opt/gtmon` 또는 `/usr/bin/gtmon` | `/opt/gtmon` 또는 `/usr/bin/gtmon` | `/Users/gt/scoringbot/scoringbot` |
| gtmon 서비스 | `gtmon.service` (systemd) | `gtmon.service` (systemd) | `gtmon` (rc) + `fscd` (rc) | `net.cr14.gtmon` (launchd) |
| auditd | `auditd` / `auditctl` | `auditd` / `auditctl` | - | - |
| stat 문법 | `stat -c '%a'` (GNU) | `stat -c '%a'` (GNU) | `stat -f '%Lp'` (BSD) | `stat -f '%Lp'` (BSD) |
| sed 문법 | `sed -i '...'` (GNU) | `sed -i '...'` (GNU) | `sed -i '' '...'` (BSD) | `sed -i '' '...'` (BSD) |
| 백업 디렉토리 | `/var/backups/hardening/` | `/var/backups/hardening/` | `/var/backups/hardening/` | `/Library/Caches/hardening/` |
| kill_other_ssh_sessions | 실행됨 | 실행됨 | 실행됨 | **실행하지 않음** |

---

## 9. ���러블슈��

### 9.1 gt 계정 관련

**증상**: 스크립트 실행 시 `[FAIL] Protected account 'gt' does not exist` 오류

**원인**: `gt` 계정이 시스템에 존재하지 않음. `guard_account_gt()`가 실패.

**해결 방법**:
```bash
# gt 계정 생성 (Debian)
useradd -m -s /bin/bash -G sudo gt

# sudoers 설정 (자동 생성되지만 수동 확인)
echo "gt ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/00-gt-nopasswd
chmod 0440 /etc/sudoers.d/00-gt-nopasswd
visudo -c -f /etc/sudoers.d/00-gt-nopasswd
```

---

**증상**: `[DRIFT] Sudoers drop-in '/etc/sudoers.d/00-gt-nopasswd' needs repair`

**원인**: sudoers 파일 내용이 변경되었거나 권한이 440이 아님

**해결 방법**: 스크립트가 자동으로 복원합니다. 수동 확인:
```bash
cat /etc/sudoers.d/00-gt-nopasswd
# 기대값: gt ALL=(ALL) NOPASSWD: ALL

stat -c '%a' /etc/sudoers.d/00-gt-nopasswd
# 기대값: 440
```

### 9.2 gtmon 관련

**증상**: `[WARN] gtmon binary not found at /opt/gtmon or /usr/bin/gtmon`

**원인**: gtmon 에이전트 바이너리가 설치되지 않음

**해결 방법**: 그린팀에서 제공한 gtmon 바이너리를 `/opt/gtmon`에 설치하세요. 하드닝 스크립트는 바이너리를 설치하지 않으며, 존재 여부만 확인합니다.

---

**증상**: `[DRIFT] gtmon.service is not running — starting`

**원인**: gtmon 서비스가 중지됨

**해결 방법**: 스크립트가 자동으로 재시작합니다. 수동 확인:
```bash
# Linux
systemctl status gtmon.service
systemctl start gtmon.service

# FreeBSD
service gtmon status
service gtmon start

# macOS
launchctl list | grep net.cr14.gtmon
launchctl load -w /Library/LaunchDaemons/net.cr14.gtmon.plist
```

### 9.3 SSH 접속 불가

**증상**: SSH 패스워드 인증으로 접속 불가

**원인**: `SSH_PASSWORD_AUTH=no`가 설정되었고 SSH 키가 등록되지 않음. 일반적으로 스크립트가 자동으로 `yes`를 유지하지만, 하드닝 후 키를 삭제한 경우 발생.

**해결 방법**:
1. 콘솔(직접 접근, IPMI, iLO 등)로 접속
2. SSH 드롭인 파일 수정:
```bash
sudo vi /etc/ssh/sshd_config.d/99-hardening.conf
# PasswordAuthentication no → PasswordAuthentication yes
sudo sshd -t && sudo systemctl reload sshd
```

---

**증상**: SSH 접속 시 `Too many authentication failures` 에러

**원인**: `MaxAuthTries=4` 설정으로 인증 시도 제한

**해결 방법**:
```bash
# SSH 클라이언트에서 특정 키만 사용하도록 지정
ssh -i ~/.ssh/specific_key -o IdentitiesOnly=yes user@host
```

---

**증상**: SSH 접속 시 연결이 바로 끊김

**원인**: `LoginGraceTime=60` 초과 또는 `sshd -t` 구문 오류로 sshd가 비정상 상태

**해결 방법**:
```bash
sudo sshd -t     # 구문 오류 확인
sudo journalctl -u sshd -n 20    # sshd 로그 확인
```

### 9.4 방화벽 관련

**증상**: 특정 포트로의 접속이 차단됨

**원인**: `HARDENING_PROFILE`에 해당 포트가 포함되지 않았거나, `CUSTOM_ALLOWED_PORTS`에 추가하지 않음

**해결 방법**:
```bash
# 현재 UFW 상태 확인
sudo ufw status verbose

# 임시로 포트 허용
sudo ufw allow 8080/tcp

# 영구 설정: config.sh 수정
CUSTOM_ALLOWED_PORTS="8080/tcp"
```

---

**증상**: `[DRIFT] UFW is inactive!`

**원인**: UFW가 비활성화됨 (수동 또는 재부�� 후)

**해결 방법**:
```bash
# 즉시 활성화
sudo ufw --force enable

# 또는 02 스크립트로 자동 복원
sudo ./02_check_and_restore.sh --auto-restore
```

---

**증상**: DNS 쿼리 실패 또는 resolv.conf 수정 불가

**원인**: `TUNNEL_LOCK_RESOLV=true`로 `/etc/resolv.conf`에 `chattr +i`(immutable)가 적용됨

**해결 방법**:
```bash
# immutable 속성 확인
lsattr /etc/resolv.conf

# 임시 해제
sudo chattr -i /etc/resolv.conf
# 수정 후 재잠금
sudo chattr +i /etc/resolv.conf
```

### 9.5 에이전트 관련

**증상**: Wazuh/CrowdStrike/Velociraptor 에이전트가 하드닝 후 중지됨

**원인**: 에이전트 서비스가 `DISABLE_SERVICES`에 포함되었거나, 포트가 방화벽에서 차단됨

**해결 방법**:
```bash
# 1. 에이전트 서비스를 SERVICE_ALLOWLIST에 추가
SERVICE_ALLOWLIST="wazuh-agent falcon-sensor velociraptor_client"

# 2. 에이전트 포트를 CUSTOM_ALLOWED_PORTS에 추가
CUSTOM_ALLOWED_PORTS="1514/tcp 1515/tcp"

# 3. 에이전트 계정을 ACCOUNT_ALLOWLIST에 추가
ACCOUNT_ALLOWLIST="wazuh ossec"
```

또는 Ansible 자동 탐색을 사용하면 에이전트가 자동으로 감지되어 allowlist에 추가됩니다.

---

**��상**: Ansible 실행 중 SSH 연결이 끊어짐

**원인**: `KILL_OTHER_SESSIONS=true`(기본)으로 하드닝 후 Ansible의 SSH 연결이 종료됨

**해결 방법**:
```bash
# config.sh에서 설정
KILL_OTHER_SESSIONS="false"
ANSIBLE_ACCOUNT="deploy"

# 또는 환경변수로 오버라이드
KILL_OTHER_SESSIONS=false ANSIBLE_ACCOUNT=deploy sudo ./01_baseline_hardening.sh
```

Ansible 플레이북의 `discover.yml`은 `KILL_OTHER_SESSIONS`를 자동으로 `true`로 설정하지만, 실제로는 Ansible 계정의 SSH 세션은 보호됩니다 (`ANSIBLE_ACCOUNT`에 의해).
