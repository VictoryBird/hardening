# Ansible 하드닝 플레이북

서버 보안 하드닝 스크립트를 다중 OS 서버에 배포하고 실행하기 위한 Ansible 플레이북입니다.

## 디렉토리 구조

```
ansible/
├── playbook_harden.yml          # 하드닝 실행 플레이북 (Playbook A)
├── playbook_check.yml           # 점검/복원 플레이북 (Playbook B)
├── host_vars/
│   └── _template.yml            # 호스트별 설정 오버라이드 템플릿
├── roles/
│   └── hardening/
│       ├── tasks/
│       │   ├── main.yml         # 진입점
│       │   ├── discover.yml     # 서버 자동 탐색
│       │   ├── deploy.yml       # 스크립트 배포
│       │   └── execute.yml      # 하드닝 실행
│       ├── defaults/
│       │   └── main.yml         # 기본 변수
│       └── files/
│           └── .gitkeep         # 하드닝 스크립트 배치 위치
```

## 사전 준비

### 1. 하드닝 스크립트 복사

배포 전에 리포지토리 루트의 스크립트를 `files/hardening/` 디렉토리로 복사해야 합니다:

```bash
mkdir -p roles/hardening/files/hardening
cp -r ../config.sh ../01_baseline_hardening.sh ../02_check_and_restore.sh ../lib roles/hardening/files/hardening/
```

### 2. 인벤토리 파일 준비

대상 서버 목록이 담긴 인벤토리 파일을 준비하세요:

```ini
# inventory.ini 예시
[webservers]
web01 ansible_host=10.0.1.10
web02 ansible_host=10.0.1.11

[dbservers]
db01 ansible_host=10.0.2.10

[all:vars]
ansible_user=deploy
ansible_become=yes
```

### 3. 호스트별 설정 (선택사항)

특정 호스트에 맞춤 설정이 필요한 경우:

```bash
cp host_vars/_template.yml host_vars/web01.yml
# web01.yml을 편집하여 필요한 항목 주석 해제
```

## 사용법

### 하드닝 실행 (Playbook A)

```bash
# 전체 서버 하드닝
ansible-playbook playbook_harden.yml -i inventory.ini

# 특정 서버만 하드닝
ansible-playbook playbook_harden.yml -i inventory.ini --limit web01

# SSH 패스워드 인증 허용으로 하드닝
ansible-playbook playbook_harden.yml -i inventory.ini -e "ssh_password_auth=yes"
```

### 점검/복원 (Playbook B)

```bash
# 하드닝 상태 점검만
ansible-playbook playbook_check.yml -i inventory.ini

# 자동 복원 포함
ansible-playbook playbook_check.yml -i inventory.ini -e "auto_restore=true"
```

## 자동 탐색 기능

플레이북은 각 서버에서 다음을 자동으로 감지합니다:

| 항목 | 설명 |
|------|------|
| 리스닝 포트 | 현재 열린 포트 기반으로 프로파일 결정 (web/dns/ad/log/base) |
| 보안 에이전트 | Wazuh, CrowdStrike, Velociraptor 프로세스 감지 |
| IP 포워딩 | 현재 포워딩 상태에 따라 자동 설정 |
| SSH 키 | authorized_keys 존재 여부로 패스워드 인증 결정 |
| 접속 계정 | Ansible 접속 계정을 자동 보호 대상에 추가 |

## 설정 우선순위

```
host_vars 오버라이드 > 자동 감지값 > config.sh 기본값
```

## 지원 OS

- Linux (ss 명령 사용)
- FreeBSD (sockstat 명령 사용)
- macOS (lsof 명령 사용)

## 주의사항

- `KILL_OTHER_SESSIONS`는 Ansible 실행 시 항상 `false`로 고정됩니다
- `any_errors_fatal: false`로 설정되어 한 서버 실패가 다른 서버에 영향을 주지 않습니다
- 하드닝 후 SSH 연결 확인을 자동으로 수행합니다
- 보안 에이전트(Wazuh, CrowdStrike, Velociraptor)는 하드닝 전에 설치되어 있어야 합니다
