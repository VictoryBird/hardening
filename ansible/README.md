# Ansible 하드닝 플레이북

서버 보안 하드닝 스크립트를 다중 OS 서버에 배포하고 실행하기 위한 Ansible 플레이북입니다.

## 2단계 워크플로

```
[1단계 FAM]                    [검토]                     [2단계 본훈련]
playbook_discover.yml  →  host_vars/*.yml 검토  →  playbook_harden.yml
  (서버 상태 수집)           (수동 확인/수정)           (하드닝 적용)
```

### 1단계 — FAM: 서버 상태 수집

```bash
ansible-playbook playbook_discover.yml -i inventory.ini
```

각 서버에 접속하여 리스닝 포트, 보안 에이전트, IP 포워딩, SSH 키 등을 자동 수집합니다.
수집 결과는 `host_vars/<hostname>.yml` 파일로 생성됩니다.

### 2단계 — host_vars 검토

```bash
# 생성된 파일 확인
ls host_vars/

# 각 서버별 설정 검토 및 필요시 수정
vi host_vars/web01.yml
```

자동 수집된 값을 검토하고, 필요한 경우 수동으로 수정하세요:
- 불필요한 포트 제거
- 추가 보호 서비스/계정 등록
- 터널링 방어 설정 조정

### 3단계 — 본훈련: 하드닝 적용

```bash
# 전체 서버 하드닝
ansible-playbook playbook_harden.yml -i inventory.ini

# 특정 서버만 하드닝
ansible-playbook playbook_harden.yml -i inventory.ini --limit web01
```

### 주기적 점검/복원

```bash
# 하드닝 상태 점검
ansible-playbook playbook_check.yml -i inventory.ini

# 자동 복원 포함
ansible-playbook playbook_check.yml -i inventory.ini -e "auto_restore=true"
```

## 디렉토리 구조

```
ansible/
├── playbook_discover.yml        # [1단계] 서버 상태 수집 (FAM)
├── playbook_harden.yml          # [2단계] 하드닝 실행
├── playbook_check.yml           # 점검/복원
├── host_vars/
│   ├── _template.yml            # 호스트별 설정 템플릿
│   └── <hostname>.yml           # playbook_discover.yml이 자동 생성
├── roles/
│   └── hardening/
│       ├── tasks/
│       │   ├── main.yml         # 진입점
│       │   ├── discover.yml     # 서버 자동 탐색 (host_vars 우선)
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

## 포트 허용 우선순위

```
host_vars (discovered_allowed_ports) > CUSTOM_ALLOWED_PORTS > HARDENING_PROFILE (폴백)
```

- host_vars가 있으면: 수집된 포트를 `CUSTOM_ALLOWED_PORTS`로 전달, 프로파일 무시
- host_vars가 없으면: 런타임 포트 수집 → 프로파일 자동 결정 (하위 호환)

## 자동 탐색 기능

| 항목 | FAM (discover) | 본훈련 (harden) |
|------|----------------|-----------------|
| 리스닝 포트 | 수집 → host_vars | host_vars에서 읽기 |
| 보안 에이전트 | 수집 → host_vars | 런타임 재감지 (변경 가능) |
| IP 포워딩 | 수집 → host_vars | host_vars에서 읽기 |
| SSH 키 | 수집 → host_vars | 런타임 재확인 |
| 접속 계정 | — | 런타임 감지 후 자동 보호 |

## 지원 OS

- Linux (ss 명령 사용)
- FreeBSD (sockstat 명령 사용)
- macOS (lsof 명령 사용)

## 주의사항

- `KILL_OTHER_SESSIONS`는 Ansible 실행 시 항상 `true`로 설정됩니다
- `any_errors_fatal: false`로 설정되어 한 서버 실패가 다른 서버에 영향을 주지 않습니다
- 하드닝 후 SSH 연결 확인을 자동으로 수행합니다
- 보안 에이전트(Wazuh, CrowdStrike, Velociraptor)는 하드닝 전에 설치되어 있어야 합니다
- 의심 포트(4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337, 12345, 54321)는 FAM 수집 시 자동 필터링됩니다
