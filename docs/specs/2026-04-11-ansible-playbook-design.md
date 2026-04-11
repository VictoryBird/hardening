# Ansible Playbook Design Spec

## 목적

사이버 훈련 환경의 다수 서버(Linux, FreeBSD, macOS)에 하드닝 스크립트를 안전하게 배포하고 실행하기 위한 Ansible 플레이북 설계.

## 전제 조건

- 자동화팀이 인벤토리를 보유하고 있음 (서버 IP, SSH 접속 계정)
- 보안 에이전트(Wazuh, CrowdStrike Falcon, Velociraptor)는 이미 설치된 상태
- 플레이북이 서버 특성(OS, 서비스, 포트)을 자동 감지하여 판단
- 서버별 예외 설정은 `host_vars/`로 관리

## 디렉토리 구조

```
ansible/
├── playbook_harden.yml              # 플레이북 A: 하드닝 실행
├── playbook_check.yml               # 플레이북 B: 점검/복원
├── host_vars/
│   └── _template.yml                # 호스트별 오버라이드 템플릿
├── roles/
│   └── hardening/
│       ├── tasks/
│       │   ├── main.yml             # 진입점: discover → deploy → execute
│       │   ├── discover.yml         # 서버 자동 탐색
│       │   ├── deploy.yml           # 스크립트 배포
│       │   └── execute.yml          # 하드닝 실행
│       ├── files/
│       │   └── hardening/           # 스크립트 디렉토리 통째로 복사
│       │       ├── config.sh
│       │       ├── 01_baseline_hardening.sh
│       │       ├── 02_check_and_restore.sh
│       │       └── lib/
│       │           ├── common.sh
│       │           ├── safety_guards.sh
│       │           ├── os_debian.sh
│       │           ├── os_rhel.sh
│       │           ├── os_freebsd.sh
│       │           └── os_macos.sh
│       └── defaults/
│           └── main.yml             # 역할 기본 변수
```

---

## 플레이북 A: playbook_harden.yml

### 사용법

```bash
# 전체 서버 하드닝
ansible-playbook playbook_harden.yml -i inventory

# 특정 서버만
ansible-playbook playbook_harden.yml -i inventory --limit webserver01

# 변수 오버라이드
ansible-playbook playbook_harden.yml -i inventory -e "ssh_password_auth=yes"
```

### 실행 흐름

```
1. discover.yml
   ├── OS 감지 (Ansible facts)
   ├── 리스닝 포트 수집
   ├── 실행 중인 서비스 수집
   ├── 보안 에이전트 감지
   ├── IP 포워딩 상태 확인
   ├── SSH 키 존재 확인
   ├── 프로파일 자동 결정
   └── environment 변수 조합

2. deploy.yml
   └── 스크립트 디렉토리 배포 → /opt/hardening/

3. execute.yml
   └── 01_baseline_hardening.sh 실행 (environment 변수 전달)
```

---

## 플레이북 B: playbook_check.yml

### 사용법

```bash
# 점검만 (기본)
ansible-playbook playbook_check.yml -i inventory

# 자동 복원
ansible-playbook playbook_check.yml -i inventory -e "auto_restore=true"
```

### 실행 흐름

```
1. discover.yml (A와 동일)
2. 02_check_and_restore.sh 실행
   - 기본: --check-only
   - auto_restore=true 시: --auto-restore
```

---

## discover.yml 상세 설계

### 1단계: OS 감지

Ansible facts 사용. 추가 태스크 불필요.

```yaml
# ansible_os_family: "Debian", "RedHat", "FreeBSD", "Darwin"
# ansible_distribution: "Ubuntu", "Rocky", "FreeBSD", "MacOSX"
# ansible_distribution_version: "22.04", "9.3", etc.
```

### 2단계: 리스닝 포트 수집

```yaml
# Linux
- command: ss -tlnp
# FreeBSD
- command: sockstat -l -4 -6
# macOS
- command: lsof -iTCP -sTCP:LISTEN -nP
```

결과를 파싱하여 포트 목록 추출 → `discovered_ports` fact 등록.

### 3단계: 프로파일 자동 결정

포트 기반 매핑 로직:

| 감지된 포트 | 프로파일 |
|------------|---------|
| 80, 443 | web |
| 53 | dns (→ full에 포함) |
| 88, 389, 636 | ad |
| 514, 1514, 1515, 1516 | log |
| 여러 카테고리 해당 | full |
| 위에 해당 없음 | base |

`host_vars`에 `hardening_profile`이 지정되어 있으면 자동 감지를 무시하고 해당 값 사용.

### 4단계: 보안 에이전트 감지

프로세스와 서비스를 확인하여 보호 대상을 자동 수집.

| 에이전트 | 프로세스명 | 서비스명 | 포트 |
|---------|-----------|---------|------|
| Wazuh | wazuh-agentd, wazuh-modulesd | wazuh-agent | 1514/tcp, 1515/tcp |
| CrowdStrike Falcon | falcon-sensor | falcon-sensor | - (커널 모듈 통신) |
| Velociraptor | velociraptor_client | velociraptor_client | 8000/tcp (가변) |

감지 결과:
- `discovered_agent_ports` → `CUSTOM_ALLOWED_PORTS`에 합산
- `discovered_agent_services` → `SERVICE_ALLOWLIST`에 합산
- CrowdStrike 감지 시 → `BLOCKED_MODULES`에서 falcon 관련 모듈 제외 보장

### 5단계: IP 포워딩 감지

```yaml
# Linux
- command: sysctl -n net.ipv4.ip_forward
# FreeBSD
- command: sysctl -n net.inet.ip.forwarding
```

현재 값이 1이면 `sysctl_disable_ip_forward: "false"` 설정 (라우터/게이트웨이로 판단).

`host_vars`에 명시적 값이 있으면 감지값을 무시.

### 6단계: SSH 키 확인

```yaml
- stat:
    path: "{{ ansible_env.HOME }}/.ssh/authorized_keys"
# 또는 /root/.ssh/authorized_keys
```

authorized_keys가 없거나 비어있으면 `ssh_password_auth: "yes"` 강제.

### 7단계: environment 변수 조합

모든 감지 결과와 host_vars 오버라이드를 합쳐서 최종 environment 구성:

```yaml
environment:
  HARDENING_PROFILE: "{{ final_profile }}"
  CUSTOM_ALLOWED_PORTS: "{{ final_custom_ports }}"
  SSH_PASSWORD_AUTH: "{{ final_ssh_pw_auth }}"
  SYSCTL_DISABLE_IP_FORWARD: "{{ final_ip_forward }}"
  SERVICE_ALLOWLIST: "{{ final_service_allowlist }}"
  ACCOUNT_ALLOWLIST: "{{ final_account_allowlist }}"
  # config.sh 기본값을 사용할 항목은 전달하지 않음 (${VAR:-default} 작동)
```

우선순위:
```
host_vars 수동 지정 (최우선)
    ↓
discover 자동 감지
    ↓
config.sh 기본값 (최하위)
```

---

## host_vars 템플릿

`ansible/host_vars/_template.yml`:

```yaml
# ═══════════════════════════════════════════════════════════════
# 호스트별 하드닝 설정 오버라이드
# ═══════════════════════════════════════════════════════════════
# 이 파일을 복사해서 <호스트명>.yml로 저장하세요.
# 필요한 항목만 주석 해제. 나머지는 자동 감지값 또는 config.sh 기본값 사용.
#
# 예: cp _template.yml webserver01.yml

# --- 추가 허용 포트 (자동 감지 외 수동 추가) ---
# extra_allowed_ports: "3306/tcp 8443/tcp"

# --- 방화벽 프로파일 강제 지정 (자동 감지 무시) ---
# hardening_profile: "web"

# --- SSH ---
# ssh_password_auth: "yes"
# ssh_permit_root_login: "no"

# --- IP 포워딩 (라우터/게이트웨이는 false) ---
# sysctl_disable_ip_forward: "false"

# --- 추가 보호 서비스 (자동 감지 외 수동 추가) ---
# extra_service_allowlist: "docker containerd"

# --- 추가 보호 계정 (자동 감지 외 수동 추가) ---
# extra_account_allowlist: "deploy monitoring"

# --- 비활성화 서비스 오버라이드 (config.sh 기본값 대체) ---
# disable_services: "avahi-daemon cups"

# --- 터널링 방어 비활성화 (특수 환경) ---
# tunnel_defense_enabled: "false"
```

---

## deploy.yml 상세 설계

```yaml
- name: Create hardening directory
  file:
    path: /opt/hardening
    state: directory
    mode: '0750'
    owner: root

- name: Deploy hardening scripts
  copy:
    src: hardening/
    dest: /opt/hardening/
    mode: preserve
    owner: root

- name: Ensure scripts are executable
  file:
    path: "/opt/hardening/{{ item }}"
    mode: '0750'
  loop:
    - 01_baseline_hardening.sh
    - 02_check_and_restore.sh
```

macOS의 경우 배포 경로를 `/opt/hardening/`에서 `/Library/Caches/hardening/`으로 변경할 수 있으나, `/opt/`도 macOS에서 사용 가능하므로 통일.

---

## execute.yml 상세 설계

### 플레이북 A (하드닝)

```yaml
- name: Run baseline hardening
  command: bash /opt/hardening/01_baseline_hardening.sh
  become: yes
  environment: "{{ hardening_environment }}"
  register: hardening_result

- name: Show hardening result
  debug:
    msg: "{{ hardening_result.stdout_lines | last }}"
```

### 플레이북 B (점검)

```yaml
- name: Run check and restore
  command: >
    bash /opt/hardening/02_check_and_restore.sh
    {{ '--auto-restore' if auto_restore | default(false) | bool else '--check-only' }}
  become: yes
  environment: "{{ hardening_environment }}"
  register: check_result

- name: Show check result
  debug:
    msg: "{{ check_result.stdout_lines | last }}"
```

---

## defaults/main.yml

role 기본 변수. 모든 값은 host_vars나 실행 시 -e 로 오버라이드 가능.

```yaml
# 자동 복원 모드 (플레이북 B에서 사용)
auto_restore: false

# 하드닝 스크립트 배포 경로
hardening_deploy_path: /opt/hardening

# discover에서 자동 감지할 보안 에이전트 목록
known_agents:
  wazuh:
    processes: "wazuh-agentd wazuh-modulesd"
    services: "wazuh-agent"
    ports: "1514/tcp 1515/tcp"
  crowdstrike:
    processes: "falcon-sensor"
    services: "falcon-sensor"
    ports: ""
  velociraptor:
    processes: "velociraptor_client"
    services: "velociraptor_client"
    ports: "8000/tcp"
```

---

## 에러 처리

| 상황 | 처리 |
|------|------|
| SSH 접속 실패 | Ansible 기본 에러 → 해당 호스트 skip |
| sudo 권한 없음 | become 실패 → 해당 호스트 skip + 경고 |
| OS 미지원 | discover에서 감지 → skip + 경고 |
| 스크립트 실행 에러 | register로 캡처 → 로그에 stdout/stderr 출력, 다음 호스트 계속 |
| 에이전트 감지 실패 | 감지 못하면 보호도 안 됨 → known_agents에 추가 필요 경고 |

`any_errors_fatal: false` 설정으로 한 서버 실패가 전체를 중단시키지 않도록.

---

## 자동화팀 전달물

```
ansible/                         # 이 디렉토리를 전달
├── playbook_harden.yml          # "이거 실행하세요"
├── playbook_check.yml           # "이거로 점검하세요"
├── host_vars/
│   └── _template.yml            # "특정 서버 설정은 이걸 복사해서"
├── roles/hardening/             # 내부 구조 (건드릴 필요 없음)
└── README.md                    # 사용법 문서
```

자동화팀이 해야 할 일:
1. 자기 인벤토리에 맞춰 실행
2. 특정 서버 예외가 필요하면 `host_vars/서버명.yml` 생성
3. 끝
