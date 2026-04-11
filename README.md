# Hardening Playbooks (4xxx Series)

자동화팀 레이아웃에 맞춘 서버 보안 하드닝 플레이북입니다.

## 자동화팀에 전달할 파일

```
playbooks/
    4001_hardening_discover.yml
    4002_hardening_apply.yml
    4003_hardening_check.yml
files/scripts/hardening/
    config.sh
    01_baseline_hardening.sh
    02_check_and_restore.sh
    lib/
        common.sh
        safety_guards.sh
        os_debian.sh
        os_rhel.sh
        os_freebsd.sh
        os_macos.sh
```

이 파일들을 자동화팀의 레포 루트에 복사하면 기존 디렉토리 구조와 동일하게 배치됩니다:
- `playbooks/` — 기존 플레이북들과 같은 위치
- `files/scripts/hardening/` — 기존 `files/scripts/` 아래에 하드닝 서브디렉토리 추가

## 2단계 워크플로

```
[1단계: 수집]                      [검토]                      [2단계: 적용]
4001_hardening_discover.yml  →  artifacts/*.yml 검토  →  4002_hardening_apply.yml
  (서버 상태 자동 수집)           (수동 확인/수정)           (하드닝 적용)
```

### 1단계 -- 수집 (Discovery)

```bash
ansible-playbook playbooks/4001_hardening_discover.yml -i inventory
```

각 서버에 접속하여 리스닝 포트, 보안 에이전트, IP 포워딩, SSH 키 등을 자동 수집합니다.
결과는 `artifacts/hardening_discover/<hostname>.yml`에 저장됩니다.

### 검토

```bash
# 수집 결과 확인
ls artifacts/hardening_discover/

# 각 서버별 설정 검토 및 수정
vi artifacts/hardening_discover/web01.yml
```

수집된 값을 검토하고 필요시 수정:
- 불필요한 포트 제거
- 추가 보호 서비스/계정 등록
- SSH/IP 포워딩 설정 조정

### 2단계 -- 적용 (Apply)

```bash
# 수집 파일을 변수로 전달하여 하드닝 적용
ansible-playbook playbooks/4002_hardening_apply.yml -i inventory \
  -e "@artifacts/hardening_discover/web01.yml" --limit web01

# 전체 서버 (host_vars에 변수가 있는 경우)
ansible-playbook playbooks/4002_hardening_apply.yml -i inventory
```

### 주기적 점검/복원

```bash
# 점검만
ansible-playbook playbooks/4003_hardening_check.yml -i inventory \
  -e "@artifacts/hardening_discover/web01.yml" --limit web01

# 자동 복원 포함
ansible-playbook playbooks/4003_hardening_check.yml -i inventory \
  -e "@artifacts/hardening_discover/web01.yml" -e "auto_restore=true" --limit web01
```

## `-e "@file"` 패턴

자동화팀의 inventory/host_vars를 건드리지 않고, 수집 결과 파일을 `-e "@file"`로 전달합니다:

```bash
# 단일 서버
ansible-playbook playbooks/4002_hardening_apply.yml -i inventory \
  -e "@artifacts/hardening_discover/db01.yml" --limit db01

# 또는 수집 파일을 자동화팀 host_vars에 복사하여 사용
cp artifacts/hardening_discover/db01.yml inventories/lab/host_vars/db01.yml
```

## 디렉토리 구조

```
├── playbooks/
│   ├── 4001_hardening_discover.yml    # 수집 (self-contained)
│   ├── 4002_hardening_apply.yml       # 적용 (self-contained)
│   └── 4003_hardening_check.yml       # 점검/복원 (self-contained)
├── files/scripts/hardening/           # 하드닝 스크립트
│   ├── config.sh
│   ├── 01_baseline_hardening.sh
│   ├── 02_check_and_restore.sh
│   └── lib/
│       ├── common.sh
│       ├── safety_guards.sh
│       ├── os_debian.sh
│       ├── os_rhel.sh
│       ├── os_freebsd.sh
│       └── os_macos.sh
├── automation-main/                   # 자동화팀 참조 레포 (수정 금지)
├── legacy/                            # 이전 v3 스크립트
└── docs/
```

## 설계 원칙

1. **Self-contained 플레이북**: 외부 task 파일 의존 없음. 모든 로직이 플레이북 내에 인라인.
2. **group_vars/host_vars 불포함**: 자동화팀이 자체 inventory를 관리. 우리는 artifacts/로 출력.
3. **상대 경로 사용**: `{{ playbook_dir }}/../files/scripts/hardening/` 로 자동화팀 레포에서도 동작.
4. **4xxx 번호 체계**: 자동화팀의 3xxx (에이전트 배포)와 9xxx (범용 스크립트) 사이에 위치.

## 지원 OS

- Linux (Debian/Ubuntu, RHEL/CentOS)
- FreeBSD
- macOS

## 주의사항

- `KILL_OTHER_SESSIONS`는 항상 `true`로 설정됩니다
- `any_errors_fatal: false` -- 한 서버 실패가 다른 서버에 영향을 주지 않습니다
- 하드닝 후 SSH 연결 확인을 자동으로 수행합니다
- 보안 에이전트(Wazuh, CrowdStrike, Velociraptor)는 하드닝 전에 설치되어 있어야 합니다
