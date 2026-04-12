# Hardening Playbooks (4xxx Series)

자동화팀 레이아웃에 맞춘 서버 보안 하드닝 플레이북입니다.

## 전체 프로세스

```
FAM (사전 훈련) — 목적: 스크립트 검증 + 서버 설정값 확보
 │
 ├─ ① Discover ──→ artifacts/서버명.yml (포트, 서비스, 에이전트 자동 수집)
 ├─ ② 검토/수정    (수집 결과 확인, 필요시 포트 추가/제거)
 └─ ③ 검증 실행    (하드닝 테스트 → 정상 작동 확인 → 이 스냅샷은 버림)

본훈련 (같은 원본 + 사전 공격이 심어진 상태)
 │
 ├─ ④ Harden ───→ FAM의 discover 결과(①) 그대로 사용하여 하드닝 적용
 │                  + 베이스라인 스냅샷 저장 ← 이것이 진짜 기준선
 └─ ⑤ Check (반복) ──→ ④의 스냅샷 기준으로 drift 감시 / 자동 복원
```

**핵심:**
- FAM과 본훈련의 원본 환경(스냅샷)은 동일
- FAM에서 확보한 discover 결과는 본훈련에서도 유효
- 본훈련에서 하드닝을 다시 실행해야 함 (사전 공격이 심어진 상태이므로)
- 하드닝이 공격 흔적도 같이 정리 (백도어 계정, 의심 서비스 등)

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
        os_debian.sh
        os_rhel.sh
        os_freebsd.sh
        os_macos.sh
```

자동화팀 레포 루트에 복사하면 기존 디렉토리 구조와 동일하게 배치됩니다:
- `playbooks/` — 기존 플레이북들과 같은 위치
- `files/scripts/hardening/` — 기존 `files/scripts/` 아래에 하드닝 서브디렉토리 추가

---

## 상세 사용법

### FAM ① Discover — 서버 상태 수집

```bash
ansible-playbook playbooks/4001_hardening_discover.yml -i inventories/lab/hosts.yml
```

각 서버에 접속하여 자동 수집:
- 리스닝 포트 (방화벽 허용 목록으로 사용)
- 보안 에이전트 (Wazuh, CrowdStrike, Velociraptor)
- IP 포워딩 상태
- SSH 키 존재 여부

결과: `artifacts/hardening_discover/<hostname>.yml`

### FAM ② 검토

```bash
ls artifacts/hardening_discover/
cat artifacts/hardening_discover/bps_dmz_git.yml
```

수집된 값을 검토하고 필요시 수정:
- 불필요한 포트 제거 (의심 포트는 자동 제외됨)
- 추가로 열어야 할 포트 추가
- 서비스/계정 보호 목록 확인

### FAM ③ 검증 실행

```bash
# 하드닝 테스트 (FAM 환경에서)
ansible-playbook playbooks/4002_hardening_apply.yml -i inventories/lab/hosts.yml \
  -e "@artifacts/hardening_discover/bps_dmz_git.yml" --limit bps_dmz_git

# 정상 작동 확인
ansible-playbook playbooks/4003_hardening_check.yml -i inventories/lab/hosts.yml \
  -e "@artifacts/hardening_discover/bps_dmz_git.yml" --limit bps_dmz_git
```

drift 0건이면 정상. 이 스냅샷은 본훈련에서 다시 만들므로 버려도 됩니다.

### 본훈련 ④ Harden — 하드닝 적용

```bash
# FAM에서 확보한 discover 결과를 그대로 사용
ansible-playbook playbooks/4002_hardening_apply.yml -i inventories/lab/hosts.yml \
  -e "@artifacts/hardening_discover/bps_dmz_git.yml" --limit bps_dmz_git
```

이때 저장되는 베이스라인 스냅샷이 **진짜 기준선**입니다.

### 본훈련 ⑤ Check — 주기적 점검

```bash
# 점검만
ansible-playbook playbooks/4003_hardening_check.yml -i inventories/lab/hosts.yml \
  -e "@artifacts/hardening_discover/bps_dmz_git.yml" --limit bps_dmz_git

# 자동 복원 (공격자가 설정 변경한 경우)
ansible-playbook playbooks/4003_hardening_check.yml -i inventories/lab/hosts.yml \
  -e "@artifacts/hardening_discover/bps_dmz_git.yml" -e "auto_restore=true" --limit bps_dmz_git
```

---

## 특정 하드닝 항목 비활성화

config.sh에 21개 토글 변수가 있습니다. Ansible에서 환경변수로 오버라이드:

```bash
# SSH 하드닝만 끄기
ansible-playbook playbooks/4002_hardening_apply.yml -i inventories/lab/hosts.yml \
  -e "@artifacts/hardening_discover/bps_dmz_git.yml" \
  -e "HARDEN_SSH=false" --limit bps_dmz_git

# 방화벽 + 터널링 방어 끄기
  -e "HARDEN_FIREWALL=false HARDEN_TUNNEL_DEFENSE=false"
```

---

## `-e "@file"` 패턴

자동화팀의 inventory/host_vars를 건드리지 않고, discover 결과 파일을 `-e "@file"`로 전달합니다:

```bash
# 단일 서버
ansible-playbook playbooks/4002_hardening_apply.yml -i inventories/lab/hosts.yml \
  -e "@artifacts/hardening_discover/bps_dmz_git.yml" --limit bps_dmz_git

# 또는 discover 결과를 자동화팀 host_vars에 복사하여 사용
cp artifacts/hardening_discover/bps_dmz_git.yml inventories/lab/host_vars/bps_dmz_git_hardening.yml
```

---

## 디렉토리 구조

```
├── playbooks/
│   ├── 4001_hardening_discover.yml    # 수집 (self-contained)
│   ├── 4002_hardening_apply.yml       # 적용 (self-contained)
│   └── 4003_hardening_check.yml       # 점검/복원 (self-contained)
├── files/scripts/hardening/           # 하드닝 스크립트
│   ├── config.sh                      # 설정 파일 (이것만 수정)
│   ├── 01_baseline_hardening.sh       # 하드닝 실행 스크립트
│   ├── 02_check_and_restore.sh        # 점검/복원 스크립트
│   └── lib/                           # 내부 라이브러리 (수정 불필요)
├── artifacts/                         # discover 결과 (자동 생성)
│   └── hardening_discover/
├── automation-main/                   # 자동화팀 참조 레포 (수정 금지)
├── legacy/                            # 이전 v3 스크립트
└── docs/
    ├── manual.md                      # 상세 매���얼
    └── improvements.md                # 개선 사항 추적
```

## 주의사항

- 보안 에이전트(Wazuh, CrowdStrike, Velociraptor)는 하드닝 전에 설치되어 있어야 합니다
- 하드닝 후 비보호 계정의 SSH 세션 자동 종료 (PROTECTED_ACCOUNTS로 보호 계정 지정)
- `any_errors_fatal: false` — 한 서버 실패가 다른 서버에 영향을 주지 않습니다
- 하드닝 후 SSH 연결 확인을 자동으로 수행합니다

## 지원 OS

- Debian / Ubuntu (20.04, 22.04, 24.04)
- RHEL / CentOS / Rocky / AlmaLinux (7+)
- FreeBSD
- macOS
