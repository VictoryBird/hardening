# 개선 사항 목록

## 1. OS 버전별 분기 처리 (우선순위: 높음)

### 1-1. RHEL 7 authconfig 폴백
- **문제**: RHEL 7 / CentOS 7에는 `authselect`이 없고 `authconfig`을 사용
- **영향**: `setup_pam`, `setup_pam_faillock`에서 authselect 명령 실패
- **수정 방향**: 버전 감지 후 분기
  ```bash
  if [[ "${OS_VERSION%%.*}" -le 7 ]]; then
      authconfig --enablefaillock --update
  else
      authselect enable-feature with-faillock
  fi
  ```

### 1-2. Ubuntu 24.04 nftables 백엔드
- **문제**: Ubuntu 24.04부터 UFW가 nftables 백엔드를 기본 사용
- **영향**: `/etc/ufw/after.rules`의 iptables 문법 터널링 방어 규칙이 미적용될 수 있음
- **수정 방향**: nftables 백엔드 감지 → nft 문법 규칙 생성 또는 iptables-legacy 폴백

### 1-3. pam_faillock 가용성
- **문제**: Ubuntu 20.04 이전, 일부 Debian에서 `pam_faillock.so` 미설치
- **영향**: `setup_pam_faillock` 실패
- **현재 상태**: 모듈 존재 여부 확인은 하지만 폴백이 `pam_tally2`로 연결되지 않음
- **수정 방향**: `pam_tally2` 폴백 또는 건너뜀 처리

### 1-4. RHEL 7 yum vs dnf 세부 차이
- **현재 상태**: `dnf` 없으면 `yum` 폴백 구현됨
- **추가 필요**: `yum`의 `--allowerasing` 미지원 등 옵션 차이 처리

### 1-5. systemd-resolved 차이
- **문제**: Ubuntu 18.04는 systemd-resolved 미사용, 22.04+는 기본
- **영향**: DNS 잠금 로직(`resolv.conf` chattr vs resolved.conf.d) 분기 필요
- **현재 상태**: 심볼릭 링크 여부로 판단하고 있으나 엣지 케이스 존재

---

## 2. 터널링 방어 개선 (우선순위: 중간)

### 2-1. 서버/워크스테이션 역할 구분
- **현재**: ICMP echo-request 아웃바운드 차단을 제거함 (워크스테이션 ping 허용)
- **개선**: `--role=server|workstation` 옵션 추가하여 역할별 분기
  - 서버: ICMP echo-request 아웃바운드 차단
  - 워크스테이션: 허용

### 2-2. nftables 기반 터널링 방어
- **문제**: 현재 터널링 방어가 iptables/after.rules 기반
- **개선**: nftables 네이티브 규칙 지원 (Ubuntu 24.04+, RHEL 9+)
- 1-2와 함께 해결 가능

---

## 3. 기능 개선 (우선순위: 중간)

### 3-1. 하드닝 프로파일 확장
- **현재**: base, web, ad, log, full
- **추가 필요**: mail, db, dns, ics(산업제어), workstation 프로파일
- ICS/HMI 워크스테이션은 아웃바운드 제한 가능 (규칙서 예외 조항)

### 3-2. usr 비밀번호 자동 생성
- **현재**: `change_usr_password()`는 외부에서 비밀번호를 전달받아야 함
- **개선**: 비밀번호 미지정 시 랜덤 생성 후 stdout 출력
  ```bash
  01_baseline_hardening.sh --randomize-usr-password
  ```

---

## 4. 안정성 개선 (우선순위: 중간)

### 4-1. dry-run 모드
- 실제 변경 없이 어떤 작업을 할지 미리 보여주는 모드
  ```bash
  01_baseline_hardening.sh --dry-run
  ```

### 4-2. SSH 잠금 방지 안전장치
- SSH 키 없이 PasswordAuthentication=no 설정 시 잠금 방지 (현재 Debian에만 있음)
- RHEL/FreeBSD/macOS에도 동일한 잠금 방지 로직 필요

---

## 5. 테스트 (우선순위: 높음)

### 5-1. 자동화 테스트 환경
- Vagrant/Docker 기반 OS별 테스트 VM 구성
  ```
  tests/
    Vagrantfile          # Ubuntu, Rocky, FreeBSD VM 정의
    test_debian.sh       # Debian에서 01 실행 → 02 점검 → 결과 검증
    test_rhel.sh
    test_freebsd.sh
    test_macos.sh        # macOS는 수동 또는 GitHub Actions macos-latest
  ```

### 5-2. 안전장치 테스트
- gt 계정 보호 검증: 하드닝 후 gt가 sudo NOPASSWD 유지하는지
- gtmon 서비스 검증: 하드닝 후 gtmon 서비스 정상 동작하는지
- 아웃바운드 포트 검증: 필수 포트가 차단되지 않았는지

### 5-3. 실제 훈련 환경 사전 검증
- 훈련 사용 예정 OS/버전 목록 확정 후 해당 환경에서 통합 테스트

---

## 6. 문서화 (우선순위: 낮음)

### 6-1. 트러블슈팅 FAQ
- "gt 계정 잠겼을 때", "gtmon 안 돌 때", "점수 안 올라갈 때" 등 대응 가이드
