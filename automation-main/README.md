## Ansible Lab

LS26 Linux Automation을 위한 repository입니다.

### Getting Started

#### 기본 환경

구축 환경은 다음과 같습니다.

- OS: `macOS 15.5` on `M3 Pro MBP 2023`
- Python: 3.10.20
    - packages: `requirements.txt` 참조

디렉터리 구조
```txt
.
├── ansible.cfg
├── artifacts/
│   └── fetched_files/      // 원격 아티팩트 수집 시 기본 저장 위치
├── files/
│   ├── falcon/             // falcon 설치 agent 모음(용량 제한으로 github 업로드 X)
│   ├── scripts/            // 배포할 스크립트(하드닝 등 목적)
│   └── velociraptor/       // velociraptor 설치 config 존재
├── inventories/
│   └── lab/
│       ├── group_vars/     // 그룹 변수 저장
│       ├── host_vars/      // 호스트 변수 저장(접속 point, creds)
│       └── hosts.yml       // 전체 inventory 정의
├── inventories_0317.7z     // 공유용 백업
├── playbooks/              // 플레이북 전체(내부 depth는 1로 통일)
├── README.md
├── requirements.txt        // python modules list
├── roles/                  // 현재 의미 없음
└── ssh/
    ├── ansiblectl.key      // 호스트 관리용 개인키 --> 보안상 사적 용도로 사용 절대 지양
    └── ansiblectl.key.pub  // 호스트 관리용 공개키 --> 각 호스트에 등록용
```

#### ((( 필독 ))) 개인별 설정

`ansible.cfg`

아래 참조하여 개인별 설정

```txt
[defaults]
inventory = ./inventories/lab/hosts.yml
host_key_checking = False
stdout_callback = yaml
retry_files_enabled = False
timeout = 30
# python -m ara.setup.ansible 결과 참고하여 아래 세 변수 설정
callback_plugins=<개인별 설정>
action_plugins=<개인별 설정>
lookup_plugins=<개인별 설정>

[ssh_connection]
pipelining = True

[ara]
api_client = http
api_server = http://192.168.219.106:8000
record_controller_name = "<개인별 control node 이름>"
record_user_name = "<개인별 표시할 이름>"
```

`files/falcon/`

별도 배포된 `falcon-sensor.7z` 내부 파일들을 해당 위치로 복사

`~/.ssh/config`

최하단에 아래 내용 추가 시 각 자산에 `ssh <IP>` 형태로 간편하게 접속 가능, `User` 필드 값은 추후 변경 예정

```txt
Host *
    User kepco
    IdentityFile <개인별로 저장한 ansiblectl.key 경로>
```

MinIO 설정

`myminio`라는 이름으로 서버 alias 설정, `<ACCESSKEY>`와 `<SECRETKEY>`는 [Service Account 등록](http://192.168.219.106:9001/identity/account)하여 발급 가능

```
mc alias set myminio http://192.168.219.106:21384 <ACCESSKEY> <SECRETKEY>
```

#### 플레이북 관련

- 모든 플레이북에서 `hosts: env_lab`으로 정의
    - 실행 시점에 `-l` 옵션을 이용해 `host`를 제한하는 방식 채택
- 실행 시 본 repo 내 최상위 위치에서 명령어 입력
    - ex) `ansible-playbook playbooks/<playbook_name>.yml -l beg_dmz_ns2:beg_dmz_mattermost`

#### 담당 구역 분배

- `-l 'bps_dmz_*'`
- `-l 'bps_int_*:bps_rtu_*:bps_water_*'`
- `-l 'beg_*'`

### 플레이북 실행 순서

- 연결 확인 및 기초 정보 수집
    - ping test
        - `ansible-playbook playbooks/0000_ping_hosts.yml -l beg_dmz_ns2:beg_dmz_mattermost`
    - 정보 수집
        - `ansible-playbook playbooks/0011_get_facts.yml -l beg_dmz_ns2:beg_dmz_mattermost`
        - (minio 동기화) `ansible-playbook playbooks/0012_get_facts_syncminio.yml -l beg_dmz_ns2:beg_dmz_mattermost`
- 백업
    - *추가 예정*
- `authorized_keys` 등록
    - `ansible-playbook playbooks/2001_bootstrap_ssh_pubkey.yml -l beg_dmz_ns2:beg_dmz_mattermost`
- 로그인 관리
    - ssh 접속 시 비밀번호 이용 차단
        - `ansible-playbook playbooks/2101_disable_ssh_password_auth.yml -l beg_dmz_ns2:beg_dmz_mattermost`
    - ssh 접속 시 비밀번호 이용 허용
        - `ansible-playbook playbooks/2111_enable_ssh_password_auth.yml -l beg_dmz_ns2:beg_dmz_mattermost`
    - ssh 접속 시 root 접근 차단
        - `ansible-playbook playbooks/2201_disable_root_ssh_login.yml -l beg_dmz_ns2:beg_dmz_mattermost`
    - ssh 접속 시 root 접근 허용
        - `ansible-playbook playbooks/2211_enable_root_ssh_login.yml -l beg_dmz_ns2:beg_dmz_mattermost`
- 계정 관리
    - 계정 암호 변경(변경 후 `ansible_password` 및 `ansible_become_password` 재확인 필요)
        - `ansible-playbook playbooks/2301_change_user_passwords.yml -l beg_dmz_ns2:beg_dmz_mattermost`
    - 관리자 계정 생성(암호는 `ansible_password`, pubkey는 `controller_public_key_path`로 설정)
        - `ansible-playbook playbooks/2401_bootstrap_admin_accounts.yml -l beg_dmz_ns2:beg_dmz_mattermost`
    - 계정 삭제
        - `ansible-playbook playbooks/2501_remove_accounts.yml -l beg_dmz_ns2:beg_dmz_mattermost`
- agent 설치
    - falcon
        - `ansible-playbook playbooks/3001_deploy_run_falcon.yml -l beg_dmz_ns2:beg_dmz_mattermost`
    - velociraptor
        - `ansible-playbook playbooks/3101_deploy_run_velociraptor.yml -l beg_dmz_ns2:beg_dmz_mattermost`
    - wazuh
        - `ansible-playbook playbooks/3201_deploy_run_wazuh.yml -l beg_dmz_ns2:beg_dmz_mattermost`
- 스크립트 배포 및 실행
    - 배포
        - `ansible-playbook playbooks/9001_deploy_scripts.yml -l beg_dmz_ns2:beg_dmz_mattermost`
    - 실행
        - `ansible-playbook playbooks/9101_run_scripts.yml -l beg_dmz_ns2:beg_dmz_mattermost`
        - (minio 동기화) `ansible-playbook playbooks/9102_run_scripts_syncminio.yml -l beg_dmz_ns2:beg_dmz_mattermost`
- 원격 파일 확보 및 삭제
    - 확보
        - `ansible-playbook playbooks/9211_recursively_fetch_files.yml -l beg_dmz_ns2:beg_dmz_mattermost`
        - (minio 동기화) `ansible-playbook playbooks/9212_recursively_fetch_files_syncminio.yml -l beg_dmz_ns2:beg_dmz_mattermost`
    - 삭제
        - `ansible-playbook playbooks/9301_remove_files.yml -l beg_dmz_ns2:beg_dmz_mattermost`
        - (minio 동기화) `ansible-playbook playbooks/9302_remove_files_syncminio.yml -l beg_dmz_ns2:beg_dmz_mattermost`
- THOR APT Scanner 실행
    - *추가 예정*
- 기타 ad-hoc 요청
    - *추가 예정*
- 로컬 `artifacts/` -> MinIO `linux-artifacts/jsung/` sync
    - `ansible-playbook playbooks/9901_sync_minio.yml`