# CVE-2026-27944 Nginx UI 취약점 스캐너 - 상세 설명서

## 1. 취약점 상세

### 1.1 취약점 개요

| 항목 | 내용 |
|------|------|
| CVE | CVE-2026-27944 |
| CVSS | 9.8 (Critical) |
| 대상 소프트웨어 | Nginx UI (웹 기반 Nginx 관리 도구) |
| 취약점 유형 | 인증 누락 (CWE-306) + 민감 데이터 암호화 누락 (CWE-311) |
| 참조 | https://nvd.nist.gov/vuln/detail/CVE-2026-27944 |

### 1.2 취약점 원리

Nginx UI의 `/api/backup` 엔드포인트에 인증(Authentication) 및 접근 제어(Authorization) 절차가 적용되어 있지 않다.
해당 엔드포인트 요청 시 시스템 백업 파일이 다운로드되며, 동시에 `X-Backup-Security` 응답 헤더에 암호화 키(Encryption Key)가 평문으로 전달된다.

**공격 흐름:**

1. 공격자가 대상 서버의 Nginx UI 포트(기본 9000)로 `GET /api/backup` 요청 전송
2. 서버가 인증 확인 없이 암호화된 백업 파일을 응답 본문으로 전달
3. 동일 응답의 `X-Backup-Security` 헤더에 복호화 키가 평문으로 포함
4. 공격자가 해당 키로 백업 파일을 즉시 복호화
5. 백업 내 사용자 계정, 세션 토큰, SSL 개인 키, Nginx 설정 등 민감 정보 탈취
6. 탈취된 인증 정보로 시스템 전체 제어권 확보

결과적으로 **단일 HTTP 요청으로** 서버의 모든 민감 정보를 탈취할 수 있다.

**PoC 검증 명령어:**
```bash
curl -i -s -k -X GET "http://<TARGET>:<PORT>/api/backup" | grep -i "X-Backup-Security"
```
`X-Backup-Security:` 헤더가 출력되거나 인증 없이 파일 다운로드가 시작되면 취약 상태이다.

### 1.3 영향 버전 및 패치 버전

| 취약 버전 | 패치 버전 |
|-----------|-----------|
| < 2.3.3 | >= 2.3.3 |

---

## 2. 스캐너 설계

### 2.1 기본 정보

| 항목 | 내용 |
|------|------|
| 파일 | `cve_2026_27944_nginxui_scanner.sh` |
| 버전 | 1.0 |
| 언어 | Bash 4+ |
| 권한 | root 필수 |
| 출력 | JSON 파일 (stdout 없음) |
| 로그 | stderr (진행 상황) |
| 리소스 보호 | `renice 19` + `ionice idle` |
| 외부 의존성 | 없음 (순수 bash + coreutils) |

### 2.2 설계 원칙

- **사용자 개입 없는 완전 자동화**: Ansible로 전사 배포 후 자동 실행, JSON 결과만 회수
- **환경 자동 탐지**: 베어메탈/VM, Docker, Podman, Kubernetes를 자동 판별하여 해당 환경에 맞는 스캔 수행
- **극한 환경 보호**: 1CPU/1MEM 환경에서도 서비스 가용성에 영향 없도록 프로세스 우선순위를 최저로 설정
- **Minimal 환경 대응**: `hostname`, `ip` 명령어 없는 최소 설치 환경에서도 `/proc` fallback으로 정상 동작
- **전역 중복 제거**: 프로세스/바이너리/systemd 간 동일 경로 중복 보고 방지 (`SCANNED_PATHS`)
- **pac4j 스캐너와 동일한 출력 구조**: JSON 조립 방식, 로깅 패턴, 파일 출력 방식 통일

### 2.3 스캔 구조

```
main()
  ├── detect_os()                  # OS 탐지 (ID, 버전, 커널)
  ├── detect_environment()         # 환경 탐지 (baremetal/docker/k8s + 런타임)
  │
  ├── Phase 1: 호스트 스캔
  │   ├── scan_host_process()      # pgrep으로 실행 중인 nginx-ui 탐지
  │   ├── scan_host_binaries()     # 일반 경로 + 전체 find 검색
  │   └── scan_host_systemd()      # systemd 유닛 파일 검색
  │
  ├── Phase 2: 컨테이너 환경
  │   ├── scan_containers()        # Docker/Podman 컨테이너 스캔
  │   └── scan_kubernetes_pods()   # K8s Pod 스캔
  │
  └── assemble_json()              # JSON 조립 및 파일 출력
```

### 2.4 스캔 범위 상세

#### Phase 1: 호스트 스캔

| 스캔 대상 | 방법 | 비고 |
|-----------|------|------|
| 실행 중인 프로세스 | `pgrep -f 'nginx-ui'` → `/proc/PID/exe` + `/proc/PID/cmdline` | 셸 스크립트 실행 시 인터프리터 경로 자동 보정 |
| 바이너리 파일 (일반 경로) | `/usr/local/bin`, `/usr/bin`, `/opt/nginx-ui` 등 직접 확인 | 프로세스에서 발견된 경로는 중복 제거 |
| 바이너리 파일 (전체) | `find / -name "nginx-ui"` | 가상 파일시스템 제외 |
| systemd 서비스 | `/etc/systemd`, `/usr/lib/systemd` 내 `*nginx-ui*` 유닛 | `ExecStart=` 에서 바이너리 경로 추출 |

`find` 최적화: `/proc`, `/sys`, `/dev`, `/run`, `/snap`, `/var/lib/docker`, `/var/lib/containers`, `/var/lib/kubelet`, `/var/lib/containerd` 제외

#### Phase 2: 컨테이너 환경

| 환경 | 탐지 방법 | 스캔 방법 |
|------|-----------|-----------|
| Docker | `docker info` 성공 여부 | 이미지명/컨테이너명에 `nginx-ui` 포함 여부 + 내부 `pgrep` |
| Podman | `podman info` 성공 여부 | 동일 (런타임 자동 선택: docker > podman) |
| Kubernetes | `kubectl cluster-info` 성공 여부 | 모든 네임스페이스 Running Pod 이미지명 + 내부 `pgrep` |

### 2.5 버전 추출 방식 (3중 폴백)

1. **바이너리 실행**: `nginx-ui -v` 출력에서 `X.Y.Z` 정규식 추출
2. **이미지 태그**: 컨테이너 이미지명에서 `X.Y.Z` 추출 (바이너리 실행 실패 시)
3. **확인불가**: 위 모두 실패 시 `unknown`으로 기록, 수동 점검 안내

### 2.6 버전 판별 로직

| 버전 범위 | 판정 |
|-----------|------|
| major < 2 | 취약 |
| major == 2 && minor < 3 | 취약 |
| major == 2 && minor == 3 && patch < 3 | 취약 |
| major == 2 && minor == 3 && patch >= 3 | 양호 |
| major == 2 && minor > 3 | 양호 |
| major >= 3 | 양호 |
| 숫자 파싱 불가 | 확인불가 |

SNAPSHOT, beta, rc 등 접미사는 숫자 부분(`X.Y.Z`)만 추출하여 판별한다.

### 2.7 Minimal 환경 대응

| 일반 명령어 | 미설치 시 fallback | 용도 |
|-------------|-------------------|------|
| `hostname` | `/etc/hostname` → `/proc/sys/kernel/hostname` | 호스트명 획득 |
| `ip` | `/proc/net/fib_trie` 파싱 | IP 주소 획득 |
| `hostname -I` | (위 `ip` fallback에 포함) | IP 주소 획득 |

### 2.8 중복 제거 메커니즘

전역 연관 배열 `SCANNED_PATHS`를 사용하여 Phase 1의 세 단계(프로세스 → 바이너리 → systemd) 간 동일 바이너리 경로가 중복 보고되지 않도록 한다.

| 순서 | 스캔 | 동작 |
|------|------|------|
| 1 | `scan_host_process()` | `/usr/local/bin/nginx-ui` 발견 → `SCANNED_PATHS`에 등록 |
| 2 | `scan_host_binaries()` | 동일 경로 → `SCANNED_PATHS`에 이미 존재 → 건너뜀 |
| 3 | `scan_host_systemd()` | `ExecStart=` 경로로 버전 추출 (서비스 파일 자체는 별도 보고) |

---

## 3. JSON 출력 구조

```json
{
  "scanner": "CVE-2026-27944 Nginx UI Scanner",
  "version": "1.0",
  "cve": "CVE-2026-27944",
  "cvss": "9.8",
  "description": "Nginx UI /api/backup 엔드포인트 인증 누락, X-Backup-Security 헤더에 복호화 키 평문 노출 (백업 데이터 무단 탈취)",
  "affected_versions": "< 2.3.3",
  "patched_versions": ">= 2.3.3",
  "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-27944",
  "scan_date": "2026-03-12T05:25:45+00:00",
  "hostname": "서버명",
  "os": "rocky",
  "os_version": "9.7",
  "kernel": "5.14.0-...",
  "host_environment": "baremetal | docker | kubernetes",
  "container_runtime": "docker | podman | cri-o/containerd | none",
  "ip_addresses": ["10.88.0.21"],
  "summary": {
    "total": 2,
    "vulnerable": 2,
    "safe": 0,
    "unknown": 0
  },
  "results": [
    {
      "location": "파일 경로 또는 이미지명",
      "version": "추출된 현재 버전",
      "status": "취약 | 양호 | 확인불가",
      "detail": "상세 설명 및 패치 안내",
      "source_type": "탐지 출처",
      "patched_version": "패치 버전 (취약 시)",
      "container": "컨테이너 정보 (호스트이면 빈 문자열)"
    }
  ]
}
```

### results 필드 설명

| 필드 | 설명 | 예시 |
|------|------|------|
| `location` | 발견된 바이너리/서비스/이미지 경로 | `/usr/local/bin/nginx-ui` |
| `version` | 추출된 Nginx UI 현재 버전 | `2.3.1`, `unknown` |
| `status` | 판정 결과 | `취약`, `양호`, `확인불가` |
| `detail` | 상태 설명 및 조치 안내 | `취약 버전 v2.3.1 → v2.3.3 이상으로 업그레이드 필요` |
| `source_type` | 탐지 출처 | `running_process(pid:1)`, `binary_file`, `systemd_unit`, `container`, `kubernetes_pod` |
| `patched_version` | 패치 버전 (양호 시 빈 문자열) | `2.3.3` |
| `container` | 컨테이너 식별 정보 | `docker:nginx-ui-prod`, `podman:my-nginx`, `k8s:ns/pod/container`, `""` (호스트) |

---

## 4. 테스트 결과

### 4.1 테스트 환경

| 항목 | 내용 |
|------|------|
| OS | Rocky Linux 9.7 |
| Kernel | 5.14.0-611.27.1.el9_7.x86_64 |
| 컨테이너 런타임 | Podman 5.6.0 (rootful) |
| 테스트 일시 | 2026-03-12 |
| 테스트 도구 의존성 | 없음 (순수 bash, python/jq 불필요) |

### 4.2 컨테이너 환경 테스트 (Podman, 1CPU/1GB)

**환경 구성:**

| 항목 | 내용 |
|------|------|
| 베이스 이미지 | `rockylinux:9-minimal` |
| CPU 제약 | `--cpus=1` |
| 메모리 제약 | `--memory=1g` |
| 설치 패키지 | `procps-ng`, `findutils`, `curl` (최소) |
| 미설치 | `hostname`, `iproute` (`ip` 명령어 없음) |

**시뮬레이션 구성:**

| 구성 요소 | 내용 |
|-----------|------|
| 취약 바이너리 | `/usr/local/bin/nginx-ui` → `nginx-ui version 2.3.1` 출력 셸 스크립트 |
| systemd 유닛 | `/etc/systemd/system/nginx-ui.service` → `ExecStart=/usr/local/bin/nginx-ui` |
| 실행 프로세스 | 백그라운드로 `nginx-ui` 실행 후 스캐너 동작 |

**실행 결과:**

```
[05:25:45] CVE-2026-27944 Nginx UI Scanner v1.0
[05:25:45] OS: rocky 9.7, Kernel: 5.14.0-611.27.1.el9_7.x86_64
[05:25:45] === Phase 1: 호스트 스캔 ===
[05:25:45] [취약] /usr/local/bin/nginx-ui (v2.3.1) [running_process(pid:1)] -> 2.3.3
[05:25:45] [취약] /etc/systemd/system/nginx-ui.service (v2.3.1) [systemd_unit] -> 2.3.3
[05:25:45] === Phase 2: 컨테이너 환경 스캔 ===
[05:25:45] Docker/Podman 미감지, 컨테이너 스캔 건너뜀
[05:25:45] 점검 완료 (소요시간: 0초)
[05:25:45] 결과: 취약=2, 양호=0, 확인불가=0
```

**검증 항목:**

| 항목 | 결과 |
|------|------|
| 1CPU/1GB 제약 환경에서 정상 동작 | PASS |
| `hostname` 미설치 시 `/proc/sys/kernel/hostname` fallback | PASS |
| `ip` 미설치 시 `/proc/net/fib_trie` fallback (IP 출력) | PASS |
| 프로세스 탐지 (pid:1) | PASS |
| 셸 스크립트 인터프리터 오탐 방지 (bash 경로 제외) | PASS |
| 바이너리 중복 제거 (프로세스에서 발견 → 바이너리 스캔 건너뜀) | PASS |
| systemd 유닛 탐지 | PASS |
| JSON 유효성 | PASS |
| 소요시간 0초 (renice/ionice 적용) | PASS |

### 4.3 자동화 QA 검증 결과: 146건 전체 PASS

```
========================================
 CVE-2026-27944 Nginx UI Scanner QA
 외부 의존성: 없음 (순수 bash)
========================================

[Group 1] check_version() 버전 판별 로직 (22건)
  [PASS] v0.1.0 → 취약 (0.x)
  [PASS] v1.0.0 → 취약 (1.x)
  [PASS] v1.9.9 → 취약 (1.x 최대)
  [PASS] v2.0.0 → 취약 (2.0.0)
  [PASS] v2.2.9 → 취약 (minor < 3)
  [PASS] v2.3.0 → 취약 (2.3.0)
  [PASS] v2.3.1 → 취약 (2.3.1)
  [PASS] v2.3.2 → 취약 (경계값 직전)
  [PASS] v2.3.3 → 양호 (정확히 패치 버전)
  [PASS] v2.3.4 → 양호 (패치 초과)
  [PASS] v2.3.10 → 양호 (patch 10)
  [PASS] v2.4.0 → 양호 (minor 상위)
  [PASS] v2.10.0 → 양호 (minor 10)
  [PASS] v3.0.0 → 양호 (3.x)
  [PASS] v3.1.5 → 양호 (3.x+)
  [PASS] v10.0.0 → 양호 (major 10)
  [PASS] 빈 문자열 → 판단불가
  [PASS] 'unknown' → 판단불가
  [PASS] 'abc' → 판단불가
  [PASS] 'v2' (불완전) → 판단불가
  [PASS] v2.3.2-beta → 취약 (접미사 무시)
  [PASS] v2.3.3-rc1 → 양호 (접미사 무시)

[Group 2] extract_version_from_output() 버전 추출 (7건)
  [PASS] 표준 출력: 'nginx-ui version 2.3.1'
  [PASS] 숫자만: '2.3.3'
  [PASS] 복잡한 출력: 'Nginx UI v2.3.2 (build ...)'
  [PASS] beta 접미사: 'v2.0.0-beta.30'
  [PASS] 빈 출력
  [PASS] 버전 없는 문자열
  [PASS] 멀티라인 출력: 첫 번째 줄 버전 추출

[Group 3] json_escape() 특수문자 이스케이프 (6건)
  [PASS] 큰따옴표 이스케이프
  [PASS] 백슬래시 이스케이프
  [PASS] 줄바꿈 이스케이프
  [PASS] 탭 이스케이프
  [PASS] 한글 텍스트 보존
  [PASS] 빈 문자열

[Group 4] report_finding() 결과 기록 (9건)
  [PASS] 취약 버전 카운트 증가
  [PASS] 취약 결과에 업그레이드 안내
  [PASS] 패치 버전 포함
  [PASS] 양호 버전 카운트 증가
  [PASS] 양호 결과에 패치 완료 메시지
  [PASS] 확인불가 카운트 증가
  [PASS] 확인불가 수동 점검 안내
  [PASS] 빈 버전도 확인불가 처리
  [PASS] 컨테이너 정보 포함

[Group 5] 통합 테스트 - 가상 취약 바이너리 (9건)
  [PASS] JSON 유효성 검증 (취약 바이너리)
  [PASS] scanner 필드
  [PASS] CVE ID
  [PASS] CVSS 점수
  [PASS] 취약 건수
  [PASS] 양호 건수
  [PASS] 결과 상태 = 취약
  [PASS] 결과 버전 = 2.3.1
  [PASS] 패치 버전 = 2.3.3

[Group 6] 통합 테스트 - 양호 바이너리 (6건)
  [PASS] JSON 유효성 검증 (양호 바이너리)
  [PASS] 취약 건수 = 0
  [PASS] 양호 건수 = 1
  [PASS] 결과 상태 = 양호
  [PASS] 결과 버전 = 2.3.3
  [PASS] 패치 버전 빈값 (양호)

[Group 7] 통합 테스트 - nginx-ui 미설치 (6건)
  [PASS] JSON 유효성 검증 (미설치)
  [PASS] 총 건수 = 0
  [PASS] 취약 = 0
  [PASS] 양호 = 0
  [PASS] 확인불가 = 0
  [PASS] results 배열 비어있음

[Group 8] 통합 테스트 - 복수 발견 (취약+양호+확인불가) (7건)
  [PASS] JSON 유효성 검증 (혼합)
  [PASS] 총 건수 = 3
  [PASS] 취약 = 1
  [PASS] 양호 = 1
  [PASS] 확인불가 = 1
  [PASS] 첫 번째 결과 = 취약
  [PASS] 두 번째 결과 = 양호

[Group 9] JSON 구조 완전성 - 필수 필드 존재 (32건)
  [PASS] 필수 필드: scanner          [PASS] 필수 필드: version
  [PASS] 필수 필드: cve              [PASS] 필수 필드: cvss
  [PASS] 필수 필드: description      [PASS] 필수 필드: affected_versions
  [PASS] 필수 필드: patched_versions [PASS] 필수 필드: reference
  [PASS] 필수 필드: scan_date        [PASS] 필수 필드: hostname
  [PASS] 필수 필드: os               [PASS] 필수 필드: os_version
  [PASS] 필수 필드: kernel           [PASS] 필수 필드: host_environment
  [PASS] 필수 필드: container_runtime [PASS] 필수 필드: ip_addresses
  [PASS] 필수 필드: summary          [PASS] 필수 필드: results
  [PASS] summary.total               [PASS] summary.vulnerable
  [PASS] summary.safe                [PASS] summary.unknown
  [PASS] result.location             [PASS] result.version
  [PASS] result.status               [PASS] result.detail
  [PASS] result.source_type          [PASS] result.patched_version
  [PASS] result.container
  [PASS] NVD reference URL
  [PASS] affected_versions
  [PASS] patched_versions

[Group 10] ip_addresses 배열 형식 검증 (1건)
  [PASS] ip_addresses는 배열 타입

[Group 11] 출력 파일 권한 검증 (1건)
  [PASS] 출력 파일 권한 600 (owner only)

[Group 12] Docker 컨테이너 탐지 시뮬레이션 (6건)
  [PASS] JSON 유효성 (컨테이너 시뮬레이션)
  [PASS] 컨테이너 취약 건수            [PASS] 컨테이너 양호 건수
  [PASS] 취약 컨테이너 정보            [PASS] 양호 컨테이너 정보
  [PASS] source_type = container

[Group 13] Kubernetes Pod 탐지 시뮬레이션 (4건)
  [PASS] JSON 유효성 (K8s 시뮬레이션)
  [PASS] K8s 취약 Pod                  [PASS] K8s 양호 Pod
  [PASS] source_type = kubernetes_pod

[Group 14] systemd 유닛 탐지 시뮬레이션 (4건)
  [PASS] JSON 유효성 (systemd)
  [PASS] systemd 탐지 상태 = 취약
  [PASS] source_type = systemd_unit    [PASS] systemd 버전 = 2.3.1

[Group 15] summary 카운트 정합성 (2건)
  [PASS] total = vulnerable + safe + unknown
  [PASS] total = len(results)

[Group 16] 특수문자 포함 경로 처리 (3건)
  [PASS] JSON 유효성 (특수문자 경로)
  [PASS] 공백 포함 경로               [PASS] 한글 경로 보존

[Group 17] CLI 옵션 테스트 (3건)
  [PASS] --help 출력에 사용법 포함
  [PASS] --help 출력에 --output 포함
  [PASS] 잘못된 옵션 에러 메시지

[Group 18] 스크립트 문법 검증 (1건)
  [PASS] bash -n 문법 검증 통과

[Group 19] scan_date ISO 형식 검증 (1건)
  [PASS] scan_date ISO 8601 형식

[Group 20] 실제 환경 실행 테스트 (8건)
  [PASS] 스캐너 정상 종료 (exit 0)    [PASS] 실제 실행 JSON 유효성
  [PASS] stderr에 시작 로그            [PASS] stderr에 완료 로그
  [PASS] stderr에 Phase 1 로그        [PASS] stderr에 Phase 2 로그
  [PASS] hostname 일치                 [PASS] OS 감지: rocky

[Group 21] Podman 컨테이너 시뮬레이션 (3건)
  [PASS] JSON 유효성 (Podman)
  [PASS] Podman 컨테이너 상태          [PASS] Podman 컨테이너 라벨

[Group 22] 대량 결과 (10건) JSON 정합성 (3건)
  [PASS] JSON 유효성 (10건 대량)
  [PASS] 총 건수 = 10                  [PASS] results 배열 길이 = 10

[Group 23] --output 경로 지정 동작 (2건)
  [PASS] 지정 경로에 파일 생성됨       [PASS] 지정 경로 JSON 유효성

========================================
 QA 결과 요약
========================================
 전체: 146
 통과: 146
 실패: 0
========================================

>> 전체 146개 테스트 통과
```

### 4.4 테스트 범위 요약

| 그룹 | 테스트 내용 | 건수 |
|------|-----------|------|
| 1 | `check_version()` 경계값 (취약/양호/불가/접미사) | 22 |
| 2 | `extract_version_from_output()` 다양한 출력 형식 | 7 |
| 3 | `json_escape()` 특수문자 이스케이프 | 6 |
| 4 | `report_finding()` 카운트/메시지/컨테이너 정보 | 9 |
| 5-8 | 통합: 취약/양호/미설치/혼합 바이너리 mock | 28 |
| 9 | JSON 구조 완전성 (18 필수필드 + 4 summary + 7 result + 3 값) | 32 |
| 10-11 | ip_addresses 배열, 파일 권한 600 | 2 |
| 12-14 | Docker/K8s/Podman/systemd 시뮬레이션 | 17 |
| 15 | summary 카운트 정합성 | 2 |
| 16 | 특수문자 경로 (공백, 한글) | 3 |
| 17-19 | CLI 옵션, 문법 검증, ISO 날짜 | 5 |
| 20 | 실제 환경 실행 (현재 호스트) | 8 |
| 21-23 | Podman, 대량 결과 (10건), --output 경로 | 8 |
| **합계** | | **146** |

### 4.5 실제 JSON 출력 예시 (1CPU/1GB 컨테이너)

취약 탐지 (실행 프로세스):
```json
{
  "location": "/usr/local/bin/nginx-ui",
  "version": "2.3.1",
  "status": "취약",
  "detail": "취약 버전 v2.3.1 → v2.3.3 이상으로 업그레이드 필요",
  "source_type": "running_process(pid:1)",
  "patched_version": "2.3.3",
  "container": ""
}
```

취약 탐지 (systemd 서비스):
```json
{
  "location": "/etc/systemd/system/nginx-ui.service",
  "version": "2.3.1",
  "status": "취약",
  "detail": "취약 버전 v2.3.1 → v2.3.3 이상으로 업그레이드 필요",
  "source_type": "systemd_unit",
  "patched_version": "2.3.3",
  "container": ""
}
```

양호 탐지 (Docker 컨테이너):
```json
{
  "location": "uozi/nginx-ui:2.3.5",
  "version": "2.3.5",
  "status": "양호",
  "detail": "패치 완료 (v2.3.5)",
  "source_type": "container",
  "patched_version": "",
  "container": "docker:nginx-ui-staging"
}
```

Kubernetes Pod 탐지:
```json
{
  "location": "uozi/nginx-ui:2.1.0",
  "version": "2.1.0",
  "status": "취약",
  "detail": "취약 버전 v2.1.0 → v2.3.3 이상으로 업그레이드 필요",
  "source_type": "kubernetes_pod",
  "patched_version": "2.3.3",
  "container": "k8s:default/nginx-ui-deploy-abc123/nginx-ui"
}
```

---

## 5. QA 과정에서 발견 및 수정된 버그

| # | 버그 | 원인 | 수정 내용 |
|---|------|------|-----------|
| 1 | 셸 스크립트 nginx-ui 실행 시 `/usr/bin/bash`를 nginx-ui로 오탐 | `readlink /proc/PID/exe`가 인터프리터 경로를 반환 | `/proc/PID/cmdline`에서 실제 nginx-ui 경로 추출, 인터프리터면 건너뜀 |
| 2 | minimal 이미지에서 `hostname` 명령어 에러 | `hostname` 미설치 | `get_hostname()` 함수: `hostname` → `/etc/hostname` → `/proc/sys/kernel/hostname` fallback |
| 3 | minimal 이미지에서 IP 주소 빈 배열 | `ip`, `hostname -I` 모두 미설치 | `/proc/net/fib_trie` 파싱 fallback 추가 |
| 4 | 동일 바이너리 경로가 프로세스/바이너리/systemd에서 3회 중복 보고 | 각 스캔 함수가 독립적 로컬 배열 사용 | 전역 `SCANNED_PATHS` 연관 배열로 통합 중복 제거 |

---

## 6. Ansible 배포 가이드

### 6.1 Playbook

```yaml
- hosts: all
  become: true
  tasks:
    - name: Copy Nginx UI scanner
      copy:
        src: cve_2026_27944_nginxui_scanner.sh
        dest: /tmp/cve_2026_27944_nginxui_scanner.sh
        mode: '0755'

    - name: Run Nginx UI scanner
      command: bash /tmp/cve_2026_27944_nginxui_scanner.sh --output /tmp/cve_2026_27944_result.json
      register: scan_result
      changed_when: false

    - name: Fetch scan result
      fetch:
        src: /tmp/cve_2026_27944_result.json
        dest: "./results/{{ inventory_hostname }}/"
        flat: true

    - name: Cleanup scanner
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /tmp/cve_2026_27944_nginxui_scanner.sh
        - /tmp/cve_2026_27944_result.json
```

### 6.2 실행

```bash
ansible-playbook -i inventory.ini nginxui_scan.yml
```

### 6.3 결과 확인

```bash
# 취약 호스트 빠른 확인
grep -rl '"vulnerable": [1-9]' results/ | while read f; do
  host=$(dirname "$f" | xargs basename)
  vuln=$(grep -o '"vulnerable": [0-9]*' "$f" | cut -d: -f2)
  echo "[취약] ${host}: ${vuln}건"
done
```
