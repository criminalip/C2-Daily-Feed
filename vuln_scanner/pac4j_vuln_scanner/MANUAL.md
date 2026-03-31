# CVE-2026-29000 pac4j-jwt 취약점 스캐너 - 상세 설명서

## 1. 취약점 상세

### 1.1 취약점 개요

| 항목 | 내용 |
|------|------|
| CVE | CVE-2026-29000 |
| CVSS | 10.0 (Critical) |
| 대상 라이브러리 | pac4j-jwt (org.pac4j:pac4j-jwt) |
| 취약점 유형 | 인증 우회 (Authentication Bypass) |
| 참조 | https://www.codeant.ai/security-research/pac4j-jwt-authentication-bypass-public-key |

### 1.2 취약점 원리

pac4j의 `JwtAuthenticator.java`는 JWE 복호화 후 내부 페이로드에서 `toSignedJWT()`를 호출하여 서명된 JWT를 추출한다.
서명 검증 로직이 `if (signedJWT != null)` 조건 블록 내부에 종속되어 있어, 공격자가 서명 없는 PlainJWT를 서버의 공개키로 JWE 암호화하여 전송하면 `toSignedJWT()`가 `null`을 반환하고, 서명 검증이 통째로 생략된다.

**공격 흐름:**

1. 공격자가 조작된 Claim(예: `subject="admin"`, `ROLE_ADMIN`)을 포함한 PlainJWT(서명 없음)를 생성
2. 서버의 공개키(RSA Public Key)로 JWE 암호화하여 전송
3. 서버가 개인키로 JWE 복호화 -> 성공
4. 내부 페이로드가 PlainJWT이므로 `toSignedJWT()` -> `null` 반환
5. `if (signedJWT != null)` 블록 미실행 -> 서명 검증 생략
6. 검증되지 않은 Claim이 `createJwtProfile()`로 전달 -> 관리자 인증 성립

결과적으로 **공개키 하나만으로** 관리자 권한 인증이 가능하다.

### 1.3 영향 버전 및 패치 버전

| 라인 | 취약 버전 | 패치 버전 |
|------|-----------|-----------|
| 4.x | < 4.5.9 | >= 4.5.9 |
| 5.x | < 5.7.9 | >= 5.7.9 |
| 6.x | < 6.3.3 | >= 6.3.3 |

---

## 2. 스캐너 설계

### 2.1 기본 정보

| 항목 | 내용 |
|------|------|
| 파일 | `cve_2026_29000_pac4j_scanner.sh` |
| 버전 | 1.0 |
| 언어 | Bash 4+ |
| 권한 | root 필수 |
| 출력 | JSON 파일 (stdout 없음) |
| 로그 | stderr (진행 상황) |
| 리소스 보호 | `renice 19` + `ionice idle` |

### 2.2 설계 원칙

- **사용자 개입 없는 완전 자동화**: Ansible로 전사 배포 후 자동 실행, JSON 결과만 회수
- **환경 자동 탐지**: 베어메탈/VM, Docker, Podman, Kubernetes를 자동 판별하여 해당 환경에 맞는 스캔 수행
- **극한 환경 보호**: 1CPU/1MEM 환경에서도 서비스 가용성에 영향 없도록 프로세스 우선순위를 최저로 설정
- **`vul_scanner.sh`와 동일한 출력 구조**: JSON 조립 방식, 로깅 패턴, 파일 출력 방식 통일

### 2.3 스캔 구조

```
main()
  ├── detect_os()                  # OS 탐지 (ID, 버전, 커널)
  ├── detect_environment()         # 환경 탐지 (baremetal/docker/k8s + 런타임)
  │
  ├── Phase 1: 호스트 파일시스템
  │   ├── scan_host_direct_jars()  # pac4j-jwt-*.jar 직접 검색
  │   ├── scan_host_archives()     # WAR/EAR/Fat-JAR 내부 검색
  │   └── scan_host_build_files()  # pom.xml / build.gradle 검색
  │
  ├── Phase 2: 컨테이너 환경
  │   ├── scan_containers()        # Docker/Podman 컨테이너 스캔
  │   └── scan_kubernetes_pods()   # K8s Pod 스캔
  │
  └── assemble_json()              # JSON 조립 및 파일 출력
```

### 2.4 스캔 범위 상세

#### Phase 1: 호스트 파일시스템

| 스캔 대상 | 방법 | 비고 |
|-----------|------|------|
| `pac4j-jwt-*.jar` | `find` 직접 검색 | 파일명 + 내부 메타데이터에서 버전 추출 |
| WAR/EAR 아카이브 | `unzip -l`로 내부 탐색 | 크기 무관하게 전체 스캔 |
| Fat JAR (Spring Boot 등) | `unzip -l`로 BOOT-INF/lib/ 탐색 | 100KB 이상 JAR만 대상 |
| pom.xml | `<artifactId>pac4j-jwt</artifactId>` 검색 | Maven 변수(`${...}`) 해석 지원 |
| build.gradle / build.gradle.kts | `pac4j-jwt` 의존성 검색 | 버전 추출 |

`find` 최적화: `/proc`, `/sys`, `/dev`, `/run`, `/snap`, `/var/lib/docker`, `/var/lib/containers`, `/var/lib/kubelet`, `/var/lib/containerd` 제외

#### Phase 2: 컨테이너 환경

| 환경 | 탐지 방법 | 스캔 방법 |
|------|-----------|-----------|
| Docker | `docker info` 성공 여부 | `docker exec`로 컨테이너 내부 `find` + `unzip` |
| Podman | `podman info` 성공 여부 | `podman exec`로 컨테이너 내부 `find` + `unzip` |
| Kubernetes | `kubectl cluster-info` 성공 여부 | `kubectl exec`로 모든 네임스페이스 Running Pod 스캔 |

런타임 자동 선택 우선순위: docker > podman

### 2.5 버전 추출 방식 (3중 폴백)

1. **파일명**: `pac4j-jwt-4.5.8.jar` -> `4.5.8`
2. **pom.properties**: JAR 내부 `META-INF/maven/org.pac4j/pac4j-jwt/pom.properties`의 `version=` 값
3. **MANIFEST.MF**: `Implementation-Version` 또는 `Bundle-Version` (OSGi)

### 2.6 버전 판별 로직

| 메이저 버전 | 취약 조건 | 판정 |
|------------|-----------|------|
| 0.x ~ 3.x | 전체 | 취약 (EOL) |
| 4.x | minor < 5 또는 (minor == 5 && patch < 9) | 취약 |
| 5.x | minor < 7 또는 (minor == 7 && patch < 9) | 취약 |
| 6.x | minor < 3 또는 (minor == 3 && patch < 3) | 취약 |
| 7.x+ | - | 확인불가 |

SNAPSHOT, RC 등 접미사는 숫자 부분만 추출하여 판별한다.

---

## 3. JSON 출력 구조

```json
{
  "scanner": "CVE-2026-29000 pac4j-jwt Scanner",
  "version": "1.0",
  "cve": "CVE-2026-29000",
  "cvss": "10.0",
  "description": "pac4j-jwt JWE+JWS 결합 시 PlainJWT로 서명 검증 우회 (인증 우회)",
  "affected_versions": "4.x < 4.5.9, 5.x < 5.7.9, 6.x < 6.3.3",
  "patched_versions": "4.x >= 4.5.9, 5.x >= 5.7.9, 6.x >= 6.3.3",
  "reference": "https://...",
  "scan_date": "2026-03-10T11:31:03+09:00",
  "hostname": "서버명",
  "os": "rocky",
  "os_version": "9.7",
  "kernel": "5.14.0-...",
  "host_environment": "baremetal | docker | kubernetes",
  "container_runtime": "docker | podman | cri-o/containerd | none",
  "ip_addresses": ["192.168.x.x"],
  "summary": {
    "total": 0,
    "vulnerable": 0,
    "safe": 0,
    "unknown": 0
  },
  "results": [
    {
      "location": "파일 경로",
      "version": "추출된 현재 버전",
      "status": "취약 | 양호 | 확인불가",
      "detail": "상세 설명 및 패치 안내",
      "source_type": "탐지 출처",
      "container": "컨테이너 정보 (호스트이면 빈 문자열)"
    }
  ]
}
```

### results 필드 설명

| 필드 | 설명 | 예시 |
|------|------|------|
| `location` | 발견된 파일의 절대 경로 | `/opt/app/lib/pac4j-jwt-4.5.8.jar` |
| `version` | 추출된 pac4j-jwt 현재 버전 | `4.5.8`, `5.7.9-SNAPSHOT`, `unknown` |
| `status` | 판정 결과 | `취약`, `양호`, `확인불가` |
| `detail` | 상태 설명 및 조치 안내 | `취약 버전 (v4.5.8). 즉시 패치 필요: ...` |
| `source_type` | 탐지 출처 | `jar_file`, `embedded_in_archive(pac4j-jwt-5.0.0.jar)`, `pom.xml`, `build.gradle` |
| `container` | 컨테이너 식별 정보 | `podman:컨테이너명`, `k8s:ns/pod/container`, `""` (호스트) |

---

## 4. 테스트 결과

### 4.1 테스트 환경

| 항목 | 내용 |
|------|------|
| OS | Rocky Linux 9.7 |
| Kernel | 5.14.0-611.27.1.el9_7.x86_64 |
| 컨테이너 런타임 | Podman (rootful) |
| 테스트 일시 | 2026-03-10 |

### 4.2 테스트 시나리오 구성

**호스트 파일시스템:**

| 유형 | 버전 | 기대 결과 |
|------|------|-----------|
| JAR (취약) | v3.9.0, v4.0.0, v4.5.8, v5.0.0, v5.7.8, v6.0.0, v6.3.2 | 취약 |
| JAR (안전) | v4.5.9, v4.6.0, v5.7.9, v5.8.0, v6.3.3, v6.4.0 | 양호 |
| JAR (특수) | v5.7.9-SNAPSHOT | 양호 |
| JAR (특수) | v7.0.0 (미래 메이저) | 확인불가 |
| WAR (취약) | 내부 pac4j-jwt-5.0.0.jar | 취약 |
| WAR (안전) | 내부 pac4j-jwt-6.3.3.jar | 양호 |
| Fat JAR (취약) | BOOT-INF/lib/pac4j-jwt-4.5.8.jar | 취약 |
| pom.xml (직접) | `<version>5.4.0</version>` | 취약 |
| pom.xml (변수) | `${pac4j.version}` = 6.3.2 | 취약 |
| build.gradle | `pac4j-jwt:4.5.9` | 양호 |

**Podman 컨테이너:**

| 컨테이너 | 내용 | 기대 결과 |
|----------|------|-----------|
| pac4j-qa-vuln | /opt/app/lib/pac4j-jwt-4.5.8.jar | 취약 |
| pac4j-qa-safe | /opt/app/lib/pac4j-jwt-6.3.3.jar | 양호 |
| pac4j-qa-war | /opt/app/vulnerable-app.war (내부 v5.0.0) | 취약 |

### 4.3 스캔 소요 시간

| 항목 | 시간 |
|------|------|
| 전체 스캔 (`/` 대상 + 컨테이너 3개) | **3초** |
| Phase 1: 호스트 파일시스템 스캔 | ~2초 |
| Phase 2: 컨테이너 스캔 (3개) | ~1초 |

### 4.4 자동화 QA 검증 결과: 57건 전체 PASS

```
============================================================
 QA 검증 시작
============================================================

--- 1. JSON 구조 검증 (8건) ---
  [PASS] JSON 유효성
  [PASS] scanner 필드
  [PASS] CVE ID
  [PASS] CVSS 점수
  [PASS] 환경 자동 탐지
  [PASS] 컨테이너 런타임 탐지
  [PASS] hostname 존재
  [PASS] IP 주소 1개 이상

--- 2. 취약 버전 탐지 - 경계값 테스트 (14건) ---
  [PASS] v3.9.0 = 취약 (EOL)         [PASS] v3.9.0 버전값 정확
  [PASS] v4.0.0 = 취약               [PASS] v4.0.0 버전값 정확
  [PASS] v4.5.8 = 취약 (경계값 -1)   [PASS] v4.5.8 버전값 정확
  [PASS] v5.0.0 = 취약               [PASS] v5.0.0 버전값 정확
  [PASS] v5.7.8 = 취약 (경계값 -1)   [PASS] v5.7.8 버전값 정확
  [PASS] v6.0.0 = 취약               [PASS] v6.0.0 버전값 정확
  [PASS] v6.3.2 = 취약 (경계값 -1)   [PASS] v6.3.2 버전값 정확

--- 3. 안전 버전 탐지 - 경계값 테스트 (12건) ---
  [PASS] v4.5.9 = 양호 (경계값 정확) [PASS] v4.5.9 버전값 정확
  [PASS] v4.6.0 = 양호               [PASS] v4.6.0 버전값 정확
  [PASS] v5.7.9 = 양호 (경계값 정확) [PASS] v5.7.9 버전값 정확
  [PASS] v5.8.0 = 양호               [PASS] v5.8.0 버전값 정확
  [PASS] v6.3.3 = 양호 (경계값 정확) [PASS] v6.3.3 버전값 정확
  [PASS] v6.4.0 = 양호               [PASS] v6.4.0 버전값 정확

--- 4. 특수 케이스 (3건) ---
  [PASS] v7.0.0 (미래 메이저) = 확인불가
  [PASS] v5.7.9-SNAPSHOT = 양호
  [PASS] SNAPSHOT 버전 추출 정확

--- 5. WAR/Fat-JAR 아카이브 내부 탐지 (3건) ---
  [PASS] WAR 내부 취약 jar 탐지 (v5.0.0)
  [PASS] WAR 내부 안전 jar 탐지 (v6.3.3)
  [PASS] WAR 내부 버전 추출 정확

--- 6. Maven/Gradle 빌드 파일 탐지 (6건) ---
  [PASS] pom.xml 직접 버전 탐지 (v5.4.0 = 취약)
  [PASS] pom.xml 버전 추출 정확
  [PASS] pom.xml 변수 참조 해석 (${pac4j.version} -> v6.3.2 = 취약)
  [PASS] pom.xml 변수 버전 추출 정확
  [PASS] build.gradle 탐지 (v4.5.9 = 양호)
  [PASS] build.gradle 버전 추출 정확

--- 7. Podman 컨테이너 탐지 (6건) ---
  [PASS] 컨테이너(취약) 탐지: pac4j-qa-vuln (v4.5.8 = 취약)
  [PASS] 컨테이너(취약) 이름: podman:pac4j-qa-vuln
  [PASS] 컨테이너(안전) 탐지: pac4j-qa-safe (v6.3.3 = 양호)
  [PASS] 컨테이너(안전) 이름: podman:pac4j-qa-safe
  [PASS] 컨테이너(WAR) 탐지: pac4j-qa-war (v5.4.0 = 취약)
  [PASS] 컨테이너(WAR) 이름: podman:pac4j-qa-war

--- 8. Summary 카운트 정합성 (5건) ---
  [PASS] total = results 배열 길이
  [PASS] total = vulnerable + safe + unknown
  [PASS] 취약 건수 정확
  [PASS] 양호 건수 정확
  [PASS] 확인불가 건수 정확

============================================================
 QA 결과: PASS=57, FAIL=0
 >>> 모든 테스트 통과! <<<
============================================================
```

### 4.5 실제 JSON 출력 예시

취약 탐지 (호스트 JAR):
```json
{
  "location": "/tmp/pac4j_qa/jars/pac4j-jwt-4.5.8.jar",
  "version": "4.5.8",
  "status": "취약",
  "detail": "취약 버전 (v4.5.8). 즉시 패치 필요: 4.x>=4.5.9 / 5.x>=5.7.9 / 6.x>=6.3.3",
  "source_type": "jar_file",
  "container": ""
}
```

취약 탐지 (컨테이너 내부 WAR):
```json
{
  "location": "/opt/app/webapp.war",
  "version": "5.4.0",
  "status": "취약",
  "detail": "취약 버전 (v5.4.0). 즉시 패치 필요: 4.x>=4.5.9 / 5.x>=5.7.9 / 6.x>=6.3.3",
  "source_type": "embedded_in_archive(pac4j-jwt-5.4.0.jar)",
  "container": "podman:pac4j-qa-war"
}
```

양호 탐지 (컨테이너 내부 JAR):
```json
{
  "location": "/opt/app/lib/pac4j-jwt-6.3.3.jar",
  "version": "6.3.3",
  "status": "양호",
  "detail": "패치된 버전 (v6.3.3)",
  "source_type": "jar_file",
  "container": "podman:pac4j-qa-safe"
}
```

Maven pom.xml 탐지:
```json
{
  "location": "/tmp/pac4j_qa/maven_project/pom.xml",
  "version": "6.3.2",
  "status": "취약",
  "detail": "취약 버전 (v6.3.2). 즉시 패치 필요: 4.x>=4.5.9 / 5.x>=5.7.9 / 6.x>=6.3.3",
  "source_type": "pom.xml",
  "container": ""
}
```

---

## 5. QA 과정에서 발견 및 수정된 버그

| # | 버그 | 원인 | 수정 내용 |
|---|------|------|-----------|
| 1 | 버전에 `.jar` 접미사 포함 (`4.0.0.jar`) | `extract_version_from_filename` 정규식이 `.jar`까지 매칭 | `.jar` 제거 후 파싱하도록 수정 |
| 2 | WAR/EAR 아카이브 호스트 스캔 미탐지 | `-size +100k` 필터가 WAR/EAR에도 적용됨 | WAR/EAR은 크기 무관, JAR만 100k 필터 적용 |
| 3 | Podman 컨테이너 미지원 | `docker` 명령어 하드코딩 | `CONTAINER_CLI` 변수로 docker/podman 자동 선택 |
