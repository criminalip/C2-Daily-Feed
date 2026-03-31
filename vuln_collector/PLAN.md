# 제로데이 & 신규취약점 수집 자동화 계획서

## 1. 개요

### 1.1 배경 및 목적
제로데이 및 신규 취약점에 대한 신속한 인지와 대응은 보안 운영의 핵심이다. 현재 취약점 정보는 NVD, MITRE, CISA 등 다수의 공개 소스에 분산되어 있어, 수동 모니터링으로는 실시간 대응이 어렵다.

본 프로젝트는 주요 취약점 데이터 소스를 자동으로 수집·정규화·번역하여 단일 대시보드에서 조회할 수 있는 시스템을 구축하고, 고위험 취약점 발생 시 즉시 알림을 통해 선제적 대응 체계를 마련하는 것을 목적으로 한다.

### 1.2 기대 효과
- 제로데이/신규 CVE 자동 수집으로 수동 모니터링 비용 제거
- 한글 번역 제공으로 보안 담당자의 분석 시간 단축
- CVSS 8.0 이상 고위험 취약점 Slack 알림으로 즉시 인지
- CISA KEV(알려진 익스플로잇 취약점) 자동 마킹으로 우선순위 판단 지원
- 기존 취약점 점검 보고서 시스템(vuln-report-was)과 통합하여 단일 포탈 운영

---

## 2. 시스템 아키텍처

### 2.1 전체 구성도

```
┌─────────────────────────────────────────────────────────────────┐
│                      외부 데이터 소스                              │
│  ┌─────────┐  ┌───────────┐  ┌──────────┐  ┌────────────────┐  │
│  │ NVD API │  │ MITRE CVE │  │ CISA KEV │  │ GitHub Advisory │  │
│  │  v2.0   │  │ (deltaLog)│  │ Catalog  │  │   (GraphQL)    │  │
│  └────┬────┘  └─────┬─────┘  └────┬─────┘  └───────┬────────┘  │
│       │             │              │                │            │
└───────┼─────────────┼──────────────┼────────────────┼────────────┘
        │             │              │                │
        ▼             ▼              ▼                ▼
  ┌─────────────────────────────────────────────────────────┐
  │              vuln_collector (Node.js)                    │
  │  ┌──────────────────────────────────────────────────┐   │
  │  │  수집 스케줄러 (setInterval 기반, 소스별 독립 폴링)    │   │
  │  │  - 지수 백오프 재시도                                 │   │
  │  │  - 동시 실행 방지                                    │   │
  │  │  - 소스 장애 격리                                    │   │
  │  └──────────────────────────────────────────────────┘   │
  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
  │  │ 정규화/병합   │  │ 한글 번역     │  │ Slack 알림    │  │
  │  │ (트랜잭션)    │  │ (Google API) │  │ (예정)        │  │
  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
  └─────────┼────────────────┼────────────────┼────────────┘
            │                │                │
            ▼                ▼                ▼
  ┌─────────────────────────────┐     ┌──────────────┐
  │  MariaDB (vuln_collector)   │     │   Slack       │
  │  - 정규화 스키마 (9개 테이블)  │     │  Webhook      │
  │  - 한글 번역 컬럼            │     │  (예정)       │
  └──────────────┬──────────────┘     └──────────────┘
                 │ (읽기 전용)
                 ▼
  ┌─────────────────────────────┐
  │  vuln-report-was (Express)  │
  │  - /vulnfeed 대시보드        │
  │  - /vulnfeed/detail 상세    │
  │  - /vulnfeed/api JSON API  │
  └─────────────────────────────┘
```

### 2.2 컴포넌트 역할

| 컴포넌트 | 역할 | 기술 스택 |
|---------|------|----------|
| vuln_collector | 취약점 수집·정규화·번역·알림 | Node.js v24, PM2 |
| MariaDB | 정규화 데이터 저장 | MariaDB (Rocky Linux 9.7) |
| vuln-report-was | 웹 대시보드 (기존 시스템 확장) | Express + EJS |
| Slack Webhook | 고위험 취약점 알림 (예정) | Slack Incoming Webhook |

---

## 3. 데이터 수집

### 3.1 수집 소스 및 주기

| 소스 | API/방식 | 수집 주기 | 수집 방식 | 특이사항 |
|------|---------|----------|----------|---------|
| **NVD** | REST API v2.0 | 2시간 | `lastModStartDate` 기반 증분 수집 | API 키 헤더 인증, 레이트 리밋 준수 |
| **MITRE CVE** | GitHub cvelistV5 deltaLog | 2시간 | deltaLog.json으로 변경분 감지 후 개별 CVE 조회 | 인증 불필요 |
| **CISA KEV** | JSON 카탈로그 다운로드 | 6시간 | 전체 카탈로그 다운로드 → DB upsert | is_kev, kev_due_date 마킹 |
| **GitHub Advisories** | GraphQL API | 4시간 | `updatedSince` 필터 + 커서 기반 페이지네이션 | Personal Access Token 필요 |

### 3.2 데이터 처리 흐름

```
수집 → 정규화 → 중복 제거(CVE ID 기준 upsert) → DB 저장(트랜잭션) → 번역(배치)
```

1. **수집**: 각 소스 API에서 JSON 데이터 fetch (30초 타임아웃)
2. **정규화**: 소스별 상이한 포맷을 통일된 구조로 변환
   - CVSS v3.1/v3.0 점수 추출 및 심각도 분류
   - CWE, CPE(영향 제품), 참조 링크 파싱
3. **중복 제거**: `INSERT ... ON DUPLICATE KEY UPDATE`로 CVE ID 기준 병합
   - 높은 CVSS 점수 유지, KEV/exploit 플래그 OR 연산
4. **트랜잭션 저장**: 하나의 CVE 관련 데이터를 원자적으로 저장
5. **한글 번역**: 미번역 항목 50건씩 배치 처리 (1시간 간격)

### 3.3 안정성 설계

| 기능 | 설명 |
|------|------|
| 소스 장애 격리 | 한 소스 실패 시 다른 소스 수집 계속 진행 |
| 지수 백오프 | HTTP 429/5xx 시 30초 → 1분 → 2분 ... 최대 30분 대기 후 재시도 |
| 동시 실행 방지 | 이전 수집이 실행 중이면 다음 인터벌 스킵 |
| Graceful Shutdown | SIGTERM 수신 시 타이머 정리 및 DB 커넥션 풀 종료 |
| fetch 타임아웃 | 모든 외부 API 호출에 AbortSignal 타임아웃 적용 |

---

## 4. 데이터베이스 설계

### 4.1 스키마

```
vuln_collector (MariaDB, utf8mb4)
├── vulnerabilities         메인 취약점 (CVE ID unique, 한글 번역 컬럼 포함)
├── affected_products       영향받는 제품 (N:1, 벤더-제품 unique)
├── reference_links         참조 링크 (N:1)
├── vulnerability_sources   수집 소스 기록 (N:M)
├── cwe_entries             CWE 마스터
├── vulnerability_cwes      취약점-CWE 매핑 (N:M)
├── tags                    태그 마스터
├── vulnerability_tags      취약점-태그 매핑 (N:M)
└── collector_state         수집기 상태 (소스별 마지막 수집 시점)
```

### 4.2 주요 인덱스

| 테이블 | 인덱스 | 용도 |
|--------|-------|------|
| vulnerabilities | `cve_id` (UNIQUE) | CVE 중복 제거 |
| vulnerabilities | `idx_severity` | 심각도 필터 |
| vulnerabilities | `idx_published` | 날짜 범위 필터/정렬 |
| vulnerabilities | `idx_cvss` | CVSS 점수 필터 |
| vulnerabilities | `idx_kev` | KEV 필터 |
| affected_products | `idx_vuln_vendor_product` (UNIQUE) | 제품 중복 방지 |
| affected_products | `idx_vendor_product` | 벤더/제품 검색 |

---

## 5. 웹 대시보드

### 5.1 화면 구성

기존 **취약점 점검 보고서 시스템**(vuln-report-was)의 네비게이션에 "취약점 피드" 탭을 추가하여 통합 운영한다.

#### 목록 페이지 (`/vulnfeed`)

| 영역 | 내용 |
|------|------|
| 요약 카드 | 전체, CRITICAL, HIGH, MEDIUM, LOW 건수 (필터 연동) |
| 차트 | 심각도 분포 도넛 차트, 최근 14일 신규 CVE 추이 차트 |
| 필터 | 심각도, 소스, KEV 여부, 날짜 범위, 키워드 검색 |
| 테이블 | CVE ID(링크), 제목(한글), 심각도 배지, CVSS, 소스, KEV 배지, 발행일 |
| 페이지네이션 | 서버사이드 30건 단위 |
| 자동 새로고침 | 5분 간격 옵션 |

#### 상세 페이지 (`/vulnfeed/detail/:cveId`)

| 영역 | 내용 |
|------|------|
| 기본 정보 | CVE ID, CVSS 점수/벡터, 심각도, 발행일/수정일, KEV 기한 |
| 설명 | 한글 번역 + 원문 접기/펼치기 |
| 영향 제품 | 벤더, 제품명, 영향 버전 테이블 |
| CWE | 관련 CWE 배지 |
| 참조 링크 | 소스별 URL 목록 (http/https만 링크) |
| 수집 소스 | 수집 소스명, 일시, 원본 URL |

### 5.2 API

| 엔드포인트 | 용도 |
|-----------|------|
| `GET /vulnfeed/api/vulnerabilities` | 취약점 목록 JSON (필터/페이지네이션) |
| `GET /vulnfeed/api/stats` | 심각도·소스·일별 통계 |

---

## 6. 한글 번역

### 6.1 구현 방식

| 항목 | 내용 |
|------|------|
| 번역 엔진 | Google Translate (비공식 API, 무료) |
| 대상 컬럼 | `title_ko`, `description_ko` |
| 배치 크기 | 50건/회 |
| 실행 주기 | 1시간 간격 |
| 레이트 리밋 | 건당 0.3초 대기, 429 에러 시 60초 대기 |

### 6.2 표시 규칙
- 목록: 한글 번역이 있으면 한글, 없으면 영어 원문 표시
- 상세: 한글 번역 기본 표시 + "원문 보기(English)" 접기/펼치기

---

## 7. 향후 계획: Slack 알림 연동

### 7.1 목적
CVSS 8.0 이상의 고위험 취약점이 새로 수집되면 Slack 채널로 즉시 알림을 전송하여, 보안 담당자가 실시간으로 인지하고 대응할 수 있도록 한다.

### 7.2 알림 조건

| 조건 | 설명 |
|------|------|
| CVSS v3 >= 8.0 | HIGH(7.0~8.9) 중 상위 + CRITICAL(9.0~10.0) 전체 |
| 신규 CVE만 | DB에 처음 INSERT되는 CVE만 대상 (UPDATE 제외) |
| CISA KEV 등재 | KEV에 새로 등재된 CVE도 알림 대상 |

### 7.3 알림 메시지 형식

```
🚨 [CRITICAL] CVE-2026-XXXXX (CVSS 9.8)

제목: (한글 번역된 취약점 설명)

• 심각도: CRITICAL
• CVSS: 9.8
• 영향 제품: vendor/product
• KEV: 등재됨 (조치기한: 2026-04-01)
• 소스: NVD, CISA KEV

🔗 상세: http://서버주소:3000/vulnfeed/detail/CVE-2026-XXXXX
```

### 7.4 구현 계획

| 단계 | 작업 | 내용 |
|------|------|------|
| 1 | Slack Webhook 생성 | Slack 앱 > Incoming Webhook 설정, 대상 채널 지정 |
| 2 | 알림 모듈 개발 | `lib/notifier.js` - Slack Webhook POST 함수 |
| 3 | 수집 파이프라인 연동 | `store.js`의 saveVulnerability에서 신규 INSERT 시 CVSS 체크 → 알림 트리거 |
| 4 | 설정 추가 | `config.js`에 `SLACK_WEBHOOK_URL`, `ALERT_CVSS_THRESHOLD` 환경변수 |
| 5 | 중복 알림 방지 | `collector_state` 또는 별도 테이블로 알림 발송 이력 관리 |
| 6 | 테스트 및 배포 | 테스트 채널로 검증 후 운영 채널 전환 |

---

## 8. 향후 확장 소스 (검토 중)

| 소스 | 설명 | 우선순위 |
|------|------|---------|
| Microsoft MSRC | Patch Tuesday 보안 업데이트 | 높음 |
| GitHub PoC 모니터링 | `CVE-202` 키워드로 PoC 존재 여부 탐지 | 중간 |
| Exploit-DB | 검증된 익스플로잇 아카이브 | 중간 |
| KISA/KrCERT | 한국 취약점 정보 | 높음 |

---

## 9. 운영 환경

### 9.1 인프라

| 항목 | 내용 |
|------|------|
| OS | Rocky Linux 9.7 |
| Node.js | v24.14.0 (nvm) |
| DB | MariaDB (시스템 패키지) |
| 프로세스 관리 | PM2 (자동 재시작, 로그 관리) |

### 9.2 프로세스 관리

```bash
# Collector 시작/재시작/로그
pm2 start collector.js --name vuln-collector
pm2 restart vuln-collector
pm2 logs vuln-collector

# WAS (기존 프로세스)
node server.js    # 포트 3000
```

### 9.3 모니터링

| 항목 | 방법 |
|------|------|
| 수집 상태 | `pm2 logs vuln-collector` |
| DB 데이터 | `mysql -u root -e "SELECT COUNT(*) FROM vuln_collector.vulnerabilities"` |
| 수집 소스별 현황 | `/vulnfeed/api/stats` API |
| 프로세스 상태 | `pm2 list` |

---

## 10. 보안 고려사항

| 항목 | 대응 |
|------|------|
| DB 접근 | 전용 사용자(`vuln_collector`), 최소 권한 원칙 |
| API 키 관리 | 환경변수로 주입 (PM2), 소스코드 노출 방지 |
| SQL 인젝션 | 모든 쿼리 파라미터 바인딩 (Prepared Statement) |
| XSS | EJS 자동 이스케이프 + JSON 출력 수동 sanitize |
| URL 검증 | 외부 피드 URL은 http/https 스킴만 링크 렌더링 |
| 에러 노출 | 사용자 응답에 DB 상세 에러 미노출 |
| fetch 타임아웃 | 외부 API 호출 시 AbortSignal 타임아웃 적용 |

---

## 11. 현재 수집 현황

> 아래는 2026-03-16 기준 실제 수집 데이터이다.

| 항목 | 수치 |
|------|------|
| **총 CVE** | 8,752건 |
| **CRITICAL** | 382건 |
| **HIGH** | 1,473건 |
| **MEDIUM** | 1,496건 |
| **LOW** | 142건 |
| **NVD 소스** | 2,271건 |
| **MITRE 소스** | 6,975건 |
| **CISA KEV 소스** | 1,542건 |
| **GitHub 소스** | 355건 |
| **한글 번역 완료** | 243건 (자동 진행 중) |
| **영향 제품** | 14,795건 |
| **참조 링크** | 36,723건 |
| **CWE 매핑** | 330종 |
