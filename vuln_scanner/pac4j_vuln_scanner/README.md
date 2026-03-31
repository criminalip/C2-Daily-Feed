# CVE-2026-29000 pac4j-jwt 인증 우회 취약점 스캐너

## 개요

| 항목 | 내용 |
|------|------|
| CVE | CVE-2026-29000 |
| CVSS | 10.0 (Critical) |
| 대상 | pac4j-jwt 라이브러리 |
| 취약점 | JWE+JWS 결합 시 PlainJWT로 서명 검증 우회 (인증 우회) |
| 참조 | https://www.codeant.ai/security-research/pac4j-jwt-authentication-bypass-public-key |

### 영향 버전 및 패치 버전

| 라인 | 취약 버전 | 패치 버전 |
|------|-----------|-----------|
| 4.x | < 4.5.9 | >= 4.5.9 |
| 5.x | < 5.7.9 | >= 5.7.9 |
| 6.x | < 6.3.3 | >= 6.3.3 |

## 사용법

```bash
# 기본 실행 (결과: /tmp/cve_2026_29000_HOSTNAME_DATE.json)
bash cve_2026_29000_pac4j_scanner.sh

# 출력 경로 지정
bash cve_2026_29000_pac4j_scanner.sh --output /tmp/result.json
```

> root 권한 필수. 환경(베어메탈/Docker/Podman/K8s) 자동 탐지.

### Ansible 연동

```yaml
- name: CVE-2026-29000 pac4j-jwt 취약점 점검
  script: cve_2026_29000_pac4j_scanner.sh --output /tmp/cve_2026_29000_{{ inventory_hostname }}.json
  become: yes

- name: 결과 수집
  fetch:
    src: /tmp/cve_2026_29000_{{ inventory_hostname }}.json
    dest: ./results/
    flat: yes
```

## 파일 구조

```
pac4j_vuln_scanner/
├── cve_2026_29000_pac4j_scanner.sh   # 스캐너 본체
├── README.md                         # 이 파일
└── MANUAL.md                         # 상세 설명서 (설계, 테스트 결과 포함)
```
