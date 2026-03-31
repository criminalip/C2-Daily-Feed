# CVE-2026-27944 Nginx UI 취약점 점검 스크립트

## 취약점 개요

| 항목 | 내용 |
|------|------|
| CVE | CVE-2026-27944 |
| 대상 | Nginx UI (웹 기반 Nginx 관리 도구) |
| CVSS | 9.8 (Critical) |
| CWE | CWE-306 (인증 누락), CWE-311 (민감 데이터 암호화 누락) |
| 취약 버전 | < 2.3.3 |
| 패치 버전 | >= 2.3.3 |
| Reference | https://nvd.nist.gov/vuln/detail/CVE-2026-27944 |

`/api/backup` 엔드포인트에 인증이 없어 익명 접근자가 서버 백업 파일을 다운로드할 수 있으며, `X-Backup-Security` 응답 헤더에 복호화 키가 평문으로 노출되어 백업 데이터(계정, 세션 토큰, SSL 키 등)를 즉시 해독할 수 있습니다.

## 사용법

```bash
# 기본 실행 (root 필요)
bash cve_2026_27944_nginxui_scanner.sh

# 출력 경로 지정
bash cve_2026_27944_nginxui_scanner.sh --output /tmp/result.json
```

## Ansible 배포

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
        path: /tmp/cve_2026_27944_nginxui_scanner.sh
        state: absent
```

## 점검 범위

| 단계 | 대상 | 방법 |
|------|------|------|
| Phase 1 | 호스트 프로세스 | `pgrep -f nginx-ui` + 바이너리 `-v` |
| Phase 1 | 호스트 바이너리 | 일반 경로 + 전체 파일시스템 `find` |
| Phase 1 | systemd 서비스 | `*nginx-ui*` 유닛 파일 검색 |
| Phase 2 | Docker/Podman | 이미지명/컨테이너명 + 내부 프로세스 확인 |
| Phase 2 | Kubernetes | Pod 이미지명 + 내부 프로세스 확인 |

## 출력 형식 (JSON)

```json
{
  "scanner": "CVE-2026-27944 Nginx UI Scanner",
  "cve": "CVE-2026-27944",
  "cvss": "9.8",
  "summary": {
    "total": 1,
    "vulnerable": 1,
    "safe": 0,
    "unknown": 0
  },
  "results": [
    {
      "location": "/usr/local/bin/nginx-ui",
      "version": "2.3.1",
      "status": "취약",
      "detail": "취약 버전 v2.3.1 → v2.3.3 이상으로 업그레이드 필요",
      "source_type": "running_process(pid:12345)",
      "patched_version": "2.3.3",
      "container": ""
    }
  ]
}
```
