# Vulnerability Scanner & Report System

Linux 서버 보안 취약점 자동 점검 도구와 웹 기반 보고서 시스템입니다.

KISA(한국인터넷진흥원) **「주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」**를 기반으로 점검 항목을 구성하였으며, 공개 취약점(CVE) 및 침해사고 흔적 점검 항목을 추가하여 확장하였습니다.

## 구성

| 구성 요소 | 설명 |
|-----------|------|
| `vul_scanner.sh` | 취약점 점검 Agent (Bash, 단일 파일) |
| `vuln-report-was/` | 취약점 보고서 WAS (Node.js + Express) |

## 취약점 점검 Agent

104개 보안 항목을 자동 점검하여 JSON 결과를 생성합니다.

### 점검 영역

| 영역 | 항목 수 | 내용 |
|------|---------|------|
| Unix 서버 보안 | 67 | 계정관리, 파일권한, 서비스, 패치, 로그 |
| 웹 서비스 보안 | 11 | Apache, Nginx, Tomcat 설정 점검 |
| DB 보안 | 8 | MySQL, MariaDB, PostgreSQL 설정 점검 |
| 공개 취약점(CVE) | 16 | Log4j, Spring4Shell, OpenSSH 등 |
| 침해사고 흔적 | 2 | Rootkit, WebShell 탐지 |

### 지원 OS

RHEL/CentOS/Rocky/Alma, Ubuntu/Debian, SUSE/openSUSE

### 실행

```bash
sudo bash vul_scanner.sh
sudo bash vul_scanner.sh --output /path/to/result.json
```

- root 권한 필요
- 외부 의존성 없음 (OS 기본 명령어만 사용)
- 시스템 설정을 변경하지 않음 (읽기 전용)

## 취약점 보고서 WAS

점검 Agent가 생성한 JSON 파일을 업로드하여 웹 브라우저에서 시각적 보고서로 확인합니다.

### 기능

- JSON 드래그&드롭 업로드 (다중 파일)
- 대시보드: 요약 카드 + 도넛/막대 차트
- 결과 테이블: 필터, 정렬, 검색
- PDF 다운로드

### 기술 스택

Node.js 18 + Express + EJS + Chart.js + Puppeteer

### 설치 및 실행

```bash
cd vuln-report-was
npm install
node server.js
```

브라우저에서 `http://localhost:3000` 접속

### systemd 서비스 등록 (백그라운드 상시 실행)

서비스 파일 생성:

```bash
cat <<'EOF' > /etc/systemd/system/vuln-report-was.service
[Unit]
Description=Vuln Report WAS - 취약점 점검 보고서 시스템
After=network.target

[Service]
Type=simple
WorkingDirectory=/volume/AISpera/vuln_scanner/vuln-report-was
ExecStart=/root/.nvm/versions/node/v24.14.0/bin/node server.js
Restart=always
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF
```

서비스 등록 및 시작:

```bash
systemctl daemon-reload
systemctl enable vuln-report-was   # 부팅 시 자동 시작
systemctl start vuln-report-was    # 서비스 시작
```

주요 관리 명령어:

| 명령어 | 설명 |
|--------|------|
| `systemctl status vuln-report-was` | 상태 확인 |
| `systemctl restart vuln-report-was` | 재시작 |
| `systemctl stop vuln-report-was` | 중지 |
| `journalctl -u vuln-report-was -f` | 실시간 로그 확인 |

### HTTPS 설정 (Nginx 리버스 프록시)

자체 서명 SSL 인증서 생성:

```bash
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/vuln-report.key \
  -out /etc/nginx/ssl/vuln-report.crt \
  -subj "/C=KR/ST=Seoul/O=AISpera/CN=vuln-report"
```

Nginx 설치 및 설정:

```bash
# RHEL/CentOS/Rocky
dnf install -y nginx
```

`/etc/nginx/conf.d/vuln-report-was.conf` 생성:

```nginx
server {
    listen 443 ssl;
    server_name _;

    ssl_certificate     /etc/nginx/ssl/vuln-report.crt;
    ssl_certificate_key /etc/nginx/ssl/vuln-report.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    client_max_body_size 50m;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}
```

Nginx 시작:

```bash
systemctl enable nginx
systemctl start nginx
```

`https://<서버IP>`로 접속 (자체 서명 인증서이므로 브라우저 보안 경고 시 "고급" → "계속 진행")

### PDF 한글 폰트 (필요 시)

```bash
# Ubuntu/Debian
sudo apt-get install -y fonts-noto-cjk

# RHEL/CentOS
sudo yum install -y google-noto-sans-cjk-ttc-fonts
```

## 운영 흐름

```
대상 서버                      보고서 WAS                    점검자
┌─────────┐   JSON 생성    ┌──────────────┐   보고서 열람   ┌────────┐
│ 점검     │ ───────────→  │  웹 서버      │ ←───────────→ │ 브라우저 │
│ Agent   │               │  (Express)    │   PDF 다운로드  │        │
└─────────┘               └──────────────┘               └────────┘
```

1. 대상 서버에서 `vul_scanner.sh` 실행 → JSON 생성
2. JSON 파일을 WAS에 업로드
3. 웹 브라우저에서 보고서 열람 및 PDF 다운로드

## License

[Apache License 2.0](LICENSE)

Copyright 2026 An Hyukjin
