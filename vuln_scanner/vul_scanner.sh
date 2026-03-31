#!/usr/bin/env bash
###############################################################################
# Unix 서버 취약점 점검 도구 (취약점 점검 Agent)
# Version: 2.0
# 점검 항목: U-01~U-67(67), W-01~W-11(11), D-01~D-08(8), V-01~V-16(16), I-01~I-02(2) = 104개
# 대상 OS: RHEL/CentOS/Rocky/Alma, Ubuntu/Debian, SUSE/openSUSE
# 출력: JSON 파일 + stderr 진행 로그
###############################################################################
set -o pipefail

###############################################################################
# Section 0: 상수 및 CLI 파싱
###############################################################################
readonly SCANNER_NAME="Unix Vulnerability Scanner"
readonly SCANNER_VERSION="2.0"
readonly STATUS_PASS="양호"
readonly STATUS_FAIL="취약"
readonly STATUS_NA="N/A"

OUTPUT_FILE=""
RESULTS=""          # JSON results array items (newline-separated)
COUNT_PASS=0
COUNT_FAIL=0
COUNT_NA=0

usage() {
    cat >&2 <<EOF
사용법: $0 [옵션]

옵션:
  --output, -o FILE   결과 JSON 파일 경로 (기본: /tmp/vul_scan_HOSTNAME_DATE.json)
  --help, -h          도움말 출력

예시:
  bash $0
  bash $0 --output /tmp/result.json
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output|-o)
            [[ -z "${2:-}" ]] && { echo "ERROR: --output 옵션에 파일 경로가 필요합니다" >&2; exit 1; }
            OUTPUT_FILE="$2"; shift 2 ;;
        --help|-h)   usage ;;
        *)           echo "알 수 없는 옵션: $1" >&2; usage ;;
    esac
done

# root 권한 확인
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: 이 스크립트는 root 권한이 필요합니다." >&2
    exit 1
fi

if [[ -z "$OUTPUT_FILE" ]]; then
    OUTPUT_FILE="/tmp/vul_scan_$(hostname)_$(date +%Y%m%d_%H%M%S).json"
fi

# 리소스 보호: CPU/IO 우선순위를 최저로 설정 (1CPU/1GB VM 서비스 가용성 보호)
renice -n 19 $$ &>/dev/null
ionice -c 3 -p $$ &>/dev/null  # idle I/O class

###############################################################################
# Section 1: 유틸리티 함수
###############################################################################
log() {
    echo "[$(date +%H:%M:%S)] $*" >&2
}

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    # Remove remaining control characters (0x00-0x1F) except already handled
    s=$(printf '%s' "$s" | tr -d '\001-\010\013\014\016-\037')
    printf '%s' "$s"
}

add_result() {
    local id="$1" category="$2" title="$3" importance="$4" status="$5" detail="$6" current="${7:-}"
    local escaped_detail escaped_current
    escaped_detail="$(json_escape "$detail")"
    escaped_current="$(json_escape "$current")"

    local entry
    entry=$(cat <<JSONEOF
    {
      "id": "${id}",
      "category": "$(json_escape "$category")",
      "title": "$(json_escape "$title")",
      "importance": "${importance}",
      "status": "${status}",
      "detail": "${escaped_detail}",
      "current_settings": "${escaped_current}"
    }
JSONEOF
)
    if [[ -n "$RESULTS" ]]; then
        RESULTS="${RESULTS},"$'\n'"${entry}"
    else
        RESULTS="${entry}"
    fi

    case "$status" in
        "$STATUS_PASS") ((COUNT_PASS++)) ;;
        "$STATUS_FAIL") ((COUNT_FAIL++)) ;;
        "$STATUS_NA")   ((COUNT_NA++))   ;;
    esac

    log "${id}. ${title} [${status}]"
}

get_octal_perms() {
    stat -c '%a' "$1" 2>/dev/null
}

get_file_owner() {
    stat -c '%U' "$1" 2>/dev/null
}

get_file_owner_uid() {
    stat -c '%u' "$1" 2>/dev/null
}

# check_file_perm FILE EXPECTED_OWNER MAX_PERM
# Returns: 0=pass, 1=fail, 2=not found
# Sets global: CFP_DETAIL
check_file_perm() {
    local file="$1" expected_owner="$2" max_perm="$3"
    CFP_DETAIL=""

    if [[ ! -e "$file" ]]; then
        CFP_DETAIL="파일이 존재하지 않음: ${file}"
        return 2
    fi

    local owner perms fail=0
    owner="$(get_file_owner "$file")"
    perms="$(get_octal_perms "$file")"

    if [[ -z "$owner" || -z "$perms" ]]; then
        CFP_DETAIL="stat 실패: ${file}"
        return 1
    fi

    if [[ "$expected_owner" != "*" && "$owner" != "$expected_owner" ]]; then
        CFP_DETAIL="소유자 부적절 (${owner}, 기대값: ${expected_owner})"
        fail=1
    fi

    if [[ -n "$max_perm" ]]; then
        local actual=$((8#${perms:-0}))
        local max=$((8#$max_perm))
        if (( (actual & ~max) != 0 )); then
            local msg="권한 부적절 (${perms}, 최대: ${max_perm})"
            if [[ -n "$CFP_DETAIL" ]]; then
                CFP_DETAIL="${CFP_DETAIL}; ${msg}"
            else
                CFP_DETAIL="$msg"
            fi
            fail=1
        fi
    fi

    if [[ $fail -eq 0 ]]; then
        CFP_DETAIL="소유자: ${owner}, 권한: ${perms}"
    fi
    return $fail
}

is_service_active() {
    local svc="$1"
    if command -v systemctl &>/dev/null; then
        systemctl is-active "$svc" &>/dev/null && return 0
        systemctl is-enabled "$svc" &>/dev/null && return 0
    fi
    if [[ -f "/etc/init.d/$svc" ]]; then
        "/etc/init.d/$svc" status &>/dev/null && return 0
    fi
    return 1
}

is_process_running() {
    pgrep -x "$1" &>/dev/null
}

get_config_value() {
    local file="$1" key="$2"
    if [[ -f "$file" ]]; then
        grep -v '^\s*#' "$file" | grep -i "^\s*${key}" | tail -1 | sed "s/^[^=]*=\s*//" | sed 's/\s*$//'
    fi
}

get_sshd_config_value() {
    local key="$1"
    local val=""
    # sshd_config.d overrides (Include is typically at top, so .d files take precedence)
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        val=$(grep -rh -v '^\s*#' /etc/ssh/sshd_config.d/ 2>/dev/null | grep -i "^\s*${key}\s" | head -1 | awk '{print $2}')
    fi
    # Fall back to main config (OpenSSH uses first-match semantics)
    if [[ -z "$val" && -f /etc/ssh/sshd_config ]]; then
        val=$(grep -v '^\s*#' /etc/ssh/sshd_config | grep -i "^\s*${key}\s" | head -1 | awk '{print $2}')
    fi
    printf '%s' "$val"
}

run_with_timeout() {
    local timeout_sec="$1"
    shift
    timeout "$timeout_sec" nice -n 19 "$@" 2>/dev/null
}

# version_compare V1 V2 → returns 0 if V1<V2, 1 if V1==V2, 2 if V1>V2
version_compare() {
    if [[ "$1" == "$2" ]]; then return 1; fi
    local IFS=.
    local i v1=($1) v2=($2)
    for ((i=0; i<${#v1[@]} || i<${#v2[@]}; i++)); do
        local n1=${v1[i]:-0} n2=${v2[i]:-0}
        # strip non-numeric suffixes (e.g. 2.17p1 → 2 17)
        n1="${n1%%[!0-9]*}"; n2="${n2%%[!0-9]*}"
        n1=${n1:-0}; n2=${n2:-0}
        if (( n1 < n2 )); then return 0; fi
        if (( n1 > n2 )); then return 2; fi
    done
    return 1
}

# version_in_range VER MIN MAX → 0 if MIN <= VER < MAX
version_in_range() {
    local ver="$1" min="$2" max="$3"
    version_compare "$ver" "$min"
    local cmp_min=$?
    # cmp_min: 0=ver<min, 1=ver==min, 2=ver>min
    if [[ $cmp_min -eq 0 ]]; then return 1; fi  # ver < min → out of range
    version_compare "$ver" "$max"
    local cmp_max=$?
    # cmp_max: 0=ver<max → in range, 1=ver==max → out, 2=ver>max → out
    if [[ $cmp_max -eq 0 ]]; then return 0; fi
    return 1
}


# 공통 find 제외 경로 (가상FS, 마운트, 컨테이너 등)
# 함수로 래핑하여 eval 없이 사용
find_system() {
    # Usage: find_system [추가 find 옵션...]
    # 공통 prune 경로 + 사용자 지정 옵션으로 find 실행
    find / \
        -path /proc -prune -o \
        -path /sys -prune -o \
        -path /dev -prune -o \
        -path /run -prune -o \
        -path /mnt -prune -o \
        -path /snap -prune -o \
        -path /var/lib/docker -prune -o \
        -path /var/lib/lxd -prune -o \
        -path /var/lib/containers -prune -o \
        "$@" 2>/dev/null
}

get_ip_addresses() {
    if command -v ip &>/dev/null; then
        ip -4 addr show 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | grep -v '^127\.' | tr '\n' ',' | sed 's/,$//'
    elif command -v hostname &>/dev/null; then
        hostname -I 2>/dev/null | tr ' ' ',' | sed 's/,$//'
    fi
}

###############################################################################
# Section 2: OS 탐지 및 전역변수 설정
###############################################################################
OS_FAMILY=""    # rhel, debian, suse
OS_ID=""
OS_VERSION=""
KERNEL_VERSION=""

detect_os() {
    KERNEL_VERSION="$(uname -r)"

    if [[ -f /etc/os-release ]]; then
        OS_ID=$(. /etc/os-release && echo "$ID")
        OS_VERSION=$(. /etc/os-release && echo "$VERSION_ID")
    elif [[ -f /etc/redhat-release ]]; then
        OS_ID="rhel"
        OS_VERSION=$(sed 's/[^0-9.]//g' /etc/redhat-release)
    elif [[ -f /etc/SuSE-release ]]; then
        OS_ID="sles"
        OS_VERSION=$(grep VERSION /etc/SuSE-release | awk '{print $3}')
    fi

    OS_ID="${OS_ID,,}"  # lowercase

    case "$OS_ID" in
        rhel|centos|rocky|almalinux|ol|fedora|amzn)
            OS_FAMILY="rhel" ;;
        ubuntu|debian)
            OS_FAMILY="debian" ;;
        sles|suse|opensuse|opensuse-leap|opensuse-tumbleweed)
            OS_FAMILY="suse" ;;
        *)
            OS_FAMILY="unknown"
            log "경고: 인식되지 않는 OS ($OS_ID). RHEL 계열로 가정합니다."
            OS_FAMILY="rhel"
            ;;
    esac

    log "OS 탐지: ${OS_ID} ${OS_VERSION} (${OS_FAMILY} 계열), 커널: ${KERNEL_VERSION}"
}

# PAM 관련 경로
PAM_SYSTEM_AUTH=""
PAM_PASSWORD_AUTH=""
PAM_COMMON_AUTH=""
PAM_COMMON_PASSWORD=""
PAM_COMMON_ACCOUNT=""

setup_os_vars() {
    case "$OS_FAMILY" in
        rhel)
            PAM_SYSTEM_AUTH="/etc/pam.d/system-auth"
            PAM_PASSWORD_AUTH="/etc/pam.d/password-auth"
            PAM_COMMON_AUTH="$PAM_SYSTEM_AUTH"
            PAM_COMMON_PASSWORD="$PAM_PASSWORD_AUTH"
            PAM_COMMON_ACCOUNT="$PAM_SYSTEM_AUTH"
            ;;
        debian|suse)
            PAM_COMMON_AUTH="/etc/pam.d/common-auth"
            PAM_COMMON_PASSWORD="/etc/pam.d/common-password"
            PAM_COMMON_ACCOUNT="/etc/pam.d/common-account"
            PAM_SYSTEM_AUTH="$PAM_COMMON_AUTH"
            PAM_PASSWORD_AUTH="$PAM_COMMON_PASSWORD"
            ;;
    esac
}

###############################################################################
# Section 2.5: 웹서버/DB 탐지 및 전역변수
###############################################################################
APACHE_INSTALLED=0; APACHE_CONF=""; APACHE_DOCROOT=""; APACHE_USER=""
NGINX_INSTALLED=0; NGINX_CONF=""; NGINX_ROOT=""
TOMCAT_INSTALLED=0; TOMCAT_HOME=""; TOMCAT_CONF=""
MYSQL_INSTALLED=0; MYSQL_CONF=""; MYSQL_RUNNING=0
PG_INSTALLED=0; PG_CONF=""; PG_HBA=""; PG_RUNNING=0

detect_web_servers() {
    # Apache
    local apache_bin=""
    for cmd in httpd apache2; do
        if command -v "$cmd" &>/dev/null; then
            apache_bin="$cmd"; break
        fi
    done
    if [[ -n "$apache_bin" ]] || [[ -d /etc/httpd ]] || [[ -d /etc/apache2 ]]; then
        APACHE_INSTALLED=1
        for f in /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf /etc/apache2/httpd.conf; do
            if [[ -f "$f" ]]; then APACHE_CONF="$f"; break; fi
        done
        if [[ -n "$APACHE_CONF" ]]; then
            APACHE_DOCROOT=$(grep -v '^\s*#' "$APACHE_CONF" | grep -i '^\s*DocumentRoot' | tail -1 | awk '{print $2}' | tr -d '"')
            APACHE_USER=$(grep -v '^\s*#' "$APACHE_CONF" | grep -i '^\s*User\s' | tail -1 | awk '{print $2}')
        fi
        [[ -z "$APACHE_DOCROOT" ]] && APACHE_DOCROOT="/var/www/html"
    fi

    # Nginx
    if command -v nginx &>/dev/null || [[ -d /etc/nginx ]]; then
        NGINX_INSTALLED=1
        for f in /etc/nginx/nginx.conf; do
            if [[ -f "$f" ]]; then NGINX_CONF="$f"; break; fi
        done
        if [[ -n "$NGINX_CONF" ]]; then
            NGINX_ROOT=$(grep -v '^\s*#' "$NGINX_CONF" /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null | grep -i '^\s*root\s' | head -1 | awk '{print $2}' | tr -d ';')
        fi
        [[ -z "$NGINX_ROOT" ]] && NGINX_ROOT="/usr/share/nginx/html"
    fi

    # Tomcat
    for d in /opt/tomcat /usr/share/tomcat /var/lib/tomcat* /opt/apache-tomcat*; do
        if [[ -d "$d" ]]; then
            TOMCAT_INSTALLED=1; TOMCAT_HOME="$d"
            [[ -f "${d}/conf/server.xml" ]] && TOMCAT_CONF="${d}/conf/server.xml"
            break
        fi
    done
    if [[ $TOMCAT_INSTALLED -eq 0 ]] && command -v catalina.sh &>/dev/null; then
        TOMCAT_INSTALLED=1
        TOMCAT_HOME="$(dirname "$(dirname "$(command -v catalina.sh)")")"
        [[ -f "${TOMCAT_HOME}/conf/server.xml" ]] && TOMCAT_CONF="${TOMCAT_HOME}/conf/server.xml"
    fi

    log "웹서버 탐지: Apache=${APACHE_INSTALLED} Nginx=${NGINX_INSTALLED} Tomcat=${TOMCAT_INSTALLED}"
}

detect_databases() {
    # MySQL/MariaDB
    if command -v mysql &>/dev/null || command -v mysqld &>/dev/null; then
        MYSQL_INSTALLED=1
        for f in /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/mariadb.conf.d/50-server.cnf; do
            if [[ -f "$f" ]]; then MYSQL_CONF="$f"; break; fi
        done
        is_process_running mysqld && MYSQL_RUNNING=1
        is_process_running mariadbd && MYSQL_RUNNING=1
    fi

    # PostgreSQL
    if command -v psql &>/dev/null || command -v pg_isready &>/dev/null; then
        PG_INSTALLED=1
        # Find postgresql.conf
        local pg_data=""
        pg_data=$(run_with_timeout 5 find /etc/postgresql /var/lib/pgsql /var/lib/postgresql -name postgresql.conf -type f 2>/dev/null | head -1)
        if [[ -n "$pg_data" ]]; then
            PG_CONF="$pg_data"
            local pg_dir; pg_dir=$(dirname "$pg_data")
            [[ -f "${pg_dir}/pg_hba.conf" ]] && PG_HBA="${pg_dir}/pg_hba.conf"
        fi
        is_process_running postgres && PG_RUNNING=1
        is_process_running postmaster && PG_RUNNING=1
    fi

    log "DB 탐지: MySQL=${MYSQL_INSTALLED}(run=${MYSQL_RUNNING}) PostgreSQL=${PG_INSTALLED}(run=${PG_RUNNING})"
}

# Get all web document roots for scanning
get_web_docroots() {
    local roots=""
    [[ $APACHE_INSTALLED -eq 1 && -d "$APACHE_DOCROOT" ]] && roots="$APACHE_DOCROOT"
    [[ $NGINX_INSTALLED -eq 1 && -d "$NGINX_ROOT" && "$NGINX_ROOT" != "$APACHE_DOCROOT" ]] && roots="${roots:+${roots} }${NGINX_ROOT}"
    if [[ $TOMCAT_INSTALLED -eq 1 && -d "${TOMCAT_HOME}/webapps" ]]; then
        roots="${roots:+${roots} }${TOMCAT_HOME}/webapps"
    fi
    echo "$roots"
}

###############################################################################
# Section 3: 점검 함수 (U-01 ~ U-67)
###############################################################################

# =============================================================================
# 1. 계정관리 (U-01 ~ U-13)
# =============================================================================

check_U01() {
    local id="U-01" category="계정관리"
    local title="root 계정 원격 접속 제한" importance="상"
    local status="$STATUS_PASS" detail="" current=""

    # SSH PermitRootLogin
    local permit_root
    permit_root="$(get_sshd_config_value PermitRootLogin)"
    permit_root="${permit_root,,}"
    local telnet_active="비활성"

    if [[ -z "$permit_root" ]]; then
        detail="SSH PermitRootLogin 미설정 (기본값 적용)"
    elif [[ "$permit_root" == "yes" ]]; then
        status="$STATUS_FAIL"
        detail="SSH PermitRootLogin이 yes로 설정됨"
    else
        detail="SSH PermitRootLogin=${permit_root}"
    fi

    # Telnet 확인
    if is_service_active telnet 2>/dev/null || is_process_running in.telnetd; then
        telnet_active="활성"
        if [[ -f /etc/securetty ]]; then
            if grep -q 'pts/' /etc/securetty 2>/dev/null; then
                status="$STATUS_FAIL"
                detail="${detail}; Telnet 활성, /etc/securetty에 pts 항목 존재"
            fi
        else
            status="$STATUS_FAIL"
            detail="${detail}; Telnet 활성, /etc/securetty 없음"
        fi
    fi

    current="sshd_config PermitRootLogin=${permit_root:-미설정}; Telnet=${telnet_active}; /etc/securetty 존재=$([ -f /etc/securetty ] && echo Y || echo N)"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_U02() {
    local id="U-02" category="계정관리"
    local title="비밀번호 관리정책 설정" importance="상"
    local status="$STATUS_PASS" detail="" findings=""

    # /etc/login.defs 확인
    if [[ -f /etc/login.defs ]]; then
        local max_days min_days min_len
        max_days=$(grep -v '^\s*#' /etc/login.defs | grep '^\s*PASS_MAX_DAYS' | awk '{print $2}')
        min_days=$(grep -v '^\s*#' /etc/login.defs | grep '^\s*PASS_MIN_DAYS' | awk '{print $2}')
        min_len=$(grep -v '^\s*#' /etc/login.defs | grep '^\s*PASS_MIN_LEN' | awk '{print $2}')

        [[ -n "$max_days" ]] && findings="PASS_MAX_DAYS=${max_days}" || findings="PASS_MAX_DAYS 미설정"
        [[ -n "$min_days" ]] && findings="${findings}, PASS_MIN_DAYS=${min_days}" || findings="${findings}, PASS_MIN_DAYS 미설정"
        [[ -n "$min_len" ]] && findings="${findings}, PASS_MIN_LEN=${min_len}" || findings="${findings}, PASS_MIN_LEN 미설정"

        if [[ -n "$max_days" ]] && (( max_days > 90 )); then
            status="$STATUS_FAIL"
        fi
        if [[ -n "$min_days" ]] && (( min_days < 1 )); then
            status="$STATUS_FAIL"
        fi
        if [[ -n "$min_len" ]] && (( min_len < 8 )); then
            status="$STATUS_FAIL"
        fi
        # 미설정인 경우도 취약
        [[ -z "$max_days" ]] && status="$STATUS_FAIL"
        [[ -z "$min_len" ]] && status="$STATUS_FAIL"
    else
        status="$STATUS_FAIL"
        findings="/etc/login.defs 없음"
    fi

    # PAM pwquality/cracklib 확인
    local pam_pw_ok=0
    for pf in "$PAM_COMMON_PASSWORD" "$PAM_SYSTEM_AUTH" /etc/pam.d/system-auth /etc/pam.d/common-password; do
        [[ -f "$pf" ]] || continue
        if grep -v '^\s*#' "$pf" | grep -q 'pam_pwquality\|pam_cracklib'; then
            pam_pw_ok=1
            findings="${findings}; PAM 비밀번호 복잡성 모듈 활성"
            break
        fi
    done
    if [[ -f /etc/security/pwquality.conf ]]; then
        local minlen
        minlen=$(grep -v '^\s*#' /etc/security/pwquality.conf | grep '^\s*minlen' | awk -F= '{print $2}' | tr -d ' ')
        [[ -n "$minlen" ]] && findings="${findings}, pwquality minlen=${minlen}"
    fi

    detail="$findings"
    current="/etc/login.defs: PASS_MAX_DAYS=${max_days:-미설정}, PASS_MIN_DAYS=${min_days:-미설정}, PASS_MIN_LEN=${min_len:-미설정}; PAM pwquality/cracklib=${pam_pw_ok}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_U03() {
    local id="U-03" category="계정관리"
    local title="계정 잠금 임계값 설정" importance="상"
    local status="$STATUS_FAIL" detail="" deny_val=""

    # RHEL 8+ faillock.conf
    if [[ -f /etc/security/faillock.conf ]]; then
        deny_val=$(grep -v '^\s*#' /etc/security/faillock.conf | grep '^\s*deny' | awk -F= '{print $2}' | tr -d ' ')
        if [[ -n "$deny_val" ]] && (( deny_val > 0 && deny_val <= 10 )); then
            status="$STATUS_PASS"
            detail="faillock.conf deny=${deny_val}"
        elif [[ -n "$deny_val" ]]; then
            detail="faillock.conf deny=${deny_val} (10 초과)"
        fi
    fi

    # PAM faillock/tally2 확인
    if [[ "$status" != "$STATUS_PASS" ]]; then
        for pf in "$PAM_COMMON_AUTH" "$PAM_SYSTEM_AUTH" /etc/pam.d/system-auth /etc/pam.d/common-auth /etc/pam.d/login; do
            [[ -f "$pf" ]] || continue
            local line
            line=$(grep -v '^\s*#' "$pf" | grep 'pam_faillock\|pam_tally2' | head -1)
            if [[ -n "$line" ]]; then
                deny_val=$(echo "$line" | sed -n 's/.*deny=\([0-9]*\).*/\1/p')
                if [[ -n "$deny_val" ]] && (( deny_val > 0 && deny_val <= 10 )); then
                    status="$STATUS_PASS"
                    detail="PAM deny=${deny_val} (${pf})"
                    break
                elif [[ -n "$deny_val" ]]; then
                    detail="PAM deny=${deny_val} (10 초과, ${pf})"
                else
                    detail="PAM faillock/tally2 설정은 있으나 deny 값 없음"
                fi
            fi
        done
    fi

    [[ -z "$detail" ]] && detail="계정 잠금 임계값 미설정"

    current="/etc/security/faillock.conf deny=${deny_val:-미설정}; PAM faillock/tally2 점검완료"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_U04() {
    local id="U-04" category="계정관리"
    local title="비밀번호 파일 보호" importance="상"
    local status="$STATUS_PASS" detail=""

    # /etc/shadow 존재 확인
    if [[ ! -f /etc/shadow ]]; then
        status="$STATUS_FAIL"
        detail="/etc/shadow 파일 없음"
        current="/etc/shadow존재=N; passwd비밀번호필드비x계정=점검불가(shadow없음)"
        add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
        return
    fi

    # /etc/passwd 2번째 필드가 모두 x인지 확인
    local non_x
    non_x=$(awk -F: '$2 != "x" {print $1}' /etc/passwd 2>/dev/null)
    if [[ -n "$non_x" ]]; then
        status="$STATUS_FAIL"
        detail="비밀번호 해시가 /etc/passwd에 존재하는 계정: ${non_x//$'\n'/, }"
    else
        detail="/etc/shadow 사용, /etc/passwd 비밀번호 필드 모두 x"
    fi

    current="/etc/shadow존재=$([ -f /etc/shadow ] && echo Y || echo N); passwd비밀번호필드비x계정=${non_x:-없음}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_U05() {
    local id="U-05" category="계정관리"
    local title="root 이외의 UID가 '0' 금지" importance="상"
    local status="$STATUS_PASS" detail=""

    local uid0_accounts
    uid0_accounts=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd 2>/dev/null)
    local total_accounts
    total_accounts=$(wc -l < /etc/passwd 2>/dev/null)
    if [[ -n "$uid0_accounts" ]]; then
        status="$STATUS_FAIL"
        detail="UID 0인 비root 계정: ${uid0_accounts//$'\n'/, } (전체 계정 수: ${total_accounts})"
    else
        detail="root 외 UID 0 계정 없음 (전체 계정 수: ${total_accounts})"
    fi

    current="UID0계정=$(awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null | tr '\n' ','); 전체계정수=${total_accounts}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_U06() {
    local id="U-06" category="계정관리"
    local title="사용자 계정 su 기능 제한" importance="상"
    local status="$STATUS_FAIL" detail=""

    if [[ -f /etc/pam.d/su ]]; then
        local wheel_line
        wheel_line=$(grep -v '^\s*#' /etc/pam.d/su | grep 'pam_wheel.so')
        if [[ -n "$wheel_line" ]]; then
            status="$STATUS_PASS"
            detail="pam_wheel.so 설정 확인: ${wheel_line}"
        else
            detail="/etc/pam.d/su에 pam_wheel.so 비활성"
        fi
    else
        detail="/etc/pam.d/su 파일 없음"
    fi

    current="/etc/pam.d/su존재=$([ -f /etc/pam.d/su ] && echo Y || echo N); pam_wheel.so=${wheel_line:-미설정}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_U07() {
    local id="U-07" category="계정관리"
    local title="불필요한 계정 제거" importance="하"
    local status="$STATUS_PASS" detail=""

    local unnecessary_accounts="adm lp sync shutdown halt news uucp games"
    local found=""
    for acct in $unnecessary_accounts; do
        local shell
        shell=$(awk -F: -v u="$acct" '$1==u {print $7}' /etc/passwd 2>/dev/null)
        if [[ -n "$shell" && "$shell" != "/sbin/nologin" && "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" && "$shell" != "/usr/bin/false" ]]; then
            found="${found} ${acct}(${shell})"
        fi
    done

    if [[ -n "$found" ]]; then
        status="$STATUS_FAIL"
        detail="로그인 쉘이 부여된 불필요 계정:${found}"
    else
        detail="불필요 계정에 로그인 쉘 미부여"
    fi

    current="점검계정: adm,lp,sync,shutdown,halt,news,uucp,games; 발견=${found:-없음}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_U08() {
    local id="U-08" category="계정관리"
    local title="관리자 그룹에 최소한의 계정 포함" importance="중"
    local status="$STATUS_PASS" detail=""

    local root_group_members
    root_group_members=$(awk -F: '$1=="root" {print $4}' /etc/group 2>/dev/null)
    # Also check users with GID 0
    local gid0_users
    gid0_users=$(awk -F: '$4==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null)

    local all_members=""
    [[ -n "$root_group_members" ]] && all_members="$root_group_members"
    [[ -n "$gid0_users" ]] && all_members="${all_members:+${all_members},}${gid0_users//$'\n'/,}"

    if [[ -n "$all_members" && "$all_members" != "," ]]; then
        # filter empty
        local cleaned
        cleaned=$(echo "$all_members" | tr ',' '\n' | grep -v '^$' | sort -u | tr '\n' ',' | sed 's/,$//')
        if [[ -n "$cleaned" ]]; then
            status="$STATUS_FAIL"
            detail="root 그룹 내 계정: ${cleaned}"
        else
            detail="root 그룹에 불필요 계정 없음"
        fi
    else
        detail="root 그룹에 불필요 계정 없음"
    fi

    current="/etc/group root멤버=${root_group_members:-없음}; GID0비root=${gid0_users:-없음}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_U09() {
    local id="U-09" category="계정관리"
    local title="계정이 존재하지 않는 GID 금지" importance="하"
    local status="$STATUS_PASS" detail=""

    # /etc/group의 GID 중 /etc/passwd에서 primary GID로 사용되지 않고
    # 그룹 멤버도 없는 것 확인은 과도할 수 있으므로
    # 기본적으로 GID가 /etc/passwd에서 참조되거나 그룹 멤버 있으면 OK
    local orphan_groups=""
    while IFS=: read -r gname _ gid members; do
        [[ "$gname" =~ ^# ]] && continue
        [[ -z "$gid" ]] && continue
        # Skip system groups (typically used by services)
        (( gid < 1000 && gid != 0 )) && continue
        # Check if any user has this as primary GID
        if ! awk -F: -v g="$gid" '$4==g {found=1; exit} END{exit !found}' /etc/passwd 2>/dev/null; then
            # Check if group has members
            if [[ -z "$members" ]]; then
                orphan_groups="${orphan_groups} ${gname}(${gid})"
            fi
        fi
    done < /etc/group

    if [[ -n "$orphan_groups" ]]; then
        # 기준: 불필요한 그룹이 존재하면 취약
        status="$STATUS_FAIL"
        detail="사용자 없는 그룹 존재:${orphan_groups}"
    else
        detail="모든 그룹에 계정 연결됨"
    fi

    current="GID>=1000 사용자없는그룹:${orphan_groups:-없음}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_U10() {
    local id="U-10" category="계정관리"
    local title="동일한 UID 금지" importance="중"
    local status="$STATUS_PASS" detail=""

    local dup_uids
    dup_uids=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
    if [[ -n "$dup_uids" ]]; then
        status="$STATUS_FAIL"
        local dup_info=""
        for uid in $dup_uids; do
            local users
            users=$(awk -F: -v u="$uid" '$3==u {print $1}' /etc/passwd | tr '\n' ',' | sed 's/,$//')
            dup_info="${dup_info} UID ${uid}: ${users};"
        done
        detail="중복 UID 발견:${dup_info}"
    else
        detail="UID 중복 없음"
    fi

    current="중복UID:${dup_uids:-없음}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_U11() {
    local id="U-11" category="계정관리"
    local title="사용자 Shell 점검" importance="하"
    local status="$STATUS_PASS" detail=""

    local login_shells="/bin/bash /bin/sh /bin/zsh /bin/csh /bin/ksh /bin/tcsh"
    local sys_with_shell=""

    while IFS=: read -r user _ uid _ _ _ shell; do
        [[ "$user" =~ ^# ]] && continue
        [[ -z "$uid" ]] && continue
        (( uid >= 1000 )) && continue
        [[ "$user" == "root" ]] && continue
        for ls in $login_shells; do
            if [[ "$shell" == "$ls" ]]; then
                sys_with_shell="${sys_with_shell} ${user}(${shell})"
                break
            fi
        done
    done < /etc/passwd

    if [[ -n "$sys_with_shell" ]]; then
        status="$STATUS_FAIL"
        detail="로그인 쉘이 부여된 시스템 계정:${sys_with_shell}"
    else
        detail="시스템 계정에 로그인 쉘 미부여"
    fi

    current="로그인쉘부여시스템계정:${sys_with_shell:-없음}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_U12() {
    local id="U-12" category="계정관리"
    local title="세션 종료 시간 설정" importance="하"
    local status="$STATUS_FAIL" detail=""

    local tmout_found=0 tmout_val=""

    # /etc/profile 확인
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc; do
        if [[ -f "$f" ]]; then
            local tv
            tv=$(grep -v '^\s*#' "$f" | sed -n 's/.*TMOUT=\([0-9]*\).*/\1/p' | tail -1)
            if [[ -n "$tv" ]]; then
                tmout_val="$tv"
                tmout_found=1
                detail="TMOUT=${tv} (${f})"
                break
            fi
        fi
    done

    # /etc/profile.d/*.sh 확인
    if [[ $tmout_found -eq 0 ]]; then
        for f in /etc/profile.d/*.sh; do
            [[ -f "$f" ]] || continue
            local tv
            tv=$(grep -v '^\s*#' "$f" | sed -n 's/.*TMOUT=\([0-9]*\).*/\1/p' | tail -1)
            if [[ -n "$tv" ]]; then
                tmout_val="$tv"
                tmout_found=1
                detail="TMOUT=${tv} (${f})"
                break
            fi
        done
    fi

    if [[ $tmout_found -eq 1 ]]; then
        if (( tmout_val <= 600 )); then
            status="$STATUS_PASS"
        else
            detail="${detail} (600초 초과)"
        fi
    else
        detail="TMOUT 미설정"
    fi

    current="TMOUT=${tmout_val:-미설정}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_U13() {
    local id="U-13" category="계정관리"
    local title="안전한 비밀번호 암호화 알고리즘 사용" importance="중"
    local status="$STATUS_PASS" detail=""

    # /etc/shadow 해시 알고리즘 확인
    local weak_hash=""
    while IFS=: read -r user hash _; do
        [[ "$user" =~ ^# ]] && continue
        [[ -z "$hash" || "$hash" == "*" || "$hash" == "!" || "$hash" == "!!" ]] && continue
        # $6$ = SHA-512, $5$ = SHA-256, $y$ = yescrypt
        if [[ ! "$hash" =~ ^\$6\$ && ! "$hash" =~ ^\$5\$ && ! "$hash" =~ ^\$y\$ && ! "$hash" =~ ^\$2[aby]\$ ]]; then
            weak_hash="${weak_hash} ${user}"
        fi
    done < /etc/shadow 2>/dev/null

    if [[ -n "$weak_hash" ]]; then
        status="$STATUS_FAIL"
        detail="취약한 암호화 알고리즘 사용 계정:${weak_hash}"
    else
        detail="비밀번호 암호화 알고리즘 적절 (SHA-512/SHA-256/yescrypt)"
    fi

    current="취약해시계정:${weak_hash:-없음}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

# =============================================================================
# 2. 파일 및 디렉토리 관리 (U-14 ~ U-33)
# =============================================================================

check_U14() {
    local id="U-14" category="파일 및 디렉토리 관리"
    local title="root 홈, 패스 디렉터리 권한 및 패스 설정" importance="상"
    local status="$STATUS_PASS" detail=""

    # root PATH에 . 포함 여부
    local root_path
    root_path="$PATH"

    if echo ":${root_path}:" | grep -q ':\.:\|^\.:\|:\.$\|^::\|::'; then
        status="$STATUS_FAIL"
        detail="root PATH에 현재 디렉토리(.) 포함. 현재값: ${root_path}"
    else
        detail="root PATH에 현재 디렉토리(.) 미포함. 현재값: ${root_path}"
    fi

    current="PATH=${root_path}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_U15() {
    local id="U-15" category="파일 및 디렉토리 관리"
    local title="파일 및 디렉터리 소유자 설정" importance="상"
    local status="$STATUS_PASS" detail=""

    local noowner_files
    noowner_files=$(run_with_timeout 30 find_system \( -nouser -o -nogroup \) -print | head -20)

    if [[ -n "$noowner_files" ]]; then
        status="$STATUS_FAIL"
        local count
        count=$(echo "$noowner_files" | wc -l)
        detail="소유자/그룹이 없는 파일 ${count}개 발견 (상위 20개): $(echo "$noowner_files" | tr '\n' ', ' | sed 's/,$//')"
    else
        detail="소유자/그룹이 없는 파일 없음"
    fi

    current="소유자없는파일: ${noowner_files:-없음}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_U16() {
    local id="U-16" category="파일 및 디렉토리 관리"
    local title="/etc/passwd 파일 소유자 및 권한 설정" importance="상"

    check_file_perm /etc/passwd root 644
    local rc=$?
    if [[ $rc -eq 0 ]]; then
        current="/etc/passwd: ${CFP_DETAIL}"
        add_result "$id" "$category" "$title" "상" "$STATUS_PASS" "$CFP_DETAIL" "$current"
    else
        current="/etc/passwd: ${CFP_DETAIL}"
        add_result "$id" "$category" "$title" "상" "$STATUS_FAIL" "$CFP_DETAIL" "$current"
    fi
}

check_U17() {
    local id="U-17" category="파일 및 디렉토리 관리"
    local title="시스템 시작 스크립트 권한 설정" importance="상"
    local status="$STATUS_PASS" detail="" findings=""

    # /etc/init.d 스크립트 점검
    local init_dirs="/etc/init.d /etc/rc.d/init.d"
    for d in $init_dirs; do
        [[ -d "$d" ]] || continue
        while IFS= read -r f; do
            [[ -f "$f" ]] || continue
            local owner perms
            owner=$(get_file_owner "$f")
            perms=$(get_octal_perms "$f")
            local actual=$((8#${perms:-0}))
            # Check other-write bit (o+w = 002)
            if [[ "$owner" != "root" ]] || (( actual & 002 )); then
                findings="${findings} ${f}(${owner}:${perms})"
                status="$STATUS_FAIL"
            fi
        done < <(find "$d" -maxdepth 1 -type f 2>/dev/null)
    done

    # systemd unit files
    for d in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
        [[ -d "$d" ]] || continue
        while IFS= read -r f; do
            local owner perms
            owner=$(get_file_owner "$f")
            perms=$(get_octal_perms "$f")
            local actual=$((8#${perms:-0}))
            if [[ "$owner" != "root" ]] || (( actual & 002 )); then
                findings="${findings} ${f}(${owner}:${perms})"
                status="$STATUS_FAIL"
            fi
        done < <(find "$d" -maxdepth 1 -name '*.service' -type f 2>/dev/null | head -50)
    done

    if [[ "$status" == "$STATUS_PASS" ]]; then
        detail="시작 스크립트 소유자/권한 적절"
    else
        detail="부적절한 시작 스크립트:${findings}"
    fi

    current="시작스크립트:${findings:-없음}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U18() {
    local id="U-18" category="파일 및 디렉토리 관리"
    local title="/etc/shadow 파일 소유자 및 권한 설정" importance="상"

    if [[ ! -f /etc/shadow ]]; then
        current="/etc/shadow: 파일없음"
        add_result "$id" "$category" "$title" "상" "$STATUS_FAIL" "/etc/shadow 파일 없음" "$current"
        return
    fi

    check_file_perm /etc/shadow root 400
    local rc=$?
    if [[ $rc -eq 0 ]]; then
        current="/etc/shadow: ${CFP_DETAIL}"
        add_result "$id" "$category" "$title" "상" "$STATUS_PASS" "$CFP_DETAIL" "$current"
    else
        current="/etc/shadow: ${CFP_DETAIL}"
        add_result "$id" "$category" "$title" "상" "$STATUS_FAIL" "$CFP_DETAIL" "$current"
    fi
}

check_U19() {
    local id="U-19" category="파일 및 디렉토리 관리"
    local title="/etc/hosts 파일 소유자 및 권한 설정" importance="상"

    if [[ ! -f /etc/hosts ]]; then
        current="/etc/hosts: 파일없음"
        add_result "$id" "$category" "$title" "상" "$STATUS_NA" "/etc/hosts 파일 없음" "$current"
        return
    fi

    check_file_perm /etc/hosts root 644
    local rc=$?
    if [[ $rc -eq 0 ]]; then
        current="/etc/hosts: ${CFP_DETAIL}"
        add_result "$id" "$category" "$title" "상" "$STATUS_PASS" "$CFP_DETAIL" "$current"
    else
        current="/etc/hosts: ${CFP_DETAIL}"
        add_result "$id" "$category" "$title" "상" "$STATUS_FAIL" "$CFP_DETAIL" "$current"
    fi
}

check_U20() {
    local id="U-20" category="파일 및 디렉토리 관리"
    local title="/etc/(x)inetd.conf 파일 소유자 및 권한 설정" importance="상"
    local status="$STATUS_PASS" detail=""

    local checked=0
    for f in /etc/inetd.conf /etc/xinetd.conf; do
        if [[ -f "$f" ]]; then
            checked=1
            check_file_perm "$f" root 600
            if [[ $? -ne 0 ]]; then
                status="$STATUS_FAIL"
                detail="${detail}${f}: ${CFP_DETAIL}; "
            else
                detail="${detail}${f}: ${CFP_DETAIL}; "
            fi
        fi
    done

    if [[ -d /etc/xinetd.d ]]; then
        checked=1
        while IFS= read -r f; do
            check_file_perm "$f" root 600
            if [[ $? -ne 0 ]]; then
                status="$STATUS_FAIL"
                detail="${detail}${f}: ${CFP_DETAIL}; "
            fi
        done < <(find /etc/xinetd.d -type f 2>/dev/null)
    fi

    if [[ $checked -eq 0 ]]; then
        status="$STATUS_NA"
        detail="inetd/xinetd 설정 파일 없음 (서비스 미사용)"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U21() {
    local id="U-21" category="파일 및 디렉토리 관리"
    local title="/etc/(r)syslog.conf 파일 소유자 및 권한 설정" importance="상"
    local status="$STATUS_PASS" detail=""

    local checked=0
    for f in /etc/rsyslog.conf /etc/syslog.conf; do
        if [[ -f "$f" ]]; then
            checked=1
            local owner perms
            owner="$(get_file_owner "$f")"
            perms="$(get_octal_perms "$f")"
            local fail=0
            # 소유자: root, bin, sys 허용
            if [[ "$owner" != "root" && "$owner" != "bin" && "$owner" != "sys" ]]; then
                fail=1
            fi
            # 권한: 640 이하
            local actual=$((8#${perms:-0}))
            local max=$((8#640))
            if (( (actual & ~max) != 0 )); then
                fail=1
            fi
            if [[ $fail -eq 1 ]]; then
                status="$STATUS_FAIL"
                detail="${detail}${f}: 소유자=${owner}, 권한=${perms} (기준: root/bin/sys, 640 이하); "
            else
                detail="${detail}${f}: 소유자=${owner}, 권한=${perms}; "
            fi
        fi
    done

    if [[ $checked -eq 0 ]]; then
        status="$STATUS_FAIL"
        detail="rsyslog.conf/syslog.conf 파일 없음"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U22() {
    local id="U-22" category="파일 및 디렉토리 관리"
    local title="/etc/services 파일 소유자 및 권한 설정" importance="상"

    if [[ ! -f /etc/services ]]; then
        current="/etc/services 소유자=N/A 권한=N/A (파일없음)"
        add_result "$id" "$category" "$title" "상" "$STATUS_FAIL" "/etc/services 파일 없음" "$current"
        return
    fi

    local owner perms status="$STATUS_PASS" detail=""
    owner="$(get_file_owner /etc/services)"
    perms="$(get_octal_perms /etc/services)"
    # 소유자: root, bin, sys 허용
    if [[ "$owner" != "root" && "$owner" != "bin" && "$owner" != "sys" ]]; then
        status="$STATUS_FAIL"
    fi
    local actual=$((8#${perms:-0}))
    local max=$((8#644))
    if (( (actual & ~max) != 0 )); then
        status="$STATUS_FAIL"
    fi
    detail="소유자: ${owner}, 권한: ${perms} (기준: root/bin/sys, 644 이하)"
    current="/etc/services 소유자=${owner} 권한=${perms}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U23() {
    local id="U-23" category="파일 및 디렉토리 관리"
    local title="SUID, SGID 설정 파일 점검" importance="상"
    local status="$STATUS_PASS" detail=""

    # 위험한 SUID/SGID 파일 목록
    local dangerous_suids="/usr/bin/newgrp /usr/sbin/traceroute /usr/bin/chfn /usr/bin/chsh /usr/bin/wall /usr/bin/write /usr/sbin/usernetctl"

    local suid_files
    suid_files=$(run_with_timeout 30 find_system -type f \( -perm -4000 -o -perm -2000 \) -print | head -200)

    local found_dangerous=""
    if [[ -n "$suid_files" ]]; then
        while IFS= read -r f; do
            for d in $dangerous_suids; do
                if [[ "$f" == "$d" ]]; then
                    found_dangerous="${found_dangerous} ${f}"
                fi
            done
        done <<< "$suid_files"
    fi

    local total_count
    total_count=$(echo "$suid_files" | grep -c . 2>/dev/null || echo 0)

    if [[ -n "$found_dangerous" ]]; then
        status="$STATUS_FAIL"
        detail="불필요한 SUID/SGID 파일 발견:${found_dangerous} (전체 ${total_count}개)"
    else
        detail="SUID/SGID 파일 ${total_count}개 (위험 파일 없음)"
    fi

    current="SUID/SGID파일수=${total_count}; 위험파일:${found_dangerous:-없음}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U24() {
    local id="U-24" category="파일 및 디렉토리 관리"
    local title="사용자, 시스템 환경변수 파일 소유자 및 권한 설정" importance="상"
    local status="$STATUS_PASS" detail="" findings=""

    local env_files=".profile .bashrc .bash_profile .bash_login .cshrc .login .kshrc"

    while IFS=: read -r user _ uid _ _ home shell; do
        [[ "$user" =~ ^# ]] && continue
        [[ -z "$uid" || -z "$home" || "$home" == "/" ]] && continue
        [[ "$shell" == "/sbin/nologin" || "$shell" == "/usr/sbin/nologin" || "$shell" == "/bin/false" ]] && continue
        [[ ! -d "$home" ]] && continue

        for ef in $env_files; do
            local fp="${home}/${ef}"
            [[ -f "$fp" ]] || continue
            local owner perms
            owner=$(get_file_owner "$fp")
            perms=$(get_octal_perms "$fp")
            local actual=$((8#${perms:-0}))

            # 소유자 확인
            if [[ "$owner" != "$user" && "$owner" != "root" ]]; then
                findings="${findings} ${fp}(소유자:${owner})"
                status="$STATUS_FAIL"
            fi
            # other-write 확인
            if (( actual & 002 )); then
                findings="${findings} ${fp}(권한:${perms})"
                status="$STATUS_FAIL"
            fi
        done
    done < /etc/passwd

    if [[ "$status" == "$STATUS_PASS" ]]; then
        detail="환경파일 소유자 및 권한 적절"
    else
        detail="부적절한 환경파일:${findings}"
    fi

    current="환경파일점검:${findings:-없음}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U25() {
    local id="U-25" category="파일 및 디렉토리 관리"
    local title="world writable 파일 점검" importance="상"
    local status="$STATUS_PASS" detail=""

    local ww_files
    ww_files=$(run_with_timeout 30 find_system -path /tmp -prune -o -path /var/tmp -prune -o -type f -perm -0002 -print | head -20)

    if [[ -n "$ww_files" ]]; then
        status="$STATUS_FAIL"
        local count
        count=$(echo "$ww_files" | wc -l)
        detail="world writable 파일 발견 (${count}개, 상위 20개): $(echo "$ww_files" | tr '\n' ', ' | sed 's/,$//')"
    else
        detail="world writable 파일 없음 (/tmp, /var/tmp 제외)"
    fi

    current="world_writable: ${ww_files:-없음}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U26() {
    local id="U-26" category="파일 및 디렉토리 관리"
    local title="/dev에 존재하지 않는 device 파일 점검" importance="상"
    local status="$STATUS_PASS" detail=""

    local dev_regular
    dev_regular=$(run_with_timeout 10 find /dev -type f 2>/dev/null | grep -v -E '(/dev/\.udev|/dev/shm/)' | head -20)

    if [[ -n "$dev_regular" ]]; then
        status="$STATUS_FAIL"
        detail="/dev 내 일반 파일 존재: $(echo "$dev_regular" | tr '\n' ', ' | sed 's/,$//')"
    else
        detail="/dev 내 비정상 일반 파일 없음"
    fi

    current="/dev일반파일: ${dev_regular:-없음}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U27() {
    local id="U-27" category="파일 및 디렉토리 관리"
    local title="\$HOME/.rhosts, hosts.equiv 사용 금지" importance="상"
    local status="$STATUS_PASS" detail="" findings=""

    # /etc/hosts.equiv 확인
    if [[ -f /etc/hosts.equiv ]]; then
        if grep -q '^+' /etc/hosts.equiv 2>/dev/null; then
            status="$STATUS_FAIL"
            findings="${findings} /etc/hosts.equiv에 + 항목 존재"
        else
            findings="${findings} /etc/hosts.equiv 존재 (+ 항목 없음)"
        fi
    fi

    # 각 사용자 ~/.rhosts 확인
    while IFS=: read -r user _ _ _ _ home _; do
        [[ "$user" =~ ^# ]] && continue
        [[ ! -d "$home" ]] && continue
        if [[ -f "${home}/.rhosts" ]]; then
            status="$STATUS_FAIL"
            findings="${findings} ${home}/.rhosts 존재"
        fi
    done < /etc/passwd

    if [[ "$status" == "$STATUS_PASS" ]]; then
        detail=".rhosts, hosts.equiv 파일 미사용"
    else
        detail="$findings"
    fi

    current="/etc/hosts.equiv=$([ -f /etc/hosts.equiv ] && echo 존재 || echo 없음); .rhosts점검완료"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U28() {
    local id="U-28" category="파일 및 디렉토리 관리"
    local title="접속 IP 및 포트 제한" importance="상"
    local status="$STATUS_FAIL" detail=""

    local firewall_found=0

    # iptables 확인
    if command -v iptables &>/dev/null; then
        local rules
        rules=$(iptables -L -n 2>/dev/null | grep -v -E '^Chain|^target|^$' | head -5)
        if [[ -n "$rules" ]]; then
            firewall_found=1
            detail="iptables 룰 존재"
        fi
    fi

    # firewalld 확인
    if command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null 2>&1; then
        firewall_found=1
        detail="${detail:+${detail}; }firewalld 활성"
    fi

    # ufw 확인
    if command -v ufw &>/dev/null; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null | head -1)
        if [[ "$ufw_status" == *"active"* ]]; then
            firewall_found=1
            detail="${detail:+${detail}; }ufw 활성"
        fi
    fi

    # nftables 확인
    if command -v nft &>/dev/null; then
        local nft_rules
        nft_rules=$(nft list ruleset 2>/dev/null | grep -c 'chain' || true)
        if (( nft_rules > 0 )); then
            firewall_found=1
            detail="${detail:+${detail}; }nftables 룰 존재"
        fi
    fi

    # hosts.allow/deny 확인
    if [[ -f /etc/hosts.allow ]]; then
        local allow_entries
        allow_entries=$(grep -v '^\s*#' /etc/hosts.allow | grep -v '^\s*$' | head -3)
        if [[ -n "$allow_entries" ]]; then
            firewall_found=1
            detail="${detail:+${detail}; }hosts.allow 설정 존재"
        fi
    fi

    if [[ $firewall_found -eq 1 ]]; then
        status="$STATUS_PASS"
    else
        detail="방화벽/접근제어 미설정"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U29() {
    local id="U-29" category="파일 및 디렉토리 관리"
    local title="hosts.lpd 파일 소유자 및 권한 설정" importance="하"
    local status="$STATUS_PASS" detail=""

    if [[ -f /etc/hosts.lpd ]]; then
        check_file_perm /etc/hosts.lpd root 600
        if [[ $? -ne 0 ]]; then
            status="$STATUS_FAIL"
            detail="hosts.lpd: ${CFP_DETAIL}"
        else
            detail="hosts.lpd: ${CFP_DETAIL}"
        fi
    else
        detail="hosts.lpd 파일 없음 (양호)"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "하" "$status" "$detail" "$current"
}

check_U30() {
    local id="U-30" category="파일 및 디렉토리 관리"
    local title="UMASK 설정 관리" importance="중"
    local status="$STATUS_FAIL" detail=""

    local umask_val=""
    for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/login.defs; do
        [[ -f "$f" ]] || continue
        local uv
        if [[ "$f" == "/etc/login.defs" ]]; then
            uv=$(grep -v '^\s*#' "$f" | grep '^\s*UMASK' | awk '{print $2}' | tail -1)
        else
            uv=$(grep -v '^\s*#' "$f" | sed -n 's/.*umask[[:space:]]*\([0-9]*\).*/\1/p' | tail -1)
        fi
        if [[ -n "$uv" && "$uv" =~ ^[0-7]+$ ]]; then
            umask_val="$uv"
            local umask_num=$((8#$uv))
            if (( (umask_num & 8#022) == 8#022 )); then
                status="$STATUS_PASS"
                detail="UMASK=${uv} (${f})"
                break
            else
                detail="UMASK=${uv} (022 미만, ${f})"
            fi
        fi
    done

    [[ -z "$detail" ]] && detail="UMASK 미설정"

    current="UMASK=${umask_val:-미설정}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

check_U31() {
    local id="U-31" category="파일 및 디렉토리 관리"
    local title="홈디렉토리 소유자 및 권한 설정" importance="중"
    local status="$STATUS_PASS" detail="" findings=""

    while IFS=: read -r user _ uid _ _ home shell; do
        [[ "$user" =~ ^# ]] && continue
        [[ -z "$uid" || -z "$home" || "$home" == "/" ]] && continue
        [[ "$shell" == "/sbin/nologin" || "$shell" == "/usr/sbin/nologin" || "$shell" == "/bin/false" ]] && continue
        (( uid < 1000 && uid != 0 )) && continue
        [[ ! -d "$home" ]] && continue

        local owner perms
        owner=$(get_file_owner "$home")
        perms=$(get_octal_perms "$home")
        local actual=$((8#${perms:-0}))

        if [[ "$owner" != "$user" ]]; then
            findings="${findings} ${home}(소유자:${owner}!=기대:${user})"
            status="$STATUS_FAIL"
        fi
        if (( (actual & ~8#755) != 0 )); then
            findings="${findings} ${home}(권한:${perms})"
            status="$STATUS_FAIL"
        fi
    done < /etc/passwd

    if [[ "$status" == "$STATUS_PASS" ]]; then
        detail="홈 디렉토리 소유자 및 권한 적절"
    else
        detail="부적절한 홈 디렉토리:${findings}"
    fi

    current="홈디렉토리:${findings:-모두적절}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

check_U32() {
    local id="U-32" category="파일 및 디렉토리 관리"
    local title="홈 디렉토리로 지정한 디렉토리의 존재 관리" importance="중"
    local status="$STATUS_PASS" detail="" findings=""

    while IFS=: read -r user _ uid _ _ home shell; do
        [[ "$user" =~ ^# ]] && continue
        [[ -z "$uid" || -z "$home" || "$home" == "/" ]] && continue
        [[ "$shell" == "/sbin/nologin" || "$shell" == "/usr/sbin/nologin" || "$shell" == "/bin/false" ]] && continue
        (( uid < 1000 && uid != 0 )) && continue

        if [[ ! -d "$home" ]]; then
            findings="${findings} ${user}(${home} 없음)"
            status="$STATUS_FAIL"
        fi
    done < /etc/passwd

    if [[ "$status" == "$STATUS_PASS" ]]; then
        detail="모든 사용자 홈 디렉토리 존재"
    else
        detail="홈 디렉토리 미존재:${findings}"
    fi

    current="홈디렉토리:${findings:-모두존재}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

check_U33() {
    local id="U-33" category="파일 및 디렉토리 관리"
    local title="숨겨진 파일 및 디렉토리 검색 및 제거" importance="하"
    local status="$STATUS_PASS" detail="" findings=""

    while IFS=: read -r user _ uid _ _ home shell; do
        [[ "$user" =~ ^# ]] && continue
        [[ -z "$uid" || -z "$home" || "$home" == "/" ]] && continue
        [[ "$shell" == "/sbin/nologin" || "$shell" == "/usr/sbin/nologin" || "$shell" == "/bin/false" ]] && continue
        (( uid < 1000 && uid != 0 )) && continue
        [[ ! -d "$home" ]] && continue

        # 의심스러운 숨김 파일 탐색 (최대 깊이 1)
        local suspicious
        suspicious=$(find "$home" -maxdepth 1 -name '.*' -type f ! -name '.bash*' ! -name '.profile' ! -name '.cshrc' ! -name '.login' ! -name '.kshrc' ! -name '.Xauthority' ! -name '.ICEauthority' ! -name '.dmrc' ! -name '.xsession*' ! -name '.cache' ! -name '.config' ! -name '.local' ! -name '.viminfo' ! -name '.lesshst' ! -name '.wget-hsts' ! -name '.gnupg' ! -name '.ssh' ! -name '.sudo_as_admin_successful' 2>/dev/null | head -5)
        if [[ -n "$suspicious" ]]; then
            findings="${findings} ${user}:$(echo "$suspicious" | tr '\n' ',')"
        fi
    done < /etc/passwd

    if [[ -n "$findings" ]]; then
        detail="의심스러운 숨김 파일 발견:${findings}"
        # 숨김 파일 존재 자체가 반드시 취약은 아니므로 정보 제공
    else
        detail="의심스러운 숨김 파일 없음"
    fi

    current="숨김파일:${findings:-없음}"
    add_result "$id" "$category" "$title" "하" "$status" "$detail" "$current"
}

# =============================================================================
# 3. 서비스 관리 (U-34 ~ U-63)
# =============================================================================

check_U34() {
    local id="U-34" category="서비스 관리"
    local title="Finger 서비스 비활성화" importance="상"
    local status="$STATUS_PASS" detail=""

    if is_service_active finger || is_process_running fingerd || is_process_running in.fingerd; then
        status="$STATUS_FAIL"
        detail="finger 서비스 활성 (systemctl/process 확인)"
    else
        detail="finger 서비스 비활성 (systemctl/process 확인)"
    fi

    current="finger서비스: ${detail}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U35() {
    local id="U-35" category="서비스 관리"
    local title="공유 서비스에 대한 익명 접근 제한 설정" importance="상"
    local status="$STATUS_PASS" detail=""

    # vsftpd anonymous
    if [[ -f /etc/vsftpd.conf ]] || [[ -f /etc/vsftpd/vsftpd.conf ]]; then
        local vconf
        for vconf in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
            [[ -f "$vconf" ]] || continue
            local anon
            anon=$(grep -v '^\s*#' "$vconf" | grep -i 'anonymous_enable' | tail -1 | awk -F= '{print $2}' | tr -d ' ')
            if [[ "${anon^^}" == "YES" ]]; then
                status="$STATUS_FAIL"
                detail="${detail}vsftpd anonymous_enable=YES; "
            fi
        done
    fi

    # NFS exports - world readable
    if [[ -f /etc/exports ]]; then
        if grep -v '^\s*#' /etc/exports | grep -q '\*\|0\.0\.0\.0'; then
            status="$STATUS_FAIL"
            detail="${detail}/etc/exports에 모든 호스트 허용; "
        fi
    fi

    # Samba guest ok
    if [[ -f /etc/samba/smb.conf ]]; then
        if grep -iv '^\s*[;#]' /etc/samba/smb.conf | grep -qi 'guest\s*ok\s*=\s*yes'; then
            status="$STATUS_FAIL"
            detail="${detail}Samba guest ok=yes; "
        fi
    fi

    [[ -z "$detail" ]] && detail="Anonymous 접근 비활성"

    current="${detail}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U36() {
    local id="U-36" category="서비스 관리"
    local title="r 계열 서비스 비활성화" importance="상"
    local status="$STATUS_PASS" detail=""

    local r_services="rlogin rsh rexec"
    local found=""
    for svc in $r_services; do
        if is_service_active "$svc" || is_process_running "in.${svc}d" || is_process_running "${svc}d"; then
            found="${found} ${svc}"
        fi
    done

    # xinetd 확인
    if [[ -d /etc/xinetd.d ]]; then
        for svc in rlogin rsh rexec; do
            if [[ -f "/etc/xinetd.d/$svc" ]]; then
                local disabled
                disabled=$(grep -v '^\s*#' "/etc/xinetd.d/$svc" | grep 'disable' | awk -F= '{print $2}' | tr -d ' ')
                if [[ "${disabled,,}" != "yes" ]]; then
                    found="${found} ${svc}(xinetd)"
                fi
            fi
        done
    fi

    if [[ -n "$found" ]]; then
        status="$STATUS_FAIL"
        detail="r 계열 서비스 활성:${found}"
    else
        detail="r 계열 서비스 비활성 (rlogin/rsh/rexec, systemctl/xinetd/process 확인)"
    fi

    current="r계열:${found:-모두비활성}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U37() {
    local id="U-37" category="서비스 관리"
    local title="crontab 설정파일 권한 설정 미흡" importance="상"
    local status="$STATUS_PASS" detail="" findings=""

    # 1) crontab/at 명령어 권한 점검 (750 이하, 소유자 root)
    for cmd in /usr/bin/crontab /usr/bin/at; do
        if [[ -f "$cmd" ]]; then
            local owner perms
            owner=$(get_file_owner "$cmd")
            perms=$(get_octal_perms "$cmd")
            local actual=$((8#$perms & 8#7777))
            # SUID 제거 후 기본 퍼미션 750 이하인지 (SUID 비트는 별도)
            local base_perm=$((actual & 8#0777))
            if [[ "$owner" != "root" ]] || (( (base_perm & ~8#750) != 0 )); then
                status="$STATUS_FAIL"
                findings="${findings} ${cmd}(${owner}:${perms})"
            fi
        fi
    done

    # 2) cron 관련 파일 권한 점검 (640 이하, 소유자 root)
    local cron_files="/etc/crontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny"
    for f in $cron_files; do
        if [[ -f "$f" ]]; then
            check_file_perm "$f" root 640
            if [[ $? -ne 0 ]]; then
                status="$STATUS_FAIL"
                findings="${findings} ${f}(${CFP_DETAIL})"
            fi
        fi
    done

    # 3) cron 디렉토리 내 파일 점검
    local cron_dirs="/etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs"
    for d in $cron_dirs; do
        [[ -d "$d" ]] || continue
        while IFS= read -r f; do
            [[ -f "$f" ]] || continue
            local owner perms
            owner=$(get_file_owner "$f")
            perms=$(get_octal_perms "$f")
            local actual=$((8#${perms:-0}))
            if [[ "$owner" != "root" ]] || (( (actual & ~8#640) != 0 )); then
                status="$STATUS_FAIL"
                findings="${findings} ${f}(${owner}:${perms})"
            fi
        done < <(find "$d" -maxdepth 1 -type f 2>/dev/null | head -20)
    done

    if [[ "$status" == "$STATUS_PASS" ]]; then
        detail="crontab/at 명령어 및 관련 파일 소유자/권한 적절"
    else
        detail="부적절:${findings}"
    fi

    current="cron점검:${findings:-모두적절}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U38() {
    local id="U-38" category="서비스 관리"
    local title="DoS 공격에 취약한 서비스 비활성화" importance="상"
    local status="$STATUS_PASS" detail=""

    local dos_services="echo discard daytime chargen"
    local found=""

    for svc in $dos_services; do
        if is_service_active "$svc" || is_process_running "$svc"; then
            found="${found} ${svc}"
        fi
        # xinetd 확인
        if [[ -f "/etc/xinetd.d/$svc" ]]; then
            local disabled
            disabled=$(grep -v '^\s*#' "/etc/xinetd.d/$svc" | grep 'disable' | awk -F= '{print $2}' | tr -d ' ')
            if [[ "${disabled,,}" != "yes" ]]; then
                found="${found} ${svc}(xinetd)"
            fi
        fi
    done

    if [[ -n "$found" ]]; then
        status="$STATUS_FAIL"
        detail="DoS 취약 서비스 활성:${found}"
    else
        detail="DoS 취약 서비스 비활성 (echo/discard/daytime/chargen, systemctl/xinetd 확인)"
    fi

    current="DoS서비스:${found:-모두비활성}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U39() {
    local id="U-39" category="서비스 관리"
    local title="불필요한 NFS 서비스 비활성화" importance="상"
    local status="$STATUS_PASS" detail=""

    if is_service_active nfs-server || is_service_active nfs || is_process_running nfsd; then
        status="$STATUS_FAIL"
        detail="NFS 서비스 활성 (systemctl/process 확인, U-40에서 접근 통제 점검)"
    else
        detail="NFS 서비스 비활성 (nfs-server/nfsd systemctl/process 확인)"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U40() {
    local id="U-40" category="서비스 관리"
    local title="NFS 접근 통제" importance="상"
    local status="$STATUS_NA" detail=""

    if ! is_service_active nfs-server && ! is_service_active nfs && ! is_process_running nfsd; then
        detail="NFS 서비스 미사용"
        current="${detail}"
        add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
        return
    fi

    status="$STATUS_PASS"
    if [[ -f /etc/exports ]]; then
        if grep -v '^\s*#' /etc/exports | grep -q '\*'; then
            status="$STATUS_FAIL"
            detail="/etc/exports에 와일드카드(*) 허용"
        elif grep -v '^\s*#' /etc/exports | grep -qi 'insecure'; then
            status="$STATUS_FAIL"
            detail="/etc/exports에 insecure 옵션 사용"
        else
            detail="/etc/exports 접근 통제 적절"
        fi
    else
        status="$STATUS_FAIL"
        detail="NFS 활성이나 /etc/exports 없음"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U41() {
    local id="U-41" category="서비스 관리"
    local title="불필요한 automountd 제거" importance="상"
    local status="$STATUS_PASS" detail=""

    if is_service_active autofs || is_process_running automountd; then
        status="$STATUS_FAIL"
        detail="autofs/automountd 서비스 활성 (systemctl/process 확인)"
    else
        detail="autofs/automountd 서비스 비활성 (systemctl/process 확인)"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U42() {
    local id="U-42" category="서비스 관리"
    local title="불필요한 RPC 서비스 비활성화" importance="상"
    local status="$STATUS_PASS" detail=""

    local rpc_services="rpc.cmsd rpc.ttdbserverd sadmind rusersd walld sprayd rstatd rpc.nisd rexd"
    local found=""
    for svc in $rpc_services; do
        if is_process_running "$svc"; then
            found="${found} ${svc}"
        fi
    done

    if [[ -n "$found" ]]; then
        status="$STATUS_FAIL"
        detail="불필요한 RPC 서비스 실행:${found}"
    else
        detail="불필요한 RPC 서비스 미실행 (rpc.cmsd/ttdbserverd/sadmind/rusersd/walld/sprayd/rstatd/nisd/rexd process 확인)"
    fi

    current="RPC서비스:${found:-모두미실행}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U43() {
    local id="U-43" category="서비스 관리"
    local title="NIS, NIS+ 점검" importance="상"
    local status="$STATUS_PASS" detail=""

    local nis_services="ypserv ypbind yppasswdd rpc.yppasswdd rpc.ypupdated"
    local found=""
    for svc in $nis_services; do
        if is_service_active "$svc" || is_process_running "$svc"; then
            found="${found} ${svc}"
        fi
    done

    if [[ -n "$found" ]]; then
        status="$STATUS_FAIL"
        detail="NIS/NIS+ 서비스 활성:${found}"
    else
        detail="NIS/NIS+ 서비스 비활성 (ypserv/ypbind/yppasswdd systemctl/process 확인)"
    fi

    current="NIS서비스:${found:-모두비활성}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U44() {
    local id="U-44" category="서비스 관리"
    local title="tftp, talk 서비스 비활성화" importance="상"
    local status="$STATUS_PASS" detail=""

    local services="tftp tftpd in.tftpd talk ntalk in.talkd"
    local found=""
    for svc in $services; do
        if is_service_active "$svc" || is_process_running "$svc"; then
            found="${found} ${svc}"
        fi
    done

    if [[ -n "$found" ]]; then
        status="$STATUS_FAIL"
        detail="tftp/talk 서비스 활성:${found}"
    else
        detail="tftp/talk 서비스 비활성 (tftp/tftpd/talk/ntalk systemctl/process 확인)"
    fi

    current="tftp/talk:${found:-모두비활성}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U45() {
    local id="U-45" category="서비스 관리"
    local title="메일 서비스 버전 점검" importance="상"
    local status="$STATUS_NA" detail=""

    if is_process_running sendmail; then
        status="$STATUS_PASS"
        local ver
        ver=$(sendmail -d0.1 -bv root 2>&1 | grep -i 'version' | head -1)
        detail="Sendmail 실행 중, 버전: ${ver:-확인불가} (최신 버전 수동 확인 필요)"
    elif is_process_running master && [[ -f /etc/postfix/main.cf ]]; then
        status="$STATUS_PASS"
        local ver
        ver=$(postconf -h mail_version 2>/dev/null)
        detail="Postfix 실행 중, 버전: ${ver:-확인불가} (최신 버전 수동 확인 필요)"
    else
        detail="메일 서비스 미사용"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U46() {
    local id="U-46" category="서비스 관리"
    local title="일반 사용자의 메일 서비스 실행 방지" importance="상"
    local status="$STATUS_NA" detail=""

    if is_process_running sendmail; then
        if [[ -f /etc/mail/sendmail.cf ]]; then
            local priv
            priv=$(grep -v '^\s*#' /etc/mail/sendmail.cf | grep -i 'PrivacyOptions' | head -1)
            if echo "$priv" | grep -qi 'restrictqrun\|goaway'; then
                status="$STATUS_PASS"
                detail="Sendmail PrivacyOptions 적절: ${priv}"
            else
                status="$STATUS_FAIL"
                detail="Sendmail PrivacyOptions 미설정 또는 부적절"
            fi
        else
            status="$STATUS_FAIL"
            detail="Sendmail 실행 중이나 sendmail.cf 없음"
        fi
    elif is_process_running master && [[ -f /etc/postfix/main.cf ]]; then
        # Postfix: 불필요한 릴레이 방지 확인
        status="$STATUS_PASS"
        detail="Postfix 사용 (Sendmail 미사용)"
    else
        detail="메일 서비스 미사용"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U47() {
    local id="U-47" category="서비스 관리"
    local title="스팸 메일 릴레이 제한" importance="상"
    local status="$STATUS_NA" detail=""

    if is_process_running sendmail && [[ -f /etc/mail/sendmail.cf ]]; then
        # Check for relay restrictions
        if grep -v '^\s*#' /etc/mail/sendmail.cf | grep -qi 'Relay'; then
            status="$STATUS_PASS"
            detail="Sendmail 릴레이 제한 설정 존재"
        else
            status="$STATUS_FAIL"
            detail="Sendmail 릴레이 제한 미설정"
        fi
    elif is_process_running master && [[ -f /etc/postfix/main.cf ]]; then
        local relay_restrict
        relay_restrict=$(postconf -h smtpd_relay_restrictions 2>/dev/null || postconf -h smtpd_recipient_restrictions 2>/dev/null)
        if [[ -n "$relay_restrict" ]]; then
            status="$STATUS_PASS"
            detail="Postfix 릴레이 제한: ${relay_restrict}"
        else
            status="$STATUS_FAIL"
            detail="Postfix 릴레이 제한 미설정"
        fi
    else
        detail="메일 서비스 미사용"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U48() {
    local id="U-48" category="서비스 관리"
    local title="expn, vrfy 명령어 제한" importance="중"
    local status="$STATUS_NA" detail=""

    if is_process_running sendmail && [[ -f /etc/mail/sendmail.cf ]]; then
        local priv
        priv=$(grep -v '^\s*#' /etc/mail/sendmail.cf | grep -i 'PrivacyOptions' | head -1)
        if echo "$priv" | grep -qi 'noexpn' && echo "$priv" | grep -qi 'novrfy'; then
            status="$STATUS_PASS"
            detail="expn/vrfy 비활성: ${priv}"
        else
            status="$STATUS_FAIL"
            detail="expn/vrfy 활성 상태: ${priv:-미설정}"
        fi
    elif is_process_running master && [[ -f /etc/postfix/main.cf ]]; then
        local vrfy
        vrfy=$(postconf -h disable_vrfy_command 2>/dev/null)
        if [[ "${vrfy,,}" == "yes" ]]; then
            status="$STATUS_PASS"
            detail="Postfix disable_vrfy_command=yes"
        else
            status="$STATUS_FAIL"
            detail="Postfix disable_vrfy_command=${vrfy:-미설정}"
        fi
    else
        detail="메일 서비스 미사용"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

check_U49() {
    local id="U-49" category="서비스 관리"
    local title="DNS 보안 버전 패치" importance="상"
    local status="$STATUS_NA" detail=""

    if is_process_running named; then
        local ver
        ver=$(named -v 2>/dev/null | head -1)
        status="$STATUS_PASS"
        detail="BIND 실행 중, 버전: ${ver:-확인불가} (최신 패치 수동 확인 필요)"
    else
        detail="DNS 서비스 미사용"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U50() {
    local id="U-50" category="서비스 관리"
    local title="DNS Zone Transfer 설정" importance="상"
    local status="$STATUS_NA" detail=""

    if ! is_process_running named; then
        detail="DNS 서비스 미사용"
        current="${detail}"
        add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
        return
    fi

    status="$STATUS_PASS"
    local named_conf=""
    for f in /etc/named.conf /etc/bind/named.conf /etc/named/named.conf; do
        [[ -f "$f" ]] && named_conf="$f" && break
    done

    if [[ -z "$named_conf" ]]; then
        status="$STATUS_FAIL"
        detail="DNS 실행 중이나 named.conf 미발견"
    else
        if grep -v '^\s*[#/]' "$named_conf" | grep -qi 'allow-transfer'; then
            local at
            at=$(grep -v '^\s*[#/]' "$named_conf" | grep -i 'allow-transfer' | head -1)
            if echo "$at" | grep -q 'any'; then
                status="$STATUS_FAIL"
                detail="Zone Transfer 제한 없음 (allow-transfer any)"
            else
                detail="Zone Transfer 제한 설정: ${at}"
            fi
        else
            status="$STATUS_FAIL"
            detail="allow-transfer 미설정 (기본 허용)"
        fi
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U51() {
    local id="U-51" category="서비스 관리"
    local title="DNS 서비스의 취약한 동적 업데이트 설정 금지" importance="중"
    local status="$STATUS_NA" detail=""

    if ! is_process_running named; then
        detail="DNS 서비스 미사용"
        current="${detail}"
        add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
        return
    fi

    status="$STATUS_PASS"
    local named_conf=""
    for f in /etc/named.conf /etc/bind/named.conf /etc/named/named.conf; do
        [[ -f "$f" ]] && named_conf="$f" && break
    done

    if [[ -z "$named_conf" ]]; then
        detail="DNS 실행 중이나 named.conf 미발견"
    else
        if grep -v '^\s*[#/]' "$named_conf" | grep -qi 'allow-update'; then
            local au
            au=$(grep -v '^\s*[#/]' "$named_conf" | grep -i 'allow-update' | head -1)
            if echo "$au" | grep -q 'any'; then
                status="$STATUS_FAIL"
                detail="동적 업데이트 제한 없음 (allow-update any)"
            else
                detail="동적 업데이트 제한 설정: ${au}"
            fi
        else
            detail="allow-update 미설정 (기본 비허용)"
        fi
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

check_U52() {
    local id="U-52" category="서비스 관리"
    local title="Telnet 서비스 비활성화" importance="중"
    local status="$STATUS_PASS" detail=""

    if is_service_active telnet || is_process_running in.telnetd || is_process_running telnetd; then
        status="$STATUS_FAIL"
        detail="Telnet 서비스 활성 (systemctl/process 확인)"
    elif grep -v '^\s*#' /etc/inetd.conf 2>/dev/null | grep -qiE '^\s*telnet'; then
        status="$STATUS_FAIL"
        detail="Telnet 서비스 활성 (inetd.conf 등록)"
    elif ss -tlnp 2>/dev/null | grep -q ':23\b'; then
        status="$STATUS_FAIL"
        detail="Telnet 서비스 활성 (포트 23 리스닝)"
    else
        detail="Telnet 서비스 비활성 (systemctl/process/inetd 확인)"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

check_U53() {
    local id="U-53" category="서비스 관리"
    local title="FTP 서비스 정보 노출 제한" importance="하"
    local status="$STATUS_NA" detail=""

    # vsftpd 배너 확인
    local ftp_active=0
    for vconf in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
        [[ -f "$vconf" ]] || continue
        ftp_active=1
        local banner
        banner=$(grep -v '^\s*#' "$vconf" | grep -i 'ftpd_banner' | awk -F= '{print $2}')
        if [[ -n "$banner" ]]; then
            status="$STATUS_PASS"
            detail="vsftpd 배너 설정됨"
        else
            status="$STATUS_FAIL"
            detail="vsftpd 배너 미설정 (기본 버전 정보 노출 가능)"
        fi
    done

    # proftpd 확인
    if [[ -f /etc/proftpd/proftpd.conf ]] || [[ -f /etc/proftpd.conf ]]; then
        ftp_active=1
        local pconf
        for pconf in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
            [[ -f "$pconf" ]] || continue
            if grep -v '^\s*#' "$pconf" | grep -qi 'ServerName'; then
                status="$STATUS_PASS"
                detail="${detail:+${detail}; }ProFTPD ServerName 설정됨"
            fi
        done
    fi

    if [[ $ftp_active -eq 0 ]]; then
        detail="FTP 서비스 미사용"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "하" "$status" "$detail" "$current"
}

check_U54() {
    local id="U-54" category="서비스 관리"
    local title="암호화되지 않는 FTP 서비스 비활성화" importance="중"
    local status="$STATUS_PASS" detail=""

    if is_service_active vsftpd || is_service_active proftpd || is_service_active pure-ftpd || \
       is_process_running vsftpd || is_process_running proftpd || is_process_running pure-ftpd; then
        status="$STATUS_FAIL"
        detail="FTP 서비스 활성 (vsftpd/proftpd/pure-ftpd systemctl/process 확인)"
    else
        detail="FTP 서비스 비활성 (vsftpd/proftpd/pure-ftpd systemctl/process 확인)"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

check_U55() {
    local id="U-55" category="서비스 관리"
    local title="FTP 계정 Shell 제한" importance="중"
    local status="$STATUS_NA" detail=""

    if ! is_service_active vsftpd && ! is_process_running vsftpd && \
       ! is_service_active proftpd && ! is_process_running proftpd; then
        detail="FTP 서비스 미사용"
        current="ftp계정쉘=서비스미사용(미점검)"
        add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
        return
    fi

    # ftp 계정 쉘 확인
    local ftp_shell
    ftp_shell=$(awk -F: '$1=="ftp" {print $7}' /etc/passwd 2>/dev/null)
    if [[ -n "$ftp_shell" ]]; then
        if [[ "$ftp_shell" == "/sbin/nologin" || "$ftp_shell" == "/usr/sbin/nologin" || "$ftp_shell" == "/bin/false" ]]; then
            status="$STATUS_PASS"
            detail="ftp 계정 쉘: ${ftp_shell}"
        else
            status="$STATUS_FAIL"
            detail="ftp 계정에 로그인 쉘 부여: ${ftp_shell}"
        fi
    else
        status="$STATUS_PASS"
        detail="ftp 계정 없음"
    fi

    current="ftp계정쉘=${ftp_shell:-계정없음}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

check_U56() {
    local id="U-56" category="서비스 관리"
    local title="FTP 서비스 접근 제어 설정" importance="하"
    local status="$STATUS_NA" detail=""

    if ! is_service_active vsftpd && ! is_process_running vsftpd && \
       ! is_service_active proftpd && ! is_process_running proftpd; then
        detail="FTP 서비스 미사용"
        current="${detail}"
        add_result "$id" "$category" "$title" "하" "$status" "$detail" "$current"
        return
    fi

    status="$STATUS_FAIL"
    # vsftpd tcp_wrappers
    for vconf in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
        [[ -f "$vconf" ]] || continue
        local tw
        tw=$(grep -v '^\s*#' "$vconf" | grep -i 'tcp_wrappers' | awk -F= '{print $2}' | tr -d ' ')
        if [[ "${tw^^}" == "YES" ]]; then
            status="$STATUS_PASS"
            detail="vsftpd tcp_wrappers=YES"
        fi
    done

    # hosts.allow 확인
    if [[ -f /etc/hosts.allow ]]; then
        if grep -v '^\s*#' /etc/hosts.allow | grep -qi 'vsftpd\|proftpd\|ftpd'; then
            status="$STATUS_PASS"
            detail="${detail:+${detail}; }hosts.allow에 FTP 접근 제어 설정"
        fi
    fi

    [[ "$status" == "$STATUS_FAIL" ]] && detail="FTP 접근 제어 미설정"

    current="${detail}"
    add_result "$id" "$category" "$title" "하" "$status" "$detail" "$current"
}

check_U57() {
    local id="U-57" category="서비스 관리"
    local title="Ftpusers 파일 설정" importance="중"
    local status="$STATUS_NA" detail=""

    if ! is_service_active vsftpd && ! is_process_running vsftpd && \
       ! is_service_active proftpd && ! is_process_running proftpd; then
        detail="FTP 서비스 미사용"
        current="${detail}"
        add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
        return
    fi

    status="$STATUS_FAIL"
    for f in /etc/vsftpd/ftpusers /etc/ftpusers /etc/vsftpd.ftpusers; do
        if [[ -f "$f" ]]; then
            if grep -q '^root$' "$f" 2>/dev/null; then
                status="$STATUS_PASS"
                detail="root가 ${f}에 등록됨 (FTP 접속 제한)"
                break
            else
                detail="root가 ${f}에 미등록"
            fi
        fi
    done

    [[ "$status" == "$STATUS_FAIL" && -z "$detail" ]] && detail="ftpusers 파일 없음"

    current="${detail}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

check_U58() {
    local id="U-58" category="서비스 관리"
    local title="불필요한 SNMP 서비스 구동 점검" importance="중"
    local status="$STATUS_PASS" detail=""

    if is_service_active snmpd || is_process_running snmpd; then
        status="$STATUS_FAIL"
        detail="SNMP 서비스 활성 (systemctl/process 확인, 불필요 시 비활성화 권고)"
    else
        detail="SNMP 서비스 비활성 (systemctl/process 확인)"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

check_U59() {
    local id="U-59" category="서비스 관리"
    local title="안전한 SNMP 버전 사용" importance="상"
    local status="$STATUS_NA" detail=""

    if ! is_service_active snmpd && ! is_process_running snmpd; then
        detail="SNMP 서비스 미사용"
        current="${detail}"
        add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
        return
    fi

    # 양호: SNMPv3 사용, 취약: v2 이하 사용
    status="$STATUS_FAIL"
    if [[ -f /etc/snmp/snmpd.conf ]]; then
        # SNMPv3 사용 여부 확인 (createUser, rouser, rwuser 설정)
        if grep -v '^\s*#' /etc/snmp/snmpd.conf | grep -qiE '^\s*(createUser|rouser|rwuser)'; then
            status="$STATUS_PASS"
            detail="SNMPv3 인증 설정 확인됨"
        else
            detail="SNMPv1/v2c 사용 중 (SNMPv3 미설정)"
        fi
    else
        detail="snmpd.conf 없음 (설정 확인 불가)"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U60() {
    local id="U-60" category="서비스 관리"
    local title="SNMP Community String 복잡성 설정" importance="중"
    local status="$STATUS_NA" detail=""

    if ! is_service_active snmpd && ! is_process_running snmpd; then
        detail="SNMP 서비스 미사용"
        current="${detail}"
        add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
        return
    fi

    status="$STATUS_PASS"
    if [[ -f /etc/snmp/snmpd.conf ]]; then
        # v2c community string 먼저 확인 (SNMPv3 병용 시에도 취약한 community 존재하면 취약)
        local communities
        communities=$(grep -v '^\s*#' /etc/snmp/snmpd.conf | grep -E '^\s*(rocommunity|rwcommunity)' | awk '{print $2}')
        if [[ -n "$communities" ]]; then
            local weak=0 weak_detail=""
            while IFS= read -r comm; do
                [[ -z "$comm" ]] && continue
                # 기본값 체크
                if [[ "$comm" == "public" || "$comm" == "private" ]]; then
                    weak=1
                    weak_detail="기본값(${comm}) 사용"
                # 복잡성 체크: 영문+숫자+특수 8자 이상 또는 영문+숫자 10자 이상
                elif (( ${#comm} < 8 )); then
                    weak=1
                    weak_detail="community string 길이 부족(${#comm}자)"
                fi
            done <<< "$communities"
            if [[ $weak -eq 1 ]]; then
                status="$STATUS_FAIL"
                detail="${weak_detail}"
            else
                detail="community string 복잡성 적절"
            fi
        elif grep -v '^\s*#' /etc/snmp/snmpd.conf | grep -qiE '^\s*(createUser|rouser|rwuser)'; then
            # community 미사용, SNMPv3 전용 → 양호
            detail="SNMPv3 전용 사용 (별도 인증)"
        else
            detail="community string 미설정"
        fi
    else
        detail="snmpd.conf 없음"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

check_U61() {
    local id="U-61" category="서비스 관리"
    local title="SNMP Access Control 설정" importance="상"
    local status="$STATUS_NA" detail=""

    if ! is_service_active snmpd && ! is_process_running snmpd; then
        detail="SNMP 서비스 미사용"
        current="${detail}"
        add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
        return
    fi

    status="$STATUS_FAIL"
    if [[ -f /etc/snmp/snmpd.conf ]]; then
        if grep -v '^\s*#' /etc/snmp/snmpd.conf | grep -qE '^\s*(com2sec|view|access|rouser|rwuser)'; then
            status="$STATUS_PASS"
            detail="SNMP 접근 제어 설정 존재"
        else
            detail="SNMP 접근 제어 미설정"
        fi
    else
        detail="snmpd.conf 없음"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

check_U62() {
    local id="U-62" category="서비스 관리"
    local title="로그인 시 경고 메시지 설정" importance="하"
    local status="$STATUS_FAIL" detail=""

    local banner_found=0
    for f in /etc/motd /etc/issue /etc/issue.net; do
        if [[ -f "$f" ]]; then
            local content
            content=$(cat "$f" 2>/dev/null | head -5 | tr -d '\n')
            if [[ -n "$content" && ${#content} -gt 3 ]]; then
                banner_found=1
                detail="${detail}${f} 설정됨; "
            fi
        fi
    done

    # SSH Banner 확인
    local ssh_banner
    ssh_banner="$(get_sshd_config_value Banner)"
    if [[ -n "$ssh_banner" && "$ssh_banner" != "none" ]]; then
        banner_found=1
        detail="${detail}SSH Banner=${ssh_banner}; "
    fi

    if [[ $banner_found -eq 1 ]]; then
        status="$STATUS_PASS"
    else
        detail="로그인 경고 메시지 미설정 (/etc/motd, /etc/issue, /etc/issue.net 모두 비어 있거나 없음)"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "하" "$status" "$detail" "$current"
}

check_U63() {
    local id="U-63" category="서비스 관리"
    local title="sudo 명령어 접근 관리" importance="중"
    local status="$STATUS_PASS" detail=""

    # 양호: /etc/sudoers 소유자가 root이고, 권한이 640인 경우
    if [[ ! -f /etc/sudoers ]]; then
        status="$STATUS_NA"
        detail="/etc/sudoers 파일 없음"
        current="/etc/sudoers 소유자=N/A 권한=N/A (파일없음)"
        add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
        return
    fi

    local owner perms
    owner="$(get_file_owner /etc/sudoers)"
    perms="$(get_octal_perms /etc/sudoers)"

    if [[ "$owner" != "root" ]]; then
        status="$STATUS_FAIL"
    fi

    local actual=$((8#${perms:-0}))
    local max=$((8#640))
    if (( (actual & ~max) != 0 )); then
        status="$STATUS_FAIL"
    fi

    detail="/etc/sudoers 소유자: ${owner}, 권한: ${perms} (기준: root, 640 이하)"
    current="/etc/sudoers 소유자=${owner:-N/A} 권한=${perms:-N/A}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

# =============================================================================
# 4. 패치 관리 (U-64)
# =============================================================================

check_U64() {
    local id="U-64" category="패치 관리"
    local title="주기적 보안 패치 및 벤더 권고사항 적용" importance="상"
    local status="$STATUS_FAIL" detail=""

    local now_epoch
    now_epoch=$(date +%s)
    local days_threshold=90
    local threshold_epoch=$(( now_epoch - days_threshold * 86400 ))
    local last_update_date=""

    case "$OS_FAMILY" in
        rhel)
            # dnf/yum 로그 확인
            for logf in /var/log/dnf.log /var/log/yum.log; do
                [[ -f "$logf" ]] || continue
                local last_line
                last_line=$(grep -i 'install\|update\|upgrade' "$logf" 2>/dev/null | tail -1)
                if [[ -n "$last_line" ]]; then
                    # Extract date from log
                    local log_date
                    log_date=$(echo "$last_line" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1)
                    [[ -z "$log_date" ]] && log_date=$(echo "$last_line" | grep -oE '^[A-Z][a-z]{2}[[:space:]]+[0-9]+' | head -1)
                    if [[ -n "$log_date" ]]; then
                        last_update_date="$log_date"
                        local update_epoch
                        update_epoch=$(date -d "$log_date" +%s 2>/dev/null)
                        if [[ -n "$update_epoch" ]] && (( update_epoch >= threshold_epoch )); then
                            status="$STATUS_PASS"
                        fi
                    fi
                fi
            done
            # rpm 마지막 설치일
            if [[ "$status" == "$STATUS_FAIL" ]]; then
                local rpm_last
                rpm_last=$(rpm -qa --last 2>/dev/null | head -1 | awk '{print $2,$3,$4,$5}')
                if [[ -n "$rpm_last" ]]; then
                    local rpm_epoch
                    rpm_epoch=$(date -d "$rpm_last" +%s 2>/dev/null)
                    if [[ -n "$rpm_epoch" ]] && (( rpm_epoch >= threshold_epoch )); then
                        status="$STATUS_PASS"
                        last_update_date="$rpm_last"
                    fi
                fi
            fi
            ;;
        debian)
            # apt history.log
            if [[ -f /var/log/apt/history.log ]]; then
                local last_line
                last_line=$(grep '^Start-Date:' /var/log/apt/history.log 2>/dev/null | tail -1)
                if [[ -n "$last_line" ]]; then
                    local log_date
                    log_date=$(echo "$last_line" | awk '{print $2}')
                    last_update_date="$log_date"
                    local update_epoch
                    update_epoch=$(date -d "$log_date" +%s 2>/dev/null)
                    if [[ -n "$update_epoch" ]] && (( update_epoch >= threshold_epoch )); then
                        status="$STATUS_PASS"
                    fi
                fi
            fi
            # dpkg.log fallback
            if [[ "$status" == "$STATUS_FAIL" && -f /var/log/dpkg.log ]]; then
                local last_line
                last_line=$(grep ' install \| upgrade ' /var/log/dpkg.log 2>/dev/null | tail -1)
                if [[ -n "$last_line" ]]; then
                    local log_date
                    log_date=$(echo "$last_line" | awk '{print $1}')
                    last_update_date="$log_date"
                    local update_epoch
                    update_epoch=$(date -d "$log_date" +%s 2>/dev/null)
                    if [[ -n "$update_epoch" ]] && (( update_epoch >= threshold_epoch )); then
                        status="$STATUS_PASS"
                    fi
                fi
            fi
            ;;
        suse)
            # zypper.log
            if [[ -f /var/log/zypper.log ]]; then
                local last_line
                last_line=$(grep -i 'install\|update' /var/log/zypper.log 2>/dev/null | tail -1)
                if [[ -n "$last_line" ]]; then
                    local log_date
                    log_date=$(echo "$last_line" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -1)
                    if [[ -n "$log_date" ]]; then
                        last_update_date="$log_date"
                        local update_epoch
                        update_epoch=$(date -d "$log_date" +%s 2>/dev/null)
                        if [[ -n "$update_epoch" ]] && (( update_epoch >= threshold_epoch )); then
                            status="$STATUS_PASS"
                        fi
                    fi
                fi
            fi
            ;;
    esac

    if [[ "$status" == "$STATUS_PASS" ]]; then
        detail="마지막 패키지 업데이트: ${last_update_date} (${days_threshold}일 이내)"
    else
        if [[ -n "$last_update_date" ]]; then
            detail="마지막 패키지 업데이트: ${last_update_date} (${days_threshold}일 초과)"
        else
            detail="패키지 업데이트 이력 확인 불가"
        fi
    fi

    current="OS=${OS_FAMILY}; 마지막업데이트=${last_update_date:-확인불가}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

# =============================================================================
# 5. 로그 관리 (U-65 ~ U-67)
# =============================================================================

check_U65() {
    local id="U-65" category="로그 관리"
    local title="NTP 및 시각 동기화 설정" importance="중"
    local status="$STATUS_FAIL" detail=""

    # chronyd or ntpd
    if is_service_active chronyd || is_process_running chronyd; then
        status="$STATUS_PASS"
        detail="chronyd 서비스 활성"
        if [[ -f /etc/chrony.conf ]] || [[ -f /etc/chrony/chrony.conf ]]; then
            local server_count=0
            for cf in /etc/chrony.conf /etc/chrony/chrony.conf; do
                [[ -f "$cf" ]] || continue
                server_count=$(grep -c -E '^\s*(server|pool)\s' "$cf" 2>/dev/null || echo 0)
            done
            detail="${detail}, NTP 서버 ${server_count}개 설정"
        fi
    elif is_service_active ntpd || is_process_running ntpd; then
        status="$STATUS_PASS"
        detail="ntpd 서비스 활성"
        if [[ -f /etc/ntp.conf ]]; then
            local server_count
            server_count=$(grep -c -E '^\s*server\s' /etc/ntp.conf 2>/dev/null || echo 0)
            detail="${detail}, NTP 서버 ${server_count}개 설정"
        fi
    elif command -v timedatectl &>/dev/null; then
        local ntp_sync
        ntp_sync=$(timedatectl 2>/dev/null | grep -i 'NTP\|synchronized\|시간 동기화' | head -1)
        if echo "$ntp_sync" | grep -qi 'yes\|active'; then
            status="$STATUS_PASS"
            detail="systemd-timesyncd 활성: ${ntp_sync}"
        else
            detail="시간 동기화 비활성"
        fi
    else
        detail="NTP/시각 동기화 서비스 미설정"
    fi

    current="${detail}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

check_U66() {
    local id="U-66" category="로그 관리"
    local title="정책에 따른 시스템 로깅 설정" importance="중"
    local status="$STATUS_FAIL" detail=""

    local syslog_conf=""
    for f in /etc/rsyslog.conf /etc/syslog.conf; do
        [[ -f "$f" ]] && syslog_conf="$f" && break
    done

    if [[ -z "$syslog_conf" ]]; then
        detail="rsyslog.conf/syslog.conf 없음"
        current="설정파일=없음; 설정룰:점검불가; 미설정:점검불가"
        add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
        return
    fi

    local required_facilities="authpriv cron"
    local missing="" found=""

    for fac in $required_facilities; do
        if grep -v '^\s*#' "$syslog_conf" | grep -q "${fac}\.\*"; then
            found="${found} ${fac}"
        else
            missing="${missing} ${fac}"
        fi
    done

    # *.emerg 확인
    if grep -v '^\s*#' "$syslog_conf" | grep -q '\*\.emerg'; then
        found="${found} *.emerg"
    else
        missing="${missing} *.emerg"
    fi

    if [[ -z "$missing" ]]; then
        status="$STATUS_PASS"
        detail="필수 로깅 룰 설정됨: ${found}"
    else
        detail="미설정 로깅 룰:${missing} (설정됨:${found})"
    fi

    current="설정파일=${syslog_conf:-없음}; 설정룰:${found:-없음}; 미설정:${missing:-없음}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

check_U67() {
    local id="U-67" category="로그 관리"
    local title="로그 디렉터리 소유자 및 권한 설정" importance="중"
    local status="$STATUS_PASS" detail="" findings=""

    if [[ ! -d /var/log ]]; then
        current="로그파일:점검불가(/var/log없음)"
        add_result "$id" "$category" "$title" "중" "$STATUS_FAIL" "/var/log 디렉토리 없음" "$current"
        return
    fi

    # /var/log 내 주요 로그 파일의 소유자=root, 권한 644 이하 점검
    local log_files="syslog messages secure auth.log kern.log cron maillog boot.log dmesg wtmp lastlog"
    local checked=0
    for lf in $log_files; do
        local fp="/var/log/${lf}"
        [[ -f "$fp" ]] || continue
        checked=1
        local owner perms
        owner="$(get_file_owner "$fp")"
        perms="$(get_octal_perms "$fp")"
        local actual=$((8#${perms:-0}))
        local max=$((8#644))
        if [[ "$owner" != "root" ]] || (( (actual & ~max) != 0 )); then
            status="$STATUS_FAIL"
            findings="${findings} ${lf}(${owner}:${perms})"
        fi
    done

    if [[ $checked -eq 0 ]]; then
        detail="/var/log 내 주요 로그 파일 없음"
    elif [[ "$status" == "$STATUS_PASS" ]]; then
        detail="/var/log 내 로그 파일 소유자/권한 적절"
    else
        detail="부적절한 로그 파일:${findings} (기준: root, 644 이하)"
    fi

    current="로그파일:${findings:-모두적절}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

# =============================================================================
# 6. 웹 서비스 보안 (W-01 ~ W-11)
# =============================================================================

check_W01() {
    local id="W-01" category="웹 서비스 보안"
    local title="웹 서비스 디렉터리 쓰기 권한 관리" importance="상"
    local status="$STATUS_NA" detail=""

    if [[ $APACHE_INSTALLED -eq 0 && $NGINX_INSTALLED -eq 0 && $TOMCAT_INSTALLED -eq 0 ]]; then
        current="DocumentRoot:웹서버 미설치"
        detail="웹서버 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    for d in "$APACHE_DOCROOT" "$NGINX_ROOT" "${TOMCAT_HOME}/webapps"; do
        [[ -d "$d" ]] || continue
        local perms; perms=$(get_octal_perms "$d")
        local actual=$((8#${perms:-777}))
        if (( (actual & ~8#755) != 0 )); then
            status="$STATUS_FAIL"
            findings="${findings} ${d}(${perms})"
        else
            findings="${findings} ${d}(${perms},양호)"
        fi
    done
    detail="DocumentRoot 권한:${findings:- 점검 대상 없음}"
    current="DocumentRoot:${findings:-점검대상없음}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_W02() {
    local id="W-02" category="웹 서비스 보안"
    local title="웹 서비스 소스/설정파일 권한 관리" importance="상"
    local status="$STATUS_NA" detail=""

    if [[ $APACHE_INSTALLED -eq 0 && $NGINX_INSTALLED -eq 0 && $TOMCAT_INSTALLED -eq 0 ]]; then
        current="설정파일:웹서버 미설치"
        detail="웹서버 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    # 설정파일 640 이하
    for f in "$APACHE_CONF" "$NGINX_CONF" "$TOMCAT_CONF"; do
        [[ -f "$f" ]] || continue
        local perms; perms=$(get_octal_perms "$f")
        local actual=$((8#${perms:-777}))
        if (( (actual & ~8#640) != 0 )); then
            status="$STATUS_FAIL"
            findings="${findings} ${f}(${perms},기준:640이하)"
        else
            findings="${findings} ${f}(${perms},양호)"
        fi
    done
    detail="설정파일 권한:${findings:- 점검 대상 없음}"
    current="설정파일:${findings:-점검대상없음}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_W03() {
    local id="W-03" category="웹 서비스 보안"
    local title="웹 서비스 파일 업로드 및 다운로드 제한" importance="상"
    local status="$STATUS_NA" detail=""

    if [[ $APACHE_INSTALLED -eq 0 && $NGINX_INSTALLED -eq 0 ]]; then
        current="Apache/Nginx 미설치"
        detail="Apache/Nginx 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_FAIL"; local findings=""
    if [[ -n "$APACHE_CONF" ]]; then
        local lrb
        lrb=$(grep -rh -v '^\s*#' "$APACHE_CONF" /etc/httpd/conf.d/*.conf /etc/apache2/conf-enabled/*.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -i 'LimitRequestBody' | head -1 | awk '{print $2}')
        if [[ -n "$lrb" ]]; then
            status="$STATUS_PASS"
            findings="${findings} Apache LimitRequestBody=${lrb}"
        else
            findings="${findings} Apache LimitRequestBody 미설정"
        fi
    fi
    if [[ -n "$NGINX_CONF" ]]; then
        local cms
        cms=$(grep -rh -v '^\s*#' "$NGINX_CONF" /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null | grep -i 'client_max_body_size' | head -1 | awk '{print $2}' | tr -d ';')
        if [[ -n "$cms" ]]; then
            [[ "$status" != "$STATUS_PASS" ]] && status="$STATUS_PASS"
            findings="${findings} Nginx client_max_body_size=${cms}"
        else
            findings="${findings} Nginx client_max_body_size 미설정"
        fi
    fi
    detail="업로드 제한:${findings:-설정확인불가}"
    current="${findings:-설정확인불가}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_W04() {
    local id="W-04" category="웹 서비스 보안"
    local title="웹 서비스 상위 디렉터리 접근 금지" importance="상"
    local status="$STATUS_NA" detail=""

    if [[ $APACHE_INSTALLED -eq 0 && $NGINX_INSTALLED -eq 0 ]]; then
        current="Apache/Nginx 미설치"
        detail="Apache/Nginx 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    if [[ -n "$APACHE_CONF" ]]; then
        local ao
        ao=$(grep -rh -v '^\s*#' "$APACHE_CONF" /etc/httpd/conf.d/*.conf /etc/apache2/conf-enabled/*.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -i 'AllowOverride' | head -3)
        if echo "$ao" | grep -qiw 'All'; then
            status="$STATUS_FAIL"
            findings="${findings} Apache AllowOverride All 설정 존재"
        else
            findings="${findings} Apache AllowOverride 적절"
        fi
    fi
    detail="상위 디렉터리 접근:${findings:-설정확인불가}"
    current="${findings:-설정확인불가}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_W05() {
    local id="W-05" category="웹 서비스 보안"
    local title="웹 서비스 정보 숨김" importance="상"
    local status="$STATUS_NA" detail=""

    if [[ $APACHE_INSTALLED -eq 0 && $NGINX_INSTALLED -eq 0 ]]; then
        current="Apache/Nginx 미설치"
        detail="Apache/Nginx 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    if [[ -n "$APACHE_CONF" ]]; then
        local st ss
        st=$(grep -rh -v '^\s*#' "$APACHE_CONF" /etc/httpd/conf.d/*.conf /etc/apache2/conf-enabled/*.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -i 'ServerTokens' | tail -1 | awk '{print $2}')
        ss=$(grep -rh -v '^\s*#' "$APACHE_CONF" /etc/httpd/conf.d/*.conf /etc/apache2/conf-enabled/*.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -i 'ServerSignature' | tail -1 | awk '{print $2}')
        findings="${findings} Apache ServerTokens=${st:-미설정}, ServerSignature=${ss:-미설정}"
        if [[ "${st,,}" != "prod" && "${st,,}" != "productonly" ]] || [[ "${ss,,}" != "off" ]]; then
            status="$STATUS_FAIL"
        fi
    fi
    if [[ -n "$NGINX_CONF" ]]; then
        local stk
        stk=$(grep -rh -v '^\s*#' "$NGINX_CONF" /etc/nginx/conf.d/*.conf 2>/dev/null | grep -i 'server_tokens' | tail -1 | awk '{print $2}' | tr -d ';')
        findings="${findings}; Nginx server_tokens=${stk:-미설정}"
        if [[ "${stk,,}" != "off" ]]; then
            status="$STATUS_FAIL"
        fi
    fi
    detail="서버 정보:${findings:-설정확인불가}"
    current="${findings:-설정확인불가}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_W06() {
    local id="W-06" category="웹 서비스 보안"
    local title="웹 서비스 링크 사용금지" importance="상"
    local status="$STATUS_NA" detail=""

    if [[ $APACHE_INSTALLED -eq 0 && $NGINX_INSTALLED -eq 0 ]]; then
        current="Apache/Nginx 미설치"
        detail="Apache/Nginx 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    if [[ -n "$APACHE_CONF" ]]; then
        local opts
        opts=$(grep -rh -v '^\s*#' "$APACHE_CONF" /etc/httpd/conf.d/*.conf /etc/apache2/conf-enabled/*.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -i '^\s*Options' | head -5)
        if echo "$opts" | grep -qi 'FollowSymLinks' && ! echo "$opts" | grep -qi '\-FollowSymLinks'; then
            status="$STATUS_FAIL"
            findings="${findings} Apache FollowSymLinks 활성"
        else
            findings="${findings} Apache FollowSymLinks 비활성 또는 -FollowSymLinks"
        fi
    fi
    detail="심볼릭 링크:${findings:-설정확인불가}"
    current="${findings:-설정확인불가}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_W07() {
    local id="W-07" category="웹 서비스 보안"
    local title="웹 서비스 CGI 스크립트 실행 제한" importance="상"
    local status="$STATUS_NA" detail=""

    if [[ $APACHE_INSTALLED -eq 0 ]]; then
        current="Apache 미설치"
        detail="Apache 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    local opts
    opts=$(grep -rh -v '^\s*#' "$APACHE_CONF" /etc/httpd/conf.d/*.conf /etc/apache2/conf-enabled/*.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -i '^\s*Options' | head -5)
    if echo "$opts" | grep -qi 'ExecCGI' && ! echo "$opts" | grep -qi '\-ExecCGI'; then
        status="$STATUS_FAIL"
        findings="Apache ExecCGI 활성"
    else
        findings="Apache ExecCGI 비활성 또는 -ExecCGI"
    fi
    detail="CGI 설정: ${findings}"
    current="${findings}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_W08() {
    local id="W-08" category="웹 서비스 보안"
    local title="웹 서비스 디렉터리 리스팅 제거" importance="상"
    local status="$STATUS_NA" detail=""

    if [[ $APACHE_INSTALLED -eq 0 && $NGINX_INSTALLED -eq 0 ]]; then
        current="Apache/Nginx 미설치"
        detail="Apache/Nginx 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    if [[ -n "$APACHE_CONF" ]]; then
        local opts
        opts=$(grep -rh -v '^\s*#' "$APACHE_CONF" /etc/httpd/conf.d/*.conf /etc/apache2/conf-enabled/*.conf /etc/apache2/sites-enabled/*.conf 2>/dev/null | grep -i '^\s*Options' | head -5)
        if echo "$opts" | grep -qi 'Indexes' && ! echo "$opts" | grep -qi '\-Indexes'; then
            status="$STATUS_FAIL"
            findings="${findings} Apache Indexes 활성"
        else
            findings="${findings} Apache Indexes 비활성 또는 -Indexes"
        fi
    fi
    if [[ -n "$NGINX_CONF" ]]; then
        local ai
        ai=$(grep -rh -v '^\s*#' "$NGINX_CONF" /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null | grep -i 'autoindex' | tail -1 | awk '{print $2}' | tr -d ';')
        findings="${findings}; Nginx autoindex=${ai:-미설정(기본off)}"
        if [[ "${ai,,}" == "on" ]]; then
            status="$STATUS_FAIL"
        fi
    fi
    detail="디렉터리 리스팅:${findings:-설정확인불가}"
    current="${findings:-설정확인불가}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_W09() {
    local id="W-09" category="웹 서비스 보안"
    local title="서비스 영역의 분리" importance="상"
    local status="$STATUS_NA" detail=""

    if [[ $APACHE_INSTALLED -eq 0 && $NGINX_INSTALLED -eq 0 ]]; then
        current="Apache/Nginx 미설치"
        detail="Apache/Nginx 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    local default_dirs="/var/www/html /usr/share/nginx/html /var/www /srv/www"
    if [[ -n "$APACHE_DOCROOT" ]]; then
        local is_default=0
        for dd in $default_dirs; do
            [[ "$APACHE_DOCROOT" == "$dd" ]] && is_default=1
        done
        if [[ $is_default -eq 1 ]]; then
            status="$STATUS_FAIL"
            findings="${findings} Apache DocumentRoot=${APACHE_DOCROOT}(OS 기본 디렉토리)"
        else
            findings="${findings} Apache DocumentRoot=${APACHE_DOCROOT}(분리됨)"
        fi
    fi
    if [[ -n "$NGINX_ROOT" ]]; then
        local is_default=0
        for dd in $default_dirs; do
            [[ "$NGINX_ROOT" == "$dd" ]] && is_default=1
        done
        if [[ $is_default -eq 1 ]]; then
            status="$STATUS_FAIL"
            findings="${findings}; Nginx root=${NGINX_ROOT}(OS 기본 디렉토리)"
        else
            findings="${findings}; Nginx root=${NGINX_ROOT}(분리됨)"
        fi
    fi
    detail="서비스 영역:${findings}"
    current="${findings}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_W10() {
    local id="W-10" category="웹 서비스 보안"
    local title="웹 서비스 불필요한 파일 제거" importance="상"
    local status="$STATUS_NA" detail=""

    if [[ $APACHE_INSTALLED -eq 0 && $NGINX_INSTALLED -eq 0 && $TOMCAT_INSTALLED -eq 0 ]]; then
        current="웹서버 미설치"
        detail="웹서버 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    local manual_dirs="/var/www/manual /usr/share/httpd/manual /usr/share/doc/apache2 /usr/share/nginx/html/index.html"
    for d in $manual_dirs; do
        if [[ -e "$d" ]]; then
            status="$STATUS_FAIL"
            findings="${findings} ${d} 존재"
        fi
    done
    # Tomcat examples/docs
    if [[ $TOMCAT_INSTALLED -eq 1 ]]; then
        for d in "${TOMCAT_HOME}/webapps/examples" "${TOMCAT_HOME}/webapps/docs"; do
            if [[ -d "$d" ]]; then
                status="$STATUS_FAIL"
                findings="${findings} ${d} 존재"
            fi
        done
    fi
    if [[ -z "$findings" ]]; then
        detail="불필요 파일/디렉토리 없음"
    else
        detail="불필요 파일:${findings}"
    fi
    current="${findings:-없음}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_W11() {
    local id="W-11" category="웹 서비스 보안"
    local title="웹 서비스 프로세스 권한 제한" importance="상"
    local status="$STATUS_NA" detail=""

    if [[ $APACHE_INSTALLED -eq 0 && $NGINX_INSTALLED -eq 0 ]]; then
        current="Apache/Nginx 미설치"
        detail="Apache/Nginx 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    if [[ -n "$APACHE_CONF" ]]; then
        local user group
        user=$(grep -rh -v '^\s*#' "$APACHE_CONF" 2>/dev/null | grep -i '^\s*User\s' | tail -1 | awk '{print $2}')
        group=$(grep -rh -v '^\s*#' "$APACHE_CONF" 2>/dev/null | grep -i '^\s*Group\s' | tail -1 | awk '{print $2}')
        findings="${findings} Apache User=${user:-미설정}, Group=${group:-미설정}"
        if [[ "${user}" == "root" ]] || [[ "${group}" == "root" ]]; then
            status="$STATUS_FAIL"
        fi
    fi
    if [[ -n "$NGINX_CONF" ]]; then
        local nuser
        nuser=$(grep -v '^\s*#' "$NGINX_CONF" | grep -i '^\s*user\s' | head -1 | awk '{print $2}' | tr -d ';')
        findings="${findings}; Nginx user=${nuser:-미설정}"
        if [[ "${nuser}" == "root" ]]; then
            status="$STATUS_FAIL"
        fi
    fi
    detail="프로세스 권한:${findings:-설정확인불가}"
    current="${findings:-설정확인불가}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

# =============================================================================
# 7. DB 보안 (D-01 ~ D-08)
# =============================================================================

check_D01() {
    local id="D-01" category="DB 보안"
    local title="DB 패스워드 복잡도 및 암호화" importance="상"
    local status="$STATUS_NA" detail=""

    if [[ $MYSQL_INSTALLED -eq 0 && $PG_INSTALLED -eq 0 ]]; then
        current="DB 미설치"
        detail="DB 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    if [[ $MYSQL_INSTALLED -eq 1 && -n "$MYSQL_CONF" ]]; then
        local vp
        vp=$(grep -rh -v '^\s*#' "$MYSQL_CONF" /etc/mysql/conf.d/*.cnf /etc/mysql/mysql.conf.d/*.cnf 2>/dev/null | grep -i 'validate_password' | head -3)
        if [[ -n "$vp" ]]; then
            findings="${findings} MySQL validate_password 설정: $(echo "$vp" | tr '\n' ', ')"
        else
            status="$STATUS_FAIL"
            findings="${findings} MySQL validate_password 미설정"
        fi
    fi
    if [[ $PG_INSTALLED -eq 1 && -n "$PG_CONF" ]]; then
        local pe
        pe=$(grep -v '^\s*#' "$PG_CONF" | grep -i 'password_encryption' | tail -1 | awk -F= '{print $2}' | tr -d "' ")
        findings="${findings}; PG password_encryption=${pe:-미설정(기본md5)}"
        if [[ "${pe,,}" == "md5" || -z "$pe" ]]; then
            status="$STATUS_FAIL"
        fi
    fi
    detail="DB 패스워드:${findings}"
    current="${findings}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_D02() {
    local id="D-02" category="DB 보안"
    local title="DB 원격 접속 제한" importance="상"
    local status="$STATUS_NA" detail=""

    if [[ $MYSQL_INSTALLED -eq 0 && $PG_INSTALLED -eq 0 ]]; then
        current="DB 미설치"
        detail="DB 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    if [[ $MYSQL_INSTALLED -eq 1 && -n "$MYSQL_CONF" ]]; then
        local ba
        ba=$(grep -rh -v '^\s*#' "$MYSQL_CONF" /etc/mysql/conf.d/*.cnf /etc/mysql/mysql.conf.d/*.cnf 2>/dev/null | grep -i 'bind-address' | tail -1 | awk -F= '{print $2}' | tr -d ' ')
        findings="${findings} MySQL bind-address=${ba:-미설정(기본 전체허용)}"
        if [[ -z "$ba" || "$ba" == "0.0.0.0" || "$ba" == "*" ]]; then
            status="$STATUS_FAIL"
        fi
    fi
    if [[ $PG_INSTALLED -eq 1 && -n "$PG_CONF" ]]; then
        local la
        la=$(grep -v '^\s*#' "$PG_CONF" | grep -i 'listen_addresses' | tail -1 | awk -F= '{print $2}' | tr -d "' ")
        findings="${findings}; PG listen_addresses=${la:-미설정(기본localhost)}"
        if [[ "$la" == "*" || "$la" == "0.0.0.0" ]]; then
            status="$STATUS_FAIL"
        fi
    fi
    detail="원격 접속:${findings}"
    current="${findings}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_D03() {
    local id="D-03" category="DB 보안"
    local title="시스템 테이블 접근 제한" importance="중"
    local status="$STATUS_NA" detail=""

    if [[ $MYSQL_INSTALLED -eq 0 && $PG_INSTALLED -eq 0 ]]; then
        current="DB 미설치"
        detail="DB 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"
    detail="DB 시스템 테이블 접근 권한은 SQL 쿼리로 확인 필요 (설정파일 점검 한계). "
    if [[ $PG_INSTALLED -eq 1 && -n "$PG_HBA" ]]; then
        local trust_lines
        trust_lines=$(grep -v '^\s*#' "$PG_HBA" | grep -i 'trust' | head -3)
        if [[ -n "$trust_lines" ]]; then
            status="$STATUS_FAIL"
            detail="${detail}pg_hba.conf trust 인증 사용: $(echo "$trust_lines" | tr '\n' '; ')"
        else
            detail="${detail}pg_hba.conf trust 인증 미사용"
        fi
    fi
    current="${detail}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

check_D04() {
    local id="D-04" category="DB 보안"
    local title="감사기록 정책 설정" importance="중"
    local status="$STATUS_NA" detail=""

    if [[ $MYSQL_INSTALLED -eq 0 && $PG_INSTALLED -eq 0 ]]; then
        current="DB 미설치"
        detail="DB 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_FAIL"; local findings=""
    if [[ $MYSQL_INSTALLED -eq 1 && -n "$MYSQL_CONF" ]]; then
        local gl
        gl=$(grep -rh -v '^\s*#' "$MYSQL_CONF" /etc/mysql/conf.d/*.cnf /etc/mysql/mysql.conf.d/*.cnf 2>/dev/null | grep -i 'general_log\s*=' | tail -1 | awk -F= '{print $2}' | tr -d ' ')
        findings="${findings} MySQL general_log=${gl:-미설정}"
        [[ "${gl,,}" == "on" || "${gl}" == "1" ]] && status="$STATUS_PASS"
    fi
    if [[ $PG_INSTALLED -eq 1 && -n "$PG_CONF" ]]; then
        local lc ls
        lc=$(grep -v '^\s*#' "$PG_CONF" | grep -i 'logging_collector' | tail -1 | awk -F= '{print $2}' | tr -d "' ")
        ls=$(grep -v '^\s*#' "$PG_CONF" | grep -i 'log_statement' | tail -1 | awk -F= '{print $2}' | tr -d "' ")
        findings="${findings}; PG logging_collector=${lc:-미설정}, log_statement=${ls:-미설정}"
        [[ "${lc,,}" == "on" ]] && status="$STATUS_PASS"
    fi
    detail="감사 로깅:${findings}"
    current="${findings}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

check_D05() {
    local id="D-05" category="DB 보안"
    local title="DB 계정 umask 설정" importance="중"
    local status="$STATUS_NA" detail=""

    if [[ $MYSQL_INSTALLED -eq 0 && $PG_INSTALLED -eq 0 ]]; then
        current="DB 미설치"
        detail="DB 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    for dbuser in mysql postgres; do
        local home
        home=$(awk -F: -v u="$dbuser" '$1==u {print $6}' /etc/passwd 2>/dev/null)
        [[ -z "$home" || ! -d "$home" ]] && continue
        local umask_val=""
        for f in "${home}/.bashrc" "${home}/.bash_profile" "${home}/.profile"; do
            [[ -f "$f" ]] || continue
            umask_val=$(grep -v '^\s*#' "$f" | sed -n 's/.*umask[[:space:]]*\([0-9]*\).*/\1/p' | tail -1)
            [[ -n "$umask_val" ]] && break
        done
        if [[ -n "$umask_val" ]]; then
            local uv=$((8#$umask_val))
            if (( uv < 8#022 )); then
                status="$STATUS_FAIL"
                findings="${findings} ${dbuser} umask=${umask_val}(022 미만)"
            else
                findings="${findings} ${dbuser} umask=${umask_val}"
            fi
        else
            findings="${findings} ${dbuser} umask 미설정(시스템기본)"
        fi
    done
    [[ -z "$findings" ]] && findings=" DB 계정(mysql/postgres) 없음"
    detail="DB umask:${findings}"
    current="${findings}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

check_D06() {
    local id="D-06" category="DB 보안"
    local title="DB 주요 파일 접근 권한" importance="중"
    local status="$STATUS_NA" detail=""

    if [[ $MYSQL_INSTALLED -eq 0 && $PG_INSTALLED -eq 0 ]]; then
        current="DB 미설치"
        detail="DB 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    # 설정파일 640 이하
    for f in "$MYSQL_CONF" "$PG_CONF" "$PG_HBA"; do
        [[ -f "$f" ]] || continue
        local perms; perms=$(get_octal_perms "$f")
        local actual=$((8#${perms:-777}))
        if (( (actual & ~8#640) != 0 )); then
            status="$STATUS_FAIL"
            findings="${findings} ${f}(${perms},기준:640이하)"
        else
            findings="${findings} ${f}(${perms},양호)"
        fi
    done
    # 데이터 디렉토리 750 이하
    local data_dirs=""
    [[ $MYSQL_INSTALLED -eq 1 ]] && data_dirs="/var/lib/mysql"
    for dd in $data_dirs; do
        [[ -d "$dd" ]] || continue
        local perms; perms=$(get_octal_perms "$dd")
        local actual=$((8#${perms:-777}))
        if (( (actual & ~8#750) != 0 )); then
            status="$STATUS_FAIL"
            findings="${findings} ${dd}(${perms},기준:750이하)"
        else
            findings="${findings} ${dd}(${perms},양호)"
        fi
    done
    detail="DB 파일 권한:${findings:- 점검 대상 없음}"
    current="${findings:-점검대상없음}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

check_D07() {
    local id="D-07" category="DB 보안"
    local title="DB 자원 제한 기능" importance="중"
    local status="$STATUS_NA" detail=""

    if [[ $MYSQL_INSTALLED -eq 0 && $PG_INSTALLED -eq 0 ]]; then
        current="DB 미설치"
        detail="DB 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    if [[ $MYSQL_INSTALLED -eq 1 && -n "$MYSQL_CONF" ]]; then
        local mc mp
        mc=$(grep -rh -v '^\s*#' "$MYSQL_CONF" /etc/mysql/conf.d/*.cnf /etc/mysql/mysql.conf.d/*.cnf 2>/dev/null | grep -i 'max_connections' | tail -1 | awk -F= '{print $2}' | tr -d ' ')
        mp=$(grep -rh -v '^\s*#' "$MYSQL_CONF" /etc/mysql/conf.d/*.cnf /etc/mysql/mysql.conf.d/*.cnf 2>/dev/null | grep -i 'max_allowed_packet' | tail -1 | awk -F= '{print $2}' | tr -d ' ')
        findings="${findings} MySQL max_connections=${mc:-미설정}, max_allowed_packet=${mp:-미설정}"
        [[ -z "$mc" && -z "$mp" ]] && status="$STATUS_FAIL"
    fi
    if [[ $PG_INSTALLED -eq 1 && -n "$PG_CONF" ]]; then
        local pgmc
        pgmc=$(grep -v '^\s*#' "$PG_CONF" | grep -i 'max_connections' | tail -1 | awk -F= '{print $2}' | tr -d "' ")
        findings="${findings}; PG max_connections=${pgmc:-미설정}"
    fi
    detail="자원 제한:${findings}"
    current="${findings}"
    add_result "$id" "$category" "$title" "중" "$status" "$detail" "$current"
}

check_D08() {
    local id="D-08" category="DB 보안"
    local title="DB EOS 버전 점검" importance="상"
    local status="$STATUS_NA" detail=""

    if [[ $MYSQL_INSTALLED -eq 0 && $PG_INSTALLED -eq 0 ]]; then
        current="DB 미설치"
        detail="DB 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    if [[ $MYSQL_INSTALLED -eq 1 ]]; then
        local ver
        ver=$(mysql --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        if [[ -z "$ver" ]]; then
            ver=$(mysqld --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        fi
        findings="${findings} MySQL/MariaDB 버전: ${ver:-확인불가}"
        # EOS: MySQL 5.6 이하, MariaDB 10.3 이하
        if [[ -n "$ver" ]]; then
            version_compare "$ver" "5.7.0"
            if [[ $? -eq 0 ]]; then
                status="$STATUS_FAIL"
                findings="${findings}(EOS 의심)"
            fi
        fi
    fi
    if [[ $PG_INSTALLED -eq 1 ]]; then
        local ver
        ver=$(psql --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)
        findings="${findings}; PostgreSQL 버전: ${ver:-확인불가}"
        # EOS: PG 11 이하
        if [[ -n "$ver" ]]; then
            version_compare "$ver" "12.0"
            if [[ $? -eq 0 ]]; then
                status="$STATUS_FAIL"
                findings="${findings}(EOS 의심)"
            fi
        fi
    fi
    detail="DB 버전:${findings}"
    current="${findings}"
    add_result "$id" "$category" "$title" "상" "$status" "$detail" "$current"
}

# =============================================================================
# 8. 공개 취약점 관리 (V-01 ~ V-16)
# =============================================================================

# JAR 파일 한번만 검색하여 캐시 (6개 개별 find 대신)
JAR_CACHE=""
cache_jar_files() {
    if [[ -z "$JAR_CACHE" ]]; then
        JAR_CACHE=$(run_with_timeout 20 find /opt /usr /var /home /srv -name '*.jar' -type f 2>/dev/null | head -500)
        [[ -z "$JAR_CACHE" ]] && JAR_CACHE="__EMPTY__"
    fi
}

search_jar_cache() {
    local pattern="$1"
    [[ "$JAR_CACHE" == "__EMPTY__" ]] && return
    echo "$JAR_CACHE" | grep "$pattern" | head -10
}

check_V01() {
    local id="V-01" category="공개 취약점 관리"
    local title="Apache Log4j 취약점 (CVE-2021-44228)" importance="상"
    local status="$STATUS_NA" detail=""

    cache_jar_files
    local jars
    jars=$(search_jar_cache 'log4j-core-')
    if [[ -z "$jars" ]]; then
        current="log4j:log4j-core jar 미발견"
        detail="log4j-core jar 미발견"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    while IFS= read -r f; do
        local ver
        ver=$(basename "$f" | sed -E 's/log4j-core-//;s/\.jar$//')
        findings="${findings} ${f}(${ver})"
        if [[ -n "$ver" ]]; then
            version_in_range "$ver" "2.0" "2.17.1" && { status="$STATUS_FAIL"; findings="${findings}[취약]"; }
        fi
    done <<< "$jars"
    detail="Log4j:${findings}"
    current="log4j:${findings:-미발견}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_V02() {
    local id="V-02" category="공개 취약점 관리"
    local title="Tomcat Ghostcat 취약점 (CVE-2020-1938)" importance="상"
    local status="$STATUS_NA" detail=""

    if [[ $TOMCAT_INSTALLED -eq 0 ]]; then
        current="Tomcat 미설치"
        detail="Tomcat 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"
    if [[ -n "$TOMCAT_CONF" ]]; then
        local ajp
        ajp=$(grep -v '^\s*<!--' "$TOMCAT_CONF" | grep -i 'AJP' | grep -v '^\s*$')
        if [[ -n "$ajp" ]]; then
            if echo "$ajp" | grep -qi 'secretRequired\s*=\s*"true"\|secret\s*='; then
                detail="Tomcat AJP 커넥터 활성, secret 설정됨"
            else
                status="$STATUS_FAIL"
                detail="Tomcat AJP 커넥터 활성, secret 미설정 (Ghostcat 취약)"
            fi
        else
            detail="Tomcat AJP 커넥터 비활성"
        fi
    else
        detail="Tomcat server.xml 미발견"
    fi
    current="${detail}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_V03() {
    local id="V-03" category="공개 취약점 관리"
    local title="OpenSSL 취약점" importance="상"
    local status="$STATUS_NA" detail=""

    if ! command -v openssl &>/dev/null; then
        current="openssl 미설치"
        detail="openssl 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    local ver
    ver=$(openssl version 2>/dev/null | awk '{print $2}')
    status="$STATUS_PASS"
    detail="OpenSSL 버전: ${ver}"
    local num_ver
    num_ver=$(echo "$ver" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+')
    if [[ -n "$num_ver" ]]; then
        version_compare "$num_ver" "1.1.0"
        if [[ $? -eq 0 ]]; then
            status="$STATUS_FAIL"; detail="${detail} (1.1.0 미만, EOS)"
        fi
        version_in_range "$num_ver" "3.0.0" "3.0.7" && { status="$STATUS_FAIL"; detail="${detail} (3.0.0~3.0.6 취약)"; }
    fi
    current="${detail}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_V04() {
    local id="V-04" category="공개 취약점 관리"
    local title="Shellshock 취약점 (CVE-2014-6271)" importance="상"
    local status="$STATUS_PASS" detail=""

    local test_result
    test_result=$(env 'x=() { :;}; echo VULNERABLE' bash -c "echo test" 2>&1)
    if echo "$test_result" | grep -q 'VULNERABLE'; then
        status="$STATUS_FAIL"
        detail="Shellshock 취약 (env 변수 주입 가능)"
    else
        local bash_ver
        bash_ver=$(bash --version | head -1)
        detail="Shellshock 안전. bash: ${bash_ver}"
    fi
    current="${detail}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_V05() {
    local id="V-05" category="공개 취약점 관리"
    local title="Spring4Shell 취약점 (CVE-2022-22965)" importance="상"
    local status="$STATUS_NA" detail=""

    local jars
    cache_jar_files
    jars=$(search_jar_cache 'spring-beans-')
    if [[ -z "$jars" ]]; then
        current="spring-beans:spring-beans jar 미발견"
        detail="spring-beans jar 미발견"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    while IFS= read -r f; do
        local ver
        ver=$(basename "$f" | sed -E 's/spring-beans-//;s/\.jar$//')
        findings="${findings} ${ver}"
        version_in_range "$ver" "5.3.0" "5.3.18" && { status="$STATUS_FAIL"; findings="${findings}[취약]"; }
    done <<< "$jars"
    detail="spring-beans:${findings}"
    current="spring-beans:${findings:-미발견}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_V06() {
    local id="V-06" category="공개 취약점 관리"
    local title="Text4Shell 취약점 (CVE-2022-42889)" importance="상"
    local status="$STATUS_NA" detail=""

    local jars
    cache_jar_files
    jars=$(search_jar_cache 'commons-text-')
    if [[ -z "$jars" ]]; then
        current="commons-text:commons-text jar 미발견"
        detail="commons-text jar 미발견"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    while IFS= read -r f; do
        local ver
        ver=$(basename "$f" | sed -E 's/commons-text-//;s/\.jar$//')
        findings="${findings} ${ver}"
        version_in_range "$ver" "1.5" "1.10.0" && { status="$STATUS_FAIL"; findings="${findings}[취약]"; }
    done <<< "$jars"
    detail="commons-text:${findings}"
    current="commons-text:${findings:-미발견}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_V07() {
    local id="V-07" category="공개 취약점 관리"
    local title="Apache Struts RCE 취약점" importance="상"
    local status="$STATUS_NA" detail=""

    local jars
    cache_jar_files
    jars=$(search_jar_cache 'struts2-core-')
    if [[ -z "$jars" ]]; then
        current="struts2:struts2-core jar 미발견"
        detail="struts2-core jar 미발견"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    while IFS= read -r f; do
        local ver
        ver=$(basename "$f" | sed -E 's/struts2-core-//;s/\.jar$//')
        findings="${findings} ${ver}"
        version_in_range "$ver" "2.0.0" "2.5.33" && { status="$STATUS_FAIL"; findings="${findings}[취약]"; }
    done <<< "$jars"
    detail="struts2-core:${findings}"
    current="struts2:${findings:-미발견}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_V08() {
    local id="V-08" category="공개 취약점 관리"
    local title="Apache ActiveMQ RCE (CVE-2023-46604)" importance="상"
    local status="$STATUS_NA" detail=""

    if ! is_process_running activemq && ! is_process_running java; then
        current="activemq:ActiveMQ 미실행"
        detail="ActiveMQ 미실행"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    local jars
    cache_jar_files
    jars=$(search_jar_cache 'activemq-broker-')
    if [[ -z "$jars" ]]; then
        current="activemq:activemq-broker jar 미발견"
        detail="activemq-broker jar 미발견"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    while IFS= read -r f; do
        local ver
        ver=$(basename "$f" | sed -E 's/activemq-broker-//;s/\.jar$//')
        findings="${findings} ${ver}"
        version_in_range "$ver" "5.0.0" "5.15.16" && { status="$STATUS_FAIL"; findings="${findings}[취약]"; }
        version_in_range "$ver" "5.16.0" "5.16.7" && { status="$STATUS_FAIL"; findings="${findings}[취약]"; }
        version_in_range "$ver" "5.17.0" "5.17.6" && { status="$STATUS_FAIL"; findings="${findings}[취약]"; }
        version_in_range "$ver" "5.18.0" "5.18.3" && { status="$STATUS_FAIL"; findings="${findings}[취약]"; }
    done <<< "$jars"
    detail="ActiveMQ:${findings}"
    current="activemq:${findings:-미발견}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_V09() {
    local id="V-09" category="공개 취약점 관리"
    local title="Apache Shiro RCE 취약점" importance="상"
    local status="$STATUS_NA" detail=""

    local jars
    cache_jar_files
    jars=$(search_jar_cache 'shiro-core-')
    if [[ -z "$jars" ]]; then
        current="shiro:shiro-core jar 미발견"
        detail="shiro-core jar 미발견"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings=""
    while IFS= read -r f; do
        local ver
        ver=$(basename "$f" | sed -E 's/shiro-core-//;s/\.jar$//')
        findings="${findings} ${ver}"
        version_in_range "$ver" "1.0.0" "1.13.0" && { status="$STATUS_FAIL"; findings="${findings}[취약]"; }
    done <<< "$jars"
    detail="Shiro:${findings}"
    current="shiro:${findings:-미발견}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_V10() {
    local id="V-10" category="공개 취약점 관리"
    local title="Jenkins RCE 취약점" importance="상"
    local status="$STATUS_NA" detail=""

    if ! is_process_running jenkins && ! is_process_running java; then
        current="Jenkins 미실행"
        detail="Jenkins 미실행"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    local war
    war=$(run_with_timeout 5 find /opt /usr /var /home /srv -name 'jenkins.war' -type f 2>/dev/null | head -1)
    if [[ -z "$war" ]]; then
        current="jenkins.war 미발견"
        detail="jenkins.war 미발견"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    local ver
    ver=$(unzip -p "$war" META-INF/MANIFEST.MF 2>/dev/null | grep -i 'Jenkins-Version' | awk '{print $2}' | tr -d '\r')
    status="$STATUS_PASS"
    detail="Jenkins 버전: ${ver:-확인불가}"
    if [[ -n "$ver" ]]; then
        version_compare "$ver" "2.441"
        [[ $? -eq 0 ]] && { status="$STATUS_FAIL"; detail="${detail} (2.441 미만, 취약)"; }
    fi
    current="${detail}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_V11() {
    local id="V-11" category="공개 취약점 관리"
    local title="Samba 취약점" importance="상"
    local status="$STATUS_NA" detail=""

    if ! command -v smbd &>/dev/null; then
        current="Samba 미설치"
        detail="Samba 미설치"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    local ver
    ver=$(smbd --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    status="$STATUS_PASS"
    detail="Samba 버전: ${ver:-확인불가}"
    if [[ -n "$ver" ]]; then
        version_compare "$ver" "4.16.0"
        [[ $? -eq 0 ]] && { status="$STATUS_FAIL"; detail="${detail} (4.16.0 미만, EOS/취약)"; }
    fi
    current="${detail}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_V12() {
    local id="V-12" category="공개 취약점 관리"
    local title="glibc 권한상승 취약점 (CVE-2023-6246)" importance="상"
    local status="$STATUS_PASS" detail=""

    local ver
    ver=$(ldd --version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+')
    detail="glibc 버전: ${ver:-확인불가}"
    if [[ -n "$ver" ]]; then
        version_in_range "$ver" "2.17" "2.38" && { status="$STATUS_FAIL"; detail="${detail} (2.17~2.37 CVE-2023-6246 취약 가능)"; }
    fi
    current="${detail}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_V13() {
    local id="V-13" category="공개 취약점 관리"
    local title="OpenSSH regreSSHion (CVE-2024-6387)" importance="상"
    local status="$STATUS_PASS" detail=""

    local ver
    ver=$(ssh -V 2>&1 | grep -oE '[0-9]+\.[0-9]+p[0-9]+' | head -1)
    local num_ver
    num_ver=$(echo "$ver" | grep -oE '^[0-9]+\.[0-9]+')
    detail="OpenSSH 버전: ${ver:-확인불가}"
    if [[ -n "$num_ver" ]]; then
        version_in_range "$num_ver" "8.5" "9.8" && { status="$STATUS_FAIL"; detail="${detail} (8.5p1~9.7p1 취약 가능)"; }
    fi
    current="${detail}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_V14() {
    local id="V-14" category="공개 취약점 관리"
    local title="curl BOF 취약점 (CVE-2023-38545)" importance="상"
    local status="$STATUS_PASS" detail=""

    if ! command -v curl &>/dev/null; then
        status="$STATUS_NA"; detail="curl 미설치"
        current="${detail}"
        add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    local ver
    ver=$(curl --version 2>/dev/null | head -1 | awk '{print $2}')
    detail="curl 버전: ${ver:-확인불가}"
    if [[ -n "$ver" ]]; then
        version_in_range "$ver" "7.69.0" "8.4.0" && { status="$STATUS_FAIL"; detail="${detail} (7.69.0~8.3.0 취약)"; }
    fi
    current="${detail}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_V15() {
    local id="V-15" category="공개 취약점 관리"
    local title="glibc Looney Tunables (CVE-2023-4911)" importance="상"
    local status="$STATUS_PASS" detail=""

    local ver
    ver=$(ldd --version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+')
    detail="glibc 버전: ${ver:-확인불가}"
    if [[ -n "$ver" ]]; then
        version_in_range "$ver" "2.34" "2.39" && { status="$STATUS_FAIL"; detail="${detail} (2.34~2.38 취약 가능)"; }
    fi
    current="${detail}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_V16() {
    local id="V-16" category="공개 취약점 관리"
    local title="커널 권한상승 취약점 (CVE-2023-0386)" importance="상"
    local status="$STATUS_PASS" detail=""

    local kver
    kver=$(uname -r)
    detail="커널 버전: ${kver}"
    # OverlayFS CVE-2023-0386 affects kernels before 6.2
    local major minor
    major=$(echo "$kver" | cut -d. -f1)
    minor=$(echo "$kver" | cut -d. -f2)
    if [[ -n "$major" && -n "$minor" ]]; then
        if (( major < 6 || (major == 6 && minor < 2) )); then
            if grep -q overlay /proc/filesystems 2>/dev/null; then
                status="$STATUS_FAIL"
                detail="${detail} (6.2 미만, OverlayFS 지원, CVE-2023-0386 취약 가능)"
            fi
        fi
    fi
    current="${detail}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

# =============================================================================
# 9. 침해사고 흔적 점검 (I-01 ~ I-02)
# =============================================================================

check_I01() {
    local id="I-01" category="침해사고 흔적 점검"
    local title="Rootkit 점검" importance="상"
    local status="$STATUS_PASS" detail=""

    local findings=""
    # 알려진 rootkit 파일/디렉토리
    local rk_paths="/dev/.lib /dev/.hidden /usr/lib/libproc.a /usr/lib/.libX11 /tmp/.font-unix/.LCK /dev/shm/.rootkit"
    rk_paths="${rk_paths} /etc/ld.so.hash /usr/include/file.h /usr/include/hosts.h /usr/lib/libext-2.so"
    for p in $rk_paths; do
        if [[ -e "$p" ]]; then
            findings="${findings} ${p}"
        fi
    done

    # 숨겨진 프로세스 탐지: /proc PID vs ps 비교
    local proc_pids ps_pids hidden=""
    proc_pids=$(ls -1 /proc/ 2>/dev/null | grep '^[0-9]*$' | sort -n)
    ps_pids=$(ps -eo pid --no-headers 2>/dev/null | tr -d ' ' | sort -n)
    if [[ -n "$proc_pids" && -n "$ps_pids" ]]; then
        hidden=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids") | head -5)
        [[ -n "$hidden" ]] && findings="${findings} 숨겨진PID: $(echo "$hidden" | tr '\n' ',')"
    fi

    # 의심 커널 모듈
    local suspicious_modules
    suspicious_modules=$(lsmod 2>/dev/null | awk 'NR>1 && $3==0 {print $1}' | head -10)

    if [[ -n "$findings" ]]; then
        status="$STATUS_FAIL"
        detail="의심 항목 발견:${findings}"
    else
        detail="알려진 rootkit 흔적 없음 ($(echo $rk_paths | wc -w) 경로 점검, PID 비교 완료)"
    fi
    [[ -n "$suspicious_modules" ]] && detail="${detail}; 참조 없는 커널 모듈: $(echo "$suspicious_modules" | tr '\n' ',')"
    current="${detail}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

check_I02() {
    local id="I-02" category="침해사고 흔적 점검"
    local title="WebShell 점검" importance="상"
    local status="$STATUS_NA" detail=""

    local docroots
    docroots=$(get_web_docroots)
    if [[ -z "$docroots" ]]; then
        current="웹서버 DocumentRoot 미발견"
        detail="웹서버 DocumentRoot 미발견"; add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"; return
    fi

    status="$STATUS_PASS"; local findings="" total_suspect=0
    local patterns='eval\s*\(|base64_decode\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(|exec\s*\(|popen\s*\(|proc_open|assert\s*\('
    local jsp_patterns='Runtime\.getRuntime\(\)\.exec|ProcessBuilder|getParameter.*cmd'

    for dr in $docroots; do
        [[ -d "$dr" ]] || continue
        local suspects
        suspects=$(run_with_timeout 30 bash -c "find '$dr' -type f \( -name '*.php' -o -name '*.jsp' -o -name '*.jspx' \) -print0 2>/dev/null | xargs -0 grep -lE '${patterns}|${jsp_patterns}' 2>/dev/null | head -20")
        if [[ -n "$suspects" ]]; then
            local cnt
            cnt=$(echo "$suspects" | wc -l)
            total_suspect=$((total_suspect + cnt))
            findings="${findings} ${dr}: ${cnt}개 의심 파일"
        fi
    done

    if [[ $total_suspect -gt 0 ]]; then
        status="$STATUS_FAIL"
        detail="WebShell 의심 파일 ${total_suspect}개:${findings}"
    else
        detail="WebShell 의심 파일 없음 (DocumentRoot: ${docroots})"
    fi
    current="${detail}"
    add_result "$id" "$category" "$title" "$importance" "$status" "$detail" "$current"
}

###############################################################################
# Section 4: main() — 전체 실행, JSON 조립, 출력
###############################################################################

assemble_json() {
    local scan_date hostname os_name ip_addrs total
    scan_date=$(date -Iseconds)
    hostname=$(hostname)
    os_name="${OS_ID}"
    ip_addrs=$(get_ip_addresses)
    total=$((COUNT_PASS + COUNT_FAIL + COUNT_NA))

    # Build IP array
    local ip_json="["
    local first=1
    IFS=',' read -ra ip_arr <<< "$ip_addrs"
    for ip in "${ip_arr[@]}"; do
        ip=$(echo "$ip" | tr -d ' ')
        [[ -z "$ip" ]] && continue
        if [[ $first -eq 1 ]]; then
            ip_json="${ip_json}\"${ip}\""
            first=0
        else
            ip_json="${ip_json}, \"${ip}\""
        fi
    done
    ip_json="${ip_json}]"

    cat <<JSONEOF
{
  "scanner": "$(json_escape "$SCANNER_NAME")",
  "version": "${SCANNER_VERSION}",
  "scan_date": "${scan_date}",
  "hostname": "$(json_escape "$hostname")",
  "os": "$(json_escape "$os_name")",
  "os_version": "$(json_escape "$OS_VERSION")",
  "kernel": "$(json_escape "$KERNEL_VERSION")",
  "ip_addresses": ${ip_json},
  "summary": {
    "total": ${total},
    "pass": ${COUNT_PASS},
    "fail": ${COUNT_FAIL},
    "na": ${COUNT_NA}
  },
  "results": [
${RESULTS}
  ]
}
JSONEOF
}

main() {
    local start_time
    start_time=$(date +%s)

    log "============================================"
    log " ${SCANNER_NAME} v${SCANNER_VERSION}"
    log " 점검 시작: $(date)"
    log "============================================"

    # OS 탐지
    detect_os
    setup_os_vars
    detect_web_servers
    detect_databases

    # 점검 실행
    log "--- 1. 계정관리 (U-01 ~ U-13) ---"
    check_U01
    check_U02
    check_U03
    check_U04
    check_U05
    check_U06
    check_U07
    check_U08
    check_U09
    check_U10
    check_U11
    check_U12
    check_U13

    log "--- 2. 파일 및 디렉토리 관리 (U-14 ~ U-33) ---"
    check_U14
    check_U15
    check_U16
    check_U17
    check_U18
    check_U19
    check_U20
    check_U21
    check_U22
    check_U23
    check_U24
    check_U25
    check_U26
    check_U27
    check_U28
    check_U29
    check_U30
    check_U31
    check_U32
    check_U33

    log "--- 3. 서비스 관리 (U-34 ~ U-63) ---"
    check_U34
    check_U35
    check_U36
    check_U37
    check_U38
    check_U39
    check_U40
    check_U41
    check_U42
    check_U43
    check_U44
    check_U45
    check_U46
    check_U47
    check_U48
    check_U49
    check_U50
    check_U51
    check_U52
    check_U53
    check_U54
    check_U55
    check_U56
    check_U57
    check_U58
    check_U59
    check_U60
    check_U61
    check_U62
    check_U63

    log "--- 4. 패치 관리 (U-64) ---"
    check_U64

    log "--- 5. 로그 관리 (U-65 ~ U-67) ---"
    check_U65
    check_U66
    check_U67

    log "--- 6. 웹 서비스 보안 (W-01 ~ W-11) ---"
    check_W01
    check_W02
    check_W03
    check_W04
    check_W05
    check_W06
    check_W07
    check_W08
    check_W09
    check_W10
    check_W11

    log "--- 7. DB 보안 (D-01 ~ D-08) ---"
    check_D01
    check_D02
    check_D03
    check_D04
    check_D05
    check_D06
    check_D07
    check_D08

    log "--- 8. 공개 취약점 관리 (V-01 ~ V-16) ---"
    check_V01
    check_V02
    check_V03
    check_V04
    check_V05
    check_V06
    check_V07
    check_V08
    check_V09
    check_V10
    check_V11
    check_V12
    check_V13
    check_V14
    check_V15
    check_V16

    log "--- 9. 침해사고 흔적 점검 (I-01 ~ I-02) ---"
    check_I01
    check_I02

    # JSON 출력
    local json_output
    json_output=$(assemble_json)

    # 출력파일 안전하게 생성 (600 퍼미션, symlink 방지)
    rm -f "$OUTPUT_FILE" 2>/dev/null
    (umask 077; echo "$json_output" > "$OUTPUT_FILE") || {
        log "ERROR: JSON 출력 실패: ${OUTPUT_FILE}"
        exit 1
    }

    local end_time elapsed
    end_time=$(date +%s)
    elapsed=$(( end_time - start_time ))

    log "============================================"
    log " 점검 완료 (소요시간: ${elapsed}초)"
    log " 결과: 양호=${COUNT_PASS}, 취약=${COUNT_FAIL}, N/A=${COUNT_NA}"
    log " 출력: ${OUTPUT_FILE}"
    log "============================================"
}

main