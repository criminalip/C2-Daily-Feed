#!/usr/bin/env bash
###############################################################################
# CVE-2026-29000 pac4j-jwt Authentication Bypass Vulnerability Scanner
# Version: 1.0
#
# 취약점: pac4j-jwt JWE+JWS 결합 시 서명 검증 우회 (CVSS 10.0)
# 원인:   JwtAuthenticator.java에서 toSignedJWT() null 반환 시
#         서명 검증 로직이 완전히 생략됨 (PlainJWT 공격)
#
# 취약 버전: 4.x < 4.5.9 | 5.x < 5.7.9 | 6.x < 6.3.3
# 패치 버전: 4.x >= 4.5.9 | 5.x >= 5.7.9 | 6.x >= 6.3.3
#
# 환경 자동 탐지: 베어메탈/VM, Docker, Kubernetes(CRI-O/containerd/docker)
# 출력: JSON 파일 + stderr 진행 로그
# 리소스: renice 19, ionice idle (1CPU/1MEM 환경 보호)
###############################################################################
set -o pipefail

###############################################################################
# Section 0: 상수 및 CLI 파싱
###############################################################################
readonly SCANNER_NAME="CVE-2026-29000 pac4j-jwt Scanner"
readonly SCANNER_VERSION="1.0"
readonly CVE_ID="CVE-2026-29000"
readonly CVSS_SCORE="10.0"
readonly STATUS_VULN="취약"
readonly STATUS_SAFE="양호"
readonly STATUS_UNKNOWN="확인불가"

OUTPUT_FILE=""
RESULTS=""          # JSON results array items (newline-separated)
COUNT_VULN=0
COUNT_SAFE=0
COUNT_UNKNOWN=0

usage() {
    cat >&2 <<EOF
사용법: $0 [옵션]

옵션:
  --output, -o FILE   결과 JSON 파일 경로 (기본: /tmp/cve_2026_29000_HOSTNAME_DATE.json)
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
    OUTPUT_FILE="/tmp/cve_2026_29000_$(hostname)_$(date +%Y%m%d_%H%M%S).json"
fi

# 리소스 보호: CPU/IO 우선순위를 최저로 설정 (1CPU/1GB VM 서비스 가용성 보호)
renice -n 19 $$ &>/dev/null || true
ionice -c 3 -p $$ &>/dev/null || true

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
    s=$(printf '%s' "$s" | tr -d '\001-\010\013\014\016-\037')
    printf '%s' "$s"
}

add_result() {
    local location="$1" version="$2" status="$3" detail="$4" source_type="$5" patched_version="${6:-}" container_info="${7:-}"

    local entry
    entry=$(cat <<JSONEOF
    {
      "location": "$(json_escape "$location")",
      "version": "$(json_escape "$version")",
      "status": "${status}",
      "detail": "$(json_escape "$detail")",
      "source_type": "$(json_escape "$source_type")",
      "patched_version": "$(json_escape "$patched_version")",
      "container": "$(json_escape "$container_info")"
    }
JSONEOF
)
    if [[ -n "$RESULTS" ]]; then
        RESULTS="${RESULTS},"$'\n'"${entry}"
    else
        RESULTS="${entry}"
    fi

    case "$status" in
        "$STATUS_VULN")    ((COUNT_VULN++)) ;;
        "$STATUS_SAFE")    ((COUNT_SAFE++)) ;;
        "$STATUS_UNKNOWN") ((COUNT_UNKNOWN++)) ;;
    esac

    log "[${status}] ${location} (v${version}) [${source_type}]${container_info:+ [${container_info}]}${patched_version:+ -> ${patched_version}}"
}

get_ip_addresses() {
    if command -v ip &>/dev/null; then
        ip -4 addr show 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | grep -v '^127\.' | tr '\n' ',' | sed 's/,$//'
    elif command -v hostname &>/dev/null; then
        hostname -I 2>/dev/null | tr ' ' ',' | sed 's/,$//'
    fi
}

# find 공통: 불필요한 가상 파일시스템 제외 (I/O 절약)
find_safe() {
    find / \
        -path /proc -prune -o \
        -path /sys -prune -o \
        -path /dev -prune -o \
        -path /run -prune -o \
        -path /snap -prune -o \
        -path /var/lib/docker -prune -o \
        -path /var/lib/containers -prune -o \
        -path /var/lib/kubelet -prune -o \
        -path /var/lib/containerd -prune -o \
        "$@" 2>/dev/null
}

###############################################################################
# Section 2: 환경 탐지
###############################################################################
OS_ID=""
OS_VERSION=""
KERNEL_VERSION=""
HOST_ENV=""         # baremetal | docker | kubernetes
CONTAINER_RUNTIME=""  # docker | containerd | cri-o | ""

detect_os() {
    KERNEL_VERSION="$(uname -r)"
    if [[ -f /etc/os-release ]]; then
        OS_ID=$(. /etc/os-release && echo "$ID")
        OS_VERSION=$(. /etc/os-release && echo "$VERSION_ID")
    elif [[ -f /etc/redhat-release ]]; then
        OS_ID="rhel"
        OS_VERSION=$(sed 's/[^0-9.]//g' /etc/redhat-release)
    fi
    OS_ID="${OS_ID,,}"
    log "OS: ${OS_ID} ${OS_VERSION}, Kernel: ${KERNEL_VERSION}"
}

detect_environment() {
    # 1) 현재 프로세스가 컨테이너 내부인지 확인
    if [[ -f /.dockerenv ]] || grep -qsE '(/docker/|/kubepods/)' /proc/1/cgroup 2>/dev/null; then
        if [[ -n "${KUBERNETES_SERVICE_HOST:-}" ]]; then
            HOST_ENV="kubernetes"
        else
            HOST_ENV="docker"
        fi
        log "실행 환경: 컨테이너 내부 (${HOST_ENV})"
        return
    fi

    # 2) 호스트 환경 - 컨테이너 런타임 탐지
    HOST_ENV="baremetal"

    if command -v kubectl &>/dev/null && kubectl cluster-info &>/dev/null 2>&1; then
        HOST_ENV="kubernetes"
        if command -v crictl &>/dev/null; then
            CONTAINER_RUNTIME="cri-o/containerd"
        elif command -v docker &>/dev/null; then
            CONTAINER_RUNTIME="docker"
        fi
    elif command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        CONTAINER_RUNTIME="docker"
    elif command -v podman &>/dev/null && podman info &>/dev/null 2>&1; then
        CONTAINER_RUNTIME="podman"
    elif command -v nerdctl &>/dev/null; then
        CONTAINER_RUNTIME="containerd"
    fi

    log "실행 환경: ${HOST_ENV}${CONTAINER_RUNTIME:+, 컨테이너 런타임: ${CONTAINER_RUNTIME}}"
}

###############################################################################
# Section 3: 버전 판별 함수
###############################################################################

# 반환값: 0=취약, 1=안전, 2=판단불가
check_version() {
    local version="$1"
    local clean_ver
    clean_ver=$(echo "$version" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' || echo "")

    if [[ -z "$clean_ver" ]]; then
        return 2
    fi

    local major minor patch
    IFS='.' read -r major minor patch <<< "$clean_ver"

    case "$major" in
        4)
            if [[ "$minor" -lt 5 ]] || { [[ "$minor" -eq 5 ]] && [[ "$patch" -lt 9 ]]; }; then
                return 0
            else
                return 1
            fi ;;
        5)
            if [[ "$minor" -lt 7 ]] || { [[ "$minor" -eq 7 ]] && [[ "$patch" -lt 9 ]]; }; then
                return 0
            else
                return 1
            fi ;;
        6)
            if [[ "$minor" -lt 3 ]] || { [[ "$minor" -eq 3 ]] && [[ "$patch" -lt 3 ]]; }; then
                return 0
            else
                return 1
            fi ;;
        [0-3])
            return 0 ;;  # EOL, 모두 취약
        *)
            return 2 ;;  # 7+ 알 수 없는 버전
    esac
}

# JAR 파일명에서 버전 추출 (pac4j-jwt-4.5.8.jar -> 4.5.8)
extract_version_from_filename() {
    local name="${1%.jar}"  # .jar 접미사 제거
    echo "$name" | sed -n 's/.*pac4j-jwt-//p' || echo ""
}

# JAR 내부 메타데이터에서 버전 추출 (pom.properties > MANIFEST.MF)
extract_version_from_jar() {
    local jarfile="$1"
    local version=""

    # 1차: pom.properties
    version=$(unzip -p "$jarfile" '*/pom.properties' 2>/dev/null \
        | grep '^version=' | head -1 | cut -d'=' -f2 | tr -d '[:space:]') || true
    [[ -n "$version" ]] && { echo "$version"; return; }

    # 2차: MANIFEST.MF Implementation-Version
    version=$(unzip -p "$jarfile" 'META-INF/MANIFEST.MF' 2>/dev/null \
        | grep -i '^Implementation-Version:' | head -1 | cut -d':' -f2 | tr -d '[:space:]') || true
    [[ -n "$version" ]] && { echo "$version"; return; }

    # 3차: Bundle-Version (OSGi)
    version=$(unzip -p "$jarfile" 'META-INF/MANIFEST.MF' 2>/dev/null \
        | grep -i '^Bundle-Version:' | head -1 | cut -d':' -f2 | tr -d '[:space:]') || true
    [[ -n "$version" ]] && { echo "$version"; return; }

    echo ""
}

# 메이저 버전에 따른 패치 버전 반환
get_patched_version() {
    local version="$1"
    local major
    major=$(echo "$version" | cut -d. -f1)
    case "$major" in
        4) echo "4.5.9" ;;
        5) echo "5.7.9" ;;
        6) echo "6.3.3" ;;
        [0-3]) echo "4.5.9 (또는 상위 버전으로 마이그레이션)" ;;
        *) echo "" ;;
    esac
}

# 버전+경로로 결과 기록
report_finding() {
    local filepath="$1" version="$2" source_type="$3" container_info="${4:-}"
    local status detail patched_ver=""

    if [[ -z "$version" || "$version" == "unknown" ]]; then
        status="$STATUS_UNKNOWN"
        detail="pac4j-jwt 발견, 버전 확인 불가. 수동 점검 필요"
        version="unknown"
    else
        check_version "$version" && rc=$? || rc=$?
        case $rc in
            0)
                status="$STATUS_VULN"
                patched_ver=$(get_patched_version "$version")
                detail="취약 버전 v${version} → v${patched_ver} 이상으로 업그레이드 필요" ;;
            1)
                status="$STATUS_SAFE"
                detail="패치 완료 (v${version})" ;;
            2)
                status="$STATUS_UNKNOWN"
                detail="버전 판별 불가 (v${version}). 수동 점검 필요" ;;
        esac
    fi

    add_result "$filepath" "$version" "$status" "$detail" "$source_type" "$patched_ver" "$container_info"
}

###############################################################################
# Section 4: 스캔 함수 - 호스트 파일시스템
###############################################################################

# 4-1: pac4j-jwt-*.jar 직접 검색
scan_host_direct_jars() {
    log "--- 호스트: pac4j-jwt JAR 직접 검색 ---"
    while IFS= read -r jarfile; do
        [[ -z "$jarfile" ]] && continue
        local filename version
        filename=$(basename "$jarfile")
        version=$(extract_version_from_filename "$filename")
        [[ -z "$version" ]] && version=$(extract_version_from_jar "$jarfile")
        [[ -z "$version" ]] && version="unknown"
        report_finding "$jarfile" "$version" "jar_file"
    done < <(find_safe -type f -name "pac4j-jwt-*.jar" -print)
}

# 4-2: WAR/EAR/Fat-JAR 내부 중첩 검색
scan_host_archives() {
    log "--- 호스트: WAR/EAR/Fat-JAR 내부 검색 ---"
    local tmpdir
    tmpdir=$(mktemp -d)

    while IFS= read -r archive; do
        [[ -z "$archive" ]] && continue
        local matches
        matches=$(unzip -l "$archive" 2>/dev/null | grep -i 'pac4j-jwt' || true)
        [[ -z "$matches" ]] && continue

        local inner_jar
        inner_jar=$(echo "$matches" | grep -oE 'pac4j-jwt-[0-9][^\s]*\.jar' | head -1 || echo "")
        local version=""

        if [[ -n "$inner_jar" ]]; then
            version=$(extract_version_from_filename "$inner_jar")
            # 파일명에서 못 찾으면 내부 jar 임시 추출
            if [[ -z "$version" ]]; then
                local inner_path
                inner_path=$(echo "$matches" | grep -oE '[^ ]*pac4j-jwt[^ ]*\.jar' | head -1 || echo "")
                if [[ -n "$inner_path" ]]; then
                    unzip -o -j "$archive" "$inner_path" -d "$tmpdir" 2>/dev/null || true
                    local extracted="$tmpdir/$(basename "$inner_path")"
                    [[ -f "$extracted" ]] && version=$(extract_version_from_jar "$extracted")
                    rm -f "$extracted" 2>/dev/null
                fi
            fi
        fi

        [[ -z "$version" ]] && version="unknown"
        report_finding "$archive" "$version" "embedded_in_archive(${inner_jar:-pac4j-jwt})"
    # WAR/EAR: 크기 무관 (항상 애플리케이션 아카이브)
    # JAR (Fat JAR): 100k 이상만 (소형 라이브러리 jar 제외)
    done < <(find_safe \( \
        \( -type f \( -name "*.war" -o -name "*.ear" \) \) -o \
        \( -type f -name "*.jar" ! -name "pac4j-jwt-*.jar" -size +100k \) \
    \) -print)

    rm -rf "$tmpdir" 2>/dev/null
}

# 4-3: Maven/Gradle 빌드 파일 검색
scan_host_build_files() {
    log "--- 호스트: Maven/Gradle 빌드 파일 검색 ---"

    # pom.xml
    while IFS= read -r pomfile; do
        [[ -z "$pomfile" ]] && continue
        grep -q '<artifactId>pac4j-jwt</artifactId>' "$pomfile" 2>/dev/null || continue

        local version
        version=$(grep -A5 '<artifactId>pac4j-jwt</artifactId>' "$pomfile" 2>/dev/null \
            | grep '<version>' | head -1 | grep -oE '>[^<]+' | sed 's/>//' || echo "")

        # Maven 변수 ${...} 해석 시도
        if [[ "$version" =~ ^\$\{(.+)\}$ ]]; then
            local prop="${BASH_REMATCH[1]}"
            local resolved
            resolved=$(grep "<${prop}>" "$pomfile" 2>/dev/null | head -1 | grep -oE '>[^<]+' | sed 's/>//' || echo "")
            version="${resolved:-unknown}"
        fi
        [[ -z "$version" ]] && version="unknown"
        report_finding "$pomfile" "$version" "pom.xml"
    done < <(find_safe -type f -name "pom.xml" -print)

    # build.gradle / build.gradle.kts
    while IFS= read -r gf; do
        [[ -z "$gf" ]] && continue
        grep -q 'pac4j-jwt' "$gf" 2>/dev/null || continue

        local version
        version=$(grep -oE "pac4j-jwt['\"]?:[0-9][^\s'\")]+" "$gf" 2>/dev/null \
            | head -1 | sed 's/.*://' || echo "unknown")
        report_finding "$gf" "$version" "build.gradle"
    done < <(find_safe -type f \( -name "build.gradle" -o -name "build.gradle.kts" \) -print)
}

###############################################################################
# Section 5: 스캔 함수 - Docker/Podman 컨테이너
###############################################################################

# 컨테이너 런타임 CLI 자동 선택 (docker > podman)
CONTAINER_CLI=""

detect_container_cli() {
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        CONTAINER_CLI="docker"
    elif command -v podman &>/dev/null && podman info &>/dev/null 2>&1; then
        CONTAINER_CLI="podman"
    fi
}

scan_containers() {
    detect_container_cli
    if [[ -z "$CONTAINER_CLI" ]]; then
        log "Docker/Podman 미감지, 컨테이너 스캔 건너뜀"
        return
    fi

    log "--- ${CONTAINER_CLI} 컨테이너 내부 스캔 ---"
    local container_ids
    container_ids=$($CONTAINER_CLI ps -q 2>/dev/null) || return
    [[ -z "$container_ids" ]] && { log "  실행 중인 컨테이너 없음"; return; }

    while IFS= read -r cid; do
        [[ -z "$cid" ]] && continue
        local cname
        cname=$($CONTAINER_CLI inspect --format='{{.Name}}' "$cid" 2>/dev/null | sed 's/^\///' || echo "$cid")
        log "  컨테이너 검사: ${cname}"

        # 직접 jar 검색
        local jar_results
        jar_results=$($CONTAINER_CLI exec "$cid" find / \
            -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o \
            -type f -name "pac4j-jwt-*.jar" -print 2>/dev/null || true)

        if [[ -n "$jar_results" ]]; then
            while IFS= read -r jarfile; do
                [[ -z "$jarfile" ]] && continue
                local filename version
                filename=$(basename "$jarfile")
                version=$(extract_version_from_filename "$filename")

                # 파일명에서 못 찾으면 컨테이너 내부에서 pom.properties 추출
                if [[ -z "$version" ]]; then
                    version=$($CONTAINER_CLI exec "$cid" unzip -p "$jarfile" '*/pom.properties' 2>/dev/null \
                        | grep '^version=' | head -1 | cut -d'=' -f2 | tr -d '[:space:]' || echo "")
                fi

                [[ -z "$version" ]] && version="unknown"
                report_finding "$jarfile" "$version" "jar_file" "${CONTAINER_CLI}:${cname}"
            done <<< "$jar_results"
        fi

        # 아카이브 내부 검색 (war/ear)
        local archive_results
        archive_results=$($CONTAINER_CLI exec "$cid" find / \
            -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o \
            -type f \( -name "*.war" -o -name "*.ear" \) -print 2>/dev/null || true)

        if [[ -n "$archive_results" ]]; then
            while IFS= read -r archive; do
                [[ -z "$archive" ]] && continue
                local matches
                matches=$($CONTAINER_CLI exec "$cid" unzip -l "$archive" 2>/dev/null | grep -i 'pac4j-jwt' || true)
                [[ -z "$matches" ]] && continue

                local inner_jar version
                inner_jar=$(echo "$matches" | grep -oE 'pac4j-jwt-[0-9][^\s]*\.jar' | head -1 || echo "")
                version=""
                [[ -n "$inner_jar" ]] && version=$(extract_version_from_filename "$inner_jar")
                [[ -z "$version" ]] && version="unknown"
                report_finding "$archive" "$version" "embedded_in_archive(${inner_jar:-pac4j-jwt})" "${CONTAINER_CLI}:${cname}"
            done <<< "$archive_results"
        fi
    done <<< "$container_ids"
}

###############################################################################
# Section 6: 스캔 함수 - Kubernetes
###############################################################################

scan_kubernetes_pods() {
    if ! command -v kubectl &>/dev/null || ! kubectl cluster-info &>/dev/null 2>&1; then
        log "Kubernetes 미감지, 건너뜀"
        return
    fi

    log "--- Kubernetes Pod 내부 스캔 ---"

    # 모든 네임스페이스의 Running Pod 목록
    local pods
    pods=$(kubectl get pods --all-namespaces --field-selector=status.phase=Running \
        -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{" "}{range .spec.containers[*]}{.name}{","}{end}{"\n"}{end}' 2>/dev/null || true)

    [[ -z "$pods" ]] && { log "  Running Pod 없음"; return; }

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local ns pod containers
        ns=$(echo "$line" | awk '{print $1}')
        pod=$(echo "$line" | awk '{print $2}')
        containers=$(echo "$line" | awk '{print $3}' | sed 's/,$//')

        IFS=',' read -ra carr <<< "$containers"
        for container in "${carr[@]}"; do
            [[ -z "$container" ]] && continue
            local pod_label="${ns}/${pod}/${container}"
            log "  Pod 검사: ${pod_label}"

            # 직접 jar 검색
            local jar_results
            jar_results=$(kubectl exec -n "$ns" "$pod" -c "$container" -- \
                find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o \
                -type f -name "pac4j-jwt-*.jar" -print 2>/dev/null || true)

            if [[ -n "$jar_results" ]]; then
                while IFS= read -r jarfile; do
                    [[ -z "$jarfile" ]] && continue
                    local filename version
                    filename=$(basename "$jarfile")
                    version=$(extract_version_from_filename "$filename")

                    if [[ -z "$version" ]]; then
                        version=$(kubectl exec -n "$ns" "$pod" -c "$container" -- \
                            unzip -p "$jarfile" '*/pom.properties' 2>/dev/null \
                            | grep '^version=' | head -1 | cut -d'=' -f2 | tr -d '[:space:]' || echo "")
                    fi

                    [[ -z "$version" ]] && version="unknown"
                    report_finding "$jarfile" "$version" "jar_file" "k8s:${pod_label}"
                done <<< "$jar_results"
            fi

            # 아카이브 내부 검색
            local archive_results
            archive_results=$(kubectl exec -n "$ns" "$pod" -c "$container" -- \
                find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o \
                -type f \( -name "*.war" -o -name "*.ear" \) -print 2>/dev/null || true)

            if [[ -n "$archive_results" ]]; then
                while IFS= read -r archive; do
                    [[ -z "$archive" ]] && continue
                    local matches
                    matches=$(kubectl exec -n "$ns" "$pod" -c "$container" -- \
                        unzip -l "$archive" 2>/dev/null | grep -i 'pac4j-jwt' || true)
                    [[ -z "$matches" ]] && continue

                    local inner_jar version
                    inner_jar=$(echo "$matches" | grep -oE 'pac4j-jwt-[0-9][^\s]*\.jar' | head -1 || echo "")
                    version=""
                    [[ -n "$inner_jar" ]] && version=$(extract_version_from_filename "$inner_jar")
                    [[ -z "$version" ]] && version="unknown"
                    report_finding "$archive" "$version" "embedded_in_archive(${inner_jar:-pac4j-jwt})" "k8s:${pod_label}"
                done <<< "$archive_results"
            fi
        done
    done <<< "$pods"
}

###############################################################################
# Section 7: JSON 조립 및 출력
###############################################################################

assemble_json() {
    local scan_date hostname ip_addrs total
    scan_date=$(date -Iseconds)
    hostname=$(hostname)
    ip_addrs=$(get_ip_addresses)
    total=$((COUNT_VULN + COUNT_SAFE + COUNT_UNKNOWN))

    # IP 배열 조립
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
  "cve": "${CVE_ID}",
  "cvss": "${CVSS_SCORE}",
  "description": "pac4j-jwt JWE+JWS 결합 시 PlainJWT로 서명 검증 우회 (인증 우회)",
  "affected_versions": "4.x < 4.5.9, 5.x < 5.7.9, 6.x < 6.3.3",
  "patched_versions": "4.x >= 4.5.9, 5.x >= 5.7.9, 6.x >= 6.3.3",
  "reference": "https://www.codeant.ai/security-research/pac4j-jwt-authentication-bypass-public-key",
  "scan_date": "${scan_date}",
  "hostname": "$(json_escape "$hostname")",
  "os": "$(json_escape "$OS_ID")",
  "os_version": "$(json_escape "$OS_VERSION")",
  "kernel": "$(json_escape "$KERNEL_VERSION")",
  "host_environment": "$(json_escape "$HOST_ENV")",
  "container_runtime": "$(json_escape "${CONTAINER_RUNTIME:-none}")",
  "ip_addresses": ${ip_json},
  "summary": {
    "total": ${total},
    "vulnerable": ${COUNT_VULN},
    "safe": ${COUNT_SAFE},
    "unknown": ${COUNT_UNKNOWN}
  },
  "results": [
${RESULTS}
  ]
}
JSONEOF
}

###############################################################################
# Section 8: main()
###############################################################################

main() {
    local start_time
    start_time=$(date +%s)

    log "============================================"
    log " ${SCANNER_NAME} v${SCANNER_VERSION}"
    log " ${CVE_ID} (CVSS ${CVSS_SCORE})"
    log " 점검 시작: $(date)"
    log "============================================"

    # 환경 탐지
    detect_os
    detect_environment

    # --- 호스트 파일시스템 스캔 ---
    log "=== Phase 1: 호스트 파일시스템 스캔 ==="
    scan_host_direct_jars
    scan_host_archives
    scan_host_build_files

    # --- 컨테이너 스캔 (환경에 따라 자동 분기) ---
    log "=== Phase 2: 컨테이너 환경 스캔 ==="
    case "$HOST_ENV" in
        kubernetes)
            scan_kubernetes_pods
            # K8s에서도 컨테이너 런타임이 docker/podman이면 추가 스캔
            scan_containers
            ;;
        *)
            # 베어메탈/docker 환경: Docker/Podman 컨테이너 스캔
            scan_containers
            ;;
    esac

    # JSON 출력
    local json_output
    json_output=$(assemble_json)

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
    log " 결과: 취약=${COUNT_VULN}, 양호=${COUNT_SAFE}, 확인불가=${COUNT_UNKNOWN}"
    log " 출력: ${OUTPUT_FILE}"
    log "============================================"
}

main
