#!/usr/bin/env bash
###############################################################################
# CVE-2026-27944 Nginx UI Unauthenticated Backup Exposure Scanner
# Version: 1.0
#
# 취약점: Nginx UI /api/backup 엔드포인트 인증 누락 + 복호화 키 헤더 노출 (CVSS 9.8)
# 원인:   /api/backup 경로에 인증/접근제어 미적용,
#         X-Backup-Security 응답 헤더에 암호화 키 평문 전달
# 영향:   인증 없이 서버 백업(계정, 세션 토큰, SSL 키 등) 탈취 및 즉시 복호화
#
# 취약 버전: < 2.3.3
# 패치 버전: >= 2.3.3
#
# 환경 자동 탐지: 베어메탈/VM, Docker, Podman, Kubernetes
# 출력: JSON 파일 + stderr 진행 로그
# 리소스: renice 19, ionice idle (1CPU/1MEM 환경 보호)
###############################################################################
set -o pipefail

###############################################################################
# Section 0: 상수 및 CLI 파싱
###############################################################################
readonly SCANNER_NAME="CVE-2026-27944 Nginx UI Scanner"
readonly SCANNER_VERSION="1.0"
readonly CVE_ID="CVE-2026-27944"
readonly CVSS_SCORE="9.8"
readonly STATUS_VULN="취약"
readonly STATUS_SAFE="양호"
readonly STATUS_UNKNOWN="확인불가"
readonly PATCHED_VERSION="2.3.3"

OUTPUT_FILE=""
RESULTS=""          # JSON results array items (newline-separated)
COUNT_VULN=0
COUNT_SAFE=0
COUNT_UNKNOWN=0
declare -A SCANNED_PATHS  # 전역 중복 경로 추적 (프로세스→바이너리→systemd 간 공유)

usage() {
    cat >&2 <<EOF
사용법: $0 [옵션]

옵션:
  --output, -o FILE   결과 JSON 파일 경로 (기본: /tmp/cve_2026_27944_HOSTNAME_DATE.json)
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

# hostname 획득 (minimal 환경 fallback 포함)
get_hostname() {
    if command -v hostname &>/dev/null; then
        hostname
    elif [[ -f /etc/hostname ]]; then
        cat /etc/hostname | tr -d '[:space:]'
    elif [[ -f /proc/sys/kernel/hostname ]]; then
        cat /proc/sys/kernel/hostname
    else
        echo "unknown"
    fi
}

if [[ -z "$OUTPUT_FILE" ]]; then
    OUTPUT_FILE="/tmp/cve_2026_27944_$(get_hostname)_$(TZ=Asia/Seoul date +%Y%m%d_%H%M%S).json"
fi

# 리소스 보호: CPU/IO 우선순위를 최저로 설정 (1CPU/1GB VM 서비스 가용성 보호)
renice -n 19 $$ &>/dev/null || true
ionice -c 3 -p $$ &>/dev/null || true

###############################################################################
# Section 1: 유틸리티 함수
###############################################################################
log() {
    echo "[$(TZ=Asia/Seoul date +%H:%M:%S)] $*" >&2
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
    elif [[ -f /proc/net/fib_trie ]]; then
        # minimal 환경 fallback: /proc/net/fib_trie에서 로컬 IP 추출
        awk '/32 host/ { print f } { f=$2 }' /proc/net/fib_trie 2>/dev/null \
            | grep -v '^127\.' | sort -u | tr '\n' ',' | sed 's/,$//'
    fi
}

###############################################################################
# Section 2: 환경 탐지
###############################################################################
OS_ID=""
OS_VERSION=""
KERNEL_VERSION=""
HOST_ENV=""           # baremetal | docker | kubernetes
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

    # 취약: < 2.3.3
    if [[ "$major" -lt 2 ]]; then
        return 0
    elif [[ "$major" -eq 2 ]]; then
        if [[ "$minor" -lt 3 ]]; then
            return 0
        elif [[ "$minor" -eq 3 ]] && [[ "$patch" -lt 3 ]]; then
            return 0
        else
            return 1
        fi
    else
        # 3.x+ 는 패치됨
        return 1
    fi
}

# nginx-ui -v 또는 --version 출력에서 버전 추출
# 예상 출력 형식: "nginx-ui version 2.3.1" 또는 "2.3.1"
extract_version_from_output() {
    local output="$1"
    echo "$output" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo ""
}

# 버전+경로로 결과 기록
report_finding() {
    local location="$1" version="$2" source_type="$3" container_info="${4:-}"
    local status detail patched_ver=""

    if [[ -z "$version" || "$version" == "unknown" ]]; then
        status="$STATUS_UNKNOWN"
        detail="Nginx UI 발견, 버전 확인 불가. 수동 점검 필요"
        version="unknown"
    else
        check_version "$version" && rc=$? || rc=$?
        case $rc in
            0)
                status="$STATUS_VULN"
                patched_ver="$PATCHED_VERSION"
                detail="취약 버전 v${version} → v${patched_ver} 이상으로 업그레이드 필요" ;;
            1)
                status="$STATUS_SAFE"
                detail="패치 완료 (v${version})" ;;
            2)
                status="$STATUS_UNKNOWN"
                detail="버전 판별 불가 (v${version}). 수동 점검 필요" ;;
        esac
    fi

    add_result "$location" "$version" "$status" "$detail" "$source_type" "$patched_ver" "$container_info"
}

###############################################################################
# Section 4: 스캔 함수 - 호스트
###############################################################################

# 4-1: 프로세스 기반 탐지 (실행 중인 nginx-ui)
scan_host_process() {
    log "--- 호스트: nginx-ui 프로세스 검색 ---"

    local pids
    pids=$(pgrep -f 'nginx-ui' 2>/dev/null || true)
    [[ -z "$pids" ]] && { log "  실행 중인 nginx-ui 프로세스 없음"; return; }

    while IFS= read -r pid; do
        [[ -z "$pid" ]] && continue

        # 프로세스의 실제 바이너리 경로 획득
        local exe_path
        exe_path=$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)
        [[ -z "$exe_path" ]] && continue

        # 셸 스크립트로 실행된 경우 exe_path가 /bin/bash 등을 가리킴
        # cmdline에서 실제 nginx-ui 바이너리 경로를 추출
        local cmdline
        cmdline=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || true)

        # exe가 nginx-ui가 아니면 cmdline에서 nginx-ui 경로 추출 시도
        if [[ "$(basename "$exe_path")" != "nginx-ui" ]]; then
            local cmd_bin=""
            # cmdline에서 nginx-ui 포함 경로 추출 (인터프리터 뒤 스크립트 경로)
            cmd_bin=$(echo "$cmdline" | grep -oE '/[^ ]*nginx-ui' | head -1 || true)
            if [[ -n "$cmd_bin" && -x "$cmd_bin" ]]; then
                exe_path="$cmd_bin"
            else
                # exe가 bash/sh 등 인터프리터이고 cmdline에서도 nginx-ui 바이너리 경로를 못 찾으면 건너뜀
                continue
            fi
        fi

        [[ -n "${SCANNED_PATHS[$exe_path]:-}" ]] && continue
        SCANNED_PATHS["$exe_path"]=1

        # 버전 추출
        local version_output version
        version_output=$("$exe_path" -v 2>&1 || "$exe_path" --version 2>&1 || echo "")
        version=$(extract_version_from_output "$version_output")
        [[ -z "$version" ]] && version="unknown"

        report_finding "$exe_path" "$version" "running_process(pid:${pid})"
    done <<< "$pids"
}

# 4-2: 파일시스템에서 nginx-ui 바이너리 검색
scan_host_binaries() {
    log "--- 호스트: nginx-ui 바이너리 파일 검색 ---"

    # 1) 일반적 설치 경로 우선 확인
    local common_paths=(
        /usr/local/bin/nginx-ui
        /usr/bin/nginx-ui
        /opt/nginx-ui/nginx-ui
        /usr/local/nginx-ui/nginx-ui
    )

    for binpath in "${common_paths[@]}"; do
        [[ ! -f "$binpath" ]] && continue
        [[ ! -x "$binpath" ]] && continue
        [[ -n "${SCANNED_PATHS[$binpath]:-}" ]] && continue
        SCANNED_PATHS["$binpath"]=1

        local version_output version
        version_output=$("$binpath" -v 2>&1 || "$binpath" --version 2>&1 || echo "")
        version=$(extract_version_from_output "$version_output")
        [[ -z "$version" ]] && version="unknown"

        report_finding "$binpath" "$version" "binary_file"
    done

    # 2) 전체 파일시스템 검색 (위 경로에서 발견 못 한 경우 보완)
    while IFS= read -r binpath; do
        [[ -z "$binpath" ]] && continue
        [[ -n "${SCANNED_PATHS[$binpath]:-}" ]] && continue
        [[ ! -x "$binpath" ]] && continue
        SCANNED_PATHS["$binpath"]=1

        local version_output version
        version_output=$("$binpath" -v 2>&1 || "$binpath" --version 2>&1 || echo "")
        version=$(extract_version_from_output "$version_output")
        [[ -z "$version" ]] && version="unknown"

        report_finding "$binpath" "$version" "binary_file"
    done < <(find / \
        -path /proc -prune -o \
        -path /sys -prune -o \
        -path /dev -prune -o \
        -path /run -prune -o \
        -path /snap -prune -o \
        -path /var/lib/docker -prune -o \
        -path /var/lib/containers -prune -o \
        -path /var/lib/kubelet -prune -o \
        -path /var/lib/containerd -prune -o \
        -type f -name "nginx-ui" -print 2>/dev/null)
}

# 4-3: systemd 서비스 유닛 검색
scan_host_systemd() {
    log "--- 호스트: systemd 서비스 검색 ---"

    local unit_files
    unit_files=$(find /etc/systemd /usr/lib/systemd /run/systemd \
        -type f -name "*nginx-ui*" -print 2>/dev/null || true)
    [[ -z "$unit_files" ]] && { log "  nginx-ui systemd 서비스 없음"; return; }

    while IFS= read -r unit_file; do
        [[ -z "$unit_file" ]] && continue
        # ExecStart 에서 바이너리 경로 추출
        local exec_path
        exec_path=$(grep -oP '^ExecStart=\K\S+' "$unit_file" 2>/dev/null | head -1 || true)

        local version="unknown"
        if [[ -n "$exec_path" && -x "$exec_path" ]]; then
            local version_output
            version_output=$("$exec_path" -v 2>&1 || "$exec_path" --version 2>&1 || echo "")
            version=$(extract_version_from_output "$version_output")
            [[ -z "$version" ]] && version="unknown"
        fi

        report_finding "$unit_file" "$version" "systemd_unit"
    done <<< "$unit_files"
}

###############################################################################
# Section 5: 스캔 함수 - Docker/Podman 컨테이너
###############################################################################

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

    log "--- ${CONTAINER_CLI} 컨테이너 스캔 ---"

    # nginx-ui 관련 이미지/이름 포함 컨테이너 검색
    local container_list
    container_list=$($CONTAINER_CLI ps --format '{{.ID}}\t{{.Names}}\t{{.Image}}' 2>/dev/null || true)
    [[ -z "$container_list" ]] && { log "  실행 중인 컨테이너 없음"; return; }

    while IFS=$'\t' read -r cid cname cimage; do
        [[ -z "$cid" ]] && continue

        # 1) 이미지명/컨테이너명에 nginx-ui 포함 여부 확인
        local is_nginxui=0
        if echo "$cimage" | grep -qi 'nginx-ui'; then
            is_nginxui=1
        elif echo "$cname" | grep -qi 'nginx-ui'; then
            is_nginxui=1
        fi

        # 2) 컨테이너 내부에 nginx-ui 프로세스/바이너리 존재 확인
        if [[ $is_nginxui -eq 0 ]]; then
            local proc_check
            proc_check=$($CONTAINER_CLI exec "$cid" pgrep -f 'nginx-ui' 2>/dev/null || true)
            if [[ -n "$proc_check" ]]; then
                is_nginxui=1
            fi
        fi

        [[ $is_nginxui -eq 0 ]] && continue

        local container_label="${CONTAINER_CLI}:${cname}"
        log "  컨테이너 검사: ${cname} (${cimage})"

        # 버전 추출: 컨테이너 내부에서 nginx-ui -v 실행
        local version_output version
        version_output=$($CONTAINER_CLI exec "$cid" sh -c 'nginx-ui -v 2>&1 || /usr/local/bin/nginx-ui -v 2>&1 || /usr/bin/nginx-ui -v 2>&1' 2>/dev/null || true)
        version=$(extract_version_from_output "$version_output")

        # 바이너리 버전 못 찾으면 이미지 태그에서 추출
        if [[ -z "$version" ]]; then
            version=$(echo "$cimage" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
        fi

        [[ -z "$version" ]] && version="unknown"
        report_finding "${cimage}" "$version" "container" "$container_label"
    done <<< "$container_list"
}

###############################################################################
# Section 6: 스캔 함수 - Kubernetes
###############################################################################

scan_kubernetes_pods() {
    if ! command -v kubectl &>/dev/null || ! kubectl cluster-info &>/dev/null 2>&1; then
        log "Kubernetes 미감지, 건너뜀"
        return
    fi

    log "--- Kubernetes Pod 스캔 ---"

    # nginx-ui 관련 Pod 검색 (이미지명 기준)
    local pods
    pods=$(kubectl get pods --all-namespaces --field-selector=status.phase=Running \
        -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{" "}{range .spec.containers[*]}{.name}{"|"}{.image}{","}{end}{"\n"}{end}' 2>/dev/null || true)

    [[ -z "$pods" ]] && { log "  Running Pod 없음"; return; }

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local ns pod containers_raw
        ns=$(echo "$line" | awk '{print $1}')
        pod=$(echo "$line" | awk '{print $2}')
        containers_raw=$(echo "$line" | awk '{print $3}' | sed 's/,$//')

        IFS=',' read -ra carr <<< "$containers_raw"
        for centry in "${carr[@]}"; do
            [[ -z "$centry" ]] && continue
            local container image
            container=$(echo "$centry" | cut -d'|' -f1)
            image=$(echo "$centry" | cut -d'|' -f2)

            # nginx-ui 관련 이미지만 검사
            if ! echo "$image" | grep -qi 'nginx-ui'; then
                # 이미지명에 없으면 프로세스 확인
                local proc_check
                proc_check=$(kubectl exec -n "$ns" "$pod" -c "$container" -- \
                    pgrep -f 'nginx-ui' 2>/dev/null || true)
                [[ -z "$proc_check" ]] && continue
            fi

            local pod_label="${ns}/${pod}/${container}"
            log "  Pod 검사: ${pod_label}"

            # 버전 추출
            local version_output version
            version_output=$(kubectl exec -n "$ns" "$pod" -c "$container" -- \
                sh -c 'nginx-ui -v 2>&1 || /usr/local/bin/nginx-ui -v 2>&1' 2>/dev/null || true)
            version=$(extract_version_from_output "$version_output")

            # 이미지 태그에서 추출 시도
            if [[ -z "$version" ]]; then
                version=$(echo "$image" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "")
            fi

            [[ -z "$version" ]] && version="unknown"
            report_finding "${image}" "$version" "kubernetes_pod" "k8s:${pod_label}"
        done
    done <<< "$pods"
}

###############################################################################
# Section 7: JSON 조립 및 출력
###############################################################################

assemble_json() {
    local scan_date cur_hostname ip_addrs total
    scan_date=$(TZ=Asia/Seoul date -Iseconds)
    cur_hostname=$(get_hostname)
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
  "description": "Nginx UI /api/backup 엔드포인트 인증 누락, X-Backup-Security 헤더에 복호화 키 평문 노출 (백업 데이터 무단 탈취)",
  "affected_versions": "< 2.3.3",
  "patched_versions": ">= 2.3.3",
  "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-27944",
  "scan_date": "${scan_date}",
  "hostname": "$(json_escape "$cur_hostname")",
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
    log " 점검 시작: $(TZ=Asia/Seoul date)"
    log "============================================"

    # 환경 탐지
    detect_os
    detect_environment

    # --- 호스트 스캔 ---
    log "=== Phase 1: 호스트 스캔 ==="
    scan_host_process
    scan_host_binaries
    scan_host_systemd

    # --- 컨테이너 스캔 (환경에 따라 자동 분기) ---
    log "=== Phase 2: 컨테이너 환경 스캔 ==="
    case "$HOST_ENV" in
        kubernetes)
            scan_kubernetes_pods
            scan_containers
            ;;
        *)
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
