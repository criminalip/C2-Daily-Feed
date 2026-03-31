#!/usr/bin/env bash
###############################################################################
# CVE-2026-27944 Nginx UI Scanner - QA 테스트 스위트
#
# 외부 의존성: 없음 (순수 bash, python/jq 불필요)
# 실행 조건: root 권한 (스캐너가 root 필요)
# 자동 실행: 사용자 개입 0, 가상 환경 자동 구성/정리
###############################################################################
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCANNER="${SCRIPT_DIR}/cve_2026_27944_nginxui_scanner.sh"
TEST_DIR=$(mktemp -d /tmp/nginxui_qa_XXXXXX)

PASS=0
FAIL=0
TOTAL=0

# 색상 (터미널 미지원 시 자동 비활성화)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' NC=''
fi

###############################################################################
# 테스트 유틸리티 (외부 의존성 없음)
###############################################################################

assert_eq() {
    local test_name="$1" expected="$2" actual="$3"
    ((TOTAL++))
    if [[ "$expected" == "$actual" ]]; then
        ((PASS++))
        echo -e "  ${GREEN}[PASS]${NC} ${test_name}"
    else
        ((FAIL++))
        echo -e "  ${RED}[FAIL]${NC} ${test_name}"
        echo -e "         expected: ${YELLOW}${expected}${NC}"
        echo -e "         actual:   ${YELLOW}${actual}${NC}"
    fi
}

assert_contains() {
    local test_name="$1" needle="$2" haystack="$3"
    ((TOTAL++))
    if echo "$haystack" | grep -qF -- "$needle"; then
        ((PASS++))
        echo -e "  ${GREEN}[PASS]${NC} ${test_name}"
    else
        ((FAIL++))
        echo -e "  ${RED}[FAIL]${NC} ${test_name}"
        echo -e "         '${YELLOW}${needle}${NC}' not found in output"
    fi
}

# 순수 bash JSON 유효성 검증 (python3/jq 불필요)
# 구조적 검증: 중괄호/대괄호 균형, 기본 문법
assert_json_valid() {
    local test_name="$1" json_file="$2"
    ((TOTAL++))

    if [[ ! -f "$json_file" ]]; then
        ((FAIL++))
        echo -e "  ${RED}[FAIL]${NC} ${test_name} (파일 없음: ${json_file})"
        return
    fi

    local content
    content=$(< "$json_file")

    # 1) 빈 파일 체크
    if [[ -z "$content" ]]; then
        ((FAIL++))
        echo -e "  ${RED}[FAIL]${NC} ${test_name} (빈 파일)"
        return
    fi

    # 2) 첫 문자가 { 인지 확인
    local trimmed
    trimmed=$(echo "$content" | sed 's/^[[:space:]]*//')
    if [[ "${trimmed:0:1}" != "{" ]]; then
        ((FAIL++))
        echo -e "  ${RED}[FAIL]${NC} ${test_name} (JSON 객체가 아님)"
        return
    fi

    # 3) 중괄호/대괄호 균형 검증
    local open_braces close_braces open_brackets close_brackets
    open_braces=$(echo "$content" | tr -cd '{' | wc -c)
    close_braces=$(echo "$content" | tr -cd '}' | wc -c)
    open_brackets=$(echo "$content" | tr -cd '[' | wc -c)
    close_brackets=$(echo "$content" | tr -cd ']' | wc -c)

    if [[ "$open_braces" -ne "$close_braces" ]]; then
        ((FAIL++))
        echo -e "  ${RED}[FAIL]${NC} ${test_name} (중괄호 불균형: { ${open_braces} vs } ${close_braces})"
        return
    fi

    if [[ "$open_brackets" -ne "$close_brackets" ]]; then
        ((FAIL++))
        echo -e "  ${RED}[FAIL]${NC} ${test_name} (대괄호 불균형: [ ${open_brackets} vs ] ${close_brackets})"
        return
    fi

    # 4) 후행 쉼표 검증 (JSON 문법 오류의 가장 흔한 원인)
    if grep -qE ',\s*[}\]]' "$json_file"; then
        ((FAIL++))
        echo -e "  ${RED}[FAIL]${NC} ${test_name} (후행 쉼표 발견)"
        return
    fi

    ((PASS++))
    echo -e "  ${GREEN}[PASS]${NC} ${test_name}"
}

# 순수 bash JSON 필드 값 추출 (python3/jq 불필요)
# 지원: 최상위 문자열/숫자 필드, summary.* 1단계 중첩, results.N.* 배열 접근
json_get() {
    local json_file="$1" field="$2"
    local content
    content=$(< "$json_file")

    if [[ "$field" == results.* ]]; then
        # results.0.fieldname 형식 파싱
        local idx subfield
        idx=$(echo "$field" | cut -d. -f2)
        subfield=$(echo "$field" | cut -d. -f3)

        # results 배열에서 N번째 객체 추출
        local in_results=0 brace_depth=0 current_idx=-1 obj=""
        while IFS= read -r line; do
            # "results": [ 시작 감지
            if [[ $in_results -eq 0 ]]; then
                if echo "$line" | grep -qE '"results"\s*:\s*\['; then
                    in_results=1
                    continue
                fi
            else
                # 객체 시작 { 감지
                if echo "$line" | grep -qE '^\s*\{' && [[ $brace_depth -eq 0 ]]; then
                    ((current_idx++))
                    brace_depth=1
                    obj="$line"
                    continue
                fi

                if [[ $brace_depth -gt 0 ]]; then
                    obj="${obj}"$'\n'"${line}"
                    local opens closes
                    opens=$(echo "$line" | tr -cd '{' | wc -c)
                    closes=$(echo "$line" | tr -cd '}' | wc -c)
                    brace_depth=$((brace_depth + opens - closes))

                    # 객체 완료
                    if [[ $brace_depth -eq 0 && $current_idx -eq $idx ]]; then
                        # 객체에서 subfield 추출
                        echo "$obj" | grep -oE "\"${subfield}\"\s*:\s*\"[^\"]*\"" | head -1 \
                            | sed -E "s/\"${subfield}\"\s*:\s*\"([^\"]*)\"/\1/"
                        return
                    fi
                fi

                # results 배열 끝
                if echo "$line" | grep -qE '^\s*\]' && [[ $brace_depth -eq 0 ]]; then
                    break
                fi
            fi
        done <<< "$content"
    elif [[ "$field" == summary.* ]]; then
        # summary.fieldname 형식
        local subfield
        subfield=$(echo "$field" | cut -d. -f2)
        # summary 블록 내에서 숫자 값 추출
        local in_summary=0
        while IFS= read -r line; do
            if echo "$line" | grep -qE '"summary"\s*:'; then
                in_summary=1
                continue
            fi
            if [[ $in_summary -eq 1 ]]; then
                if echo "$line" | grep -qE "\"${subfield}\"\s*:"; then
                    echo "$line" | grep -oE "\"${subfield}\"\s*:\s*[0-9]+" | head -1 \
                        | sed -E "s/\"${subfield}\"\s*:\s*([0-9]+)/\1/"
                    return
                fi
                # summary 블록 끝
                if echo "$line" | grep -qE '^\s*}'; then
                    in_summary=0
                fi
            fi
        done <<< "$content"
    else
        # 최상위 필드 (문자열)
        local val
        val=$(echo "$content" | grep -oE "\"${field}\"\s*:\s*\"[^\"]*\"" | head -1 \
            | sed -E "s/\"${field}\"\s*:\s*\"([^\"]*)\"/\1/")
        if [[ -n "$val" ]]; then
            echo "$val"
            return
        fi
        # 최상위 필드 (숫자)
        echo "$content" | grep -oE "\"${field}\"\s*:\s*[0-9]+" | head -1 \
            | sed -E "s/\"${field}\"\s*:\s*([0-9]+)/\1/"
    fi
}

assert_json_field() {
    local test_name="$1" json_file="$2" field="$3" expected="$4"
    ((TOTAL++))
    local actual
    actual=$(json_get "$json_file" "$field")
    if [[ "$actual" == "$expected" ]]; then
        ((PASS++))
        echo -e "  ${GREEN}[PASS]${NC} ${test_name}"
    else
        ((FAIL++))
        echo -e "  ${RED}[FAIL]${NC} ${test_name}"
        echo -e "         field '${field}': expected=${YELLOW}${expected}${NC}, actual=${YELLOW}${actual}${NC}"
    fi
}

# JSON 필드 존재 여부 (순수 bash)
assert_json_has_field() {
    local test_name="$1" json_file="$2" field="$3"
    ((TOTAL++))
    if grep -qE "\"${field}\"\s*:" "$json_file"; then
        ((PASS++))
        echo -e "  ${GREEN}[PASS]${NC} ${test_name}"
    else
        ((FAIL++))
        echo -e "  ${RED}[FAIL]${NC} ${test_name}"
        echo -e "         필드 '${field}' 미발견"
    fi
}

# results 배열 길이 (순수 bash)
json_results_count() {
    local json_file="$1"
    local content
    content=$(< "$json_file")
    local in_results=0 brace_depth=0 count=0
    while IFS= read -r line; do
        if [[ $in_results -eq 0 ]]; then
            if echo "$line" | grep -qE '"results"\s*:\s*\['; then
                in_results=1
                continue
            fi
        else
            if echo "$line" | grep -qE '^\s*\{' && [[ $brace_depth -eq 0 ]]; then
                ((count++))
                brace_depth=1
                continue
            fi
            if [[ $brace_depth -gt 0 ]]; then
                local opens closes
                opens=$(echo "$line" | tr -cd '{' | wc -c)
                closes=$(echo "$line" | tr -cd '}' | wc -c)
                brace_depth=$((brace_depth + opens - closes))
            fi
            if echo "$line" | grep -qE '^\s*\]' && [[ $brace_depth -eq 0 ]]; then
                break
            fi
        fi
    done <<< "$content"
    echo "$count"
}

# ip_addresses가 배열인지 확인 (순수 bash)
assert_json_array_field() {
    local test_name="$1" json_file="$2" field="$3"
    ((TOTAL++))
    if grep -qE "\"${field}\"\s*:\s*\[" "$json_file"; then
        ((PASS++))
        echo -e "  ${GREEN}[PASS]${NC} ${test_name}"
    else
        ((FAIL++))
        echo -e "  ${RED}[FAIL]${NC} ${test_name}"
    fi
}

# 스캐너에서 함수만 소싱 (main 실행 방지, root 체크/renice 제거)
source_functions() {
    local tmp_source="${TEST_DIR}/_scanner_functions.sh"
    sed -e 's/^main$/# main/' \
        -e '/^if \[\[ \$EUID -ne 0 \]\]/,/^fi$/d' \
        -e '/^renice /d' \
        -e '/^ionice /d' \
        "$SCANNER" > "$tmp_source"
    source "$tmp_source"
}

cleanup() {
    rm -rf "$TEST_DIR" 2>/dev/null
}
trap cleanup EXIT

###############################################################################
echo -e "\n${CYAN}========================================${NC}"
echo -e "${CYAN} CVE-2026-27944 Nginx UI Scanner QA${NC}"
echo -e "${CYAN} 외부 의존성: 없음 (순수 bash)${NC}"
echo -e "${CYAN}========================================${NC}\n"

###############################################################################
# TEST GROUP 1: check_version() 버전 판별 로직
###############################################################################
echo -e "${CYAN}[Group 1] check_version() 버전 판별 로직 (22건)${NC}"

source_functions

# 취약 케이스 (< 2.3.3) → return 0
check_version "0.1.0"; assert_eq "v0.1.0 → 취약 (0.x)" "0" "$?"
check_version "1.0.0"; assert_eq "v1.0.0 → 취약 (1.x)" "0" "$?"
check_version "1.9.9"; assert_eq "v1.9.9 → 취약 (1.x 최대)" "0" "$?"
check_version "2.0.0"; assert_eq "v2.0.0 → 취약 (2.0.0)" "0" "$?"
check_version "2.2.9"; assert_eq "v2.2.9 → 취약 (minor < 3)" "0" "$?"
check_version "2.3.0"; assert_eq "v2.3.0 → 취약 (2.3.0)" "0" "$?"
check_version "2.3.1"; assert_eq "v2.3.1 → 취약 (2.3.1)" "0" "$?"
check_version "2.3.2"; assert_eq "v2.3.2 → 취약 (경계값 직전)" "0" "$?"

# 안전 케이스 (>= 2.3.3) → return 1
check_version "2.3.3"; assert_eq "v2.3.3 → 양호 (정확히 패치 버전)" "1" "$?"
check_version "2.3.4"; assert_eq "v2.3.4 → 양호 (패치 초과)" "1" "$?"
check_version "2.3.10"; assert_eq "v2.3.10 → 양호 (patch 10)" "1" "$?"
check_version "2.4.0"; assert_eq "v2.4.0 → 양호 (minor 상위)" "1" "$?"
check_version "2.10.0"; assert_eq "v2.10.0 → 양호 (minor 10)" "1" "$?"
check_version "3.0.0"; assert_eq "v3.0.0 → 양호 (3.x)" "1" "$?"
check_version "3.1.5"; assert_eq "v3.1.5 → 양호 (3.x+)" "1" "$?"
check_version "10.0.0"; assert_eq "v10.0.0 → 양호 (major 10)" "1" "$?"

# 판단 불가 → return 2
check_version ""; assert_eq "빈 문자열 → 판단불가" "2" "$?"
check_version "unknown"; assert_eq "'unknown' → 판단불가" "2" "$?"
check_version "abc"; assert_eq "'abc' → 판단불가" "2" "$?"
check_version "v2"; assert_eq "'v2' (불완전) → 판단불가" "2" "$?"

# 접미사 처리
check_version "2.3.2-beta"; assert_eq "v2.3.2-beta → 취약 (접미사 무시)" "0" "$?"
check_version "2.3.3-rc1"; assert_eq "v2.3.3-rc1 → 양호 (접미사 무시)" "1" "$?"

###############################################################################
# TEST GROUP 2: extract_version_from_output() 버전 추출
###############################################################################
echo -e "\n${CYAN}[Group 2] extract_version_from_output() 버전 추출 (7건)${NC}"

v=$(extract_version_from_output "nginx-ui version 2.3.1")
assert_eq "표준 출력: 'nginx-ui version 2.3.1'" "2.3.1" "$v"

v=$(extract_version_from_output "2.3.3")
assert_eq "숫자만: '2.3.3'" "2.3.3" "$v"

v=$(extract_version_from_output "Nginx UI v2.3.2 (build 20260301)")
assert_eq "복잡한 출력: 'Nginx UI v2.3.2 (build ...)'" "2.3.2" "$v"

v=$(extract_version_from_output "nginx-ui version v2.0.0-beta.30")
assert_eq "beta 접미사: 'v2.0.0-beta.30'" "2.0.0" "$v"

v=$(extract_version_from_output "")
assert_eq "빈 출력" "" "$v"

v=$(extract_version_from_output "no version here")
assert_eq "버전 없는 문자열" "" "$v"

v=$(extract_version_from_output $'nginx-ui version 2.3.5\nsome other output')
assert_eq "멀티라인 출력: 첫 번째 줄 버전 추출" "2.3.5" "$v"

###############################################################################
# TEST GROUP 3: json_escape() 특수문자 이스케이프
###############################################################################
echo -e "\n${CYAN}[Group 3] json_escape() 특수문자 이스케이프 (6건)${NC}"

r=$(json_escape 'hello "world"')
assert_eq "큰따옴표 이스케이프" 'hello \"world\"' "$r"

r=$(json_escape 'path\to\file')
assert_eq "백슬래시 이스케이프" 'path\\to\\file' "$r"

r=$(json_escape $'line1\nline2')
assert_eq "줄바꿈 이스케이프" 'line1\nline2' "$r"

r=$(json_escape $'tab\there')
assert_eq "탭 이스케이프" 'tab\there' "$r"

r=$(json_escape "일반 텍스트")
assert_eq "한글 텍스트 보존" "일반 텍스트" "$r"

r=$(json_escape "")
assert_eq "빈 문자열" "" "$r"

###############################################################################
# TEST GROUP 4: report_finding() 결과 기록 로직
###############################################################################
echo -e "\n${CYAN}[Group 4] report_finding() 결과 기록 (9건)${NC}"

# 상태 초기화
RESULTS=""
COUNT_VULN=0
COUNT_SAFE=0
COUNT_UNKNOWN=0

report_finding "/usr/bin/nginx-ui" "2.3.0" "binary_file" "" 2>/dev/null
assert_eq "취약 버전 카운트 증가" "1" "$COUNT_VULN"
assert_contains "취약 결과에 업그레이드 안내" "v2.3.3 이상으로 업그레이드 필요" "$RESULTS"
assert_contains "패치 버전 포함" '"patched_version": "2.3.3"' "$RESULTS"

report_finding "/usr/bin/nginx-ui" "2.3.3" "binary_file" "" 2>/dev/null
assert_eq "양호 버전 카운트 증가" "1" "$COUNT_SAFE"
assert_contains "양호 결과에 패치 완료 메시지" "패치 완료 (v2.3.3)" "$RESULTS"

report_finding "/usr/bin/nginx-ui" "unknown" "binary_file" "" 2>/dev/null
assert_eq "확인불가 카운트 증가" "1" "$COUNT_UNKNOWN"
assert_contains "확인불가 수동 점검 안내" "수동 점검 필요" "$RESULTS"

report_finding "/usr/bin/nginx-ui" "" "binary_file" "" 2>/dev/null
assert_eq "빈 버전도 확인불가 처리" "2" "$COUNT_UNKNOWN"

# 컨테이너 정보 포함
RESULTS=""
COUNT_VULN=0
report_finding "uozi/nginx-ui:2.3.1" "2.3.1" "container" "docker:nginx-ui-web" 2>/dev/null
assert_contains "컨테이너 정보 포함" '"container": "docker:nginx-ui-web"' "$RESULTS"

###############################################################################
# TEST GROUP 5: 통합 테스트 - 가상 취약 바이너리
###############################################################################
echo -e "\n${CYAN}[Group 5] 통합 테스트 - 가상 취약 바이너리 (9건)${NC}"

MOCK_BIN_DIR="${TEST_DIR}/mock_bin"
mkdir -p "$MOCK_BIN_DIR"

cat > "${MOCK_BIN_DIR}/nginx-ui" << 'MOCKEOF'
#!/bin/bash
echo "nginx-ui version 2.3.1"
MOCKEOF
chmod +x "${MOCK_BIN_DIR}/nginx-ui"

MOCK_OUTPUT="${TEST_DIR}/mock_result.json"

(
    source_functions

    scan_host_binaries() {
        local binpath="${MOCK_BIN_DIR}/nginx-ui"
        if [[ -f "$binpath" && -x "$binpath" ]]; then
            local version_output version
            version_output=$("$binpath" -v 2>&1 || echo "")
            version=$(extract_version_from_output "$version_output")
            [[ -z "$version" ]] && version="unknown"
            report_finding "$binpath" "$version" "binary_file"
        fi
    }
    scan_host_process() { :; }
    scan_host_systemd() { :; }
    scan_containers() { :; }
    scan_kubernetes_pods() { :; }

    OUTPUT_FILE="$MOCK_OUTPUT"
    detect_os
    detect_environment
    scan_host_binaries
    json_output=$(assemble_json)
    (umask 077; echo "$json_output" > "$OUTPUT_FILE")
) 2>/dev/null

assert_json_valid "JSON 유효성 검증 (취약 바이너리)" "$MOCK_OUTPUT"
assert_json_field "scanner 필드" "$MOCK_OUTPUT" "scanner" "CVE-2026-27944 Nginx UI Scanner"
assert_json_field "CVE ID" "$MOCK_OUTPUT" "cve" "CVE-2026-27944"
assert_json_field "CVSS 점수" "$MOCK_OUTPUT" "cvss" "9.8"
assert_json_field "취약 건수" "$MOCK_OUTPUT" "summary.vulnerable" "1"
assert_json_field "양호 건수" "$MOCK_OUTPUT" "summary.safe" "0"
assert_json_field "결과 상태 = 취약" "$MOCK_OUTPUT" "results.0.status" "취약"
assert_json_field "결과 버전 = 2.3.1" "$MOCK_OUTPUT" "results.0.version" "2.3.1"
assert_json_field "패치 버전 = 2.3.3" "$MOCK_OUTPUT" "results.0.patched_version" "2.3.3"

###############################################################################
# TEST GROUP 6: 통합 테스트 - 양호 바이너리
###############################################################################
echo -e "\n${CYAN}[Group 6] 통합 테스트 - 양호 바이너리 (6건)${NC}"

cat > "${MOCK_BIN_DIR}/nginx-ui" << 'MOCKEOF'
#!/bin/bash
echo "nginx-ui version 2.3.3"
MOCKEOF
chmod +x "${MOCK_BIN_DIR}/nginx-ui"

MOCK_OUTPUT2="${TEST_DIR}/mock_result_safe.json"

(
    source_functions

    scan_host_binaries() {
        local binpath="${MOCK_BIN_DIR}/nginx-ui"
        if [[ -f "$binpath" && -x "$binpath" ]]; then
            local version_output version
            version_output=$("$binpath" -v 2>&1 || echo "")
            version=$(extract_version_from_output "$version_output")
            [[ -z "$version" ]] && version="unknown"
            report_finding "$binpath" "$version" "binary_file"
        fi
    }
    scan_host_process() { :; }
    scan_host_systemd() { :; }
    scan_containers() { :; }
    scan_kubernetes_pods() { :; }

    OUTPUT_FILE="$MOCK_OUTPUT2"
    detect_os
    detect_environment
    scan_host_binaries
    json_output=$(assemble_json)
    (umask 077; echo "$json_output" > "$OUTPUT_FILE")
) 2>/dev/null

assert_json_valid "JSON 유효성 검증 (양호 바이너리)" "$MOCK_OUTPUT2"
assert_json_field "취약 건수 = 0" "$MOCK_OUTPUT2" "summary.vulnerable" "0"
assert_json_field "양호 건수 = 1" "$MOCK_OUTPUT2" "summary.safe" "1"
assert_json_field "결과 상태 = 양호" "$MOCK_OUTPUT2" "results.0.status" "양호"
assert_json_field "결과 버전 = 2.3.3" "$MOCK_OUTPUT2" "results.0.version" "2.3.3"
assert_json_field "패치 버전 빈값 (양호)" "$MOCK_OUTPUT2" "results.0.patched_version" ""

###############################################################################
# TEST GROUP 7: 통합 테스트 - nginx-ui 미설치 (결과 0건)
###############################################################################
echo -e "\n${CYAN}[Group 7] 통합 테스트 - nginx-ui 미설치 (6건)${NC}"

MOCK_OUTPUT3="${TEST_DIR}/mock_result_none.json"

(
    source_functions

    scan_host_process() { :; }
    scan_host_binaries() { :; }
    scan_host_systemd() { :; }
    scan_containers() { :; }
    scan_kubernetes_pods() { :; }

    OUTPUT_FILE="$MOCK_OUTPUT3"
    detect_os
    detect_environment
    json_output=$(assemble_json)
    (umask 077; echo "$json_output" > "$OUTPUT_FILE")
) 2>/dev/null

assert_json_valid "JSON 유효성 검증 (미설치)" "$MOCK_OUTPUT3"
assert_json_field "총 건수 = 0" "$MOCK_OUTPUT3" "summary.total" "0"
assert_json_field "취약 = 0" "$MOCK_OUTPUT3" "summary.vulnerable" "0"
assert_json_field "양호 = 0" "$MOCK_OUTPUT3" "summary.safe" "0"
assert_json_field "확인불가 = 0" "$MOCK_OUTPUT3" "summary.unknown" "0"

result_count=$(json_results_count "$MOCK_OUTPUT3")
assert_eq "results 배열 비어있음" "0" "$result_count"

###############################################################################
# TEST GROUP 8: 통합 테스트 - 복수 발견 (혼합 상태)
###############################################################################
echo -e "\n${CYAN}[Group 8] 통합 테스트 - 복수 발견 (취약+양호+확인불가) (7건)${NC}"

MOCK_OUTPUT4="${TEST_DIR}/mock_result_mixed.json"

# 가상 바이너리들
cat > "${MOCK_BIN_DIR}/nginx-ui-old" << 'MOCKEOF'
#!/bin/bash
echo "nginx-ui version 2.2.0"
MOCKEOF
chmod +x "${MOCK_BIN_DIR}/nginx-ui-old"

cat > "${MOCK_BIN_DIR}/nginx-ui-new" << 'MOCKEOF'
#!/bin/bash
echo "nginx-ui version 2.4.0"
MOCKEOF
chmod +x "${MOCK_BIN_DIR}/nginx-ui-new"

cat > "${MOCK_BIN_DIR}/nginx-ui-broken" << 'MOCKEOF'
#!/bin/bash
echo "error: config not found"
MOCKEOF
chmod +x "${MOCK_BIN_DIR}/nginx-ui-broken"

(
    source_functions

    scan_host_binaries() {
        local v
        v=$(extract_version_from_output "$("${MOCK_BIN_DIR}/nginx-ui-old" -v 2>&1)")
        report_finding "${MOCK_BIN_DIR}/nginx-ui-old" "$v" "binary_file"

        v=$(extract_version_from_output "$("${MOCK_BIN_DIR}/nginx-ui-new" -v 2>&1)")
        report_finding "${MOCK_BIN_DIR}/nginx-ui-new" "$v" "binary_file"

        v=$(extract_version_from_output "$("${MOCK_BIN_DIR}/nginx-ui-broken" -v 2>&1)")
        [[ -z "$v" ]] && v="unknown"
        report_finding "${MOCK_BIN_DIR}/nginx-ui-broken" "$v" "binary_file"
    }
    scan_host_process() { :; }
    scan_host_systemd() { :; }
    scan_containers() { :; }
    scan_kubernetes_pods() { :; }

    OUTPUT_FILE="$MOCK_OUTPUT4"
    detect_os
    detect_environment
    scan_host_binaries
    json_output=$(assemble_json)
    (umask 077; echo "$json_output" > "$OUTPUT_FILE")
) 2>/dev/null

assert_json_valid "JSON 유효성 검증 (혼합)" "$MOCK_OUTPUT4"
assert_json_field "총 건수 = 3" "$MOCK_OUTPUT4" "summary.total" "3"
assert_json_field "취약 = 1" "$MOCK_OUTPUT4" "summary.vulnerable" "1"
assert_json_field "양호 = 1" "$MOCK_OUTPUT4" "summary.safe" "1"
assert_json_field "확인불가 = 1" "$MOCK_OUTPUT4" "summary.unknown" "1"
assert_json_field "첫 번째 결과 = 취약" "$MOCK_OUTPUT4" "results.0.status" "취약"
assert_json_field "두 번째 결과 = 양호" "$MOCK_OUTPUT4" "results.1.status" "양호"

###############################################################################
# TEST GROUP 9: JSON 구조 완전성 검증
###############################################################################
echo -e "\n${CYAN}[Group 9] JSON 구조 완전성 - 필수 필드 존재 (32건)${NC}"

# 최상위 필드
for field in scanner version cve cvss description affected_versions \
    patched_versions reference scan_date hostname os os_version \
    kernel host_environment container_runtime ip_addresses summary results; do
    assert_json_has_field "필수 필드: ${field}" "$MOCK_OUTPUT" "$field"
done

# summary 하위 필드
for field in total vulnerable safe unknown; do
    assert_json_has_field "summary.${field}" "$MOCK_OUTPUT" "$field"
done

# result 항목 필드
for field in location version status detail source_type patched_version container; do
    assert_json_has_field "result.${field}" "$MOCK_OUTPUT" "$field"
done

# 값 검증
assert_json_field "NVD reference URL" "$MOCK_OUTPUT" "reference" \
    "https://nvd.nist.gov/vuln/detail/CVE-2026-27944"
assert_json_field "affected_versions" "$MOCK_OUTPUT" "affected_versions" "< 2.3.3"
assert_json_field "patched_versions" "$MOCK_OUTPUT" "patched_versions" ">= 2.3.3"

###############################################################################
# TEST GROUP 10: ip_addresses 배열 형식 검증
###############################################################################
echo -e "\n${CYAN}[Group 10] ip_addresses 배열 형식 검증 (1건)${NC}"

assert_json_array_field "ip_addresses는 배열 타입" "$MOCK_OUTPUT" "ip_addresses"

###############################################################################
# TEST GROUP 11: 출력 파일 권한 검증
###############################################################################
echo -e "\n${CYAN}[Group 11] 출력 파일 권한 검증 (1건)${NC}"

file_perms=$(stat -c '%a' "$MOCK_OUTPUT" 2>/dev/null)
assert_eq "출력 파일 권한 600 (owner only)" "600" "$file_perms"

###############################################################################
# TEST GROUP 12: Docker 컨테이너 시뮬레이션
###############################################################################
echo -e "\n${CYAN}[Group 12] Docker 컨테이너 탐지 시뮬레이션 (6건)${NC}"

MOCK_OUTPUT5="${TEST_DIR}/mock_result_container.json"

(
    source_functions

    scan_containers() {
        CONTAINER_CLI="docker"
        report_finding "uozi/nginx-ui:2.3.0" "2.3.0" "container" "docker:nginx-ui-prod"
        report_finding "uozi/nginx-ui:2.3.5" "2.3.5" "container" "docker:nginx-ui-staging"
    }
    scan_host_process() { :; }
    scan_host_binaries() { :; }
    scan_host_systemd() { :; }
    scan_kubernetes_pods() { :; }

    OUTPUT_FILE="$MOCK_OUTPUT5"
    detect_os
    detect_environment
    scan_containers
    json_output=$(assemble_json)
    (umask 077; echo "$json_output" > "$OUTPUT_FILE")
) 2>/dev/null

assert_json_valid "JSON 유효성 (컨테이너 시뮬레이션)" "$MOCK_OUTPUT5"
assert_json_field "컨테이너 취약 건수" "$MOCK_OUTPUT5" "summary.vulnerable" "1"
assert_json_field "컨테이너 양호 건수" "$MOCK_OUTPUT5" "summary.safe" "1"
assert_json_field "취약 컨테이너 정보" "$MOCK_OUTPUT5" "results.0.container" "docker:nginx-ui-prod"
assert_json_field "양호 컨테이너 정보" "$MOCK_OUTPUT5" "results.1.container" "docker:nginx-ui-staging"
assert_json_field "source_type = container" "$MOCK_OUTPUT5" "results.0.source_type" "container"

###############################################################################
# TEST GROUP 13: Kubernetes Pod 시뮬레이션
###############################################################################
echo -e "\n${CYAN}[Group 13] Kubernetes Pod 탐지 시뮬레이션 (4건)${NC}"

MOCK_OUTPUT6="${TEST_DIR}/mock_result_k8s.json"

(
    source_functions

    scan_kubernetes_pods() {
        report_finding "uozi/nginx-ui:2.1.0" "2.1.0" "kubernetes_pod" "k8s:default/nginx-ui-deploy-abc123/nginx-ui"
        report_finding "uozi/nginx-ui:2.3.3" "2.3.3" "kubernetes_pod" "k8s:monitoring/nginx-ui-mon-xyz789/nginx-ui"
    }
    scan_host_process() { :; }
    scan_host_binaries() { :; }
    scan_host_systemd() { :; }
    scan_containers() { :; }

    OUTPUT_FILE="$MOCK_OUTPUT6"
    detect_os
    detect_environment
    scan_kubernetes_pods
    json_output=$(assemble_json)
    (umask 077; echo "$json_output" > "$OUTPUT_FILE")
) 2>/dev/null

assert_json_valid "JSON 유효성 (K8s 시뮬레이션)" "$MOCK_OUTPUT6"
assert_json_field "K8s 취약 Pod" "$MOCK_OUTPUT6" "results.0.status" "취약"
assert_json_field "K8s 양호 Pod" "$MOCK_OUTPUT6" "results.1.status" "양호"
assert_json_field "source_type = kubernetes_pod" "$MOCK_OUTPUT6" "results.0.source_type" "kubernetes_pod"

###############################################################################
# TEST GROUP 14: systemd 유닛 탐지 시뮬레이션
###############################################################################
echo -e "\n${CYAN}[Group 14] systemd 유닛 탐지 시뮬레이션 (4건)${NC}"

MOCK_SYSTEMD_DIR="${TEST_DIR}/mock_systemd"
mkdir -p "$MOCK_SYSTEMD_DIR"

cat > "${MOCK_SYSTEMD_DIR}/nginx-ui.service" << UNITEOF
[Unit]
Description=Nginx UI
After=network.target

[Service]
Type=simple
ExecStart=${MOCK_BIN_DIR}/nginx-ui
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNITEOF

cat > "${MOCK_BIN_DIR}/nginx-ui" << 'MOCKEOF'
#!/bin/bash
echo "nginx-ui version 2.3.1"
MOCKEOF
chmod +x "${MOCK_BIN_DIR}/nginx-ui"

MOCK_OUTPUT7="${TEST_DIR}/mock_result_systemd.json"

(
    source_functions

    scan_host_systemd() {
        local unit_file="${MOCK_SYSTEMD_DIR}/nginx-ui.service"
        local exec_path
        exec_path=$(grep -oP '^ExecStart=\K\S+' "$unit_file" 2>/dev/null | head -1 || true)

        local version="unknown"
        if [[ -n "$exec_path" && -x "$exec_path" ]]; then
            local version_output
            version_output=$("$exec_path" -v 2>&1 || echo "")
            version=$(extract_version_from_output "$version_output")
            [[ -z "$version" ]] && version="unknown"
        fi
        report_finding "$unit_file" "$version" "systemd_unit"
    }
    scan_host_process() { :; }
    scan_host_binaries() { :; }
    scan_containers() { :; }
    scan_kubernetes_pods() { :; }

    OUTPUT_FILE="$MOCK_OUTPUT7"
    detect_os
    detect_environment
    scan_host_systemd
    json_output=$(assemble_json)
    (umask 077; echo "$json_output" > "$OUTPUT_FILE")
) 2>/dev/null

assert_json_valid "JSON 유효성 (systemd)" "$MOCK_OUTPUT7"
assert_json_field "systemd 탐지 상태 = 취약" "$MOCK_OUTPUT7" "results.0.status" "취약"
assert_json_field "source_type = systemd_unit" "$MOCK_OUTPUT7" "results.0.source_type" "systemd_unit"
assert_json_field "systemd 버전 = 2.3.1" "$MOCK_OUTPUT7" "results.0.version" "2.3.1"

###############################################################################
# TEST GROUP 15: summary 정합성 검증
###############################################################################
echo -e "\n${CYAN}[Group 15] summary 카운트 정합성 (2건)${NC}"

# Group 8의 혼합 결과 검증
sum_total=$(json_get "$MOCK_OUTPUT4" "summary.total")
sum_vuln=$(json_get "$MOCK_OUTPUT4" "summary.vulnerable")
sum_safe=$(json_get "$MOCK_OUTPUT4" "summary.safe")
sum_unknown=$(json_get "$MOCK_OUTPUT4" "summary.unknown")
computed=$((sum_vuln + sum_safe + sum_unknown))
assert_eq "total = vulnerable + safe + unknown" "$sum_total" "$computed"

result_len=$(json_results_count "$MOCK_OUTPUT4")
assert_eq "total = len(results)" "$sum_total" "$result_len"

###############################################################################
# TEST GROUP 16: 특수문자 경로 처리
###############################################################################
echo -e "\n${CYAN}[Group 16] 특수문자 포함 경로 처리 (3건)${NC}"

MOCK_OUTPUT8="${TEST_DIR}/mock_result_special.json"

(
    source_functions

    scan_host_binaries() {
        report_finding '/opt/apps/nginx ui/nginx-ui' "2.3.0" "binary_file"
        report_finding '/opt/서버/nginx-ui' "2.3.3" "binary_file"
    }
    scan_host_process() { :; }
    scan_host_systemd() { :; }
    scan_containers() { :; }
    scan_kubernetes_pods() { :; }

    OUTPUT_FILE="$MOCK_OUTPUT8"
    detect_os
    detect_environment
    scan_host_binaries
    json_output=$(assemble_json)
    (umask 077; echo "$json_output" > "$OUTPUT_FILE")
) 2>/dev/null

assert_json_valid "JSON 유효성 (특수문자 경로)" "$MOCK_OUTPUT8"
assert_json_field "공백 포함 경로" "$MOCK_OUTPUT8" "results.0.location" "/opt/apps/nginx ui/nginx-ui"

korean_path=$(json_get "$MOCK_OUTPUT8" "results.1.location")
assert_eq "한글 경로 보존" "/opt/서버/nginx-ui" "$korean_path"

###############################################################################
# TEST GROUP 17: CLI 옵션 테스트
###############################################################################
echo -e "\n${CYAN}[Group 17] CLI 옵션 테스트 (3건)${NC}"

help_output=$(bash "$SCANNER" --help 2>&1 || true)
assert_contains "--help 출력에 사용법 포함" "사용법" "$help_output"
assert_contains "--help 출력에 --output 포함" "--output" "$help_output"

bad_output=$(bash "$SCANNER" --invalid 2>&1 || true)
assert_contains "잘못된 옵션 에러 메시지" "알 수 없는 옵션" "$bad_output"

###############################################################################
# TEST GROUP 18: 스크립트 문법 검증
###############################################################################
echo -e "\n${CYAN}[Group 18] 스크립트 문법 검증 (1건)${NC}"

syntax_check=$(bash -n "$SCANNER" 2>&1)
assert_eq "bash -n 문법 검증 통과" "" "$syntax_check"

###############################################################################
# TEST GROUP 19: scan_date ISO 형식 검증
###############################################################################
echo -e "\n${CYAN}[Group 19] scan_date ISO 형식 검증 (1건)${NC}"

scan_date=$(json_get "$MOCK_OUTPUT" "scan_date")
((TOTAL++))
if echo "$scan_date" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}'; then
    ((PASS++))
    echo -e "  ${GREEN}[PASS]${NC} scan_date ISO 8601 형식: ${scan_date}"
else
    ((FAIL++))
    echo -e "  ${RED}[FAIL]${NC} scan_date 형식 이상: ${scan_date}"
fi

###############################################################################
# TEST GROUP 20: 실제 환경 실행 (현재 호스트)
###############################################################################
echo -e "\n${CYAN}[Group 20] 실제 환경 실행 테스트 (8건)${NC}"

REAL_OUTPUT="${TEST_DIR}/real_result.json"
real_stderr=$(bash "$SCANNER" --output "$REAL_OUTPUT" 2>&1)
real_rc=$?

assert_eq "스캐너 정상 종료 (exit 0)" "0" "$real_rc"
assert_json_valid "실제 실행 JSON 유효성" "$REAL_OUTPUT"
assert_contains "stderr에 시작 로그" "점검 시작" "$real_stderr"
assert_contains "stderr에 완료 로그" "점검 완료" "$real_stderr"
assert_contains "stderr에 Phase 1 로그" "Phase 1" "$real_stderr"
assert_contains "stderr에 Phase 2 로그" "Phase 2" "$real_stderr"

real_hostname=$(json_get "$REAL_OUTPUT" "hostname")
assert_eq "hostname 일치" "$(hostname)" "$real_hostname"

real_os=$(json_get "$REAL_OUTPUT" "os")
((TOTAL++))
if [[ -n "$real_os" ]]; then
    ((PASS++))
    echo -e "  ${GREEN}[PASS]${NC} OS 감지: ${real_os}"
else
    ((FAIL++))
    echo -e "  ${RED}[FAIL]${NC} OS 미감지"
fi

###############################################################################
# TEST GROUP 21: Podman 컨테이너 시뮬레이션
###############################################################################
echo -e "\n${CYAN}[Group 21] Podman 컨테이너 시뮬레이션 (3건)${NC}"

MOCK_OUTPUT9="${TEST_DIR}/mock_result_podman.json"

(
    source_functions

    scan_containers() {
        CONTAINER_CLI="podman"
        report_finding "docker.io/uozi/nginx-ui:2.2.5" "2.2.5" "container" "podman:nginxui-test"
    }
    scan_host_process() { :; }
    scan_host_binaries() { :; }
    scan_host_systemd() { :; }
    scan_kubernetes_pods() { :; }

    OUTPUT_FILE="$MOCK_OUTPUT9"
    detect_os
    detect_environment
    scan_containers
    json_output=$(assemble_json)
    (umask 077; echo "$json_output" > "$OUTPUT_FILE")
) 2>/dev/null

assert_json_valid "JSON 유효성 (Podman)" "$MOCK_OUTPUT9"
assert_json_field "Podman 컨테이너 상태" "$MOCK_OUTPUT9" "results.0.status" "취약"
assert_json_field "Podman 컨테이너 라벨" "$MOCK_OUTPUT9" "results.0.container" "podman:nginxui-test"

###############################################################################
# TEST GROUP 22: 대량 결과 (10건) JSON 정합성
###############################################################################
echo -e "\n${CYAN}[Group 22] 대량 결과 (10건) JSON 정합성 (3건)${NC}"

MOCK_OUTPUT10="${TEST_DIR}/mock_result_bulk.json"

(
    source_functions

    scan_host_binaries() {
        report_finding "/srv/app1/nginx-ui" "2.0.0" "binary_file"
        report_finding "/srv/app2/nginx-ui" "2.1.0" "binary_file"
        report_finding "/srv/app3/nginx-ui" "2.2.0" "binary_file"
        report_finding "/srv/app4/nginx-ui" "2.3.0" "binary_file"
        report_finding "/srv/app5/nginx-ui" "2.3.2" "binary_file"
        report_finding "/srv/app6/nginx-ui" "2.3.3" "binary_file"
        report_finding "/srv/app7/nginx-ui" "2.3.4" "binary_file"
        report_finding "/srv/app8/nginx-ui" "2.4.0" "binary_file"
        report_finding "/srv/app9/nginx-ui" "3.0.0" "binary_file"
        report_finding "/srv/app10/nginx-ui" "unknown" "binary_file"
    }
    scan_host_process() { :; }
    scan_host_systemd() { :; }
    scan_containers() { :; }
    scan_kubernetes_pods() { :; }

    OUTPUT_FILE="$MOCK_OUTPUT10"
    detect_os
    detect_environment
    scan_host_binaries
    json_output=$(assemble_json)
    (umask 077; echo "$json_output" > "$OUTPUT_FILE")
) 2>/dev/null

assert_json_valid "JSON 유효성 (10건 대량)" "$MOCK_OUTPUT10"
assert_json_field "총 건수 = 10" "$MOCK_OUTPUT10" "summary.total" "10"

bulk_count=$(json_results_count "$MOCK_OUTPUT10")
assert_eq "results 배열 길이 = 10" "10" "$bulk_count"

###############################################################################
# TEST GROUP 23: 출력 파일 --output 경로 지정 동작
###############################################################################
echo -e "\n${CYAN}[Group 23] --output 경로 지정 동작 (2건)${NC}"

CUSTOM_OUTPUT="${TEST_DIR}/custom/nested/dir/result.json"
mkdir -p "$(dirname "$CUSTOM_OUTPUT")"
bash "$SCANNER" --output "$CUSTOM_OUTPUT" 2>/dev/null

((TOTAL++))
if [[ -f "$CUSTOM_OUTPUT" ]]; then
    ((PASS++))
    echo -e "  ${GREEN}[PASS]${NC} 지정 경로에 파일 생성됨"
else
    ((FAIL++))
    echo -e "  ${RED}[FAIL]${NC} 지정 경로에 파일 없음"
fi

assert_json_valid "지정 경로 JSON 유효성" "$CUSTOM_OUTPUT"

###############################################################################
# 결과 요약
###############################################################################
echo -e "\n${CYAN}========================================${NC}"
echo -e "${CYAN} QA 결과 요약${NC}"
echo -e "${CYAN}========================================${NC}"
echo -e " 전체: ${TOTAL}"
echo -e " ${GREEN}통과: ${PASS}${NC}"
echo -e " ${RED}실패: ${FAIL}${NC}"
echo -e "${CYAN}========================================${NC}"

if [[ $FAIL -gt 0 ]]; then
    echo -e "\n${RED}!! ${FAIL}개 테스트 실패${NC}"
    exit 1
else
    echo -e "\n${GREEN}>> 전체 ${TOTAL}개 테스트 통과${NC}"
    exit 0
fi
