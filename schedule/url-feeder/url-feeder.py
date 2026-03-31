import requests
import json
import configparser
import re
import os
import csv
import shutil
import time
import subprocess
from subprocess import Popen, PIPE
from datetime import datetime, timedelta

DATE_FORMAT = "%Y-%m-%d"  # 날짜 포맷

# 에러 메시지를 저장할 리스트
error_messages = []

def is_response_successful(response):
    return response.status_code == 200

def cip_domain_scan(scan_url, api_key):
    try:
        url = "https://api.criminalip.io/v1/domain/scan"
        payload = {"query": scan_url}
        headers = {"x-api-key": api_key}
        response = requests.request("POST", url, headers=headers, data=payload)
        if is_response_successful(response):
            try:
                result_data = response.json()
                if result_data.get("status") != 200:
                    error_message = f"Scan failed with status: {result_data.get('status')}"
                    error_messages.append(error_message)
                    return None
                return result_data.get("data", {}).get("scan_id")
            except (json.JSONDecodeError, KeyError) as e:
                error_message = f"[ERROR] {e}"
                error_messages.append(error_message)
                return None
        else:
            error_message = "Domain scan failed"
            error_messages.append(error_message)
        return None
    except Exception as e:
        error_message = f"Domain scan encountered an error: {e}"
        error_messages.append(error_message)
        return None

def cip_domain_reports(scan_url, api_key):
    try:
        print(f"report scan url -> {scan_url}")
        url = f"https://api.criminalip.io/v1/domain/reports?query={scan_url}"
        headers = {"x-api-key": api_key}
        response = requests.request("GET", url, headers=headers)
        if is_response_successful(response):
            try:
                result_data = response.json()
                if result_data.get("status") != 200:
                    error_message = f"Scan failed with status: {result_data.get('status')}"
                    error_messages.append(error_message)
                    return None, error_message
                
                reports = result_data.get("data", {}).get("reports", [])
                if reports:
                    first_report = reports[0]
                    country_code = first_report.get("country_code", [None])[0]
                    score = first_report.get("score", "Unknown")
                    title = first_report.get("title", "No Title")
                    reg_dtime = first_report.get("reg_dtime", "Unknown Date")
                    scan_id = first_report.get("scan_id", None)
                    
                    print(scan_url)
                    return {
                        "domain": scan_url,
                        "country_code": country_code,
                        "score": score,
                        "title": title,
                        "reg_dtime": reg_dtime,
                        "scan_id": scan_id
                    }, None
                else:
                    error_message = "No reports found in the response"
                    return None, None
            except (json.JSONDecodeError, KeyError) as e:
                error_message = f"Error processing JSON or missing key: {e}"
                error_messages.append(error_message)
                return None, error_message
        else:
            error_message = "Domain scan failed with response status code other than 200"
            error_messages.append(error_message)
            return None, error_message
    except Exception as e:
        error_message = f"Domain scan encountered an error: {e}"
        error_messages.append(error_message)
        return None, error_message

def collect_domain(Token, web_hook):
    url = "https://auth.criminalip.io:49862/api/v1/list"
    headers = {
        "Authorization": f"Bearer {Token}"
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            error_message = f"Error while collecting domain: {response.status_code}"
            error_messages.append(error_message)
            return None
        result_data = response.json()
        domains = result_data.get("domains", [])
        if not domains:
            error_message = "No domains found in the response"
            error_messages.append(error_message)
            return None
        return domains[:300] # 수집할 도메인 개수
    except Exception as e:
        error_message = f"Error while collecting domain: {e}"
        error_messages.append(error_message)
        return None

def cip_domain_status(scan_url, api_key):
    url = f"https://api.criminalip.io/v1/domain/status/{scan_url}"

    payload={}
    headers = {
        "x-api-key": api_key
    }
    try:
        response = requests.request("GET", url, headers=headers, data=payload)
        result_data = response.json()

        if result_data.get("status") == 200:
            return result_data.get("data", {}).get("scan_percentage")

    except (json.JSONDecodeError, KeyError) as e:
        print(f"[ERROR] {e}")


def send_slack_message(message, web_hook):
    webhook_url = web_hook
    headers = {'Content-Type': 'application/json'}
    slack_message = {"text": f"```{message}```"} 
    response = requests.post(webhook_url, headers=headers, data=json.dumps(slack_message))
    if response.status_code == 200:
        print("메시지가 성공적으로 전송되었습니다.")
    else:
        print(f"메시지 전송 실패: {response.status_code}, {response.text}")

def save_to_csv(data, file_name):
    keys = ["title", "domain", "score", "country_code", "reg_dtime", "scan_id"]
    with open(file_name, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=keys)
        dict_writer.writeheader()
        for row in data:
            if row.get("reg_dtime"):
                row["reg_dtime"] = f"{row['reg_dtime']} (UTC)"  # UTC 추가
            dict_writer.writerow(row)

def scan_and_collect(urls, api_key):
    scan_ids = []
    for url in urls:
        # URL 스캔 시작
        scan_id = cip_domain_scan(f"http://{url}", api_key)
        
        if not scan_id:
            print(f"{url}의 스캔에 실패했습니다. scan_id가 반환되지 않았습니다.")
            continue
        
        # 스캔 상태 확인을 최대 12번 (총 2분간) 시도
        for attempt in range(1, 13):
            scan_percentage = cip_domain_status(scan_id, api_key)
            
            if scan_percentage is None or not (0 <= scan_percentage <= 100):
                print(f"{url}의 스캔 상태를 가져오는 데 실패했습니다.")
                break  # 스캔 상태를 가져오지 못하면 루프 중단
            
            if scan_percentage == 100:
                scan_ids.append(url)
                print(f"{url}의 스캔이 완료되었습니다. scan_id: {scan_id}")
                break  # 스캔이 완료되면 루프 종료

            # 진행 상황 출력 및 대기
            print(f"{attempt}번째 시도: {url} 스캔 진행률 {scan_percentage}%")
            time.sleep(10)
        
        else:
            # 최대 시도 횟수 초과 시 타임아웃 처리
            print(f"{url} 스캔이 120초 후에 시간 초과되었습니다.")
    
    return scan_ids

def process_reports(urls, api_key):
    results = []
    failed_urls = []
    for url in urls:
        scan_result, error = cip_domain_reports(f"http://{url}", api_key)
        if scan_result:
            results.append(scan_result)
        else:
            failed_urls.append(url)
    return results, failed_urls


def generate_readme(filename, num_entries=3):
    readme_content = f"""# 🌐 CriminalIP-Daily-Mal-Phishing

This repository provides a **daily list of malicious or phishing URLs** collected via Criminal IP's Domain Search. It is hosted on the official Criminal IP GitHub, offering a direct window into our extensive threat intelligence data. By presenting a sample of our complete dataset, we aim to raise awareness about potential online threats and encourage users to explore our full range of threat intelligence services.

> [!NOTE]
> For a **comprehensive security response** with expanded threat insights, contact us at [Criminal IP Contact Us](https://www.criminalip.io/contact-us) for samples and API access to our complete dataset.

---

## 🛠️ Overview

![Criminal-IP-Domain-Search](Domain-Search-Image.png)

The URLs listed in this repository are randomly selected from those categorized as **Dangerous** or **Critical** in Criminal IP's Domain Search. Each day, a fresh batch of URLs is provided, which may include:
- Malicious websites
- Phishing sites
- Fraudulent domains

Criminal IP’s **AI-driven real-time detection** ensures a wide range of harmful sites are quickly identified and classified.

#### 🔗 Examples of Malicious Domains

![Criminal-IP-Found-Microsoft-Phishing](microsoft_phishing_site.png)
![Criminal-IP-Found-Netflix-Phishing](netflix_phishing_site.png)

---

## 🎯 Criteria for URL Selection

- **Score**: URLs with a score of "Dangerous" or "Critical."
- **Additional Conditions**: As defined by senior threat analysts.

---

## 🗂️ Data Fields

The following fields are included in the daily list:

| **Field**      | **Description**                                             |
|----------------|-------------------------------------------------------------|
| **Title**      | The webpage title of the malicious or phishing site          |
| **URL**        | The URL of the malicious or phishing site                    |
| **Score**      | The threat score assigned to the domain                      |
| **Country**    | The country where the domain is registered or originates     |
| **reg_dtime**  | The date and time the domain was registered                  |

---

## 📅 Example of Daily URLs List

Below is an example of the daily list format:

| **Title**               | **URL**                                                                                                            | **Score**  | **Country**   | **reg_dtime**   |
|-------------------------|--------------------------------------------------------------------------------------------------------------------|------------|---------------|-----------------|
"""

    count = 0
    with open("/usr/share/AISpera/schedule/url-feeder/README.md", "w", encoding="utf-8") as readme:
        readme.write(readme_content)
        with open(filename, "r", encoding="utf-8") as file:
            reader = csv.reader(file, quotechar='"', delimiter=',', quoting=csv.QUOTE_MINIMAL)
            next(reader)  # Skip the header
            for row in reader:
                count += 1
                if count > num_entries:
                    break
                # 각 필드에 빈 값이 있을 수 있으므로 기본 값을 설정
                title = f'"{row[0]}"' if row[0] else '"N/A"'
                domain = row[1] if row[1] else "N/A"
                score = row[2] if row[2] else "N/A"
                country_code = row[3] if row[3] else "N/A"
                reg_dtime = row[4] if row[4] else "N/A"
                scan_id = row[5] if len(row) > 5 else "N/A"

                readme.write(
                    f"| {title} | [{domain}](https://www.criminalip.io/domain/report?scan_id={scan_id}) | {score} | {country_code} | {reg_dtime} |\n"
                )
    # TIP 섹션을 가장 마지막에 추가
    tip_section = """
---

> [!TIP]
> For additional resources, please refer to the below:
> - Additional Code Examples: **[GitHub Reference Page](https://www.criminalip.io/developer/github-reference)**
> *This page provides you with multiple code usage references using the resources of Criminal IP such as API, search queries and etc., both from Criminal IP itself and actual user base.*
> - Chrome Extension: **[Criminal IP: AI-based Phishing Link Checker](https://www.criminalip.io/products/chrome-extension)**
> *This Chrome extension automatically scans and blocks malicious domains on your browser based on the threat intelligence of Criminal IP, ensuring a safer internet surfing experience.*
"""
    with open("/usr/share/AISpera/schedule/url-feeder/README.md", "a", encoding="utf-8") as readme:
        readme.write(tip_section)

def remove_scan_id_from_csv(file_name):
    # 수정된 데이터를 저장할 임시 리스트
    modified_rows = []

    # CSV 파일을 읽어들이면서 scan_id 필드를 제거
    with open(file_name, 'r', encoding='utf-8') as input_file:
        reader = csv.DictReader(input_file)
        fieldnames = [field for field in reader.fieldnames if field != "scan_id"]
        for row in reader:
            # scan_id 필드를 삭제
            if "scan_id" in row:
                del row["scan_id"]
            modified_rows.append(row)

    # 변경된 데이터를 다시 CSV에 기록
    with open(file_name, 'w', newline='', encoding='utf-8') as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(modified_rows)

    print(f"scan_id 필드가 {file_name}에서 성공적으로 삭제되었습니다.")

def move_old_files(directory):
    today = datetime.now()
    current_month = today.strftime("%Y-%m")
    
    # 작업 디렉토리 설정
    os.chdir(directory)
    print(f"현재 작업 디렉토리: {directory}")
    
    for file in os.listdir("."):
        if file.endswith(".csv"):
            try:
                # 파일 이름에서 날짜 부분을 추출하고 datetime 객체로 변환 (파일 형식: YYYY-MM-DD.csv 가정)
                file_date = datetime.strptime(file.split(".")[0], "%Y-%m-%d")
                file_month = file_date.strftime("%Y-%m")

                # 현재 월에 생성된 파일은 제외하고 이동
                if file_month != current_month:
                    # 이동할 폴더 경로 설정
                    target_folder = os.path.join(directory, file_month)

                    # 폴더가 존재하지 않으면 생성
                    if not os.path.exists(target_folder):
                        print(f"폴더 생성: {target_folder}")
                        os.makedirs(target_folder)

                    # 파일을 해당 폴더로 이동
                    print(f"파일 이동: {file} -> {os.path.join(target_folder, file)}")
                    shutil.move(file, os.path.join(target_folder, file))

            except ValueError as e:
                # 파일 이름이 날짜 형식에 맞지 않으면 무시하고 로그 출력
                print(f"파일 이름이 날짜 형식에 맞지 않음: {file}, 오류: {e}")
                continue

def run_command(command, cwd=None):
    """명령어를 실행하고 결과를 반환하는 함수"""
    process = Popen(command, cwd=cwd, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        raise Exception(f"Command {command} failed with error: {stderr.decode()}")
    
    return stdout.decode()

def push_to_github(repo_dir, github_token, repo_url):
    try:
        os.chdir(repo_dir)

        print(run_command(["git", "config", "--global", "user.name", "speraUser"]))
        print(run_command(["git", "config", "--global", "user.email", "security@aispera.com"]))

        # 1) 원래 등록하던 safe.directory
        print(run_command(["git", "config", "--global", "--add", "safe.directory", repo_dir]))

        # 2) 여기 추가!! Git이 실제로 사용하는 repo root를 자동 탐지하여 안전 폴더로 등록
        git_root = run_command(["git", "rev-parse", "--show-toplevel"], cwd=repo_dir).strip()
        print(run_command(["git", "config", "--global", "--add", "safe.directory", git_root]))

        # 스태시
        print(run_command(["git", "stash"], cwd=repo_dir))

        pull_url = f"https://{github_token}@{repo_url}"
        print(run_command(["git", "pull", "--rebase", pull_url], cwd=repo_dir))

        print(run_command(["git", "stash", "pop"], cwd=repo_dir))

        print(run_command(["git", "add", "--all"], cwd=repo_dir))

        commit_message = f"Auto Feed update at {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        print(run_command(["git", "commit", "-m", commit_message], cwd=repo_dir))

        push_url = f"https://{github_token}@{repo_url}"
        print(run_command(["git", "push", push_url, "main"], cwd=repo_dir))

        print("성공적으로 GitHub에 푸시되었습니다.")

    except Exception as e:
        print(f"오류 발생: {e}")



def copy_and_push_files(source_dir, dest_dir, github_token, repo_url):
    # 생성된 csv 파일과 README.md 파일을 이동
    try:
        # Move README.md
        readme_path = "/usr/share/AISpera/schedule/url-feeder/README.md"
        dest_readme_path = os.path.join(dest_dir, "README.md")
        if os.path.exists(dest_readme_path):
            os.remove(dest_readme_path)  # 기존 파일 삭제
            print(f"기존 README.md 파일을 삭제했습니다: {dest_readme_path}")

        if os.path.exists(readme_path):
            shutil.move(readme_path, dest_dir)  
            print("README.md 파일이 성공적으로 이동되었습니다.")
        else:
            error_message = "README.md 파일이 존재하지 않습니다."
            error_messages.append(error_message)

        # Move CSV files
        csv_files = [f for f in os.listdir(source_dir) if f.endswith(".csv")]
        for csv_file in csv_files:
            dest_csv_path = os.path.join(dest_dir, csv_file)
            if os.path.exists(dest_csv_path):
                os.remove(dest_csv_path)  # 기존 CSV 파일 삭제
                print(f"기존 CSV 파일을 삭제했습니다: {dest_csv_path}")

            shutil.move(os.path.join(source_dir, csv_file), dest_dir)  
            print(f"{csv_file} 파일이 성공적으로 이동되었습니다.")
        
        # 이동이 완료되면 GitHub에 푸시
        push_to_github(dest_dir, github_token, repo_url)
    
    except Exception as e:
        error_message = f"파일 이동 또는 푸시 작업 중 오류 발생: {e}"
        error_messages.append(error_message)


def main():
    config = configparser.ConfigParser()
    if not os.path.exists("/usr/share/AISpera/schedule/url-feeder/config/.env"):
        error_message = ".env 파일을 찾을 수 없습니다."
        error_messages.append(error_message)
        return
    config.read("/usr/share/AISpera/schedule/url-feeder/config/.env")

    Token = config["TOKEN"]["TOKEN_KEY"] # catch phishing token
    api_key = config["APIKEY"]["API_KEY"]
    web_hook = config["WEBHOOK"]["WEB_HOOK"]
    github_token = config["GITHUB"]["GIT_TOKEN"]

    urls = collect_domain(Token, web_hook)
    if not urls:
        return

    print(urls)

    # 먼저 스캔을 수행
    scan_ids = scan_and_collect(urls, api_key)

    if not scan_ids:
        return
    
    print(scan_ids)

    scanned_results = []
    for scan_id in scan_ids:
        susses, failed = process_reports([scan_id], api_key)
        scanned_results.extend(susses)

    print(scanned_results)

    if scanned_results:
        # 100개만 저장하도록 리스트 슬라이싱
        current_date = datetime.now().strftime(DATE_FORMAT)
        file_name = f"/usr/share/AISpera/schedule/url-feeder/{current_date}.csv"
        save_to_csv(scanned_results[:100], file_name)
        print(f"{len(scanned_results[:100])}개의 도메인 스캔 결과가 CSV 파일에 저장되었습니다.")

        # README 파일 생성
        generate_readme(file_name, num_entries=3)

        # CSV 파일에서 scan_id 필드 삭제
        remove_scan_id_from_csv(file_name)

        # 파일을 GitHub 리포지토리에 복사하고 푸시
        source_directory = "/usr/share/AISpera/schedule/url-feeder/"
        destination_directory = "/usr/share/AISpera/schedule/url-feeder/Daily-Mal-Phishing"
        repository_url = "github.com/criminalip/Daily-Mal-Phishing.git"

        # 월마다 폴더 생성해서 이동
        move_old_files(destination_directory)

        copy_and_push_files(source_directory, destination_directory, github_token, repository_url)

        # 성공 메시지를 슬랙으로 전송
        success_message = f"{len(scanned_results[:100])}개의 도메인 스캔 CSV 파일 Github에 배포 성공!!!"
        send_slack_message(success_message, web_hook)

    # 에러 메시지가 있으면 슬랙으로 전송
    if error_messages:
        combined_errors = "\n".join(error_messages)
        send_slack_message(combined_errors, web_hook)

if __name__ == "__main__":
    main()
