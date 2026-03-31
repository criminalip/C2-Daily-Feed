import requests
import json
import configparser
import re
import os
import csv
import random
import shutil
import calendar
from datetime import datetime, timedelta
from subprocess import Popen, PIPE

BASE_URL = "https://api.criminalip.io/v1/banner/search"  # banner search API URL
C2_TAGS = [  # 검색할 C2 태그 목록
    "c2_darkcomet",
    "c2_sliver",
    "c2_covenant",
    "c2_posh",
    "c2_mythic",
    "c2_havoc",
    "C2",
    "c2_metasploit",
    "c2_meshagent",
]
MAX_IPS = 100  # 검색할 최대 IP 주소 수
MAX_NEW_IPS = 50  # 새로운 IP 주소 수
DATE_FORMAT = "%Y-%m-%d"  # 날짜 포맷

# 에러 메시지를 저장할 리스트
error_messages = []

def is_response_successful(response):
    return response.status_code == 200

def get_cip_banner_search(tag, offset, api_key):
    headers = {"x-api-key": api_key}
    params = {"query": f"tag : {tag}", "offset": offset}
    try:
        response = requests.get(BASE_URL, params=params, headers=headers)
        if is_response_successful(response):
            return response.text
    except requests.RequestException as e:
        print(f"[오류] {e}")
    return None


def get_cip_ip_report(ip_address, api_key):
    headers = {"x-api-key": api_key}
    response = requests.get(
        f"https://api.criminalip.io/v1/asset/ip/summary?ip={ip_address}",
        headers=headers,
    )
    if is_response_successful(response):
        try:
            data = response.json()
            inbound_score = data["score"]["inbound"]
            outbound_score = data["score"]["outbound"]
            country = data["country_code"]
            return f"{inbound_score}/{outbound_score}", country
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            print(f"[오류] {e}")
    else:
        print(f"[오류] {response.status_code}")
    return "", "Unknown"


def extract_data_from_response(response_text):
    ip_addresses, countries, tags_list, open_ports, scan_times = [], [], [], [], []
    try:
        result_data = json.loads(response_text)
        if (
            result_data.get("status") != 200
            or result_data.get("data", {}).get("count", 0) == 0
        ):
            print("[정보] API 응답에 데이터가 없습니다.")
            return ip_addresses, countries, tags_list, open_ports, scan_times

        result_list = result_data.get("data", {}).get("result", [])
        for result in result_list:
            c2_tags = [tag for tag in result.get("tags", []) if "c2" in tag.lower()]
            if c2_tags:
                ip_addresses.append(result.get("ip_address", "Unknown"))
                countries.append(result.get("country", "Unknown"))
                tags_list.append(c2_tags)
                open_ports.append(result.get("open_port_no", "Unknown"))
                scan_times.append(result.get("scan_dtime", "Unknown"))
    except (json.JSONDecodeError, KeyError) as e:
        print(f"[오류] 데이터 파싱 중 오류 발생: {e}")
    return ip_addresses, countries, tags_list, open_ports, scan_times



def is_valid_api_key(api_key):
    pattern = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{60}$")
    return bool(pattern.match(api_key))


def get_config(config_filename):
    config_path = os.path.join(os.path.dirname(__file__), config_filename)
    config = configparser.ConfigParser()
    try:
        config.read(config_path)
        api_key = config["CIP"]["APIKEY"]
        if is_valid_api_key(api_key):
            return api_key
        else:
            print(f"[오류] API 키가 유효하지 않습니다.")
    except Exception as e:
        print(f"[오류] {e}")
    return None


def save_data_to_csv(
    ip_addresses, tags_list, open_ports, scores, countries, scan_times, filename
):
    print(filename)
    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(
            [
                "IP",
                "Target C2",
                "OpenPorts",
                "Score(Inbound/Outbound)",
                "Country",
                "Scan Time",
            ]
        )
        for ip, tags, port, score, country, scan_time in zip(
            ip_addresses, tags_list, open_ports, scores, countries, scan_times
        ):
            writer.writerow([ip, "|".join(tags), port, score, country, scan_time])
            print([ip, "|".join(tags), port, score, country, scan_time])


def read_existing_ips():
    yesterday_date = (datetime.now() - timedelta(days=1)).strftime(DATE_FORMAT)
    existing_ips = set()
    if os.path.exists(f"{yesterday_date}.csv"):
        with open(f"{yesterday_date}.csv", "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # 헤더 건너뛰기
            for row in reader:
                existing_ips.add(row[0])
    return existing_ips


def fetch_unique_ips(api_key, existing_ips):
    ip_data = {
        tag: {"ips": [], "countries": [], "tags": [], "ports": [], "scan_times": []}
        for tag in C2_TAGS
    }

    for c2_tag in C2_TAGS:
        offset = 0
        print(f"[정보] {c2_tag} 태그 처리 중...")

        response_text = get_cip_banner_search(c2_tag, offset, api_key)
        if not response_text:
            print(f"[오류] {c2_tag} 태그에서 데이터를 가져오지 못했습니다.")
            continue

        result_data = json.loads(response_text)
        total_count = result_data.get("data", {}).get("count", 0)

        num_calls = min(total_count // 10, MAX_IPS // 10) + 1 if total_count > 0 else 0
        if total_count > 50:
            num_calls = min(num_calls, 5)

        for _ in range(num_calls):
            response_text = get_cip_banner_search(c2_tag, offset, api_key)
            if not response_text:
                break

            new_ips, new_countries, new_tags, new_ports, new_scan_times = (
                extract_data_from_response(response_text)
            )

            # 빈 데이터 필터링
            if not new_ips:
                print(f"[경고] {c2_tag}: 유효한 데이터가 없습니다.")
                continue

            new_ip_set = set(new_ips)
            unique_ips = new_ip_set - existing_ips
            existing_ips.update(unique_ips)

            ip_data[c2_tag]["ips"].extend(list(unique_ips))
            ip_data[c2_tag]["countries"].extend(
                [
                    country
                    for ip, country in zip(new_ips, new_countries)
                    if ip in unique_ips
                ]
            )
            ip_data[c2_tag]["tags"].extend(
                [tags for ip, tags in zip(new_ips, new_tags) if ip in unique_ips]
            )
            ip_data[c2_tag]["ports"].extend(
                [port for ip, port in zip(new_ips, new_ports) if ip in unique_ips]
            )
            ip_data[c2_tag]["scan_times"].extend(
                [
                    scan_time
                    for ip, scan_time in zip(new_ips, new_scan_times)
                    if ip in unique_ips
                ]
            )

            offset += 10
            if len(new_ips) < 10:
                break

    return ip_data


def sample_random_ips(ip_data, max_ips):
    sampled_data = []  # 샘플링된 데이터를 저장할 리스트
    remaining_data = []  # 남은 데이터를 저장할 리스트

    # 태그별로 데이터를 묶어서 저장
    for tag, data in ip_data.items():
        tag_data = [
            {
                "ip": ip,
                "country": country,
                "tags": tags,
                "port": port,
                "scan_time": scan_time,
            }
            for ip, country, tags, port, scan_time in zip(
                data["ips"], data["countries"], data["tags"], data["ports"], data["scan_times"]
            )
        ]
        remaining_data.extend(tag_data)

    # 무작위로 섞기
    random.shuffle(remaining_data)

    # 샘플링
    sampled_data = remaining_data[:max_ips]

    # 샘플링된 데이터의 각 필드를 리스트로 변환하여 반환
    sampled_ips = [item["ip"] for item in sampled_data]
    sampled_countries = [item["country"] for item in sampled_data]
    sampled_tags = [item["tags"] for item in sampled_data]
    sampled_ports = [item["port"] for item in sampled_data]
    sampled_scan_times = [item["scan_time"] for item in sampled_data]

    return sampled_ips, sampled_countries, sampled_tags, sampled_ports, sampled_scan_times


def generate_readme(current_date, filename, num_ips):
    readme_content = f"""# C2-Daily-Feed

This repository provides a daily updated list of IP addresses derived from Criminal IP (https://www.criminalip.io/) under the C2_TI license. Our goal is to offer a daily sample of 50 malicious IP addresses identified by the Criminal IP real-time threat hunting search engine, specializing in OSINT-based Cyber Threat Intelligence (CTI). This includes Command and Control (C2, C&C) IP addresses categorized under the C2_TI license.

Hosted on Criminal IP's official GitHub, this repository serves as a direct access point to our threat intelligence data. By showcasing a subset of our comprehensive data, we aim to raise awareness of potential threats and inspire users to delve deeper into our complete range of threat intelligence offerings.

For enhanced security response processes with broader threat intelligence insights, please contact us (https://www.criminalip.io/contact-us) to inquire about samples and API access for our complete dataset.

## Overview

The selection criteria for the IP addresses listed in this repository are based on various conditions such as Criminal IP's threat tags (https://www.criminalip.io/developer/filters-and-tags/tags) and honeypot detections. This ensures a diverse representation of threats within the C2_TI dataset. The repository updates daily with a sample of 50 IP addresses, providing insights into a subset of the extensive C2_TI data.

These IP addresses are intentionally chosen to reflect a broad spectrum of conditions, showcasing different types of threats identified by Criminal IP's real-time threat hunting capabilities.

## Criteria for IP Selection

- **Tags:** IPs with C2_xx tags.
- **Honeypot Detections:** IPs caught in [Criminal IP](https://www.criminalip.io)'s honeypots.
- **Additional conditions** as specified by senior analysts.

## Data Fields

The data provided includes the following fields, identical to those in the C2_TI license:

| Field                  | Description                                           |
|------------------------|-------------------------------------------------------|
| **IP Address**         | The IP address.                                       |
| **Target C2**          | Type of Command and Control server.                   |
| **Open Ports**         | Ports open on the IP address (formatted as [80, 443]).|
| **Score (Inbound/Outbound)** | Threat score for inbound and outbound traffic.  |
| **Country**            | Country of origin.                                    |
| **Scan Time**          | Time when the scan was conducted.                     |


## Example of Daily IP Addresses List

Here is an example of the daily list format:

| IP Address     | Target C2      | Open Ports | Score (Inbound/Outbound) | Country | Scan Time             |
|----------------|----------------|------------|--------------------------|---------|-----------------------|
"""

    count = 0
    with open("/usr/share/AISpera/schedule/c2-feeder/README.md", "w", encoding="utf-8") as readme:
        readme.write(readme_content)
        with open(filename, "r", encoding="utf-8") as file:
            reader = csv.reader(file)
            next(reader)
            for row in reader:
                count = count + 1
                if count > 3:
                    print(count)
                    break
                ip, tags, port, score, country, scan_time = row
                readme.write(
                    f"| [{ip}](https://www.criminalip.io/asset/report/{ip})  | {tags} | {port} | {score} | {country} | {scan_time} |\n"
                )


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

        # Git 설정
        run_command(["git", "config", "--global", "user.name", "speraUser"])
        run_command(["git", "config", "--global", "user.email", "security@aispera.com"])
        run_command(["git", "config", "--global", "--add", "safe.directory", repo_dir])
        run_command(["git", "config", "--global", "--add", "safe.directory", "/volume/AISpera/schedule/c2-feeder/C2-Daily-Feed"])

        # 변경 사항 스테이징 및 커밋
        run_command(["git", "add", "--all"], cwd=repo_dir)
        status_output = run_command(["git", "status", "--porcelain"], cwd=repo_dir)

        if status_output:  # 변경 사항이 있을 경우에만 커밋 실행
            commit_message = f"Auto Feed update at {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            run_command(["git", "commit", "-m", commit_message], cwd=repo_dir)

        # GitHub에서 변경 사항 가져오기
        pull_url = f"https://{github_token}@{repo_url}"
        run_command(["git", "pull", "--rebase", pull_url], cwd=repo_dir)

        # 변경 사항 푸시
        push_url = f"https://{github_token}@{repo_url}"
        run_command(["git", "push", push_url, "main"], cwd=repo_dir)

        print("성공적으로 GitHub에 푸시되었습니다.")

    except Exception as e:
        print(f"오류 발생: {e}")

def copy_and_push_files(source_dir, dest_dir, github_token, repo_url):
    # 생성된 csv 파일과 README.md 파일을 이동
    try:
        # Move README.md
        readme_path = "/usr/share/AISpera/schedule/c2-feeder/README.md"
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

def send_slack_message(message, web_hook):
    webhook_url = web_hook
    headers = {'Content-Type': 'application/json'}
    slack_message = {"text": f"```{message}```"} 
    response = requests.post(webhook_url, headers=headers, data=json.dumps(slack_message))
    if response.status_code == 200:
        print("메시지가 성공적으로 전송되었습니다.")
    else:
        print(f"메시지 전송 실패: {response.status_code}, {response.text}")

def main():
    config = configparser.ConfigParser()
    if not os.path.exists("/usr/share/AISpera/schedule/c2-feeder/config/.env"):
        error_message = ".env 파일을 찾을 수 없습니다."
        error_messages.append(error_message)
        return
    config.read("/usr/share/AISpera/schedule/c2-feeder/config/.env")
    
    api_key = config["APIKEY"]["API_KEY"]
    web_hook = config["WEBHOOK"]["WEB_HOOK"]
    github_token = config["GITHUB"]["GIT_TOKEN"]

    # 파일을 GitHub 리포지토리에 복사하고 푸시
    source_directory = "/usr/share/AISpera/schedule/c2-feeder/"
    destination_directory = "/usr/share/AISpera/schedule/c2-feeder/C2-Daily-Feed"
    repository_url = "github.com/criminalip/C2-Daily-Feed.git"

    existing_ips = read_existing_ips()
    ip_data = fetch_unique_ips(api_key, existing_ips)

    sampled_ips, sampled_countries, sampled_tags, sampled_ports, sampled_scan_times = (
        sample_random_ips(ip_data, MAX_NEW_IPS)
    )

    current_date = datetime.now().strftime(DATE_FORMAT)
    new_ips_filename = f"/usr/share/AISpera/schedule/c2-feeder/C2-Daily-Feed/{current_date}.csv"
    print(new_ips_filename)
    # 점수와 국가를 분리하여 저장
    sampled_scores_and_countries = [get_cip_ip_report(ip, api_key) for ip in sampled_ips]
    sampled_scores = [item[0] for item in sampled_scores_and_countries]  # 점수만 추출
    sampled_countries = [item[1] for item in sampled_scores_and_countries]  # 국가만 추출

    save_data_to_csv(
        sampled_ips,
        sampled_tags,
        sampled_ports,
        sampled_scores,
        sampled_countries,
        sampled_scan_times,
        new_ips_filename,
    )
    generate_readme(current_date, new_ips_filename, len(sampled_ips))

    # 월마다 폴더 생성해서 이동
    move_old_files(destination_directory)

    success_message = f"C2-Feed Github에 배포 성공!!!"
    copy_and_push_files(source_directory, destination_directory, github_token, repository_url)

    send_slack_message(success_message, web_hook)

    # 에러 메시지가 있으면 슬랙으로 전송
    if error_messages:
        combined_errors = "\n".join(error_messages)
        send_slack_message(combined_errors, web_hook)

if __name__ == "__main__":
    main()