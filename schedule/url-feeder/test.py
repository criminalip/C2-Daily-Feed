import configparser
import os
from datetime import datetime, timedelta
from subprocess import Popen, PIPE

def run_command(command, cwd=None):
    """명령어를 실행하고 결과를 반환하는 함수"""
    process = Popen(command, cwd=cwd, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        raise Exception(f"Command {command} failed with error: {stderr.decode()}")
    
    return stdout.decode()

def push_to_github(repo_dir, github_token, repo_url):
    try:
        # Git 저장소 디렉토리로 이동
        os.chdir(repo_dir)

        # 사용자 정보 설정
        print(run_command(["git", "config", "--global", "user.name", "speraUser"]))
        print(run_command(["git", "config", "--global", "user.email", "pypygeek@aispera.com"]))

        # 해당 디렉토리를 안전한 디렉토리로 추가
        print(run_command(["git", "config", "--global", "--add", "safe.directory", repo_dir]))

        # 변경 사항을 스태시로 저장
        print(run_command(["git", "stash"], cwd=repo_dir))

        # GitHub 인증을 사용하여 리모트 리포지토리에서 업데이트 가져오기
        pull_url = f"https://{github_token}@{repo_url}"
        print(run_command(["git", "pull", "--rebase", pull_url], cwd=repo_dir))

        # 스태시된 변경 사항 복원
        print(run_command(["git", "stash", "pop"], cwd=repo_dir))

        # 모든 변경 사항을 스테이징
        print(run_command(["git", "add", "--all"], cwd=repo_dir))

        # 커밋 메시지 생성
        commit_message = f"Auto Feed update at {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        print(run_command(["git", "commit", "-m", commit_message], cwd=repo_dir))

        # GitHub PAT(Personal Access Token)을 사용하여 푸시
        push_url = f"https://{github_token}@{repo_url}"
        print(run_command(["git", "push", push_url, "main"], cwd=repo_dir))

        print("성공적으로 GitHub에 푸시되었습니다.")

    except Exception as e:
        print(f"오류 발생: {e}")




def main():
    # 파일을 GitHub 리포지토리에 복사하고 푸시
    source_directory = "/home/pypygeek/schedule/url-feeder/"
    destination_directory = "/home/pypygeek/schedule/url-feeder/Daily-Mal-Phishing"
    repository_url = "github.com/criminalip/Daily-Mal-Phishing.git"

    config = configparser.ConfigParser()
    if not os.path.exists("/home/pypygeek/schedule/url-feeder/config/.env"):
        return
    config.read("/home/pypygeek/schedule/url-feeder/config/.env")

    github_token = config["GITHUB"]["GIT_TOKEN"]

    push_to_github(destination_directory, github_token, repository_url)

if __name__ == "__main__":
    main()