#!/bin/bash

# 환경 설정 파일에서 GITHUB_TOKEN 가져오기
source /usr/share/AISpera/schedule/url-feeder/config/git.env

# Git 저장소 디렉토리로 이동
cd /usr/share/AISpera/schedule/url-feeder/Daily-Mal-Phishing || { echo "Failed to navigate to repository directory"; exit 1; }

# 파일 목록 출력
ls -al

# Git 상태 확인
git status

# 변경 사항 스테이징
git add .

# 커밋 메시지 생성 및 커밋 (변경 사항이 없으면 오류 무시)
git commit -m "Auto Feed update at $(date +'%Y-%m-%d %H:%M')" || true

# GitHub 토큰을 사용하여 푸시
git push https://$GIT_TOKEN@github.com/criminalip/Daily-Mal-Phishing.git main

if [ $? -eq 0 ]; then
  echo "성공적으로 GitHub에 푸시되었습니다."
else
  echo "푸시 작업 중 오류가 발생했습니다."
fi
