# -*- coding: utf-8 -*-
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import traceback
import os

def sendSlack(text=None, channel='#daily_report_com', username='Report-Bot', attachments=None, file_name=None):
    token = os.environ.get('SLACK_BOT_TOKEN', '')
    
    try:
        client = WebClient(token=token)
        
        # 메시지 보내기
        response = client.chat_postMessage(
            channel=channel,
            text=text,
            username=username
        )
        
        return response
        
    except SlackApiError as e:
        print(f"Slack API Error: {e.response['error']}")
        print(traceback.format_exc())
        return None
    except Exception as ex:
        print(f"General Error: {ex}")
        print(traceback.format_exc())
        return None
