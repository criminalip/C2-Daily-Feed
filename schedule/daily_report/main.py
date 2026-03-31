#!/usr/bin/env python3
import requests
from datetime import datetime, timedelta
from requests.auth import HTTPBasicAuth
from utils.logger import set_logger
from utils.lib import sendSlack
import logging
import os
from utils.config import get_config
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =========================
# Global Config
# =========================
bTestmode = False

fw_list = ["fortinet-7f", "fortinet-5f", "fortinet-7f-server", "pfsense"]
aud_list = ["snoopy"]
sec_fw_list = ["proxy"]  # firewall ES에서 조회할 Security 로그
av_list = ["clam"]

target = "log_monitoring"
logPath = os.getenv('CIP_LOG_PATH')
set_logger(logPath, target)
logger = logging.getLogger("daily_report")

config = get_config()
fw_conf = config.es
audit_conf = config.es_audit

HEADERS = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

# =========================
# Common Functions
# =========================
def parse_store_size(text: str) -> float:
    if not text:
        return 0.0

    text = text.strip().upper()

    if '"SECURITY_EXCEPTION"' in text or '"ERROR"' in text:
        logger.error(f"Elasticsearch error response: {text}")
        return 0.0

    try:
        if 'KB' in text:
            return float(text.replace('KB', ''))
        elif 'MB' in text:
            return float(text.replace('MB', '')) * 1024
        elif 'GB' in text:
            return float(text.replace('GB', '')) * 1024 * 1024
    except ValueError:
        return 0.0

    return 0.0


def format_amount(size_kb: float) -> str:
    if size_kb >= 1024 * 1024:
        return f"{size_kb / (1024 * 1024):.1f} GB"
    elif size_kb >= 1024:
        return f"{size_kb / 1024:.1f} MB"
    return f"{size_kb:.1f} KB"


def calc_percentage(today: float, yesterday: float) -> int:
    if yesterday <= 0:
        return 0
    return int((today - yesterday) / yesterday * 100)

# =========================
# Firewall Logs
# =========================
def firewall_log():
    two_days_before = (datetime.today() - timedelta(days=2)).strftime('%Y.%m.%d')
    one_day_before = (datetime.today() - timedelta(days=1)).strftime('%Y.%m.%d')

    amount_list = []
    percentage_list = []

    try:
        for index in fw_list:
            url_two = (
                f"https://{fw_conf['ES_HOST']}:{fw_conf['ES_PORT']}"
                f"/_cat/indices/{index}-{two_days_before}?h=store.size"
            )
            url_one = (
                f"https://{fw_conf['ES_HOST']}:{fw_conf['ES_PORT']}"
                f"/_cat/indices/{index}-{one_day_before}?h=store.size"
            )

            res_two = requests.get(
                url_two,
                auth=HTTPBasicAuth(fw_conf["ES_USER"], fw_conf["ES_PW"]),
                headers=HEADERS,
                timeout=10,
                verify=False,
            )
            res_one = requests.get(
                url_one,
                auth=HTTPBasicAuth(fw_conf["ES_USER"], fw_conf["ES_PW"]),
                headers=HEADERS,
                timeout=10,
                verify=False,
            )

            size_two = parse_store_size(res_two.text)
            size_one = parse_store_size(res_one.text)

            amount_list.append(format_amount(size_one))
            percentage_list.append(calc_percentage(size_one, size_two))

        firewall = ["Fortinet 7F", "Fortinet 5F", "Fortinet-7f-server", "pfsense"]
        return firewall, amount_list, percentage_list

    except Exception as e:
        logger.error(e)
        firewall = ["Fortinet 7F", "Fortinet 5F", "Fortinet-7f-server", "pfsense"]
        return firewall, ["0.0 MB"] * len(firewall), [0] * len(firewall)

# =========================
# Audit Logs
# =========================
def audit_log():
    two_days_before = (datetime.today() - timedelta(days=2)).strftime('%Y.%m.%d')
    one_day_before = (datetime.today() - timedelta(days=1)).strftime('%Y.%m.%d')

    amount_list = []
    percentage_list = []

    try:
        # audit ES에서 조회 (snoopy)
        for index in aud_list:
            url_two = (
                f"http://{audit_conf['ES_HOST']}:{audit_conf['ES_PORT']}"
                f"/_cat/indices/{index}-{two_days_before}?h=store.size"
            )
            url_one = (
                f"http://{audit_conf['ES_HOST']}:{audit_conf['ES_PORT']}"
                f"/_cat/indices/{index}-{one_day_before}?h=store.size"
            )

            res_two = requests.get(
                url_two,
                auth=HTTPBasicAuth(audit_conf["ES_USER"], audit_conf["ES_PW"]),
                headers=HEADERS,
                timeout=10,
            )
            res_one = requests.get(
                url_one,
                auth=HTTPBasicAuth(audit_conf["ES_USER"], audit_conf["ES_PW"]),
                headers=HEADERS,
                timeout=10,
            )

            size_two = parse_store_size(res_two.text)
            size_one = parse_store_size(res_one.text)

            amount_list.append(format_amount(size_one))
            percentage_list.append(calc_percentage(size_one, size_two))

        # firewall ES에서 조회 (proxy)
        for index in sec_fw_list:
            url_two = (
                f"https://{fw_conf['ES_HOST']}:{fw_conf['ES_PORT']}"
                f"/_cat/indices/{index}-{two_days_before}?h=store.size"
            )
            url_one = (
                f"https://{fw_conf['ES_HOST']}:{fw_conf['ES_PORT']}"
                f"/_cat/indices/{index}-{one_day_before}?h=store.size"
            )

            res_two = requests.get(
                url_two,
                auth=HTTPBasicAuth(fw_conf["ES_USER"], fw_conf["ES_PW"]),
                headers=HEADERS,
                timeout=10,
                verify=False,
            )
            res_one = requests.get(
                url_one,
                auth=HTTPBasicAuth(fw_conf["ES_USER"], fw_conf["ES_PW"]),
                headers=HEADERS,
                timeout=10,
                verify=False,
            )

            size_two = parse_store_size(res_two.text)
            size_one = parse_store_size(res_one.text)

            amount_list.append(format_amount(size_one))
            percentage_list.append(calc_percentage(size_one, size_two))

        audit = ["Snoopy", "Proxy"]
        return audit, amount_list, percentage_list

    except Exception as e:
        logger.error(e)
        audit = ["Snoopy", "Proxy"]
        return audit, ["0.0 MB"] * len(audit), [0] * len(audit)

# =========================
# Antivirus Logs
# =========================
def antivirus_log():
    two_days_before = (datetime.today() - timedelta(days=2)).strftime('%Y.%m.%d')
    one_day_before = (datetime.today() - timedelta(days=1)).strftime('%Y.%m.%d')

    amount_list = []
    percentage_list = []

    try:
        for index in av_list:
            url_two = (
                f"https://{fw_conf['ES_HOST']}:{fw_conf['ES_PORT']}"
                f"/_cat/indices/{index}-{two_days_before}?h=store.size"
            )
            url_one = (
                f"https://{fw_conf['ES_HOST']}:{fw_conf['ES_PORT']}"
                f"/_cat/indices/{index}-{one_day_before}?h=store.size"
            )

            res_two = requests.get(
                url_two,
                auth=HTTPBasicAuth(fw_conf["ES_USER"], fw_conf["ES_PW"]),
                headers=HEADERS,
                timeout=10,
                verify=False,
            )
            res_one = requests.get(
                url_one,
                auth=HTTPBasicAuth(fw_conf["ES_USER"], fw_conf["ES_PW"]),
                headers=HEADERS,
                timeout=10,
                verify=False,
            )

            size_two = parse_store_size(res_two.text)
            size_one = parse_store_size(res_one.text)

            amount_list.append(format_amount(size_one))
            percentage_list.append(calc_percentage(size_one, size_two))

        antivirus = ["ClamAV"]
        return antivirus, amount_list, percentage_list

    except Exception as e:
        logger.error(e)
        antivirus = ["ClamAV"]
        return antivirus, ["0.0 MB"] * len(antivirus), [0] * len(antivirus)

# =========================
# Main
# =========================
def elasticsearch():
    try:
        one_day_before = (datetime.today() - timedelta(days=1)).strftime('%Y.%m.%d')

        fw_idx, fw_amt, fw_pct = firewall_log()
        au_idx, au_amt, au_pct = audit_log()
        av_idx, av_amt, av_pct = antivirus_log()

        text = '=================================================\n'
        text += f'== {one_day_before} 방화벽 별 로그 수집 양 및 전일 대비 증감률\n=\n'

        for i in range(len(fw_idx)):
            text += f'= {fw_idx[i]} : {fw_amt[i]} (전일 대비 {fw_pct[i]} %)\n'

        text += '=\n=================================================\n'
        text += f'== {one_day_before} Security 로그 수집 양 및 전일 대비 증감률\n=\n'

        for i in range(len(au_idx)):
            text += f'= {au_idx[i]} : {au_amt[i]} (전일 대비 {au_pct[i]} %)\n'

        text += '=\n=================================================\n'
        text += f'== {one_day_before} Antivirus 로그 수집 양 및 전일 대비 증감률\n=\n'

        for i in range(len(av_idx)):
            text += f'= {av_idx[i]} : {av_amt[i]} (전일 대비 {av_pct[i]} %)\n'

        text += '=\n=================================================\n'

        logger.info(text)

        # Slack 전송
        channel = '#daily_report_com_test' if bTestmode else '#daily_report_audit'
        sendSlack(text=text, channel=channel, username='Report-Bot')

        logger.info('success')

    except Exception as e:
        logger.error(e)
        sendSlack(
            text=f"[ERROR] daily_report 실행 중 오류 발생\n{e}",
            channel='#daily_report_com_test',
            username='Report-Bot'
        )

# =========================
# Run
# =========================
if __name__ == "__main__":
    elasticsearch()
