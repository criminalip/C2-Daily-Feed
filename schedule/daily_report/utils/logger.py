import logging
import os
from colorlog import ColoredFormatter


def set_logger(log_path, insertion_type):
    """
    로그 경로가 None 이거나 'None' 문자열이면 프로젝트 루트의 logs 디렉터리를 기본으로 사용한다.
    디렉터리가 없으면 자동으로 생성한다.
    """
    # 기본 로그 경로 보정
    if not log_path or str(log_path).lower() == "none":
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        log_path = os.path.join(base_dir, "logs")

    # 디렉터리 생성
    os.makedirs(log_path, exist_ok=True)

    log = logging.getLogger("daily_report")
    log.setLevel(logging.DEBUG)

    handler = logging.StreamHandler()
    formatter = ColoredFormatter(
        "%(log_color)s%(levelname)s%(reset)s | %(asctime)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={
            "DEBUG": "white",
            "ERROR": "red",
            "INFO": "green",
            "WARNING": "yellow",
            "CRITICAL": "red,bg_white",
        },
    )
    handler.setFormatter(formatter)
    log.addHandler(handler)

    # File Handler
    log_file = os.path.join(log_path, f"{insertion_type}.log")
    c_file_handler = logging.FileHandler(log_file)
    c_file_handler.setFormatter(formatter)
    c_file_handler.suffix = "%Y%m%d"
    log.addHandler(c_file_handler)
