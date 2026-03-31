import os
import yaml
from typing import Any, Dict, Optional


class Config:
    """
    애플리케이션 공통 설정을 담는 클래스.

    - 기본 경로: 프로젝트 루트의 common.yaml
    - VPN_DAEMON_CONFIG_PATH 가 설정되어 있고 파일이 존재하면 그 경로를 우선 사용
    """

    def __init__(self, data: Dict[str, Any], path: str) -> None:
        self._data = data or {}
        self.path = path  # 실제로 로드한 설정 파일 경로

    # ----------------------------------------------------------------------
    # 공통 접근 메서드
    # ----------------------------------------------------------------------
    def get(self, group: str, field: Optional[str] = None, default: Any = None) -> Any:
        """
        YAML 구조를 기준으로 group / field 단위로 값을 조회한다.
        예) get("ES", "ES_HOST")
        """
        group_data = self._data.get(group)
        if group_data is None:
            return default

        if field is None:
            return group_data

        value = group_data.get(field, default)

        # 문자열 공백 처리
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return default

        return value

    # ----------------------------------------------------------------------
    # 편의 프로퍼티: ES / ES_AUDIT
    # ----------------------------------------------------------------------
    @property
    def es(self) -> Dict[str, Any]:
        """ES 설정 전체 (ES_HOST, ES_PORT, ES_USER, ES_PW 등)"""
        return self.get("ES", default={}) or {}

    @property
    def es_audit(self) -> Dict[str, Any]:
        """ES_AUDIT 설정 전체"""
        return self.get("ES_AUDIT", default={}) or {}


# ==========================================================================
# 내부용: 설정 파일 로더
# ==========================================================================
def _resolve_config_path() -> str:
    """
    실제로 사용할 설정 파일 경로를 결정한다.

    1) VPN_DAEMON_CONFIG_PATH 환경변수가 설정되어 있고, 해당 파일이 존재하면 그 경로 사용
    2) 아니면 프로젝트 루트의 common.yaml 사용
    """
    env_path = os.environ.get("VPN_DAEMON_CONFIG_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    # utils/config.py 기준으로 상위 디렉터리(프로젝트 루트)에서 common.yaml 찾기
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_path = os.path.join(base_dir, "common.yaml")
    return default_path


def _load_config() -> Config:
    config_path = _resolve_config_path()

    data: Dict[str, Any] = {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
            if isinstance(loaded, dict):
                data = loaded
    except Exception as ex:
        # 필요하면 나중에 logging 으로 변경
        print(f"[Config] 설정 파일 로드 실패: {config_path} - {ex}")

    return Config(data=data, path=config_path)


# 모듈 import 시 한 번만 로드해서 재사용
_APP_CONFIG = _load_config()


def get_config() -> Config:
    """
    외부에서 사용하는 단일 진입점.
    """
    return _APP_CONFIG
