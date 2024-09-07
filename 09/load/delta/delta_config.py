import logging

class DeltaConfig:
    DELTA_FILE_NAME = 'delta.json'
    DELTA_LOG_FILE_NAME = 'deltaLog.json'
    URL_PATH = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/'
    MAX_DOWNLOAD_TASK_COUNT = 10
    CHECK_INTERVAL = 60 * 1
    LOG_LEVEL = logging.DEBUG
    SERVICE_HOST = 'localhost'
    SERVICE_PORT = 8001
    MESSAGE = 'changed'
