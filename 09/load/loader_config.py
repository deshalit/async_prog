import logging

class LoaderConfig:
    URI = "http://localhost:8000/api/cves/bulk"
    """Endpoint to post data"""

    DIR = "./cves"
    """Directory that stores json-files with CVE records to import"""

    PARSE_NOTIFY_LIMIT = 3000
    """The number of cve-files after which parsing progress info is updated"""

    IMPORT_TASK_COUNT = 5
    """The number of async tasks to work with the database during an import process"""

    IMPORT_MONITOR_INTERVAL = 7
    """The number of seconds after which the import progress info is updated"""

    BATCH_SIZE = 200
    """The number of CVE records (and their secondary entities) that are uploaded to the server at one time"""

    LOG_LEVEL = logging.INFO
