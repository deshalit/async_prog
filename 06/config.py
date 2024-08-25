DB_URI = "postgresql+asyncpg://postgres:postgres@localhost:5432/app"

# DB_ECHO = True
DB_ECHO = False

PARSE_NOTIFY_LIMIT = 3000
"""The number of cve-files after which parsing progress info is updated"""

DB_BATCH_SIZE = 1200
"""The number of CVE records (and their secondary entities) that are bulk-inserted to the database at one time"""

IMPORT_TASK_COUNT = 2
"""The number of async tasks to work with the database during an import process"""

IMPORT_MONITOR_INTERVAL = 5
"""The number of seconds after which the import progress info is updated"""