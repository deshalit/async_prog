Перед запуском треба підняти контейнер з БД:
    docker run --rm -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=app -p 5432:5432 postgres:16
та запустити
    alembic upgrade head
Запуск:
    python main.py <path_to_cve_dir>

Scenario of work:
    * всі вказані нижче таймінги отримані на моєму старенькому компі. Сподіваюся на зменшення часу виконання
      під час перевірки ДЗ на більш сучасному обладнанні.

    1. Скануємо вказаний каталог та всі підлеглі. Отримали список повних імен cve-файлів. Time elapsed ~ 5 sec
    2. Далі стартуємо окремі процеси, по одному на кожне фізичне ядро процу. Кожен процесс отримує свою частину
        списку файлів, отриманому на попередньому кроці. Далі кожен процес робить наступне:
        * парсить контент, фільтрує (для спрощення відхиляємо записи із state <> "PUBLISHED" та відсутньою датою
          публікації), зберігає в списку parsed_records.
          Time elapsed ~ 1 min
        * стартує декілька asyncio tasks та імпортує записи в БД. Кількість тасок можна регулювати через параметр
          IMPORT_TASK_COUNT в файлі config.py
          Time elapsed ~10 min - це жахливо, але зменшити цей показник мені так і не вдалося :(

Виконані команди alembic:
    alembic init --template async ./migrations
    alembic revision --autogenerate -m "create database structure"
    alembic upgrade head
