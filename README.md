# ContainerGuard

Веб-платформа агрегованого аналізу безпеки Docker-образів.

> Дипломна робота: «Засоби та методи захисту контейнерних аплікацій»

---

## Що робить система

ContainerGuard запускає сканування Docker-образу через п'ять інструментів одночасно та зводить результати в єдиний дашборд:

| Інструмент | Що аналізує |
|------------|-------------|
| **Trivy** | CVE-вразливості в пакетах образу (Alpine SecDB, Debian Tracker та ін.) |
| **Grype** | CVE-вразливості (NVD + GHSA — незалежне джерело) |
| **Syft** | Software Bill of Materials (SBOM) у форматі CycloneDX |
| **Hadolint** | Статичний аналіз Dockerfile за best practices |
| **TruffleHog** | Пошук секретів (ключі, токени, паролі) у шарах образу |

Результати Trivy і Grype **дедуплікуються** — якщо обидва знайшли одну CVE, вона зберігається один раз із позначкою `trivy+grype`. На основі знайдених вразливостей розраховується **Security Score** від 0 до 100.

> **Чому два CVE-сканери?** Trivy для Alpine-образів спирається на Alpine SecDB (дистрибутив-підтверджені CVE), Grype — на NVD (ширше охоплення). Разом вони знаходять більше вразливостей та взаємно верифікують результати.

---

## Стек технологій

- **FastAPI** — HTTP-сервер, HTML-сторінки та JSON API
- **Celery + Redis** — асинхронна черга сканувань
- **PostgreSQL** — зберігання результатів
- **SQLAlchemy (async) + Alembic** — ORM та міграції БД
- **Jinja2 + htmx** — серверний рендеринг і AJAX без React/Vue
- **Chart.js 4** — інтерактивні графіки на вкладці «Аналітика»
- **Docker Compose** — оркестрація всіх сервісів

---

## Швидкий старт

### Вимоги

- Docker Engine 20+
- Docker Compose plugin (`docker compose`)

### Запуск

```bash
# 1. Клонувати репозиторій
git clone <repo-url>
cd ContainerGuard

# 2. Скопіювати змінні середовища
cp .env.example .env

# 3. Підняти всі сервіси
docker compose up --build -d

# 4. Застосувати міграції БД
docker compose exec app alembic upgrade head

# 5. Відкрити застосунок
open http://localhost:8000
```

### Зупинка

```bash
docker compose down          # зупинити контейнери
docker compose down -v       # зупинити + видалити дані БД
```

---

## Використання

1. Перейти на головну сторінку `http://localhost:8000`
2. Ввести назву образу, наприклад `nginx:latest` або `python:3.10`
3. За бажанням вставити вміст Dockerfile для аналізу Hadolint
4. Натиснути **Сканувати**
5. Дочекатись завершення — Trivy, Grype, Syft і TruffleHog запускаються паралельно
6. Переглянути результати

Всі попередні скани доступні на сторінці **Історія**.

### Сторінка результатів

Вгорі сторінки — **SVG-gauge** Security Score із кольоровим індикатором, сітка кількостей CVE по severity та мета-рядок (статус, час запуску/завершення, UUID).

Результати організовані у п'ять табів:

| Таб | Зміст |
|-----|-------|
| **Вразливості** | Таблиця CVE з фільтрами по severity та джерелу (Trivy / Grype / обидва) |
| **SBOM** | Список компонентів образу; кнопка завантаження CycloneDX JSON |
| **Dockerfile Issues** | Порушення best practices від Hadolint |
| **Секрети** | Знайдені TruffleHog секрети з деталями в модальному вікні |
| **Аналітика** | Чотири інтерактивні графіки (Chart.js) |

Кнопка **Видалити** прихована поки скан виконується і з'являється лише після завершення.

### Вкладка «Секрети»

TruffleHog сканує всі шари образу на наявність витоку:

- **Тип детектора** — AWS, GitHub, Stripe, Aiven тощо
- **Статус** — «Підтверджено» (verified) або «Не перевірено» (potential match)
- Кнопка **Деталі** відкриває модальне вікно з повним значенням секрету, шляхом до файлу, шаром образу та декодером; кнопка **Копіювати** копіює значення в буфер обміну

### Вкладка «Аналітика»

Завантажується при першому кліку, генерує чотири Chart.js графіки:

| Графік | Опис |
|--------|------|
| Розподіл за severity | Donut-діаграма з відсотками по кожному рівню |
| Наявність виправлень | Donut із центральним відсотком «X% можна виправити» |
| Джерела виявлення | Bar-chart: Тільки Trivy / Тільки Grype / Обидва знайшли |
| Топ пакетів | Горизонтальний bar-chart топ-12 пакетів за кількістю CVE |

### Завантаження звітів

Кнопка **↓ Завантажити** (з'являється після завершення скану) містить три опції:

| Файл | Вміст |
|------|-------|
| JSON звіт | Повні дані: метадані, всі CVE, SBOM, Dockerfile issues, секрети |
| CSV вразливості | Тільки CVE-список, зручно для Excel / Google Sheets |
| SBOM CycloneDX | Компоненти образу у форматі CycloneDX 1.4 |

### Видалення сканів

Кнопка **Видалити** є на сторінці результатів і в рядку таблиці Історії. Видалення каскадно прибирає всі пов'язані записи (вразливості, SBOM, Dockerfile issues, секрети).

---

## Структура проєкту

```
ContainerGuard/
├── app/                        # FastAPI-застосунок
│   ├── main.py                 # точка входу
│   ├── config.py               # налаштування (pydantic-settings)
│   ├── database.py             # async SQLAlchemy engine
│   ├── models/                 # ORM-моделі
│   │   ├── scan.py
│   │   ├── vulnerability.py
│   │   ├── sbom.py
│   │   ├── dockerfile_issue.py
│   │   └── secret.py           # знайдені TruffleHog секрети
│   ├── schemas/                # Pydantic-схеми для JSON API
│   ├── routers/
│   │   ├── pages.py            # HTML-сторінки (/, /scan, /results/{id}, /history)
│   │   ├── api.py              # JSON API (/api/scan/{id}/...)
│   │   └── hx.py               # HTML-фрагменти для htmx (/hx/scan/{id}/...)
│   ├── services/
│   │   ├── scan_service.py     # створення скану, відправка задачі в Celery
│   │   └── score_service.py    # розрахунок Security Score
│   ├── static/
│   │   ├── css/style.css       # темна тема, усі компоненти UI
│   │   └── js/
│   │       ├── htmx.min.js     # htmx 1.9.12
│   │       └── chart.umd.min.js# Chart.js 4
│   └── templates/
│       ├── base.html
│       ├── index.html
│       ├── results.html
│       ├── history.html
│       └── partials/
│           ├── summary.html        # SVG-gauge + сітка severity
│           ├── vuln_table.html     # таблиця CVE
│           ├── sbom_table.html     # таблиця SBOM
│           ├── dockerfile_table.html
│           ├── secrets_table.html  # таблиця секретів + модальне вікно
│           └── charts.html         # Chart.js графіки
│
├── worker/                     # Celery worker (окремий контейнер)
│   ├── celery_app.py
│   ├── tasks.py                # scan_image: оркестрація 5 сканерів
│   └── scanners/
│       ├── base.py             # BaseScanner (_docker_run з mount_docker)
│       ├── trivy.py
│       ├── grype.py
│       ├── syft.py
│       ├── hadolint.py
│       └── trufflehog.py       # пошук секретів у шарах образу
│
├── migrations/
│   └── versions/
│       ├── 0001_initial.py     # scans, vulnerabilities, sbom_components, dockerfile_issues
│       ├── 0002_add_secrets.py # таблиця secrets
│       └── 0003_add_secret_raw_value.py  # колонка raw_value
│
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── .env.example
```

---

## API

### HTML-сторінки

| Метод | URL | Опис |
|-------|-----|------|
| GET | `/` | Головна сторінка з формою |
| POST | `/scan` | Запуск сканування → редірект на результати |
| GET | `/results/{id}` | Сторінка результатів |
| GET | `/history` | Список останніх 50 сканувань |

### JSON API

| Метод | URL | Опис |
|-------|-----|------|
| GET | `/api/scan/{id}/status` | Статус скану (`pending` / `running` / `completed` / `failed`) |
| GET | `/api/scan/{id}/summary` | Security Score + зведення по severity |
| GET | `/api/scan/{id}/vulnerabilities` | CVE-список (`?severity=critical&source=trivy`) |
| GET | `/api/scan/{id}/sbom` | SBOM-компоненти |
| GET | `/api/scan/{id}/sbom/download` | Завантажити SBOM як CycloneDX JSON |
| GET | `/api/scan/{id}/dockerfile` | Проблеми Dockerfile |
| GET | `/api/scan/{id}/secrets` | Знайдені секрети |
| GET | `/api/scan/{id}/report` | Повний JSON-звіт (`attachment`) |
| GET | `/api/scan/{id}/vulnerabilities/csv` | Вразливості як CSV |
| DELETE | `/api/scan/{id}` | Видалити скан і всі пов'язані дані (→ 204) |

### HTML-фрагменти (htmx)

| Метод | URL | Опис |
|-------|-----|------|
| GET | `/hx/scan/{id}/summary` | SVG-gauge + сітка severity |
| GET | `/hx/scan/{id}/vulnerabilities` | Таблиця CVE (`?severity=&source=`) |
| GET | `/hx/scan/{id}/sbom` | Таблиця SBOM |
| GET | `/hx/scan/{id}/dockerfile` | Таблиця Dockerfile Issues |
| GET | `/hx/scan/{id}/secrets` | Таблиця секретів |
| GET | `/hx/scan/{id}/charts` | Chart.js графіки (аналітика) |

Інтерактивна документація Swagger: `http://localhost:8000/docs`

---

## Security Score

Оцінка від **0** (критично) до **100** (безпечно). Базується лише на CVE — секрети в Score не враховуються.

| Severity | Штраф |
|----------|-------|
| Critical | −20 |
| High | −10 |
| Medium | −3 |
| Low | −1 |
| Negligible | 0 |

| Діапазон | Стан |
|----------|------|
| 80–100 | Безпечний |
| 50–79 | Є ризики |
| 0–49 | Критичний стан |

---

## Змінні середовища

```bash
DATABASE_URL=postgresql+asyncpg://cguser:changeme@db:5432/containergard

CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/1

DB_PASSWORD=changeme
APP_SECRET_KEY=change-this-secret
```

---

## Розробка

Зміни в `app/` підхоплюються автоматично — Uvicorn запущено з `--reload` і код змонтовано через volume.

Зміни в `worker/` потребують перезапуску:

```bash
docker compose restart worker
```

Після зміни моделей — нова міграція:

```bash
docker compose exec app alembic revision --autogenerate -m "опис"
docker compose exec app alembic upgrade head
```

> У цьому проєкті міграції пишуться вручну (не autogenerate), щоб мати повний контроль над SQL. Кожен файл у `migrations/versions/` описує один атомарний набір змін із `upgrade()` і `downgrade()`.
