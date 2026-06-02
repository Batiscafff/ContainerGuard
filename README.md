# ContainerGuard

Веб-платформа агрегованого аналізу безпеки Docker-образів.

> Дипломна робота: «Засоби та методи захисту контейнерних аплікацій»

---

## Що робить система

ContainerGuard запускає сканування Docker-образу через чотири інструменти одночасно та зводить результати в єдиний дашборд:

| Інструмент | Що аналізує |
|------------|-------------|
| **Trivy** | CVE-вразливості в пакетах образу (Alpine SecDB, Debian Tracker та ін.) |
| **Grype** | CVE-вразливості (NVD + GHSA — незалежне джерело) |
| **Syft** | Software Bill of Materials (SBOM) у форматі CycloneDX |
| **Hadolint** | Статичний аналіз Dockerfile за best practices |

Результати Trivy і Grype **дедуплікуються** — якщо обидва знайшли одну CVE, вона зберігається один раз із позначкою `trivy+grype`. На основі знайдених вразливостей розраховується **Security Score** від 0 до 100.

> **Чому два CVE-сканери?** Trivy і Grype використовують різні бази даних. Trivy для Alpine-образів спирається на Alpine SecDB (дистрибутив-підтверджені CVE), Grype — на NVD (ширше охоплення). Разом вони знаходять більше вразливостей та взаємно верифікують результати.

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
- Docker Compose plugin (`docker compose`) або `docker-compose` v1.29+

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
5. Дочекатись завершення (spinner зникне автоматично — сторінка перезавантажиться)
6. Переглянути результати

Всі попередні скани доступні на сторінці **Історія**.

### Сторінка результатів

Результати організовані у чотири таби:

| Таб | Зміст |
|-----|-------|
| **Вразливості** | Таблиця CVE з фільтрами по severity та джерелу (Trivy / Grype / обидва) |
| **SBOM** | Список компонентів образу; кнопка завантаження CycloneDX JSON |
| **Dockerfile Issues** | Порушення best practices від Hadolint |
| **Аналітика** | Чотири інтерактивні графіки (Chart.js) |

Вгорі сторінки розміщено:
- **SVG-gauge** Security Score (0–100) із кольоровим індикатором
- **Сітка статистики** — кількість CVE по кожному рівню severity та загальна сума
- **Мета-рядок** — статус, час запуску, час завершення, UUID скану

### Вкладка «Аналітика»

Завантажується при першому кліку на таб, генерує чотири графіки:

| Графік | Опис |
|--------|------|
| Розподіл за severity | Donut-діаграма з відсотками по кожному рівню |
| Наявність виправлень | Donut із центральним відсотком та підписом «N із M мають фікс» |
| Джерела виявлення | Bar-chart: Тільки Trivy / Тільки Grype / Обидва знайшли |
| Топ пакетів | Горизонтальний bar-chart топ-12 пакетів за кількістю CVE |

### Видалення сканів

Скан можна видалити кнопкою **Видалити** на сторінці результатів або в рядку таблиці на сторінці Історія. Видалення каскадно прибирає всі пов'язані вразливості, компоненти SBOM та проблеми Dockerfile.

---

## Структура проєкту

```
ContainerGuard/
├── app/                        # FastAPI-застосунок
│   ├── main.py                 # точка входу
│   ├── config.py               # налаштування (pydantic-settings)
│   ├── database.py             # async SQLAlchemy engine
│   ├── models/                 # ORM-моделі (Scan, Vulnerability, SbomComponent, DockerfileIssue)
│   ├── schemas/                # Pydantic-схеми
│   ├── routers/
│   │   ├── pages.py            # HTML-сторінки (/, /scan, /results/{id}, /history)
│   │   ├── api.py              # JSON API (/api/scan/{id}/...)
│   │   └── hx.py              # HTML-фрагменти для htmx (/hx/scan/{id}/...)
│   ├── services/
│   │   ├── scan_service.py     # створення скану, відправка задачі в Celery
│   │   └── score_service.py    # розрахунок Security Score
│   ├── static/
│   │   ├── css/style.css       # темна тема, усі компоненти UI
│   │   └── js/
│   │       ├── htmx.min.js     # htmx 1.9.12
│   │       └── chart.umd.min.js# Chart.js 4 (графіки аналітики)
│   └── templates/              # Jinja2-шаблони
│       ├── base.html
│       ├── index.html
│       ├── results.html        # сторінка результатів (gauge, таби, графіки)
│       ├── history.html
│       └── partials/           # HTML-фрагменти для htmx
│           ├── summary.html    # SVG-gauge + сітка severity
│           ├── vuln_table.html # таблиця CVE
│           ├── sbom_table.html # таблиця SBOM
│           ├── dockerfile_table.html
│           └── charts.html     # Chart.js графіки
│
├── worker/                     # Celery worker (окремий контейнер)
│   ├── celery_app.py
│   ├── tasks.py                # задача scan_image: оркестрація сканерів
│   └── scanners/
│       ├── base.py             # BaseScanner (subprocess → docker run)
│       ├── trivy.py
│       ├── grype.py
│       ├── syft.py
│       └── hadolint.py
│
├── migrations/                 # Alembic
│   └── versions/
│       └── 0001_initial.py
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
| DELETE | `/api/scan/{id}` | Видалити скан і всі пов'язані дані (→ 204 No Content) |

### HTML-фрагменти (htmx)

Ці ендпоінти повертають готовий HTML для підстановки через htmx без перезавантаження сторінки:

| Метод | URL | Опис |
|-------|-----|------|
| GET | `/hx/scan/{id}/summary` | SVG-gauge + сітка severity |
| GET | `/hx/scan/{id}/vulnerabilities` | Таблиця CVE (`?severity=&source=`) |
| GET | `/hx/scan/{id}/sbom` | Таблиця SBOM-компонентів |
| GET | `/hx/scan/{id}/dockerfile` | Таблиця Dockerfile Issues |
| GET | `/hx/scan/{id}/charts` | Чотири Chart.js графіки (аналітика) |

Інтерактивна документація Swagger: `http://localhost:8000/docs`

---

## Security Score

Оцінка від **0** (критично) до **100** (безпечно).

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

Скопіюй `.env.example` в `.env` та за потреби зміни значення:

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

Створити нову міграцію після зміни моделей:

```bash
docker compose exec app alembic revision --autogenerate -m "опис змін"
docker compose exec app alembic upgrade head
```
