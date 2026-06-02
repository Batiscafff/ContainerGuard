# ContainerGuard — Архітектура системи

> Веб-платформа агрегованого аналізу безпеки Docker-образів  
> Дипломна робота: «Засоби та методи захисту контейнерних аплікацій»

---

## Зміст

1. [Загальний огляд](#1-загальний-огляд)
2. [Структура проєкту](#2-структура-проєкту)
3. [Компоненти системи](#3-компоненти-системи)
4. [База даних](#4-база-даних)
5. [API](#5-api)
6. [Сканери](#6-сканери)
7. [Черга задач (Celery + Redis)](#7-черга-задач-celery--redis)
8. [Frontend (Jinja2 + htmx)](#8-frontend-jinja2--htmx)
9. [Docker Compose](#9-docker-compose)
10. [Потік даних](#10-потік-даних)
11. [Security Score — алгоритм](#11-security-score--алгоритм)
12. [Змінні середовища](#12-змінні-середовища)

---

## 1. Загальний огляд

```
┌─────────────────────────────────────────────────────────┐
│                     Браузер користувача                  │
│              Jinja2 HTML + htmx (AJAX-запити)           │
└───────────────────────┬─────────────────────────────────┘
                        │ HTTP
┌───────────────────────▼─────────────────────────────────┐
│                   FastAPI (port 8000)                    │
│   /               – головна сторінка                    │
│   /scan           – запуск сканування                   │
│   /results/{id}   – сторінка результатів                │
│   /history        – історія сканувань                   │
│   /api/...        – JSON API для htmx-поллінгу          │
└──────────┬───────────────────────┬──────────────────────┘
           │ SQLAlchemy (async)    │ Celery task
┌──────────▼──────────┐  ┌────────▼──────────────────────┐
│    PostgreSQL        │  │        Redis (broker)         │
│                      │  │        Redis (backend)        │
│  scans               │  └────────┬──────────────────────┘
│  vulnerabilities     │           │ worker.py
│  sbom_components     │  ┌────────▼──────────────────────┐
│  dockerfile_issues   │  │      Celery Worker             │
└──────────▲──────────┘  │                               │
           │ write        │  ┌──────────────────────────┐ │
           └──────────────┤  │   Scanner Orchestrator   │ │
                          │  │                          │ │
                          │  │  run_trivy()             │ │
                          │  │  run_grype()             │ │
                          │  │  run_syft()              │ │
                          │  │  run_hadolint()          │ │
                          │  └──────────┬───────────────┘ │
                          └─────────────┼─────────────────┘
                                        │ docker run --rm
                          ┌─────────────▼─────────────────┐
                          │  Docker Engine (host socket)   │
                          │                               │
                          │  aquasec/trivy                │
                          │  anchore/grype                │
                          │  anchore/syft                 │
                          │  hadolint/hadolint            │
                          └───────────────────────────────┘
```

---

## 2. Структура проєкту

```
containergard/
│
├── docker-compose.yml          # оркестрація всіх сервісів
├── .env                        # змінні середовища
├── .env.example
│
├── app/                        # FastAPI-застосунок
│   ├── main.py                 # точка входу, реєстрація роутерів
│   ├── config.py               # налаштування через pydantic-settings
│   ├── database.py             # async SQLAlchemy engine + session
│   │
│   ├── models/                 # SQLAlchemy ORM-моделі
│   │   ├── __init__.py
│   │   ├── scan.py             # Scan
│   │   ├── vulnerability.py    # Vulnerability
│   │   ├── sbom.py             # SbomComponent
│   │   └── dockerfile_issue.py # DockerfileIssue
│   │
│   ├── schemas/                # Pydantic-схеми (request / response)
│   │   ├── scan.py
│   │   └── vulnerability.py
│   │
│   ├── routers/                # HTTP-маршрути
│   │   ├── pages.py            # GET / (HTML-сторінки)
│   │   └── api.py              # GET /api/... (JSON для htmx)
│   │
│   ├── services/               # бізнес-логіка
│   │   ├── scan_service.py     # створення скану, запуск задачі
│   │   └── score_service.py    # розрахунок Security Score
│   │
│   ├── templates/              # Jinja2-шаблони
│   │   ├── base.html
│   │   ├── index.html
│   │   ├── results.html
│   │   └── history.html
│   │
│   └── static/
│       ├── css/
│       │   └── style.css
│       └── js/
│           └── htmx.min.js
│
├── worker/                     # Celery worker (окремий контейнер)
│   ├── celery_app.py           # ініціалізація Celery
│   ├── tasks.py                # задача scan_image_task
│   │
│   └── scanners/               # обгортки над Docker-сканерами
│       ├── __init__.py
│       ├── base.py             # абстрактний BaseScanner
│       ├── trivy.py            # TrivyScanner
│       ├── grype.py            # GrypeScanner
│       ├── syft.py             # SyftScanner
│       └── hadolint.py         # HadolintScanner
│
├── migrations/                 # Alembic-міграції БД
│   ├── env.py
│   └── versions/
│
└── requirements.txt
```

---

## 3. Компоненти системи

### 3.1 FastAPI (app/)

Відповідає виключно за:
- рендеринг HTML-сторінок через Jinja2
- прийом форми запуску сканування
- JSON-ендпоінти для htmx-поллінгу статусу
- читання результатів з БД

**Не виконує сканування напряму** — лише ставить задачу в чергу Celery.

### 3.2 Celery Worker (worker/)

- запускається як окремий Docker-контейнер
- отримує задачу `scan_image_task(scan_id, image_name, dockerfile_content)`
- послідовно викликає всі сканери
- записує результати в PostgreSQL
- оновлює статус скану (`pending` → `running` → `completed` / `failed`)

### 3.3 Redis

Виконує дві ролі:
- **Broker** — черга задач між FastAPI і Celery
- **Result backend** — зберігання статусу виконання задач Celery

### 3.4 PostgreSQL

Постійне сховище всіх результатів сканувань. Детальна схема — у розділі 4.

---

## 4. База даних

### Діаграма таблиць

```
scans
─────────────────────────────────────────
id            UUID         PK
image_name    VARCHAR(255) NOT NULL
status        ENUM         pending|running|completed|failed
security_score INT         0-100, NULL поки не завершено
created_at    TIMESTAMP    DEFAULT now()
finished_at   TIMESTAMP    NULL
error_message TEXT         NULL

    │ 1
    │
    ├─── vulnerabilities (N)
    │    ────────────────────────────────
    │    id            UUID   PK
    │    scan_id       UUID   FK → scans.id
    │    cve_id        VARCHAR(30)     наприклад CVE-2023-1234
    │    package_name  VARCHAR(255)
    │    installed_ver VARCHAR(100)
    │    fixed_ver     VARCHAR(100)
    │    severity      ENUM   critical|high|medium|low|negligible
    │    source        ENUM   trivy|grype    ← який сканер знайшов
    │    title         TEXT
    │    url           TEXT
    │
    ├─── sbom_components (N)
    │    ────────────────────────────────
    │    id            UUID   PK
    │    scan_id       UUID   FK → scans.id
    │    name          VARCHAR(255)
    │    version       VARCHAR(100)
    │    type          VARCHAR(50)    os|library|application
    │    purl          TEXT           package URL (стандарт)
    │
    └─── dockerfile_issues (N)
         ────────────────────────────────
         id            UUID   PK
         scan_id       UUID   FK → scans.id
         rule          VARCHAR(20)    наприклад DL3008
         severity      ENUM   error|warning|info
         line          INT
         message       TEXT
```

### Індекси

```sql
CREATE INDEX idx_vuln_scan_id    ON vulnerabilities(scan_id);
CREATE INDEX idx_vuln_severity   ON vulnerabilities(severity);
CREATE INDEX idx_vuln_cve_id     ON vulnerabilities(cve_id);
CREATE INDEX idx_sbom_scan_id    ON sbom_components(scan_id);
CREATE INDEX idx_issues_scan_id  ON dockerfile_issues(scan_id);
```

---

## 5. API

### HTML-сторінки (routers/pages.py)

| Метод | URL | Опис |
|-------|-----|------|
| GET | `/` | Головна сторінка з формою |
| POST | `/scan` | Прийом форми, запуск задачі → редірект на `/results/{id}` |
| GET | `/results/{id}` | Сторінка результатів скану |
| GET | `/history` | Список останніх 50 сканувань |

### JSON API для htmx (routers/api.py)

| Метод | URL | Опис |
|-------|-----|------|
| GET | `/api/scan/{id}/status` | Статус та прогрес (`pending/running/completed`) |
| GET | `/api/scan/{id}/summary` | Security Score + CVE-зведення по severity |
| GET | `/api/scan/{id}/vulnerabilities` | Список CVE з фільтрами `?severity=critical&source=trivy` |
| GET | `/api/scan/{id}/sbom` | Список SBOM-компонентів |
| GET | `/api/scan/{id}/sbom/download` | Завантаження SBOM як CycloneDX JSON |
| GET | `/api/scan/{id}/dockerfile` | Проблеми Dockerfile |

---

## 6. Сканери

Кожен сканер — клас, що наслідує `BaseScanner`:

```python
# worker/scanners/base.py
from abc import ABC, abstractmethod

class BaseScanner(ABC):
    def run(self, image_name: str, **kwargs) -> dict:
        """Запускає Docker-контейнер сканера, повертає розпарсений dict."""
        ...

    def _docker_run(self, image: str, args: list[str]) -> str:
        """subprocess.run(['docker', 'run', '--rm', image, *args])"""
        ...

    @abstractmethod
    def parse(self, raw_output: str) -> dict:
        ...
```

### Параметри запуску сканерів

```python
# worker/scanners/trivy.py
DOCKER_IMAGE = "aquasec/trivy:latest"

def run(self, image_name: str) -> dict:
    args = [
        "image",
        "--format", "json",
        "--quiet",
        image_name
    ]
    # docker run --rm aquasec/trivy image --format json --quiet nginx:latest
```

```python
# worker/scanners/grype.py
DOCKER_IMAGE = "anchore/grype:latest"

def run(self, image_name: str) -> dict:
    args = [
        image_name,
        "-o", "json"
    ]
    # docker run --rm anchore/grype nginx:latest -o json
```

```python
# worker/scanners/syft.py
DOCKER_IMAGE = "anchore/syft:latest"

def run(self, image_name: str) -> dict:
    args = [
        image_name,
        "-o", "cyclonedx-json"
    ]
    # docker run --rm anchore/syft nginx:latest -o cyclonedx-json
```

```python
# worker/scanners/hadolint.py
DOCKER_IMAGE = "hadolint/hadolint:latest"

def run(self, dockerfile_content: str) -> dict:
    # dockerfile передається через stdin
    # docker run --rm -i hadolint/hadolint hadolint --format json -
```

### Доступ до Docker socket

Worker-контейнер потребує доступу до Docker Engine хост-машини:

```yaml
# docker-compose.yml (фрагмент worker)
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```

---

## 7. Черга задач (Celery + Redis)

### Ініціалізація

```python
# worker/celery_app.py
from celery import Celery

celery = Celery(
    "containergard",
    broker="redis://redis:6379/0",
    backend="redis://redis:6379/1",
)

celery.conf.update(
    task_serializer="json",
    result_expires=86400,       # результати Celery живуть 24 години
    worker_concurrency=2,       # два паралельних скани
)
```

### Задача сканування

```python
# worker/tasks.py
@celery.task(bind=True, name="scan_image")
def scan_image_task(self, scan_id: str, image_name: str,
                    dockerfile_content: str | None = None):

    # 1. Оновити статус → running
    update_scan_status(scan_id, "running")

    try:
        # 2. Паралельний запуск Trivy + Grype + Syft
        with ThreadPoolExecutor(max_workers=3) as executor:
            f_trivy  = executor.submit(TrivyScanner().run,  image_name)
            f_grype  = executor.submit(GrypeScanner().run,  image_name)
            f_syft   = executor.submit(SyftScanner().run,   image_name)

        # 3. Hadolint (тільки якщо є Dockerfile)
        hadolint_result = {}
        if dockerfile_content:
            hadolint_result = HadolintScanner().run(dockerfile_content)

        # 4. Агрегація + дедупликація CVE
        vulns = merge_vulnerabilities(f_trivy.result(), f_grype.result())

        # 5. Запис в БД
        save_vulnerabilities(scan_id, vulns)
        save_sbom(scan_id, f_syft.result())
        save_dockerfile_issues(scan_id, hadolint_result)

        # 6. Розрахунок Security Score
        score = calculate_score(vulns)
        update_scan_status(scan_id, "completed", score=score)

    except Exception as e:
        update_scan_status(scan_id, "failed", error=str(e))
        raise
```

### Алгоритм дедупликації CVE

Trivy і Grype можуть знаходити одну й ту саму CVE. Правило злиття:

1. Групуємо за `cve_id + package_name`
2. Якщо обидва сканери знайшли — записуємо `source = "trivy+grype"`
3. Якщо тільки один — `source = "trivy"` або `source = "grype"`
4. Пріоритет severity: беремо вищий із двох

---

## 8. Frontend (Jinja2 + htmx)

### Потік htmx-поллінгу на сторінці результатів

```html
<!-- templates/results.html (спрощено) -->

<!-- 1. Поки статус не completed — кожні 3 сек опитуємо API -->
<div id="status-block"
     hx-get="/api/scan/{{ scan_id }}/status"
     hx-trigger="every 3s [status != 'completed']"
     hx-swap="outerHTML">
  <p>⏳ Сканування виконується...</p>
</div>

<!-- 2. Коли completed — htmx замінює блок на реальні результати -->
<!-- Відповідь /api/scan/{id}/status при completed містить: -->
<div id="status-block">
  <!-- Security Score gauge -->
  <div hx-get="/api/scan/{{ scan_id }}/summary"
       hx-trigger="load"
       hx-target="#summary-block">
  </div>

  <!-- Таблиця CVE з live-фільтрами -->
  <select hx-get="/api/scan/{{ scan_id }}/vulnerabilities"
          hx-target="#vuln-table"
          hx-trigger="change"
          name="severity">
    <option value="">Всі</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
  </select>

  <div id="vuln-table"
       hx-get="/api/scan/{{ scan_id }}/vulnerabilities"
       hx-trigger="load">
  </div>
</div>
```

### Сторінки

| Шаблон | Опис |
|--------|------|
| `base.html` | Навігація, підключення htmx.min.js та style.css |
| `index.html` | Форма: поле image name + textarea Dockerfile |
| `results.html` | Дашборд: Score, CVE-таблиця, SBOM, Dockerfile-issues |
| `history.html` | Таблиця минулих сканувань з посиланнями |

---

## 9. Docker Compose

```yaml
# docker-compose.yml
version: "3.9"

services:

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: containergard
      POSTGRES_USER: cguser
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - pg_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "cguser"]
      interval: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s

  app:
    build: .
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
    ports:
      - "8000:8000"
    env_file: .env
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - .:/code

  worker:
    build: .
    command: celery -A worker.celery_app worker --loglevel=info
    env_file: .env
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - .:/code
      - /var/run/docker.sock:/var/run/docker.sock  # доступ до Docker Engine

volumes:
  pg_data:
```

### Dockerfile застосунку

```dockerfile
FROM python:3.12-slim

WORKDIR /code

RUN apt-get update && apt-get install -y docker.io && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
```

---

## 10. Потік даних

```
Користувач вводить "nginx:latest" → натискає "Сканувати"
        │
        ▼
POST /scan  (FastAPI)
  1. Створює запис Scan у БД зі статусом "pending"
  2. Викликає celery.send_task("scan_image", args=[scan_id, image_name])
  3. Повертає redirect → GET /results/{scan_id}
        │
        ▼
GET /results/{scan_id}  (FastAPI)
  Рендерить results.html з scan_id
  htmx починає поллінг /api/scan/{scan_id}/status кожні 3 сек
        │
        ▼
Celery Worker (паралельно)
  1. docker run aquasec/trivy   → JSON → parse → []Vulnerability
  2. docker run anchore/grype   → JSON → parse → []Vulnerability
  3. docker run anchore/syft    → CycloneDX JSON → parse → []SbomComponent
  4. docker run hadolint        → JSON → parse → []DockerfileIssue
  5. merge_vulnerabilities() — дедупликація
  6. calculate_score()
  7. Запис у PostgreSQL
  8. Статус → "completed"
        │
        ▼
htmx отримує status="completed"
  → завантажує summary, CVE-таблицю, SBOM, Dockerfile-issues
  → зупиняє поллінг
```

---

## 11. Security Score — алгоритм

Оцінка від **0** (найгірше) до **100** (найкраще).

```python
# app/services/score_service.py

WEIGHTS = {
    "critical":   -20,
    "high":       -10,
    "medium":      -3,
    "low":         -1,
    "negligible":   0,
}

MAX_PENALTY = 100   # при якому штрафі score = 0

def calculate_score(vulnerabilities: list[dict]) -> int:
    penalty = 0
    for vuln in vulnerabilities:
        penalty += abs(WEIGHTS.get(vuln["severity"], 0))

    score = max(0, 100 - int((penalty / MAX_PENALTY) * 100))
    return score
```

| Діапазон | Оцінка |
|----------|--------|
| 80–100 | 🟢 Безпечний |
| 50–79  | 🟡 Є ризики |
| 0–49   | 🔴 Критичний стан |

---

## 12. Змінні середовища

```bash
# .env.example

# PostgreSQL
DB_HOST=db
DB_PORT=5432
DB_NAME=containergard
DB_USER=cguser
DB_PASSWORD=changeme

DATABASE_URL=postgresql+asyncpg://cguser:changeme@db:5432/containergard

# Redis / Celery
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/1

# Застосунок
APP_SECRET_KEY=change-this-secret
DEBUG=true
```

---

## Порядок запуску для розробки

```bash
# 1. Клонувати репозиторій і перейти в директорію
git clone <repo>
cd containergard

# 2. Скопіювати змінні середовища
cp .env.example .env

# 3. Підняти всі сервіси
docker compose up --build

# 4. Застосувати міграції БД (в окремому терміналі)
docker compose exec app alembic upgrade head

# 5. Відкрити застосунок
open http://localhost:8000
```

---

*Документ описує архітектуру v1.0. Розширення: підтримка приватних реєстрів (credentials), webhook-нотифікації, порівняння двох сканів одного образу.*
