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
11. [Алгоритми оцінювання](#11-алгоритми-оцінювання)
12. [Змінні середовища](#12-змінні-середовища)
13. [Відомі обмеження безпеки](#13-відомі-обмеження-безпеки)

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
│   /               – головна сторінка (вибір режиму)     │
│   /scan           – запуск сканування (форма)           │
│   /results/{id}   – сторінка результатів                │
│   /history        – історія сканувань                   │
│   /api/scan       – POST: запустити скан (JSON API)     │
│   /api/scan/{id}  – GET: статус, результати, звіти      │
│   /hx/scan/{id}   – GET: HTML-фрагменти для htmx        │
└──────────┬───────────────────────┬──────────────────────┘
           │ SQLAlchemy (async)    │ Celery send_task
┌──────────▼──────────┐  ┌────────▼──────────────────────┐
│    PostgreSQL        │  │        Redis (broker)         │
│                      │  │        Redis (backend)        │
│  scans               │  └────────┬──────────────────────┘
│  vulnerabilities     │           │ Celery worker
│  sbom_components     │  ┌────────▼──────────────────────┐
│  dockerfile_issues   │  │      Celery Worker             │
│  secrets             │  │                               │
└──────────▲──────────┘  │  scan_mode == "image":        │
           │ psycopg2     │  ┌────────────────────────┐   │
           └──────────────┤  │  ThreadPoolExecutor    │   │
                          │  │  ├─ TrivyScanner        │   │
                          │  │  ├─ GrypeScanner        │   │
                          │  │  ├─ SyftScanner         │   │
                          │  │  └─ TruffleHogScanner   │   │
                          │  │  + HadolintScanner      │   │
                          │  └────────────────────────┘   │
                          │                               │
                          │  scan_mode == "dockerfile":   │
                          │  └─ HadolintScanner only      │
                          └───────────────────────────────┘
                                        │ docker run --rm
                          ┌─────────────▼─────────────────┐
                          │  Docker Engine (host socket)   │
                          │  aquasec/trivy                │
                          │  anchore/grype                │
                          │  anchore/syft                 │
                          │  trufflesecurity/trufflehog   │
                          │  hadolint/hadolint            │
                          └───────────────────────────────┘
```

---

## 2. Структура проєкту

```
ContainerGuard/
│
├── docker-compose.yml
├── .env / .env.example
│
├── app/                        # FastAPI-застосунок
│   ├── main.py                 # точка входу, реєстрація роутерів
│   ├── config.py               # налаштування через pydantic-settings
│   ├── database.py             # async SQLAlchemy engine + session
│   │
│   ├── models/
│   │   ├── scan.py             # Scan (status, scan_mode, progress, stage, security_score)
│   │   ├── vulnerability.py    # Vulnerability
│   │   ├── sbom.py             # SbomComponent
│   │   ├── dockerfile_issue.py # DockerfileIssue
│   │   └── secret.py           # Secret (TruffleHog)
│   │
│   ├── schemas/
│   │   ├── scan.py             # ScanStatus (включає progress, stage, scan_mode)
│   │   └── vulnerability.py
│   │
│   ├── routers/
│   │   ├── pages.py            # HTML-сторінки (GET /, POST /scan, GET /results, /history)
│   │   ├── api.py              # JSON API (POST /api/scan, GET /api/scan/{id}/*)
│   │   └── hx.py               # HTML-фрагменти для htmx (/hx/scan/{id}/*)
│   │
│   ├── services/
│   │   ├── scan_service.py     # create_scan(): запис в БД + Celery send_task
│   │   └── score_service.py    # (не використовується напряму — логіка в worker)
│   │
│   ├── templates/
│   │   ├── base.html
│   │   ├── index.html          # перемикач режимів Образ / Dockerfile
│   │   ├── results.html        # умовний рендер під scan_mode
│   │   ├── history.html
│   │   └── partials/
│   │       ├── summary.html            # gauge + CVE-сітка
│   │       ├── dockerfile_summary.html # gauge + Error/Warning/Info-сітка
│   │       ├── vuln_table.html
│   │       ├── sbom_table.html
│   │       ├── dockerfile_table.html
│   │       ├── secrets_table.html
│   │       ├── charts.html             # 4 графіки (режим образу)
│   │       └── dockerfile_charts.html  # 2 графіки (режим dockerfile)
│   │
│   └── static/
│       ├── css/style.css
│       └── js/
│           ├── htmx.min.js
│           └── chart.umd.min.js
│
├── worker/
│   ├── celery_app.py
│   ├── tasks.py                # scan_image_task, _run_dockerfile_scan
│   └── scanners/
│       ├── base.py             # BaseScanner (_docker_run, mount_docker)
│       ├── trivy.py
│       ├── grype.py
│       ├── syft.py
│       ├── hadolint.py
│       └── trufflehog.py
│
├── migrations/
│   └── versions/
│       ├── 0001_initial.py           # scans, vulnerabilities, sbom_components, dockerfile_issues
│       ├── 0002_add_secrets.py       # таблиця secrets
│       ├── 0003_add_secret_raw_value.py
│       ├── 0004_add_scan_progress.py # колонки progress, stage
│       └── 0005_add_scan_mode.py     # колонка scan_mode
│
└── requirements.txt
```

---

## 3. Компоненти системи

### 3.1 FastAPI (app/)

- Рендеринг HTML-сторінок через Jinja2
- Прийом форми та JSON API для запуску сканувань
- HTML-фрагменти для htmx (`/hx/`) і JSON (`/api/`)
- Читання результатів з БД (async SQLAlchemy)

**Не виконує сканування** — тільки ставить задачу в чергу Celery.

### 3.2 Celery Worker (worker/)

- Окремий Docker-контейнер
- Два режими виконання задачі `scan_image_task`:
  - `scan_mode="image"` — 4 паралельних сканери (Trivy, Grype, Syft, TruffleHog) + Hadolint опціонально
  - `scan_mode="dockerfile"` — тільки Hadolint
- Оновлює `progress` і `stage` в БД після кожного завершеного сканера (через `add_done_callback`)
- Записує результати в PostgreSQL через sync psycopg2

### 3.3 Redis

- **Broker** — черга задач між FastAPI і Celery
- **Result backend** — зберігання статусів задач Celery

### 3.4 PostgreSQL

Постійне сховище всіх результатів. Два DB-клієнти:
- `app/` — async SQLAlchemy + asyncpg
- `worker/` — sync psycopg2 (Celery синхронний)

---

## 4. База даних

```
scans
─────────────────────────────────────────────────────
id             VARCHAR(36)  PK
image_name     VARCHAR(255) NOT NULL
status         ENUM         pending|running|completed|failed
scan_mode      VARCHAR(20)  image|dockerfile  DEFAULT 'image'
security_score INT          0-100, NULL поки не завершено
progress       INT          0-100, поточний прогрес  DEFAULT 0
stage          VARCHAR(120) текст поточного етапу, NULL
created_at     TIMESTAMP    DEFAULT now()
finished_at    TIMESTAMP    NULL
error_message  TEXT         NULL

    │ 1
    │
    ├─── vulnerabilities (N)
    │    id, scan_id, cve_id, package_name, installed_ver, fixed_ver
    │    severity ENUM critical|high|medium|low|negligible
    │    source   VARCHAR  trivy|grype|trivy+grype
    │    title, url
    │
    ├─── sbom_components (N)
    │    id, scan_id, name, version, type, purl
    │
    ├─── dockerfile_issues (N)
    │    id, scan_id, rule, line, message
    │    severity ENUM error|warning|info
    │
    └─── secrets (N)
         id, scan_id, detector_name, verified
         raw_redacted  VARCHAR  (замаскований вигляд для відображення)
         raw_value     TEXT     (повне значення, тільки для БД і модального вікна)
         file_path, layer, line, decoder_name
```

### ENUM-типи PostgreSQL

```sql
CREATE TYPE scan_status   AS ENUM ('pending','running','completed','failed');
CREATE TYPE vuln_severity AS ENUM ('critical','high','medium','low','negligible');
CREATE TYPE issue_severity AS ENUM ('error','warning','info');
```

> При помилці `DuplicateObjectError` під час міграції — `docker compose down -v`.

---

## 5. API

### POST /api/scan — запуск сканування

```json
// Тіло запиту
{
  "image_name": "nginx:latest",      // обов'язково для scan_mode=image
  "scan_mode": "image",              // "image" (за замовчуванням) | "dockerfile"
  "dockerfile_content": "FROM ..."   // опціонально для image, обов'язково для dockerfile
}

// Відповідь 201
{
  "id": "uuid",
  "image_name": "nginx:latest",
  "status": "pending",
  "scan_mode": "image"
}
```

### GET /api/scan/{id}/status

```json
{
  "id": "uuid",
  "status": "running",
  "scan_mode": "image",
  "progress": 44,
  "stage": "Grype завершено",
  "security_score": null,
  "created_at": "...",
  "finished_at": null,
  "error_message": null
}
```

### Повна таблиця ендпоінтів

| Метод | URL | Опис |
|-------|-----|------|
| POST | `/api/scan` | Запустити скан |
| GET | `/api/scan/{id}/status` | Статус + прогрес |
| GET | `/api/scan/{id}/summary` | Score + CVE-зведення |
| GET | `/api/scan/{id}/vulnerabilities` | CVE (`?severity=&source=`) |
| GET | `/api/scan/{id}/sbom` | SBOM-компоненти |
| GET | `/api/scan/{id}/sbom/download` | SBOM CycloneDX JSON |
| GET | `/api/scan/{id}/dockerfile` | Dockerfile Issues |
| GET | `/api/scan/{id}/secrets` | Секрети |
| GET | `/api/scan/{id}/report` | Повний JSON-звіт |
| GET | `/api/scan/{id}/vulnerabilities/csv` | CVE як CSV |
| DELETE | `/api/scan/{id}` | Видалити скан (→ 204) |

### HTML-фрагменти (htmx)

| GET | `/hx/scan/{id}/summary` | SVG-gauge + CVE-сітка |
|-----|------------------------|----------------------|
| GET | `/hx/scan/{id}/dockerfile-summary` | SVG-gauge + Error/Warning/Info |
| GET | `/hx/scan/{id}/vulnerabilities` | Таблиця CVE |
| GET | `/hx/scan/{id}/sbom` | Таблиця SBOM |
| GET | `/hx/scan/{id}/dockerfile` | Таблиця Issues |
| GET | `/hx/scan/{id}/secrets` | Таблиця секретів |
| GET | `/hx/scan/{id}/charts` | 4 графіки (режим образу) |
| GET | `/hx/scan/{id}/dockerfile-charts` | 2 графіки (режим dockerfile) |

---

## 6. Сканери

Всі наслідують `BaseScanner` (`worker/scanners/base.py`). Метод `_docker_run()` запускає `docker run --rm`. Trivy, Grype і TruffleHog потребують `mount_docker=True` (монтує `/var/run/docker.sock`) — вони самостійно завантажують образ.

| Сканер | Docker-образ | mount_docker | Вхід | Вихід |
|--------|-------------|-------------|------|-------|
| TrivyScanner | `aquasec/trivy` | ✓ | image name | JSON |
| GrypeScanner | `anchore/grype` | ✓ | image name | JSON |
| SyftScanner | `anchore/syft` | — | image name | CycloneDX JSON |
| TruffleHogScanner | `trufflesecurity/trufflehog` | ✓ | image name | NDJSON |
| HadolintScanner | `hadolint/hadolint` | — | Dockerfile (stdin) | JSON |

TruffleHog виводить NDJSON (один JSON-об'єкт на рядок). Парсер пропускає не-JSON рядки. Зберігаються `raw_value` (повне значення) і `raw_redacted` (маскований вигляд). `raw_value` ніколи не логується.

---

## 7. Черга задач (Celery + Redis)

### Задача `scan_image_task`

```python
@celery.task(bind=True, name="scan_image")
def scan_image_task(self, scan_id, image_name,
                    dockerfile_content=None, scan_mode="image"):

    if scan_mode == "dockerfile":
        _run_dockerfile_scan(scan_id, dockerfile_content)
        return

    # --- режим "image" ---
    _update_status(scan_id, "running")
    _update_progress(scan_id, 5, "Перевірка образу...")
    _check_image_exists(image_name)           # docker pull — fail-fast
    _update_progress(scan_id, 10, "Запуск сканерів")

    # Паралельний запуск 4 сканерів
    with ThreadPoolExecutor(max_workers=4) as executor:
        f_trivy      = executor.submit(TrivyScanner().run, image_name)
        f_grype      = executor.submit(GrypeScanner().run, image_name)
        f_syft       = executor.submit(SyftScanner().run, image_name)
        f_trufflehog = executor.submit(TruffleHogScanner().run, image_name)

        # Оновлення прогресу після кожного завершеного (thread-safe callback)
        f_trivy.add_done_callback(on_scanner_done("trivy"))
        f_grype.add_done_callback(on_scanner_done("grype"))
        f_syft.add_done_callback(on_scanner_done("syft"))
        f_trufflehog.add_done_callback(on_scanner_done("trufflehog"))

    # Після всіх 4: progress = 10 + 4×17 = 78%
    vulns = _merge_vulnerabilities(trivy_result, grype_result)

    if dockerfile_content:
        hadolint_result = HadolintScanner().run(dockerfile_content)
        _update_progress(scan_id, 85, "Hadolint завершено")

    _update_progress(scan_id, 92, "Збереження результатів...")
    # ... save to DB ...
    _update_status(scan_id, "completed", score=score)
```

### Прогрес (режим «Образ»)

| Подія | progress |
|-------|---------|
| Старт | 5% |
| Образ завантажено | 10% |
| +1 сканер завершено | 27% |
| +2 сканери | 44% |
| +3 сканери | 61% |
| +4 сканери | 78% |
| Hadolint (якщо є) | 85% |
| Збереження | 92% |

### Алгоритм дедупликації CVE

1. Групуємо за `(cve_id, package_name)`
2. Якщо обидва знайшли → `source = "trivy+grype"`, беремо вищий severity
3. Тільки один → `source = "trivy"` або `"grype"`

---

## 8. Frontend (Jinja2 + htmx)

### Два режими на головній сторінці

JS-перемикач змінює `scan_mode` hidden input, показує/приховує поле образу, змінює `required` на textarea.

### htmx-поллінг прогресу

```javascript
// results.html — кожні 3 сек поки pending/running
document.body.addEventListener("htmx:afterRequest", function(evt) {
  const data = JSON.parse(evt.detail.xhr.responseText);
  if (data.status === "completed" || data.status === "failed") {
    window.location.reload();
  } else {
    // Оновити progress bar і чипи сканерів без перезавантаження
    fill.style.width = data.progress + "%";
    pctEl.textContent = data.progress + "%";
    stageEl.textContent = data.stage;
  }
});
```

### Умовний рендер результатів

`results.html` перевіряє `scan.scan_mode`:
- `"image"` → gauge CVE + 5 табів (Вразливості, SBOM, Dockerfile, Секрети, Аналітика)
- `"dockerfile"` → gauge Dockerfile Score + 2 таби (Проблеми, Аналітика)

### Lazy-loading вкладок

- Всі таби завантажують дані через `hx-trigger="load"` при першому відкритті
- Вкладка «Аналітика» — `hx-trigger="click once"` (Chart.js не рендерить у прихованих елементах)

---

## 9. Docker Compose

```yaml
services:
  db:      # postgres:16-alpine
  redis:   # redis:7-alpine
  app:     # uvicorn --reload, port 8000, volume .:/code
  worker:  # celery worker, volume /var/run/docker.sock
```

`app` і `worker` будуються з одного `Dockerfile`, але запускаються з різними командами. `worker` додатково монтує Docker socket для запуску сканерів.

---

## 10. Потік даних

### Режим «Образ»

```
POST /scan або POST /api/scan
  → create_scan(): запис Scan(status=pending) в БД
  → celery.send_task("scan_image", scan_mode="image")
  → redirect → GET /results/{id}

Celery Worker:
  status=running, progress=5
  docker pull → progress=10
  ThreadPoolExecutor(4):
    TrivyScanner   → done → progress=27
    GrypeScanner   → done → progress=44
    SyftScanner    → done → progress=61
    TruffleHogScanner → done → progress=78
  [HadolintScanner якщо є Dockerfile] → progress=85
  merge_vulnerabilities() (dedup Trivy+Grype)
  calculate_score()
  save → progress=92
  status=completed, security_score=N

Browser (htmx polling /api/scan/{id}/status кожні 3с):
  → оновлює progress bar
  → на completed → window.location.reload()
  → lazy-load summary, CVE-table, SBOM, secrets, dockerfile, charts
```

### Режим «Dockerfile»

```
POST /scan або POST /api/scan (scan_mode=dockerfile)
  → create_scan(): image_name="Dockerfile"
  → celery.send_task("scan_image", scan_mode="dockerfile")

Celery Worker:
  status=running, progress=10
  HadolintScanner().run(dockerfile_content)
  calculate_dockerfile_score()
  save → progress=85
  status=completed

Browser:
  → на completed → reload
  → lazy-load dockerfile_summary, dockerfile_table, dockerfile_charts
```

---

## 11. Алгоритми оцінювання

### Security Score (режим «Образ»)

Логарифмічна шкала — реалістичніша для образів із великою кількістю low/medium CVE:

```python
import math
WEIGHTS = {"critical": 7, "high": 3, "medium": 1, "low": 0.3, "negligible": 0}
SOURCE_WEIGHT = {"trivy+grype": 1.0, "trivy": 0.1, "grype": 0.1}
penalty = sum(WEIGHTS[v["severity"]] * SOURCE_WEIGHT.get(v["source"], 0.1) for v in vulns)
score = max(0, round(100 - 30 * math.log10(1 + penalty))) if penalty > 0 else 100
```

CVE підтверджена обома сканерами — повна вага. Знайдена тільки одним — вага 0.1 (Grype через NVD часто знаходить CVE, які Alpine SecDB вважає неактуальними).

### Dockerfile Score (режим «Dockerfile»)

```python
WEIGHTS = {"error": 10, "warning": 3, "info": 1}
penalty = sum(WEIGHTS.get(i["severity"], 0) for i in issues)
score = max(0, 100 - penalty)
```

### Вердикти

| Діапазон | Режим образу | Режим Dockerfile |
|----------|-------------|-----------------|
| 65–100 | Безпечний | Добре написаний |
| 40–64 | Є ризики | Є порушення |
| 0–39 | Критичний стан | Потребує виправлень |

---

## 12. Змінні середовища

```bash
DATABASE_URL=postgresql+asyncpg://cguser:changeme@db:5432/containergard

CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/1

DB_PASSWORD=changeme
APP_SECRET_KEY=change-this-secret
```

---

## 13. Відомі обмеження безпеки

### Docker socket у контейнері воркера

`worker` монтує `/var/run/docker.sock` хост-системи, і передає цей socket у контейнери сканерів (Trivy, Grype, TruffleHog):

```yaml
# docker-compose.yml
worker:
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock
```

```python
# worker/scanners/base.py — прапор mount_docker=True
cmd += ["-v", "/var/run/docker.sock:/var/run/docker.sock"]
```

**Наслідок:** будь-який процес усередині `worker` або будь-якого сканера має root-еквівалентний доступ до хост-машини. Через socket можна запустити `docker run --privileged -v /:/host ...` і отримати повний контроль над файловою системою хоста.

**Чому так реалізовано:** Trivy, Grype і TruffleHog потребують доступу до Docker daemon для завантаження та читання шарів образу — це штатний режим роботи цих інструментів.

**Можливі пом'якшення (не реалізовані в поточній версії):**

| Підхід | Опис |
|--------|------|
| `docker save` + tar-файл | Воркер зберігає образ як `.tar`, передає файл сканерам — socket потрібен тільки воркеру, не сканерам |
| Registry-режим Trivy/Grype | `trivy image registry:image` та `grype registry:image` підключаються напряму до реєстру, без Docker daemon |
| Socket-proxy | Tecnative docker-socket-proxy обмежує дозволені API-виклики білим списком |

> Система призначена для роботи в ізольованому середовищі розробки або лабораторних умовах. Використання в production без усунення цього обмеження є неприйнятним.
