# ContainerGuard

Веб-платформа агрегованого аналізу безпеки Docker-образів.

> Дипломна робота: «Засоби та методи захисту контейнерних аплікацій»

---

## Що робить система

ContainerGuard підтримує два режими сканування:

### Режим «Образ»

Запускає п'ять інструментів паралельно та зводить результати в єдиний дашборд:

| Інструмент | Що аналізує |
|------------|-------------|
| **Trivy** | CVE-вразливості в пакетах образу (Alpine SecDB, Debian Tracker та ін.) |
| **Grype** | CVE-вразливості (NVD + GHSA — незалежне джерело) |
| **Syft** | Software Bill of Materials (SBOM) у форматі CycloneDX |
| **TruffleHog** | Пошук секретів (ключі, токени, паролі) у шарах образу |
| **Hadolint** | Статичний аналіз Dockerfile за best practices (якщо Dockerfile вставлено) |

Результати Trivy і Grype **дедуплікуються** — якщо обидва знайшли одну CVE, вона зберігається один раз із позначкою `trivy+grype`. На основі знайдених вразливостей розраховується **Security Score** від 0 до 100.

### Режим «Dockerfile»

Тільки статичний аналіз Dockerfile через Hadolint — без завантаження образу. Зручно для перевірки Dockerfile на ранніх етапах розробки. Розраховується **Dockerfile Score** на основі знайдених порушень.

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

### Веб-інтерфейс

1. Перейти на головну сторінку `http://localhost:8000`
2. Вибрати режим: **Образ** або **Dockerfile**

**Режим «Образ»:**
- Ввести назву образу, наприклад `nginx:latest` або `python:3.10`
- За бажанням вставити вміст Dockerfile для аналізу Hadolint
- Натиснути **Сканувати**

**Режим «Dockerfile»:**
- Вставити вміст Dockerfile
- Натиснути **Аналізувати Dockerfile**

Всі попередні скани доступні на сторінці **Історія**.

### Сторінка результатів — режим «Образ»

Вгорі — **SVG-gauge** Security Score, сітка кількостей CVE по severity та мета-рядок.

| Таб | Зміст |
|-----|-------|
| **Вразливості** | Таблиця CVE з фільтрами по severity та джерелу (Trivy / Grype / обидва) |
| **SBOM** | Список компонентів образу; кнопка завантаження CycloneDX JSON |
| **Dockerfile Issues** | Порушення best practices від Hadolint |
| **Секрети** | Знайдені TruffleHog секрети з деталями в модальному вікні |
| **Аналітика** | Чотири інтерактивні графіки (Chart.js) |

### Сторінка результатів — режим «Dockerfile»

Вгорі — **SVG-gauge** Dockerfile Score, сітка Error / Warning / Info / Всього.

| Таб | Зміст |
|-----|-------|
| **Проблеми** | Таблиця порушень Hadolint з номером рядка та правилом |
| **Аналітика** | Donut-діаграма severity + топ порушених правил |

### Прогрес-бар

Під час сканування відображається прогрес-бар з поточним етапом та відсотком завершення. Чипи сканерів підсвічуються по мірі завершення кожного.

### Завантаження звітів (режим «Образ»)

| Файл | Вміст |
|------|-------|
| JSON звіт | Повні дані: метадані, всі CVE, SBOM, Dockerfile issues, секрети |
| CSV вразливості | Тільки CVE-список |
| SBOM CycloneDX | Компоненти образу у форматі CycloneDX 1.4 |

---

## Структура проєкту

```
ContainerGuard/
├── app/                        # FastAPI-застосунок
│   ├── main.py
│   ├── config.py
│   ├── database.py
│   ├── models/
│   │   ├── scan.py             # поля: status, scan_mode, progress, stage, security_score
│   │   ├── vulnerability.py
│   │   ├── sbom.py
│   │   ├── dockerfile_issue.py
│   │   └── secret.py
│   ├── schemas/
│   │   ├── scan.py
│   │   └── vulnerability.py
│   ├── routers/
│   │   ├── pages.py            # HTML-сторінки
│   │   ├── api.py              # JSON API (+ POST /api/scan)
│   │   └── hx.py               # HTML-фрагменти для htmx
│   ├── services/
│   │   ├── scan_service.py
│   │   └── score_service.py
│   ├── static/
│   │   ├── css/style.css
│   │   └── js/
│   │       ├── htmx.min.js
│   │       └── chart.umd.min.js
│   └── templates/
│       ├── base.html
│       ├── index.html          # перемикач режимів Образ / Dockerfile
│       ├── results.html        # умовний рендер під scan_mode
│       ├── history.html
│       └── partials/
│           ├── summary.html            # SVG-gauge + CVE-сітка (режим образу)
│           ├── dockerfile_summary.html # SVG-gauge + Error/Warning/Info (режим dockerfile)
│           ├── vuln_table.html
│           ├── sbom_table.html
│           ├── dockerfile_table.html
│           ├── secrets_table.html
│           ├── charts.html             # аналітика образу (4 графіки)
│           └── dockerfile_charts.html  # аналітика dockerfile (2 графіки)
│
├── worker/
│   ├── celery_app.py
│   ├── tasks.py                # scan_image_task + _run_dockerfile_scan
│   └── scanners/
│       ├── base.py
│       ├── trivy.py
│       ├── grype.py
│       ├── syft.py
│       ├── hadolint.py
│       └── trufflehog.py
│
├── migrations/
│   └── versions/
│       ├── 0001_initial.py
│       ├── 0002_add_secrets.py
│       ├── 0003_add_secret_raw_value.py
│       ├── 0004_add_scan_progress.py
│       └── 0005_add_scan_mode.py
│
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── .env.example
```

---

## API

### JSON API

| Метод | URL | Опис |
|-------|-----|------|
| **POST** | `/api/scan` | Запустити сканування (JSON body) → `201 { id, status, scan_mode }` |
| GET | `/api/scan/{id}/status` | Статус + прогрес (`progress`, `stage`) |
| GET | `/api/scan/{id}/summary` | Security Score + зведення по severity |
| GET | `/api/scan/{id}/vulnerabilities` | CVE-список (`?severity=critical&source=trivy`) |
| GET | `/api/scan/{id}/sbom` | SBOM-компоненти |
| GET | `/api/scan/{id}/sbom/download` | SBOM як CycloneDX JSON |
| GET | `/api/scan/{id}/dockerfile` | Проблеми Dockerfile |
| GET | `/api/scan/{id}/secrets` | Знайдені секрети |
| GET | `/api/scan/{id}/report` | Повний JSON-звіт |
| GET | `/api/scan/{id}/vulnerabilities/csv` | Вразливості як CSV |
| DELETE | `/api/scan/{id}` | Видалити скан (→ 204) |

#### POST /api/scan — приклади

```bash
# Сканування образу
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"image_name": "nginx:latest"}'

# Образ + Dockerfile
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"image_name": "nginx:latest", "dockerfile_content": "FROM nginx:latest\nEXPOSE 80"}'

# Тільки Dockerfile
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"scan_mode": "dockerfile", "dockerfile_content": "FROM ubuntu:22.04\nRUN apt-get update"}'
```

### HTML-сторінки

| Метод | URL | Опис |
|-------|-----|------|
| GET | `/` | Головна сторінка з формою |
| POST | `/scan` | Запуск сканування (форма) → редірект |
| GET | `/results/{id}` | Сторінка результатів |
| GET | `/history` | Список останніх 50 сканувань |

### HTML-фрагменти (htmx)

| GET | `/hx/scan/{id}/summary` | SVG-gauge + сітка severity |
|-----|------------------------|---------------------------|
| GET | `/hx/scan/{id}/dockerfile-summary` | SVG-gauge + Error/Warning/Info |
| GET | `/hx/scan/{id}/vulnerabilities` | Таблиця CVE |
| GET | `/hx/scan/{id}/sbom` | Таблиця SBOM |
| GET | `/hx/scan/{id}/dockerfile` | Таблиця Dockerfile Issues |
| GET | `/hx/scan/{id}/secrets` | Таблиця секретів |
| GET | `/hx/scan/{id}/charts` | Графіки аналітики образу |
| GET | `/hx/scan/{id}/dockerfile-charts` | Графіки аналітики dockerfile |

Інтерактивна документація Swagger: `http://localhost:8000/docs`

---

## Security Score

### Режим «Образ»

Оцінка від **0** до **100**, базується лише на CVE. Використовує логарифмічну шкалу — кожне подвоєння кількості CVE коштує однакову кількість балів, що дає реалістичніші результати для образів із великою кількістю low/medium вразливостей.

```
score = max(0, round(100 − 30 × log₁₀(1 + penalty)))

penalty = Σ severity_weight × source_weight
```

| Severity | Вага |
|----------|------|
| Critical | 7 |
| High | 3 |
| Medium | 1 |
| Low | 0.3 |
| Negligible | 0 |

| Джерело | Множник |
|---------|---------|
| trivy+grype (підтверджено обома) | 1.0 |
| trivy або grype (тільки один) | 0.1 |

CVE знайдена лише одним сканером враховується з вагою 0.1 — Grype через NVD часто знаходить CVE, які Alpine SecDB вважає неактуальними.

Орієнтовні значення:

| Ситуація | Score |
|----------|-------|
| Без CVE | 100 |
| Alpine (100+ Grype-only CVE) | ~65–75 |
| 5 confirmed critical | ~53 |
| 38 confirmed critical | ~27 |

### Режим «Dockerfile»

Оцінка від **0** до **100**, базується на порушеннях Hadolint.

| Severity | Штраф |
|----------|-------|
| Error | −10 |
| Warning | −3 |
| Info | −1 |

### Вердикти

| Діапазон | Режим образу | Режим Dockerfile |
|----------|-------------|-----------------|
| 65–100 | Безпечний | Добре написаний |
| 40–64 | Є ризики | Є порушення |
| 0–39 | Критичний стан | Потребує виправлень |

---

## Відомі обмеження безпеки

### Монтування Docker socket у воркері

Контейнер `worker` отримує доступ до `/var/run/docker.sock` хост-системи:

```yaml
# docker-compose.yml
worker:
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock
```

Це надає воркеру **root-еквівалентний доступ** до хост-машини — через socket можна запустити привілейований контейнер і отримати повний доступ до файлової системи хоста. Сканери Trivy, Grype та TruffleHog також отримують цей socket (`mount_docker=True` у `BaseScanner`), оскільки їм потрібно завантажувати та читати шари образів.

**Чому це зроблено саме так:** всі три сканери звертаються до Docker daemon для отримання образу та читання його шарів — це штатний спосіб їх роботи.

**Можливі пом'якшення (не реалізовані):**
- Передавати сканерам tar-архів образу (`docker save`) замість socket — сканери підтримують `--input file.tar`, але воркер все одно потребує socket для `docker save`
- Режим підключення до реєстру напряму (Trivy/Grype підтримують `registry:<image>`) — прибирає потребу в socket для цих двох, але TruffleHog потребує окремого рішення
- Socket-proxy (наприклад, Tecnative docker-socket-proxy) з білим списком дозволених API-викликів

> Для production-середовища монтування Docker socket є неприйнятним. Ця система призначена для використання в ізольованому середовищі розробки або лабораторних умовах.

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

Зміни в `app/` підхоплюються автоматично (Uvicorn `--reload` + volume mount).

Зміни в `worker/` потребують перезапуску:

```bash
docker compose restart worker
```

Нова міграція:

```bash
# Створити файл migrations/versions/000N_description.py вручну
docker compose exec app alembic upgrade head
```

> Міграції пишуться вручну (не `--autogenerate`). Кожен файл описує один атомарний набір змін з `upgrade()` і `downgrade()`.
