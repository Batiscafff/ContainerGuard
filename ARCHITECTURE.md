# ContainerGuard — Архітектура системи

> Веб-платформа агрегованого аналізу безпеки Docker-образів  
> Дипломна робота: «Засоби та методи захисту контейнерних аплікацій»

---

## Зміст

1. [Загальний огляд](#1-загальний-огляд)
2. [Структура проєкту](#2-структура-проєкту)
3. [Компоненти системи](#3-компоненти-системи)
4. [База даних](#4-база-даних)
5. [Автентифікація та авторизація](#5-автентифікація-та-авторизація)
6. [API](#6-api)
7. [Сканери](#7-сканери)
8. [Черга задач (Celery + Redis)](#8-черга-задач-celery--redis)
9. [Frontend (Jinja2 + htmx)](#9-frontend-jinja2--htmx)
10. [Docker Compose](#10-docker-compose)
11. [Потік даних](#11-потік-даних)
12. [Алгоритми оцінювання](#12-алгоритми-оцінювання)
13. [Змінні середовища](#13-змінні-середовища)
14. [Відомі обмеження безпеки](#14-відомі-обмеження-безпеки)

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
│   │   ├── scan.py             # Scan (status, scan_mode, progress, stage, security_score, image_digest)
│   │   ├── vulnerability.py    # Vulnerability
│   │   ├── sbom.py             # SbomComponent
│   │   ├── dockerfile_issue.py # DockerfileIssue
│   │   ├── secret.py           # Secret (TruffleHog)
│   │   └── user.py             # User (email, hashed_password, api_key, is_active, is_admin)
│   │
│   ├── schemas/
│   │   ├── scan.py             # ScanStatus (включає progress, stage, scan_mode)
│   │   └── vulnerability.py
│   │
│   ├── dependencies.py         # get_current_user(), require_active(), require_admin(), require_auth()
│   │
│   ├── routers/
│   │   ├── auth.py             # /login, /logout, /register, /pending, /profile
│   │   ├── admin.py            # /admin/users — керування користувачами
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
│   │   ├── login.html          # сторінка входу
│   │   ├── register.html       # реєстрація нового користувача
│   │   ├── pending.html        # очікування активації адміном
│   │   ├── profile.html        # профіль + API-ключ
│   │   ├── admin_users.html    # адмін-консоль: список користувачів
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
│       ├── 0005_add_scan_mode.py     # колонка scan_mode
│       ├── 0006_add_users.py         # таблиця users
│       ├── 0007_add_user_roles.py    # колонки is_active, is_admin
│       └── 0008_add_image_digest.py  # колонка image_digest + індекс
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
image_digest   VARCHAR(100) SHA256-digest образу, NULL (тільки режим image)
                            INDEX ix_scans_image_digest — для швидкого пошуку кешу

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

users
─────────────────────────────────────────────────────
id              VARCHAR(36)  PK
email           VARCHAR(255) UNIQUE NOT NULL
hashed_password VARCHAR(255) NOT NULL  (bcrypt)
api_key         VARCHAR(64)  UNIQUE NOT NULL
is_active       BOOL         DEFAULT false  (доступ до сканера)
is_admin        BOOL         DEFAULT false  (доступ до /admin/*)
created_at      TIMESTAMP    DEFAULT now()
```

### ENUM-типи PostgreSQL

```sql
CREATE TYPE scan_status   AS ENUM ('pending','running','completed','failed');
CREATE TYPE vuln_severity AS ENUM ('critical','high','medium','low','negligible');
CREATE TYPE issue_severity AS ENUM ('error','warning','info');
```

> При помилці `DuplicateObjectError` під час міграції — `docker compose down -v`.

---

## 5. Автентифікація та авторизація

### Ролі користувачів

| Поле | Значення | Доступ |
|------|----------|--------|
| `is_active=false, is_admin=false` | Новий / заблокований | Тільки `/login`, `/register`, `/pending`, `/profile` |
| `is_active=true, is_admin=false` | Звичайний користувач | Сканер, API |
| `is_active=true, is_admin=true` | Адміністратор | Сканер, API + `/admin/*` |

### Реєстрація та активація

Будь-хто може зареєструватись через `/register`. Новий акаунт створюється з `is_active=false` — доступу до сканера немає. Після входу користувач бачить сторінку `/pending` з повідомленням про очікування.

Адмін активує акаунт через консоль `/admin/users`.

### Ініціалізація першого адміна

При першому старті (порожня таблиця `users`) автоматично створюється адмін з `is_active=true, is_admin=true`:

```python
# app/main.py — lifespan
password = secrets.token_urlsafe(16)   # генерується один раз
user = User(
    email=settings.admin_email,
    hashed_password=pwd_context.hash(password),  # bcrypt
    api_key=secrets.token_hex(32),
    is_active=True,
    is_admin=True,
)
```

Пароль виводиться в stdout (`docker compose logs app`) і більше ніде не зберігається у відкритому вигляді.

### Сесійна авторизація (веб-інтерфейс)

Використовує `starlette.middleware.sessions.SessionMiddleware` — підписаний cookie на базі `itsdangerous`. Session зберігає `user_id`, `user_email`, `is_admin`.

```
GET  /register → форма реєстрації
POST /register → створити User(is_active=false) → redirect /pending
GET  /login    → форма входу
POST /login    → перевірка bcrypt → set session → redirect / або /pending
POST /logout   → session.clear() → redirect /login
GET  /pending  → сторінка очікування для неактивних
```

### Dependency-ланцюг

```
get_current_user()   → будь-який залогінений (DB lookup по user_id із сесії)
    │
    ├── require_active()  → is_active=true  → інакше 307 /pending
    │       └── використовується в pages.py, hx.py
    │
    └── require_admin()   → is_admin=true   → інакше 403
            └── використовується в admin.py
```

### API-ключ (JSON API)

Кожен користувач має персональний API-ключ. Ключ видно на сторінці `/profile`, може бути перегенерований. `require_auth` приймає обидва методи і перевіряє `is_active`:

```
Session cookie  → браузер надсилає автоматично (htmx-запити)
X-API-Key header → зовнішні клієнти (curl, скрипти)
```

### Адмін-консоль (`/admin/users`)

| Дія | Ендпоінт |
|-----|----------|
| Переглянути всіх користувачів | `GET /admin/users` |
| Активувати | `POST /admin/users/{id}/activate` |
| Деактивувати | `POST /admin/users/{id}/deactivate` |
| Призначити адміном | `POST /admin/users/{id}/promote` |
| Зняти права адміна | `POST /admin/users/{id}/demote` |
| Видалити | `POST /admin/users/{id}/delete` |

Адмін не може деактивувати, понизити або видалити сам себе.

### Таблиця захисту роутів

| Роутер | Захист | Поведінка при відмові |
|--------|--------|-----------------------|
| `pages.py` | `require_active` | → 307 /login або /pending |
| `hx.py` | `require_active` | → 307 /pending |
| `admin.py` | `require_admin` | → 403 |
| `api.py` | `require_auth` | → 401 або 403 |
| `/login`, `/register`, `/pending`, `/static/*` | Без захисту | — |

---

## 6. API

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

## 7. Сканери

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

## 8. Черга задач (Celery + Redis)

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

    # Кеш за digest: якщо той самий образ сканувався < 7 днів тому —
    # копіюємо результати і завершуємо без запуску сканерів
    digest = _get_image_digest(image_name)    # docker inspect → sha256:...
    if digest:
        _update_image_digest(scan_id, digest)
        cached = _find_cached_scan(scan_id, digest)
        if cached:
            cached_id, cached_score = cached
            _copy_scan_results(cached_id, scan_id)
            _update_status(scan_id, "completed", score=cached_score)
            return                            # ← сканери не запускаються

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

### Кешування (режим «Образ»)

| Функція | Дія |
|---------|-----|
| `_get_image_digest(image)` | `docker inspect --format {{.Id}}` → `sha256:abc…` |
| `_update_image_digest(scan_id, digest)` | Зберігає digest у `scans.image_digest` |
| `_find_cached_scan(scan_id, digest)` | `SELECT id, security_score FROM scans WHERE image_digest=… AND status='completed' AND created_at > NOW()-7d` |
| `_copy_scan_results(from_id, to_id)` | `INSERT INTO vulnerabilities/sbom_components/secrets … SELECT … FROM … WHERE scan_id=from_id` |

Digest прив'язаний до **вмісту** образу, а не до тегу: `nginx:latest` після оновлення на Docker Hub отримає новий digest і кеш не спрацює.

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

## 9. Frontend (Jinja2 + htmx)

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

## 10. Docker Compose

```yaml
services:
  db:      # postgres:16-alpine
  redis:   # redis:7-alpine
  app:     # uvicorn --reload, port 8000, volume .:/code
  worker:  # celery worker, volume /var/run/docker.sock
```

`app` і `worker` будуються з одного `Dockerfile`, але запускаються з різними командами. `worker` додатково монтує Docker socket для запуску сканерів.

---

## 11. Потік даних

### Режим «Образ»

```
POST /scan або POST /api/scan
  → create_scan(): запис Scan(status=pending) в БД
  → celery.send_task("scan_image", scan_mode="image")
  → redirect → GET /results/{id}

Celery Worker:
  status=running, progress=5
  docker pull → progress=10
  docker inspect → digest sha256:…
  ┌─ digest знайдено в кеші (< 7 днів)?
  │   YES → copy vulnerabilities/sbom/secrets → status=completed ✓
  │   NO  → зберегти digest, запустити сканери
  └─ ThreadPoolExecutor(4):
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

## 12. Алгоритми оцінювання

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

## 13. Змінні середовища

```bash
DATABASE_URL=postgresql+asyncpg://cguser:changeme@db:5432/containergard

CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/1

DB_PASSWORD=changeme
APP_SECRET_KEY=change-this-secret
```

---

## 14. Відомі обмеження безпеки

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
