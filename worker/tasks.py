import math
import os
import re
import subprocess
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import psycopg2

from worker.celery_app import celery
from worker.scanners.grype import GrypeScanner
from worker.scanners.hadolint import HadolintScanner
from worker.scanners.syft import SyftScanner
from worker.scanners.trivy import TrivyScanner
from worker.scanners.trufflehog import TruffleHogScanner


def _connect():
    url = os.environ["DATABASE_URL"].replace("+asyncpg", "")
    m = re.match(r"postgresql://([^:]+):([^@]+)@([^:]+):(\d+)/(\w+)", url)
    if not m:
        raise ValueError(f"Cannot parse DATABASE_URL: {url}")
    user, password, host, port, dbname = m.groups()
    return psycopg2.connect(host=host, port=int(port), dbname=dbname, user=user, password=password)


def _update_progress(scan_id: str, progress: int, stage: str):
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE scans SET progress=%s, stage=%s WHERE id=%s",
            (progress, stage, scan_id),
        )
        conn.commit()


def _update_status(scan_id: str, status: str, score: int | None = None, error: str | None = None):
    with _connect() as conn, conn.cursor() as cur:
        if status == "completed":
            cur.execute(
                "UPDATE scans SET status=%s, security_score=%s, finished_at=%s WHERE id=%s",
                (status, score, datetime.now(timezone.utc), scan_id),
            )
        elif status == "failed":
            cur.execute(
                "UPDATE scans SET status=%s, error_message=%s, finished_at=%s WHERE id=%s",
                (status, error, datetime.now(timezone.utc), scan_id),
            )
        else:
            cur.execute("UPDATE scans SET status=%s WHERE id=%s", (status, scan_id))
        conn.commit()


def _merge_vulnerabilities(trivy: dict, grype: dict) -> list[dict]:
    merged: dict[tuple, dict] = {}

    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "negligible": 1, "unknown": 0}

    for v in trivy.get("vulnerabilities", []):
        key = (v["cve_id"], v["package_name"])
        merged[key] = {**v, "source": "trivy"}

    for v in grype.get("vulnerabilities", []):
        key = (v["cve_id"], v["package_name"])
        if key in merged:
            existing = merged[key]
            existing["source"] = "trivy+grype"
            if severity_rank.get(v["severity"], 0) > severity_rank.get(existing["severity"], 0):
                existing["severity"] = v["severity"]
        else:
            merged[key] = {**v, "source": "grype"}

    return list(merged.values())


def _save_vulnerabilities(scan_id: str, vulns: list[dict]):
    if not vulns:
        return
    with _connect() as conn, conn.cursor() as cur:
        cur.executemany(
            """INSERT INTO vulnerabilities
               (id, scan_id, cve_id, package_name, installed_ver, fixed_ver,
                severity, source, title, url)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            [
                (
                    str(uuid.uuid4()),
                    scan_id,
                    v["cve_id"],
                    v["package_name"],
                    v.get("installed_ver"),
                    v.get("fixed_ver"),
                    v["severity"],
                    v["source"],
                    v.get("title"),
                    v.get("url"),
                )
                for v in vulns
            ],
        )
        conn.commit()


def _save_sbom(scan_id: str, syft_result: dict):
    components = syft_result.get("components", [])
    if not components:
        return
    with _connect() as conn, conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO sbom_components (id, scan_id, name, version, type, purl) VALUES (%s,%s,%s,%s,%s,%s)",
            [
                (str(uuid.uuid4()), scan_id, c["name"], c.get("version"), c.get("type"), c.get("purl"))
                for c in components
            ],
        )
        conn.commit()


def _save_secrets(scan_id: str, trufflehog_result: dict):
    secrets = trufflehog_result.get("secrets", [])
    if not secrets:
        return
    with _connect() as conn, conn.cursor() as cur:
        cur.executemany(
            """INSERT INTO secrets
               (id, scan_id, detector_name, verified, raw_redacted, raw_value, file_path, layer, line, decoder_name)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            [
                (
                    str(uuid.uuid4()),
                    scan_id,
                    s["detector_name"],
                    s["verified"],
                    s.get("raw_redacted"),
                    s.get("raw_value"),
                    s.get("file_path"),
                    s.get("layer"),
                    s.get("line"),
                    s.get("decoder_name"),
                )
                for s in secrets
            ],
        )
        conn.commit()


def _save_dockerfile_issues(scan_id: str, hadolint_result: dict):
    issues = hadolint_result.get("issues", [])
    if not issues:
        return
    with _connect() as conn, conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO dockerfile_issues (id, scan_id, rule, severity, line, message) VALUES (%s,%s,%s,%s,%s,%s)",
            [
                (str(uuid.uuid4()), scan_id, i["rule"], i["severity"], i.get("line"), i["message"])
                for i in issues
            ],
        )
        conn.commit()


def _calculate_score(vulns: list[dict]) -> int:
    weights = {"critical": 7, "high": 3, "medium": 1, "low": 0.3, "negligible": 0}
    # trivy+grype = підтверджена CVE, повна вага
    # тільки один сканер = ймовірний шум (Grype/NVD часто знаходить неактуальні для Alpine)
    source_weight = {"trivy+grype": 1.0, "trivy": 0.1, "grype": 0.1}
    penalty = sum(
        weights.get(v["severity"], 0) * source_weight.get(v.get("source", ""), 0.5)
        for v in vulns
    )
    if penalty == 0:
        return 100
    return max(0, round(100 - 30 * math.log10(1 + penalty)))


_CACHE_TTL_DAYS = 7


def _get_image_digest(image_name: str) -> str | None:
    result = subprocess.run(
        ["docker", "inspect", image_name, "--format", "{{.Id}}"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode == 0:
        return result.stdout.strip()
    return None


def _update_image_digest(scan_id: str, digest: str):
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("UPDATE scans SET image_digest=%s WHERE id=%s", (digest, scan_id))
        conn.commit()


def _find_cached_scan(current_scan_id: str, digest: str) -> tuple[str, int] | None:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """SELECT id, security_score FROM scans
               WHERE image_digest = %s
                 AND status = 'completed'
                 AND id != %s
                 AND created_at > NOW() - INTERVAL '%s days'
               ORDER BY created_at DESC
               LIMIT 1""",
            (digest, current_scan_id, _CACHE_TTL_DAYS),
        )
        row = cur.fetchone()
        return (row[0], row[1]) if row else None


def _copy_scan_results(from_scan_id: str, to_scan_id: str):
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO vulnerabilities
                   (id, scan_id, cve_id, package_name, installed_ver, fixed_ver, severity, source, title, url)
               SELECT gen_random_uuid(), %s, cve_id, package_name, installed_ver, fixed_ver, severity, source, title, url
               FROM vulnerabilities WHERE scan_id = %s""",
            (to_scan_id, from_scan_id),
        )
        cur.execute(
            """INSERT INTO sbom_components (id, scan_id, name, version, type, purl)
               SELECT gen_random_uuid(), %s, name, version, type, purl
               FROM sbom_components WHERE scan_id = %s""",
            (to_scan_id, from_scan_id),
        )
        cur.execute(
            """INSERT INTO secrets
                   (id, scan_id, detector_name, verified, raw_redacted, raw_value, file_path, layer, line, decoder_name)
               SELECT gen_random_uuid(), %s, detector_name, verified, raw_redacted, raw_value, file_path, layer, line, decoder_name
               FROM secrets WHERE scan_id = %s""",
            (to_scan_id, from_scan_id),
        )
        conn.commit()


def _check_image_exists(image_name: str) -> None:
    result = subprocess.run(
        ["docker", "pull", image_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        if "not found" in stderr.lower() or "does not exist" in stderr.lower() or "manifest unknown" in stderr.lower():
            raise RuntimeError(f"Образ '{image_name}' не знайдено в реєстрі Docker Hub.")
        raise RuntimeError(f"Не вдалось завантажити образ '{image_name}':\n{stderr[:400]}")


def _calculate_dockerfile_score(issues: list[dict]) -> int:
    weights = {"error": 10, "warning": 3, "info": 1}
    penalty = sum(weights.get(i["severity"], 0) for i in issues)
    return max(0, 100 - penalty)


def _run_dockerfile_scan(scan_id: str, dockerfile_content: str | None):
    _update_status(scan_id, "running")
    _update_progress(scan_id, 10, "Запуск Hadolint...")
    try:
        if not dockerfile_content:
            raise RuntimeError("Dockerfile не надано")
        hadolint_result = HadolintScanner().run(dockerfile_content)
        score = _calculate_dockerfile_score(hadolint_result.get("issues", []))
        _update_progress(scan_id, 85, "Збереження результатів...")
        _save_dockerfile_issues(scan_id, hadolint_result)
        _update_status(scan_id, "completed", score=score)
    except Exception as exc:
        _update_status(scan_id, "failed", error=str(exc))
        raise


@celery.task(bind=True, name="scan_image")
def scan_image_task(
    self,
    scan_id: str,
    image_name: str,
    dockerfile_content: str | None = None,
    scan_mode: str = "image",
):
    if scan_mode == "dockerfile":
        _run_dockerfile_scan(scan_id, dockerfile_content)
        return

    _update_status(scan_id, "running")
    _update_progress(scan_id, 5, "Перевірка образу...")

    try:
        _check_image_exists(image_name)

        digest = _get_image_digest(image_name)
        if digest:
            _update_image_digest(scan_id, digest)
            cached = _find_cached_scan(scan_id, digest)
            if cached:
                cached_id, cached_score = cached
                _update_progress(scan_id, 50, "Завантаження з кешу...")
                _copy_scan_results(cached_id, scan_id)
                _update_status(scan_id, "completed", score=cached_score)
                return

        _update_progress(scan_id, 10, "Запуск сканерів")

        progress_lock = threading.Lock()
        completed_count = [0]

        scanner_names = {
            "trivy": "Trivy",
            "grype": "Grype",
            "syft": "Syft",
            "trufflehog": "TruffleHog",
        }

        def on_scanner_done(key):
            def callback(fut):
                if fut.exception() is not None:
                    return
                with progress_lock:
                    completed_count[0] += 1
                    pct = 10 + completed_count[0] * 17
                    label = f"{scanner_names[key]} завершено"
                _update_progress(scan_id, pct, label)
            return callback

        with ThreadPoolExecutor(max_workers=4) as executor:
            f_trivy = executor.submit(TrivyScanner().run, image_name)
            f_grype = executor.submit(GrypeScanner().run, image_name)
            f_syft = executor.submit(SyftScanner().run, image_name)
            f_trufflehog = executor.submit(TruffleHogScanner().run, image_name)

            f_trivy.add_done_callback(on_scanner_done("trivy"))
            f_grype.add_done_callback(on_scanner_done("grype"))
            f_syft.add_done_callback(on_scanner_done("syft"))
            f_trufflehog.add_done_callback(on_scanner_done("trufflehog"))

        # after all 4 scanners: 10 + 4*17 = 78%
        trivy_result = f_trivy.result()
        grype_result = f_grype.result()
        syft_result = f_syft.result()
        trufflehog_result = f_trufflehog.result()

        hadolint_result = {}
        if dockerfile_content:
            hadolint_result = HadolintScanner().run(dockerfile_content)
            _update_progress(scan_id, 85, "Hadolint завершено")

        _update_progress(scan_id, 92, "Збереження результатів...")
        vulns = _merge_vulnerabilities(trivy_result, grype_result)
        score = _calculate_score(vulns)

        _save_vulnerabilities(scan_id, vulns)
        _save_sbom(scan_id, syft_result)
        _save_dockerfile_issues(scan_id, hadolint_result)
        _save_secrets(scan_id, trufflehog_result)
        _update_status(scan_id, "completed", score=score)

    except Exception as exc:
        _update_status(scan_id, "failed", error=str(exc))
        raise
