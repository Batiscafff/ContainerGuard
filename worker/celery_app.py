import os

from celery import Celery

celery = Celery(
    "containergard",
    broker=os.environ["CELERY_BROKER_URL"],
    backend=os.environ["CELERY_RESULT_BACKEND"],
    include=["worker.tasks"],
)

celery.conf.update(
    task_serializer="json",
    result_expires=86400,
    worker_concurrency=2,
)
