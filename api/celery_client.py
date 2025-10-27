from celery import Celery
import os
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Initialize Celery app
celery_app = Celery(
    "sectestops",
    broker=REDIS_URL,
    backend=REDIS_URL
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max per task
    task_soft_time_limit=3000,  # 50 minutes soft limit
)

# Import task to register it
@celery_app.task(name="start_scan_task", bind=True)
def start_scan_task(self, scan_id: str, target_url: str, tools: list):
    """
    Placeholder task - actual implementation is in worker/tasks.py
    This is just for API to send tasks to worker
    """
    return {"scan_id": scan_id, "status": "queued"}

