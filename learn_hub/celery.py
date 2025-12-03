from celery import Celery
import os
from celery.schedules import crontab


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'learn_hub.settings')

app = Celery("learn_hub")

app.config_from_object("django.conf:settings", namespace="CELERY")

app.autodiscover_tasks()
