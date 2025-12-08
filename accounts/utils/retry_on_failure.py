
from django.conf import settings 
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

max_retries = getattr(settings, "MAX_TRIES_PER_DAY", 3)

def retry_request_on_failure(request):
    if request is not None:
        attempts = 0
        try:
            for _ in range(1, max_retries+1):
                if request and request is not None:
                    return {"success": True, "data": request}
                if attempts < max_retries:
                    time.sleep(2)
                    logging.info(f"Retryinng {attempts} ....")
                attempts += 1
            return {"success": False, "message": f"Unable to process request after {attempts} retries"}
        except Exception as exc:
            return {"succees":False, "message": f"Error: {exc}"}
    return {"success": False, "message": "No data to process"}