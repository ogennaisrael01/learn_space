from celery import shared_task
from .email_notif import EmailService
from django.utils import timezone
from django.conf import settings
from accounts.models import OTP
import logging

logger =logging.getLogger(__name__)

@shared_task
def send_notification_email(*args, **kwargs):
    email = EmailService()
    email_service = email.send_email(*args, **kwargs)  
    return email_service

@shared_task
def expire_otp():
    try:
        logger.info("Scheduled task running......")

        expriry_minutes = getattr(settings, "OTP_EXPIRY", None)
        unused_otps = OTP.objects.filter(is_used=False, is_expired=False).iterator()
        now = timezone.now()

        for otp in unused_otps:
            expire_time = otp.created_at + timezone.timedelta(minutes=expriry_minutes)
            """ Compare the time the OTP was created + expiry munites with the current time"""
            if now > expire_time: 
                " update the otp table"
                logger.info("updating OTP")
                otp.is_expired = True
                otp.save(update_fields=["is_expired"])

        logger.info("OTP expiration check complete")

    except Exception as e:
        logger.error(f"Task not running....: {str(e)}", exc_info=True)
        raise e


