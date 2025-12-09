from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from django.conf import settings
from .utils.otp import otp_token
from .models import OTP
from .utils.tasks import send_notification_email
from .profile_models import UserRoles, StudentProfile, TeacherProfile

User=get_user_model()
@receiver(post_save, sender=User)
def send_token_after_account_registration(sender, instance, created, **kwargs):
    if isinstance(instance, User) and created:
        otp_data = otp_token()
        if not otp_data.get("success"):
            return 
        code  = otp_data.get("code")
        if OTP.objects.filter(otp_code=code).exists():
            send_token_after_account_registration(sender, instance, created, **kwargs)
        create_otp = OTP.objects.create(user=instance, otp_code=code)

        if create_otp:
            # send email notif
            subject = f" Hello {instance.username if instance.username else instance.email}"
            receiver = instance.email
            context = {
                "name": instance.username if instance.username else instance.email,
                "code": code,
                "app_name": getattr(settings, "APP_NAME"),
                "expires_at": getattr(settings, "OTP_EXPIRY")
            }
            try:
                send_notification_email.delay(
                    subject,
                    receiver,
                    template="accounts/otp_email.html",
                    context=context
                )
            except Exception as e:
                print("Failed")
                return {"success": False, "message": "Failed to send mail"}

@receiver(post_save, sender=User)
def save_profile_after_account_registration(
    sender, 
    instance, 
    created, 
    **kwargs):
    """"
    Create or save user profile after user account is created. 
    - Detect both teacher and student profiles
    """
    if created:
        try:
            user_role = UserRoles.objects.get(user=instance)
            if user_role.role == UserRoles.RoleChoices.STUDENT:
                StudentProfile.objects.create(user=instance)
            elif user_role.role == UserRoles.RoleChoices.TEACHER:
                TeacherProfile.objects.create(user=instance)
        except UserRoles.DoesNotExist:
            return {"success": False, "msg": "Error saving profile"}

