from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings

class EmailService:
    def __init__(self):
        self.email_host= getattr(settings, "EMAIL_HOST_USER")
        

    def send_email(self, *args, **kwargs):
        subject = args[0]
        receiver = args[1]
        template = kwargs.get("template")
        context = kwargs.get("context")

        """
            - send email method 
            - retries up to 3 times on execution
        """
        try:
            if template and context is not None:
                body = render_to_string(template_name=template, context=context)
            if body is None:
                body = ""


            subject_title = subject.title() # Convert the title to title case

            send_email_notif = send_mail(
                subject=subject_title,
                message="", 
                from_email=self.email_host,
                recipient_list=[receiver],
                fail_silently=False,
                html_message=body
            )
            if send_email_notif:
                return {"success": True, "message_to": receiver}
        except Exception as exc:
            return f"Error ocurred {exc}"

    def otp_email(self, user, app_name, expires_at, code):
        subject = f"OTP Verification [{user}]"
        context = {
            "name": user,
            "app_name": app_name, 
            "expires_at": expires_at,
            "code": code
        }

        return subject, context

    def verify_email(self, user, app_name, login_url):
        subject = f"Account Verification [{app_name}]"
        context = {
            "name": user,
            "app_name": app_name,
            "login_url": login_url
        }
        return subject, context
    
    def password_reset_email(self, user, app_name, reset_url):
        subject = f"Password Reset [{app_name}]"
        context = {
            "name": user,
            "app_name": app_name,
            "reset_url": reset_url
        }
        return subject, context