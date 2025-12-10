from django.dispatch import receiver
from django.db.models.signals import post_save
from .models import Classroom, ClassroomMembership, ClassroomInvite
from accounts.utils.tasks import send_notification_email
from .utils.email_service import EmailService
from django.conf import settings
from django.utils.crypto import get_random_string

app_name =  getattr(settings, "APP_NAME")

@receiver(post_save, sender=Classroom)
def invite_code(sender, instance, created, *args, **kwargs):
    """ Send invite code to the teacher atfer classrom creation """
    if isinstance(instance, Classroom) and created:
        user_email = instance.teacher.email # get the teacher email
        code = instance.invite_code # get invite code 

        service = EmailService()
        email_service = service.send_invite_code(code, user_email, app_name)
        subject = email_service[0]
        context = email_service[1]

        try:
            send_notification_email.delay(
                subject,
                user_email,
                template="app_classroom/invite.html",
                context=context
            )
        except Exception as exc:
            raise exc

@receiver(post_save, sender=Classroom)
def class_membership(sender, instance, created, **kwargs):
        """ Create classroom membership for the teacher after classroom is created """
        if isinstance(instance, Classroom) and created:
            user = instance.teacher
            membership = ClassroomMembership(user=user, classroom=instance, role=ClassroomMembership.RoleChoices.TEACHER)
            membership.save()
            
@receiver(post_save, sender=Classroom)
def classroom_invite(sender, instance, created, **kwargs):
     if created:
          random_string = get_random_string(length=18)
          invite = ClassroomInvite(classroom=instance, token=random_string)
          invite.save()


 