from rest_framework.views import APIView
from .serializers import SendInviteSerializer
from .models import Classroom
from rest_framework import status
from rest_framework.response import Response
from .utils.email_service import EmailService
from accounts.utils.tasks import send_notification_email
from django.conf import settings

app_name = getattr(settings, "APP_NAME")

class SendInviteView(APIView):
    http_method_names = ["post"]

    serializer_class = SendInviteSerializer

    def get_queryset(self):
        return Classroom.objects.select_related("invite_code")
    
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data.get("email")
        code = serializer.validated_data.get("code")
        queryset = self.get_queryset()

        # retrieve classroom with the provided code 
        classroom = queryset.filter(invite_code=code).first()
        if classroom.DoesNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST, data={"success": False, "msg": "Can't fild classroom instance"})
        
        class_name = classroom.name
        service = EmailService()
        email_service = service.send_invite_code(code, email, app_name)
        subject = email_service[0]
        context = email_service[1]
        context. update({
            "class_name": class_name
        })

        try:
            send_notification_email.delay(
                subject,
                email,
                template="app_classroom/join.html",
                context=context
            )
        except Exception as exc:
            return Response(
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                data={"success": False, "msg": f"An error occurred: {str(exc)}"},
            )
        return Response(
            status=status.HTTP_200_OK,
            data={"success": True, "msg": "Invitation sent successfully"},
        )
        
    