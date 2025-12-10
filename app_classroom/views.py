from rest_framework.views import APIView
from .serializers import SendInviteSerializer, ClassRoomInviteSerializer
from .models import Classroom, ClassroomInvite
from rest_framework import status
from rest_framework.response import Response
from .utils.email_service import EmailService
from accounts.utils.tasks import send_notification_email
from django.conf import settings
from django.db import transaction
from .utils.helpers.service_helpers import email_service_helper
from django.shortcuts import get_object_or_404

app_name = getattr(settings, "APP_NAME")
base_url = getattr(settings, "BASE_URL")

class SendInviteView(APIView):
    http_method_names = ["post"]

    serializer_class = SendInviteSerializer

    def get_queryset(self):
        return Classroom.objects.select_related("invite_code")
    
    @transaction.atomic()
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data.get("email")
        code = serializer.validated_data.get("code")
        queryset = self.get_queryset()

        # retrieve classroom with the provided code 
        classroom = queryset.filter(invite_code=code).first()
        if not classroom:
            return Response(status=status.HTTP_400_BAD_REQUEST, data={"success": False, "msg": "Can't find classroom instance"})
        
        class_name = classroom.name
        service = EmailService()
        
        # Use helper function to manage email service and context
        subject, context = email_service_helper(
            service.send_invite_code,
            code, email, app_name,
            context_updates={"class_name": class_name}
        )
        
        # Handle case where context wasn't updated or service failed
        if not subject or not context:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"success": False, "msg": "Failed to prepare email"},
            )

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
        
class ClassroomInvite(APIView):
    """ 
    - Invite a user to join a classroom via email 
    - Only teachers can send out this class invite
    
    """
    http_method_names = ["post"]
    serializer_class = ClassRoomInviteSerializer
    def post(self, request, *args, **kwargs):
        invite_token = self.kwargs["invite_token"].strip()
        if not invite_token:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"success": False, "msg": "Failed to retrieve classroom id"}
            )
        classroomm_invite = get_object_or_404(ClassroomInvite, token=invite_token)
        if not request.user == classroomm_invite.classroom.teacher:
            return Response(
                status=status.HTTP_403_FORBIDDEN,
                data={"success": False, "msg": "You can not perform this action"}
            )
        serializer = self.serializer_class(data=request.data)
        email = serializer.validated_data.get("email")

        invite_token = classroomm_invite.token
        if invite_token is None:
            raise Exception
        invite_link = base_url + "api/v1/classroom/invite/{token}"