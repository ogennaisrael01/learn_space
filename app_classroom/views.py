from rest_framework.views import APIView
from .serializers import (
    SendInviteSerializer, 
    ClassRoomInviteSerializer, 
    ClassroomCreateSerializer,
    JoinClassViaCodeSerializer
)
from .models import Classroom, ClassroomInvite, ClassroomMembership
from rest_framework import status, permissions, viewsets
from rest_framework.response import Response
from .utils.email_service import EmailService
from accounts.utils.tasks import send_notification_email
from django.conf import settings
from django.db import transaction
from .utils.helpers.service_helpers import email_service_helper
from django.shortcuts import get_object_or_404
from django.utils.crypto import get_random_string
from .utils.classroom_membership import classroom_membership

app_name = getattr(settings, "APP_NAME")
base_url = getattr(settings, "BASE_URL")

class SendInviteView(APIView):
    http_method_names = ["post"]

    serializer_class = SendInviteSerializer

    def get_queryset(self):
        return Classroom.objects.select_related("teacher")
    
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
        
class ClassroomInviteView(APIView):
    """ 
    - Invite a user to join a classroom via email 
    - Only members in the class can send out invite.
    
    """
    http_method_names = ["post"]
    

    def get_object(self):
        """ return the class object based on the classroom_id"""
        classroom_id = self.kwargs["classroon_id"]
        print(classroom_id)
        classroom = get_object_or_404(Classroom, class_id=classroom_id)
        return classroom

    serializer_class = ClassRoomInviteSerializer
    def post(self, request, *args, **kwargs):

        # retrieve the classroom object
        classroom = self.get_object()
        allowed_users = [classroom.teacher, *classroom.students.all()]

        if request.user not in allowed_users:
            return Response(
                status=status.HTTP_403_FORBIDDEN,
                data={"success": False, "msg": "You can not perform this action"}
            )
        
        invite_token = get_random_string(length=20) # randomly generated token per invite.

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get("email")

        if invite_token is None:
            return Response(status=status.HTTP_400_BAD_REQUEST, 
                    data={
                        "success": False,
                        "msg": "No token is associated with this account"
                    })
        classroom_invite_obj = ClassroomInvite(
            classroom=classroom,
            email=email,
            invited_by=request.user,
            token=invite_token.strip()
        )
        
        invite_link = base_url + f"/api/v1/classroom/invite/accept/{invite_token}"

        # Send email invite
        service = EmailService()

        subject, context = email_service_helper(
            service.send_classroom_invite,
            invite_link, email, app_name, request.user.email, classroom.name
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
                template="app_classroom/classroom_invite.html",
                context=context
            )
        except Exception as exc:
            return Response(
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                data={"success": False, "msg": f"An error occurred: {str(exc)}"},
            )
        classroom_invite_obj.save()
        return Response(
            status=status.HTTP_200_OK,
            data={"success": True, "msg": "Invitation sent successfully"},
        )
        
class AccetpInviteView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    # http_method_names = ["patch"]

    def patch(self, request, *args, **kwargs):
        print(kwargs)
        invite_token = kwargs.get("invite_token")
        if invite_token is None:
            return Response(status=status.HTTP_400_BAD_REQUEST, 
                        data={"success": False, "msg": "Invalid request"})

        classroom_invite = get_object_or_404(ClassroomInvite, token=invite_token.strip())

        # If this invite exists add user to list of students 
        try:
            classroom_invite.classroom.students.add(request.user)
        except Exception as exc:
            raise exc
        invited_by = classroom_invite.invited_by 
        classroom_invite.accepted = True
        classroom_invite.save()
        membership = classroom_membership(request.user, 
                                          classroom_invite.classroom, 
                                          ClassroomMembership.RoleChoices.STUDENT
                                        
                                        
            )
        
        if not membership.get("success"):
            return Response(data=membership.get("message"))
        
        # Send email to the inviter notifying them of acceptance
        service = EmailService()
        subject, context = email_service_helper(
            service.send_invitation_accepted,
            invited_by.email,
            app_name,
            request.user.email,
        )

        try:
            send_notification_email.delay(
                subject,
                invited_by.email,
                template="app_classroom/invitation_accepted.html",
                context=context
            )
        except Exception as exc:
            raise exc
        
    
        return Response(
            status=status.HTTP_200_OK,
            data={"success": True, "msg": "You have successfully joined the classroom"},
        )

class JoinClasViaCodeView(APIView):
    http_method_names = ["patch"]
    serializer_class = JoinClassViaCodeSerializer

    def patch(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data.get("code")
        
        # get the class object
        classroom = get_object_or_404(Classroom, invite_code=code)
        # check if user is already in the list of students
        if request.user in classroom.students.all():
            return Response(status=status.HTTP_200_OK,
                            data={
                                "success": True,
                                "msg": "You are already a mmmber in this classrom"
                            })

        try:
            classroom.students.add(request.user)
        except Exception as exc:
            raise exc
        
        # create a class memebership for this user
        membership = classroom_membership(request.user, 
                                          classroom, 
                                          ClassroomMembership.RoleChoices.STUDENT
                                        
                                        
            )


        
        # TODO: SEND IN APP NOTIFICATION VIA WEBSOCKET

        if membership.get("success"):
            return Response(status=status.HTTP_200_OK, 
                            data={
                                "success": True,
                                "msg": "You have successfully joined the class"
                            })
        