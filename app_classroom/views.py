from rest_framework.views import APIView
from .serializers import (
    SendInviteSerializer, 
    ClassRoomInviteSerializer, 
    ClassroomCreateSerializer,
    JoinClassViaCodeSerializer,
    JoinRequestSerializer,
    JoinRequestUpdateSerializer,
    JoinRequestListSerializer
)
from .models import Classroom, ClassroomInvite, ClassroomMembership, JoinRequest
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
from django.utils.translation import gettext_lazy as _
from accounts.utils.helpers.helpers import get_username
from .permissions import IsSupervisorOrStudent
from .paginations import CustomPageNumberpagination
from drf_yasg.utils import swagger_auto_schema

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
        serializer = self.serializer_class(data=request.data, partial=True)
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
    
class JoinRequestView(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated, IsSupervisorOrStudent]
    lookup_field = "pk"
    pagination_class = CustomPageNumberpagination

    def get_permissions(self):
        if self.action == "create": 
            permission_classes = [permissions.IsAuthenticated]
        else:
            permission_classes = [permissions.IsAuthenticated, IsSupervisorOrStudent]
        return [perm() for perm in permission_classes]
    

    def get_queryset(self):
        if self.action in ("list", "retireve"):
            return  JoinRequest.objects.select_related("user", "classroom")
        return JoinRequest.objects.all()


    def get_serializer_class(self, *args, **kwargs):
        if self.action in ("create", "update"):
            return JoinRequestSerializer
        if self.action == "partial_update":
            return JoinRequestUpdateSerializer
        return JoinRequestListSerializer

    def get_class_obj(self):
        return get_object_or_404(Classroom, class_id=self.kwargs["class_pk"])

    
    def create(self,request, *args, **kwargs):
        """ Create a join request """  
        classroom = self.get_class_obj()
        serializer = self.get_serializer(data=request.data, 
                                         context={
                                            "request": request,
                                            "classroom": classroom
                                            })
        serializer.is_valid(raise_exception=True)
        serializer.save()
        class_supervisor = classroom.teacher

        if not class_supervisor:
            return Response(data=_("No class Supervisor for this class to accept invite"))
        
        service = EmailService()
        user = get_username(request.user)

        subject, context = email_service_helper(
            service.send_request_email,
            classroom.name, app_name, user
        )
        
        if not subject or not context:
            return Response(data=_("Error initializing email notification"))
        print(class_supervisor.email)
        try:
            send_notification_email.delay(
                subject,
                class_supervisor.email,
                template="app_classroom/join_request.html",
                context=context
            )
        except Exception as exc:
            raise exc
        
        return Response(status=status.HTTP_201_CREATED, data=_("request sent, wait for approval"))

                  
    def partial_update(self, request, *args, **kwargs):
        """ Update user request. Either accept or reject request """

        request_id = kwargs.get("pk").strip()
        classroom = self.get_class_obj()

        if not request_id:
            return Response(data=_("No request provided"))

        join_request_obj = get_object_or_404(JoinRequest, join_request_id=request_id)
        if not request.user == join_request_obj.classroom.teacher:
            return Response(status=403, data=_("You are not permitted to perform this action"))
        
        serializer = self.get_serializer(
            join_request_obj,
            data=request.data,
            context={
                "request": request,
            },
            partial=True
        )
        serializer.is_valid(raise_exception=True)
        if  join_request_obj.status != JoinRequest.Status.PENDING:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=_("Can only updated pending request"))
        
        if join_request_obj.classroom != classroom:
            return Response(data=_("Request does not belong to this classroom"))
        
        serializer.save()
        status = serializer.validated_data["status"]
        # if the status is Accepted add  user to classroom membership
        if status != JoinRequest.Status.APPROVED:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=_("Request terminated. Not accepted"))
        
        # update  classroom and add user to classroom memebership
        try:
            join_request_obj.classroom.students.add(join_request_obj.user)

            # Add user to class membership as students

            membership = classroom_membership(
                user=join_request_obj.user,
                classroom=join_request_obj.classroom,
                role=ClassroomMembership.RoleChoices.STUDENT
            )
        except Exception as exc:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=_(f"error: {exc}"))
        

        service = EmailService()
        user = get_username(join_request_obj.user)
        accepted_by = get_username(request.user)
        classroom = join_request_obj.classroom.name

        subject, context = email_service_helper(
            service.accept_join_request_email,
            user, accepted_by, app_name, classroom
        )

        if not subject or not context:
            return Response(_("Email initalization failed"))
        try:
            send_notification_email.delay(
                subject,
                context,
                template="app_classroom/join_request_accepted.html",
                context=context
            )

        except Exception as exc:
            raise exc

        return Response(status=status.HTTP_200_OK, data=_("Request accepted and approved"))

    def update(self, request, *args, **kwargs):
        classroom = self.get_class_obj()
        request_id = kwargs.get("pk").strip()
        if not request_id:
            return Response(data=_("No request provided"))
        join_request_obj = get_object_or_404(JoinRequest, join_request_id=request_id)
        if request.user != join_request_obj.user:
            return Response(data=_("You can not perform this action"))
        
        serializer = self.get_serializer(
            data=request.data,
            context={
                "request": request,
                "classroom": classroom
            }
        )
        serializer.is_valid(raise_exception=True)
        serializer.update(join_request_obj, serializer.validated_data)
        return Response(status=status.HTTP_200_OK, data=_("Request updated successfully"))

    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)

    @swagger_auto_schema(auto_schema=None)
    def list(self, request, *args, **kwargs):
        classroom = self.get_class_obj()

        if request.user != classroom.teacher:
            return Response(
                {"detail": _("You are not permitted to perform this action")},
                status=status.HTTP_403_FORBIDDEN
            )

        queryset = self.filter_queryset(
            self.get_queryset().filter(classroom=classroom)
        )

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

        

        
class ClassroomViewSets(viewsets.ModelViewSet):
    serializer_class = ClassroomCreateSerializer
    queryset = Classroom.objects.all()
        