from rest_framework import viewsets, status, permissions
from .profile_serializers import (
    StudentProfileSerializerCreate,
    StudentProfileSerializerOut,
    TeacherProfileCreate,
    TeacherProfileOut,
    CertificateSerializer,
    AvaterSerializer
)
from .profile_models import StudentProfile, TeacherProfile, Certificates, ProfileAvater
from .permissions import IsAuthenticatedOrUser, IsStudent, IsTeacher, IsOwner
from rest_framework.response import Response
from rest_framework.decorators import action
from django.shortcuts import get_object_or_404



class StudentProfileViewsets(viewsets.ModelViewSet):
    """ 
        - Viewset for managing student profiles.
        - Supports CRUD operations.
        - Uses different serializers for read and write operations.
        - Applies custom permissions to restrict access.
        - Optimizes queryset with select_related for user data.
    """
    def get_serializer(self, *args, **kwargs):
        if self.request.method in ["post", "put", "partial_update"]:
            return StudentProfileSerializerCreate(*args, **kwargs)
        return StudentProfileSerializerOut(*args, **kwargs)
    
    def get_queryset(self):
        return StudentProfile.objects.select_related("user")
    
    permission_classes = [IsAuthenticatedOrUser]

    def perform_create(self, serializer):
        serializer.save(user=self.requst.user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.validated_data, status=status.HTTP_201_CREATED)

    @action(methods={"get"}, url_path="me", detail=False)
    def profile_me(self, request, *args, **kwargs):
        """ Logged in user profile (method "get")"""
        user = request.user
        queryset = self.get_queryset()

        try:
            user_profile = queryset.filter(user=user).first()
            if user_profile is None:
                return Response(status=status.HTTP_404_NOT_FOUND, data={
                        "success": False, "msg": "No Profile is associated with this account"
                        })
            serializer = self.get_serializer(user_profile)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as exc:
            return Response(status=status.HTTP_400_BAD_REQUEST, data={              
                        "success": False, "msg": f"Error while retrieving profile : {exc}"
                        })
         
        

class TeacherProfileViewsets(StudentProfileViewsets):
    """
        - Viewsets for managing teacher profiles
        - uses diffrent serializer to read and write output 
        - optimizes queryset
    """
    def get_serializer(self, *args, **kwargs):
        if self.request.method in ("post", "put", "patch"):
            return TeacherProfileCreate(*args, **kwargs)

        return TeacherProfileOut(*args, **kwargs)


    def get_queryset(self):
        return  TeacherProfile.objects.select_related("user")


class CertificateViewsets(viewsets.ModelViewSet):
    """" 
        - Viewset for managing certificates.
        - Supports CRUD operations.
        - Applies custom permissions to restrict access.
        - Optimizes queryset with select_related for user data.
    """
    
    def get_permissions(self):
        """ 
            - Assign permissions based on action type.
        """
        if self.action in ("create", "update", "patial_update"):
            permission_classes = [permissions.IsAuthenticated, IsOwner]
        else:
            permission_classes = [IsAuthenticatedOrUser]
        return [perm() for perm in permission_classes]

    def get_queryset(self):
        """ 
            - Optimize queryset with select_related for user data.
        """
        return Certificates.objects.select_related("user")
    
    serializer_class = CertificateSerializer

    def perform_create(self, serializer):
        """ Assign the current user to the certificate upon creation."""
        serializer.save(user=self.request.user)

    def create(self, request, *args, **kwargs):
        """ validate and save certificate instance """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.validated_data, status=status.HTTP_201_CREATED)
    

class AvaterViewsets(CertificateViewsets):
    """ 
        - Viewset for managing profile avatars.
        - Inherits from CertificateViewsets to reuse permission and creation logic.
        - Optimizes queryset with select_related for user data.
    """
    def get_queryset(self):
        return ProfileAvater.objects.select_related("user")

    serializer_class = AvaterSerializer

