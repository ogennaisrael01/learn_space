from rest_framework import viewsets
from .profile_serializers import (
    StudentProfileSerializerCreate
)
from .profile_models import StudentProfile


class StudentProfileViewsets(viewsets.ModelViewSet):
    serializer_class = StudentProfileSerializerCreate
    queryset = StudentProfile.objects.all()

    