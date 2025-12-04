from django.db import models    
from django.conf import settings
import uuid

User = getattr(settings, "AUTH_USER_MODEL", None)


class StudentProfile(models.Model):
    profile_id = models.UUIDField(max_length=20, primary_key=True, unique=True, default=uuid.uuid4)
    grade_level = models.CharField()
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    bio = models.TextField(null=True, blank=True)
    
    guardians = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)



class TeacherProfile(models.Model):
    profile_id = models.UUIDField(max_length=20, primary_key=True, unique=True, default=uuid.uuid4)

    