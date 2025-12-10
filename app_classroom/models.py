from django.db import models
import uuid
from django.conf import settings

User = getattr(settings, "AUTH_USER_MODEL", None)

class Classroom(models.Model):
    class_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, max_length=20)
    
    # class room members
    teacher = models.ForeignKey(User, on_delete=models.CASCADE, related_name="classroom", help_text="Classroom supervisor")
    students = models.ManyToManyField(User, related_name="classroom_memebers", help_text="class room members")

    # Class Info
    name = models.CharField(max_length=255)
    description = models.TextField()
    section = models.CharField(max_length=255)

    # Invitation 
    invite_code = models.CharField(max_length=100, unique=True, editable=False)

    # boolean fields 
    is_assigned = models.BooleanField(default=False, help_text="Assign class to another user")
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False)

    # datetime
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    def __str__(self):
        return f"Classroom({self.name}, {self.teacher.username})"
    
    class Meta:
        db_table = "classroom"
        verbose_name_plural = "classrooms"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["name"], name="name_idx"),
            models.Index(fields=["is_active"], name="is_active_idx"),
            models.Index(fields=["is_deleted"], name="deleted_idx"),
            models.Index(fields=["invite_code"], name="invite_code_idx")
        ]


class ClassroomMembership(models.Model):
    class RoleChoices(models.TextChoices):
        TEACHER = "TEACHER", "teacher"
        TEACHING_ASSISTANT = 'TEACHING_ASSISTANT', "teaching_assistant"
        STUDENT = 'STUDENT', "student"

    classroom_membership_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, max_length=20)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="memebership")
    classroom = models.ForeignKey(Classroom, on_delete=models.CASCADE, related_name="memebership")
    role = models.CharField(max_length=20, choices=RoleChoices.choices, default=RoleChoices.STUDENT)

    date_joined = models.DateTimeField(auto_now_add=True)

    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ["user, classroom"]


class  ClassroomInvite(models.Model):
    classroom_invite_id = ...

class JoinRequest(models.Model):
    join_request_id = ...

    class Status(models.TextChoices):
        PENDING = ...
        APPROVED = ...
        REJECTED = ...