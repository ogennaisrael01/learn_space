from django.db import models
import uuid
from django.conf import settings

User = getattr(settings, "AUTH_USER_MODEL", None)

class Classroom(models.Model):
    class_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, max_length=20)
    
    # class room members
    teacher = models.ForeignKey(User, on_delete=models.CASCADE, related_name="classroom", help_text="classroom_supervisor")
    students = models.ManyToManyField(User, related_name="classroom_memebers", help_text="class_room_members")

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
    role = models.CharField(max_length=20, choices=RoleChoices.choices, default=RoleChoices.STUDENT, db_index=True)

    date_joined = models.DateTimeField(auto_now_add=True)

    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "classroom_membership"
        constraints = [
            models.UniqueConstraint(fields=("user", "classroom"), name="unique_user_classroom")
        ]
    
    def __str__(self):
        return f"ClassroomMembership({self.user.username}, {self.classroom.name})"

class  ClassroomInvite(models.Model):
    classroom_invite_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, max_length=20)
    classroom = models.ForeignKey(Classroom, on_delete=models.CASCADE, related_name="invites")
    email= models.EmailField()
    invited_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name="invites")
    accepted = models.BooleanField(default=False)
    token = models.CharField(max_length=100, unique=True, editable=False) # Unique token class Invitation(class teachers only)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"ClassroomInvite({self.email}, {self.classroom.name})"  
    
    class Meta:
        db_table = "classroom_invite"
        indexes = [
            models.Index(fields=["email"], name="email_idx_class_invite"),
            models.Index(fields=["accepted"], name="accepted_idx"),
        ]

class JoinRequest(models.Model):
    class Status(models.TextChoices):
        PENDING = "PENDING", "pending"
        APPROVED = 'APPROVED', "approved"
        REJECTED = 'REJECTED', "rejected"

    join_request_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, max_length=20)
    classroom = models.ForeignKey(Classroom, on_delete=models.CASCADE, related_name="join_requests")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="join_requests")
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING, db_index=True)
    reason = models.TextField(null=True, blank=True)
    responded_at = models.DateTimeField(null=True, blank=True)
    responded_by = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name="responded_requests")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"JoinRequest({self.user.email}, {self.classroom.name}, {self.status})"

    class Meta:
        ordering = ["-created_at"]
        db_table = "join_request"
        constraints = [
            models.UniqueConstraint(fields=("user", "classroom"), name="unique_user_classroom_request")
        ]
        indexes = [
            models.Index(fields=["status"], name="status_idx"),
        ]