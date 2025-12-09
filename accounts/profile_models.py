from django.db import models    
from django.conf import settings
import uuid
from phonenumber_field.modelfields import PhoneNumberField

User = getattr(settings, "AUTH_USER_MODEL", None)


class StudentProfile(models.Model):
    profile_id = models.UUIDField(max_length=20, primary_key=True, unique=True, default=uuid.uuid4)
    grade_level = models.CharField()
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="student_profile")
    bio = models.TextField(null=True, blank=True)
    
    contact_number = PhoneNumberField(max_length=200, blank=True, null=True)
    social_links  = models.JSONField(blank=True, null=True)
    guardians = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"StudentProfile({self.user.username},)"


    class Meta:
        db_table = "student_profile"
        verbose_name = "students"

        indexes = [
            models.Index(fields=["created_at"], name="created_idx")
        ]
        ordering = ["-created_at"]
    

class TeacherProfile(models.Model):
    profile_id = models.UUIDField(max_length=20, primary_key=True, unique=True, default=uuid.uuid4)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="teacher_profile")
    subjects = models.TextField()
    bio = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    contact_number = PhoneNumberField(max_length=200, blank=True, null=True)
    social_links  = models.JSONField(blank=True, null=True)

    def __str__(self):
        return f"TeacherProfile({self.user.username})"
    
    class Meta:
        db_table = "teacher_profile"
        verbose_name = "teacher"

    def subjects(self):
        user_subjects = self.subjects.split(",")
        return [subj.strip() for subj in user_subjects]

class UserRoles(models.Model):
    class RoleChoices(models.TextChoices):
        STUDENT = "STUDENT", "student"
        TEACHER = "TEACHER", "teacher"
        ADMIN = "ADMIN", 'admin'


    role_id = models.UUIDField(
        max_length=20, 
        primary_key=True, 
        unique=True,
        db_index=True,
        default=uuid.uuid4
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="roles")
    role = models.CharField(
        max_length=20, 
        choices=RoleChoices.choices, 
        default=RoleChoices.STUDENT, 
        db_index=True
        )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"UserRoles({self.user.username}, {self.role})"

    class Meta:
        db_table = "roles"

class Certificates(models.Model):
    certificate_id = models.UUIDField(
        max_length=20, 
        primary_key=True, 
        db_index=True,
        default=uuid.uuid4,
        unique=True
    )
    name = models.CharField(max_length=200)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="certificates")
    description = models.TextField()
    certificate_uri = models.ImageField(upload_to="certificates/")
    issued_on = models.DateField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Certificates({self.user.username}, {self.description[:30]})"
    
    class Meta: 
        db_table = "certificates"

class ProfileAvater(models.Model):
    avater_id = models.UUIDField(
        max_length=20, 
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        db_index=True
    )
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="avater")
    avater_uri = models.ImageField(upload_to="profiles/")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta: 
        db_table = "avaters"
        verbose_name = "images"

    def __str__(self):
        return f"ProfileAvater({self.user.username})"