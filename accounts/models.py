from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
import uuid
from phonenumber_field.modelfields import PhoneNumberField

from . import profile_models

class CustomUserManager(BaseUserManager):
    """ 
        - Manager for handling account creation (CustomUser.objects.create_user(email=...., phone=..., username=..., password=...))
    """

    def create_user(self, email, phone, username, password, **extra_fields):
        """ 
            - Creata a normal/quest user in our application 
        """
        if not email:
            raise ValueError("Email mmust be provided")
        if not password:
            raise ValueError("Password must be provided")
        
        normalized_email = self.normalize_email(email)
        user = self.model(email=normalized_email, phone=phone, username=username, **extra_fields)
        user.set_password(password) # Hash user password before storage
        user.save(using=self._db) # Sace user to database
        return user        

    def create_superuser(self, email, phone, username, password, **extra_fields):
        """" 
            - Creat and save a super user/admin user 
        """
        if not extra_fields.get("is_superuser"):
            raise ValueError("Super user field must be provided")
        if not extra_fields.get("is_staff"):
            raise ValueError("Is staff field must be provided")
        
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_staff", True)

        user = self.create_user(email, phone, password, username, **extra_fields)
        return user


class CustomUser(AbstractBaseUser, PermissionsMixin):
    """ 
        - Add fields and methods necessary to support user account model
        - Custom user model using email, username, phone for authentication
        - Email (unique)
        - username (unique)
        - phone (unique)
        - get_full_name()
        - Role can be determined via classroom memebership
    """

    user_id = models.UUIDField(
        default=uuid.uuid4,
        primary_key=True,
        unique=True, 
        max_length=20,
        db_index=True

    )
    email = models.EmailField(max_length=200, null=False, blank=False, unique=True)
    username = models.CharField(unique=True, max_length=200)
    phone = PhoneNumberField(blank=False, null=False)
    first_name = models.CharField(max_length=200)
    middle_name = models.CharField(max_length=200)
    last_name = models.CharField(max_length=200)

    is_teacher = models.BooleanField(blank=True, null=True)
    is_student = models.BooleanField(blank=True, null=True)
    is_staff = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    objects = CustomUserManager()
    REQUIRED_FIELDS = ["phone", "username"]
    USERNAME_FIELD = "email"


    def get_full_name(self):
        return f"{self.first_name} {self.last_name} {self.middle_name}" \
            if self.first_name and self.last_name and self.middle_name else "Unknown"
    
    @property
    def is_admin(self):
        if not self.is_superuser:
            return False
        return self.is_superuser
    
    def __str__(self):
        return f"CustomUser({self.email}, {self.is_superuser})"
    
    class Meta:
        ordering = ["-created_at"]
        verbose_name = "user"
        db_table = 'users'
        constraints = [
            models.UniqueConstraint(
                fields=("first_name", "last_name", "middle_name"),
                name="unique_fisrtname_middlname_lastname"
            )
        ]
        indexes = [
            models.Index(fields=("email", "phone", "username", ), name="email_phone_username_idx"),
            models.Index(fields=("email", ), name="email_idx"),
            models.Index(fields=("is_deleted", ), name="is_deleted_idx"),
            models.Index(fields=("created_at", ), name="created_at_idx")
        ]


class OTP(models.Model):
    otp_id = models.UUIDField(
        max_length=20,
        primary_key=True,
        unique=True,
        default=uuid.uuid4,
        db_index=True
    )
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="otps")
    is_expired = models.BooleanField(default=False, db_index=True)
    is_used = models.BooleanField(default=False, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    otp_code = models.CharField(max_length=50, unique=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"OTP({self.user.email if self.user.email else self.user.username}, {self.otp_code})"
    
    class Meta:
        db_table="otps"
        verbose_name = "otp"

class PasswordReset(models.Model):
    reset_id = models.UUIDField(primary_key=True, unique=True, default=uuid.uuid4, max_length=20, db_index=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="rest_tokens")
    token = models.CharField(max_length=200, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    def __str__(self):
        return f"PasswordReset({self.user.username}, {self.token})"
    
    class Meta:
        db_table = "passwords_resets"
        ordering = ["-created_at"]