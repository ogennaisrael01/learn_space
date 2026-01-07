from rest_framework import serializers
from phonenumber_field.serializerfields import PhoneNumberField
from django.contrib.auth.password_validation import validate_password as _validate_password
import email_validator
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.db.models import Q
from .profile_models import StudentProfile, TeacherProfile


User = get_user_model()
class RegistrationSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=200,
                                    required=True, 
                                    error_messages={
                                        "required": _("Email field is required for account registration")
                                    })
    phone = PhoneNumberField(max_length=50)
    username = serializers.CharField(max_length=200)
    password = serializers.CharField(max_length=50,
                                     write_only=True,
                                     required=True,
                                     error_messages={
                                        "required": _("Provide your password"),
                                        "blank": _("Field cannot be blank")
                                     })

    first_name = serializers.CharField(max_length=200, required=False)
    last_name = serializers.CharField(max_length=200, required=False)
    middle_name = serializers.CharField(max_length=200, required=False)

    def validate_password(self, value):
        """" Validate and return passwoed using the built in validation function"""
        if not value:
            return 
        _validate_password(value)
        return value
      
    def validate(self, attrs):
        """ Capitalize first_name, last_name, middle_name before storing"""
        if attrs["first_name"]:
            attrs["first_name"].title()
        if attrs["last_name"]:
            attrs["last_name"].title()
        if attrs["middle_name"]:
            attrs["middle_name"].title()

        return attrs

    def validate_email(self, value):
        email = value.lower()
        try:
            # Validate user email
            valid_email = email_validator.validate_email(email, check_deliverability=True)
        except (Exception, email_validator.EmailNotValidError) as e:
            raise serializers.ValidationError(f"Error Occured: {e}")
        # check is user already in the exits
        if  User.objects.filter(email=valid_email).exists():
            raise serializers.ValidationError({
                "email": _(f"User with {valid_email} already exists. Try loggingin or contact admin for support")
            })
        return valid_email.normalized

    def validate_username(self, value):
        username = value.strip()
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError({
                "username": _(f"A user with {username} already exists. Try loggingin or contact admin for support")
            }
            )
        return username
    
    def create(self, validated_data):
        password = validated_data.get("password")
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user

    


class ResendOtpSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=200,
                                    required=True, 
                                    error_messages={
                                        "required": _("Email field is required for account registration")
                                    })

    def validate_email(self, value):
        email = value.lower()
        try:
            valid_email = email_validator.validate_email(email, check_deliverability=True)
        except (Exception, email_validator.EmailNotValidError) as e:
            raise serializers.ValidationError(_("Email field invalid, provide a valid email address"))

        return valid_email.normalized


class VerifyOTPSerializer(serializers.Serializer):
    """ Serializer for verify OTP """

    code = serializers.CharField(max_length=50, required=True, 
                                 error_messages={
                                     "required": _("Provide the OTP code that was sent to your email")
                                 })

    def validate_code(self, value: str):
        if not value:
            raise serializers.ValidationError(_("code required"))
        value.strip()
        return value

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """ Custom token obtain pai serializer by adding extra token claims """

    def validate(self, attrs):
        login_identifier = attrs.get("email")
        password = attrs.get("password")
        try:
            user = User.objects.filter(
                    Q(email__iexact=login_identifier) |
                    Q(phone__iexact=login_identifier) | 
                    Q(username__iexact=login_identifier) 
            ).first()
            if not user:
                raise serializers.ValidationError(_("Invalid login credentials"))
            
            if not user.check_password(password):
                raise serializers.ValidationError(_("Password mismatch"))
            if not user.is_verified:
                raise serializers.ValidationError(_("Account not verified. Please varify your account to login"))
            if not user.is_active:
                raise serializers.ValidationError(_("Account is banned, try contacting the admin/support"))
        except Exception as e:
            raise serializers.ValidationError(_(f"Error occured: {e}"))
        
        self.user = user
        data = super().validate(attrs)
        
        data["user"] = {
            "user_id": user.user_id,
            "email": user.email,
            "username": user.username
        }
        return data
    
    @classmethod
    def get_token(cls, user):
        "provide extra claims. Email, username"
        token = super().get_token(user)

        token["email"] = user.email
        token["username"] = user.username

        return token
    
class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(max_length=1500, write_only=True,
                                          error_messages={
                                              "required": _("refresh token required to logout")
                                          })
    def validate_refresh_token(self, value):
        if not value:
            raise serializers.ValidationError(_("refresh token is required"))
        value.strip()
        return value
 
class AccountUpdateSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=200, 
                                   required=False)
    username = serializers.CharField(max_length=200, required=False)
    phone = PhoneNumberField()
    first_name = serializers.CharField(max_length=200, required=False)
    last_name = serializers.CharField(max_length=200, required=False)
    middle_name = serializers.CharField(max_length=200, required=False)

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance

    def validate(self, attrs):
        """ Capitalize first_name, last_name, middle_name before storing"""
        if attrs["first_name"]:
            attrs["first_name"].title()
        if attrs["last_name"]:
            attrs["last_name"].title()
        if attrs["middle_name"]:
            attrs["middle_name"].title()

        return attrs

    def validate_email(self, value):
        email = value.lower()
        try:
            # Validate user email
            valid_email = email_validator.validate_email(email, check_deliverability=True)
        except (Exception, email_validator.EmailNotValidError) as e:
            raise serializers.ValidationError(f"Error Occured: {e}")
        # check is user already in the exits
        if  User.objects.filter(email=valid_email).exists():
            raise serializers.ValidationError({
                "email": _(f"User with {valid_email} already exists. Try loggingin or contact admin for support")
            })
        return valid_email.normalized

    def validate_username(self, value):
        username = value.strip()
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError({
                "username": _(f"A user with {username} already exists. Try loggingin or contact admin for support")
            }
            )
        return username


class PasswordResetRequestSerializer(serializers.Serializer):
    """ Password reset request serializer 
        - Can enter your email, username or phone for password reset
    """
    user_itentifier = serializers.CharField(max_length=200, required=True)

    def validate_user_itentifier(self, value): 
        if not value:
            raise serializers.ValidationError(_("Provide your password identifier to request to password reset. either email, phone, or your username"))
        value.strip()
        return value

class PasswordResetConfirmSerializer(serializers.Serializer):
    """ Password Reset confirm serializer """
    new_password = serializers.CharField(max_length=200,
                                        required=True, 
                                        write_only=True,
                                        error_messages={
                                            "required": _("provide your password")
                                        }
                                        )
    confirm_password = serializers.CharField(max_length=200,
                                            required=True,
                                            write_only=True)

    def validate_new_password(self, value):
        _validate_password(value)
        return value
    
    def validate_confirm_password(self, value):
        _validate_password(value)
        return value

    def validate(self, attrs):
        password = attrs["new_password"].strip()
        confirm_password = attrs["confirm_password"].strip()

        if password != confirm_password:
            raise serializers.ValidationError(_("Password mismatch"))
        
        return attrs


class GoogleAuthSerializer(serializers.Serializer):
    id_token = serializers.CharField(required=True, write_only=True)

    def validate_id_token(self, value):
        if value is None:
            raise serializers.ValidationError(_("Id token cannot be blank when registring with google"))
        
        value.strip()
        return value

class UserOutSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = [
            "user_id", 
            "email",
            "phone",
            "username",
            "full_name",
            "is_teacher",
            "is_student",
            "is_verified",
            'created_at'
            ]

    def get_full_name(self, obj):
        return obj.get_full_name()



class OnboadingSerializer(serializers.Serializer):
    """
    A serializer for onboarding either teachers or students
    """
    role_choices = ["STUDENT", "TEACHER", "BOTH"]
    role = serializers.ChoiceField(choices=role_choices, required=True)


    def validate_role(self, value):

        if value.upper() not in self.role_choices:
            raise serializers.ValidationError("This role is not allowed in our application")
        return value
    def create(self, validated_data):
        user = self.context["request"].user
        role = validated_data.get("role").upper()

       
        if role == self.role_choices[0]:
            if not hasattr(user, "is_student"):
                raise serializers.ValidationError("User dosen't have the is_student field, contact support")

            setattr(user, "is_student", True)
            profile = StudentProfile(user=user)

        elif role == self.role_choices[1]:
            if not hasattr(user, "is_teacher"):
                raise serializers.ValidationError("User dosen't have the is_teacher field, contact support")

            setattr(user, "is_teacher", True)
            profile = TeacherProfile(user=user)
        elif role == self.role_choices[2]:
            if not hasattr(user, "is_student") and not hasattr(user, "is_teacher"):
                raise serializers.ValidationError("User is not capable of becoming both student and teacher at the same time")

            setattr(user, "is_teacher", True)
            setattr(user, "is_student", True)
            student_profile = StudentProfile(user=user)
            teacher_profile = TeacherProfile(user=user)


            student_profile.save()

            teacher_profile.save()

        else:
            raise serializers.ValidationError("Invalid request.", code=400)

        if role.upper() == self.role_choices[2]:
            role = self.role_choices[0]

        setattr(user, "active_role", role.upper())

        profile.save()
        user.save()

        return user


class SwitchRoleSerializer(serializers.Serializer):

    role = serializers.ChoiceField(choices=["STUDENT", "TEACHER"], required=True)

    def validate_role(self, value):
        allowed_roles = ["STUDENT", "TEACHER"]
        if value.upper() not in allowed_roles:
            raise serializers.ValidationError("Role not in allowed roles")

        user = self.context["request"].user

        if user.active_role == value.upper():
            raise serializers.ValidationErro(f"You are already in the {value} role")

        return value

    def create(self, validated_data):
        role = validated_data.get("role")
        user = self.context["request"].user
        if hasattr(user, "active_role"):
            setattr(user, "active_role", role.upper)

        user.save(update_fields=["active_role"])

        return user


    

