from rest_framework import serializers
from phonenumber_field.serializerfields import PhoneNumberField
from django.contrib.auth.password_validation import validate_password as _validate_password
import email_validator
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.db.models import Q

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

    first_name = serializers.CharField(max_length=200)
    middle_name = serializers.CharField(max_length=200)
    last_name = serializers.CharField(max_length=200)

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
        user = User.objects.create_user(**validated_data)
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
