from rest_framework import serializers
from phonenumber_field.serializerfields import PhoneNumberField
from django.contrib.auth.password_validation import validate_password as _validate_password
import email_validator
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
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
    
    def update(self, instance, validated_data):
        password = validated_data.get("password", None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance



