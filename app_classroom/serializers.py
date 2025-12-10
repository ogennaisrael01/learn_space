from rest_framework import serializers
from .utils.invite import invite_code
from .models import Classroom
from django.utils.translation import gettext_lazy as _
import email_validator


class ClassroomCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Classroom
        fields  = [
            "name",
            "description",
            "section"
        ]
    
    def validate_name(self, value):
        if value:
            value.title()
        return value

    def create(self, validated_data):
        name = validated_data.get("name")

        # get invite code for 
        invite = invite_code(name).strip()
        if not invite_code:
            raise serializers.ValidationError(_("Error Creating class invite code"))
        
        classroom = Classroom(**validated_data)
        classroom.invite_code = invite
        classroom.save()
        
        return classroom
    
class SendInviteSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=255)
    email = serializers.EmailField()

    def validate_email(self, value):
        email = value.strip()
        try:
            valid_email = email_validator.validate_email(email, check_deliverability=True)
        except Exception as exc:
            raise serializers.ValidationError(_(f"Error while validating email address: {exc}"))
        return valid_email.normalized

    def validate_code(self, value):
        return value.strip()
    