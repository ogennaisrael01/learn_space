from rest_framework import serializers
from .utils.invite import invite_code
from .models import Classroom, JoinRequest
from django.utils.translation import gettext_lazy as _
import email_validator
from django.utils import timezone


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
        # get invite random access invite code for the object
        invite = invite_code()
        if not invite:
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

class ClassRoomInviteSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        email = value.strip()
        try:
            valid_email = email_validator.validate_email(email, check_deliverability=True)
        except Exception as exc:
            raise serializers.ValidationError(_(f"Error while validating email address: {exc}"))
        return valid_email.normalized
    
class JoinClassViaCodeSerializer(serializers.Serializer):
    code = serializers.CharField(required=True,
                                error_messages={
                                    "required": _("Please provide you access code")
                                })

    def validate_code(self, value):
        return value.strip()

class JoinRequestSerializer(serializers.Serializer):
    reason = serializers.CharField(max_length=1000)
    
    def validate(self, attrs):
        """ Check is user already sent an invite """
        user = self.context.get("request")
        classroom = self.context.get("classroom")
        if JoinRequest.objects.filter(user=user.user, classroom=classroom, status=JoinRequest.Status.PENDING).exists():
            raise serializers.ValidationError(_("You have already sent a join request for this classroom. Please wait for approval."))
        return attrs

    def create(self, validated_data):
        user = self.context["request"].user
        classroom = self.context["classroom"]
        if user == classroom.teacher:
            raise serializers.ValidationError(_("Sending request to join your own classroom is not allowed."))
        request_instance = JoinRequest(
            user=user, 
            classroom=classroom, 
            **validated_data
            )
        request_instance.save()
        return validated_data
    
    def update(self, instance, validated_data):
        user = self.context["request"].user
        classroom = self.context["classroom"]
        instance.reason = validated_data.get("reason",  instance.reason)
        instance.save(user=user, classroom=classroom, **validated_data)
        return instance

class JoinRequestUpdateSerializer(serializers.ModelSerializer):

    class Meta:
        model = JoinRequest
        fields = ["status"]

    def validate_status(self, value):
        return value.strip()
    
    def update(self, instance, validated_data):
        instance.status = validated_data.get("status", instance.status)
        instance.responded_by = self.context["request"].user
        instance.responded_at = timezone.now()
        instance.save()
        return instance

class JoinRequestListSerializer(serializers.ModelSerializer):
    classroom = serializers.StringRelatedField()
    user = serializers.StringRelatedField()
    responded_by = serializers.StringRelatedField()
    class Meta:
        model = JoinRequest
        fields = [
            "join_request_id",
            "classroom",
            "user",
            "status",
            "reason",
            "responded_at",
            "responded_by",
            "created_at",
        ]
