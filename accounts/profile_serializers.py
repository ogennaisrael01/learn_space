from rest_framework import serializers
from .profile_models import StudentProfile, User

class StudentProfileSerializerCreate(serializers.ModelSerializer):
    class Meta:
        model = StudentProfile
        fields = ["bio", "contact_number", "social_links", "guardians"]


class StudentProfileSerializerOut(serializers.ModelSerializer):
    student_profile = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields  = ["id", "email", "username", ""]

    def get_student_profile(self, obj):
        profile = obj.student_profile.all()
        if profile is None:
            return None
        return {
            "id": profile.profile_id,
        }
