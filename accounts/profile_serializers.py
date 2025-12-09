from rest_framework import serializers
from .profile_models import StudentProfile, User, TeacherProfile
from .serializers import UserOutSerializer

class StudentProfileSerializerCreate(serializers.ModelSerializer):
    class Meta:
        model = StudentProfile
        fields = ["bio", "contact_number", "social_links", "guardians"]


class StudentProfileSerializerOut(serializers.ModelSerializer):
    certificates = serializers.SerializerMethodField()
    user = UserOutSerializer()

    class Meta:
        model = StudentProfile
        fields = [
            "user",
            "profile_id",
            "grade_level",
            "bio",
            "contact_number",
            "guardians",
            "social_links",
            "created_at",
            "certificates",
        ]

    def get_certificates(self, obj):
        certifications = obj.user.certificates.all()

        if not certifications.exists():
            return None

        return [
            {
                "name": certificate.name,
                "description": certificate.description,
                "certificate": certificate.certificate_uri,
                "issued_on": certificate.issued_on,
            }
            for certificate in certifications
        ]

class TeacherProfileCreate(serializers.ModelSerializer):
    class Meta:
        model = TeacherProfile
        fields = [
            "bio",
            "subjects",
            "contact_number",
            "social_links"
        ]

class TeacherProfileOut(serializers.ModelSerializer):
    subjects = serializers.SerializerMethodField()
    user = UserOutSerializer(read_only=True)
    class Meta:
        model = TeacherProfile
        fields = [
            "profile_id",
            "user",
            "subjects",
            "created_at",
            "contact_number",
            "social_links"
        ]
    
    def get_subjects(self, obj):
        return obj.subjects()