from rest_framework import serializers
from .profile_models import StudentProfile, User, TeacherProfile, Certificates, ProfileAvater
from .serializers import UserOutSerializer
from django.utils import timezone
from .serializers import _

class AvaterSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProfileAvater
        fields = [
            "avater_id",
            "avater_uri",
            "created_at"
        ]

class CertificateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Certificates
        fields = [
            "certificate_id",
            "name",
            "description",
            "certificate_uri",
            "issued_on",
            "created_at"
        ]
        read_only_fields = ["certificate_id", "created_at"]
    
    def validate_name(self, value: str):
        if value:
            value.title()
        return value
    

    def validate_issued_on(self, value):
        today = timezone.now().date()
        """ Ensure the the issue data is not greater than today"""
        if value > today:
            raise serializers.ValidationError(_("Issued date can't be greatet than today"))
        
        return value
        

class StudentProfileSerializerCreate(serializers.ModelSerializer):
    class Meta:
        model = StudentProfile
        fields = ["bio", "contact_number", "social_links", "guardians"]

class StudentProfileSerializerOut(serializers.ModelSerializer):
    certificates = CertificateSerializer(source="user.certificates", read_only=True, many=True)
    user = UserOutSerializer()
    avater = AvaterSerializer(source="user.avater", read_only=True)
     

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
            "avater"
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
    certificates = CertificateSerializer(source="user.certificates", read_only=True, many=True)
    user = UserOutSerializer()
    avater = AvaterSerializer(source="user.avater", read_only=True)
    class Meta:
        model = TeacherProfile
        fields = [
            "profile_id",
            "user",
            "subjects",
            "created_at",
            "contact_number",
            "social_links",
            "certificates",
            "avater"
        ]
    
    def get_subjects(self, obj):
        return obj.subjects()


