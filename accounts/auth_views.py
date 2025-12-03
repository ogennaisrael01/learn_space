from rest_framework.views import APIView
from django.db import transaction
from .serializers import RegistrationSerializer
from rest_framework import status, permissions
from rest_framework.response import Response
from .exceptions import RequestDataNotPassed



class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = RegistrationSerializer
    http_method_names = ["post"]


    def post(self, request):
        """
            - create user and save user instance 
        """
        if request.data is None:
            raise RequestDataNotPassed()
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(data={"message": "registrations successful. verify your account", "success": True
        }, status=201)