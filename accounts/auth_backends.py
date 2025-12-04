from django.contrib.auth.backends import ModelBackend
from django.db.models import Q
from django.contrib.auth import get_user_model
from django.http import HttpResponseNotFound
from django.shortcuts import get_object_or_404


User = get_user_model()
class EmailPhoneUsernameBackend(ModelBackend):
    """
        - Custom backend for authenticating user with either email, phone, or username
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        """
            - authentication backend 
            - auhenticate(request, username,, password, **kwargs)
            - if username=email or username=phone or username=username -> True else False
        """
        if hasattr(User, "username") or hasattr(User, "email") or hasattr(User, "phone"):
            if username is None:
                username = kwargs.get("email")
            user = User.objects.filter(
                Q(email__iexact=username) |
                Q(phone__iexact=username) | 
                Q(username__iexact=username) 
            ).first()

            if not user:
                return HttpResponseNotFound(content={"success": False, "message": f"{username} was not found, try registring an account"})

            if user and user.check_password(password):
                return user

        return False
    
    def  get_user(self, user_id):
        if user_id is None:
            return 
        try:
            user = get_object_or_404(User, pk=user_id)
        except User.DoesNotExist:
            return None
        return user if user.is_active == True and user.is_deleted==False else None
            