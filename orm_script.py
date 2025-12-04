import os
import django
from django.db import connection

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'learn_hub.settings')
django.setup()

import string
import random
from django.contrib.auth import get_user_model
from accounts.utils.tasks import expire_otp
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from accounts.models import PasswordReset

User = get_user_model()


  
def run():
    token = PasswordReset.objects.first()
    print(token)



if __name__ == "__main__":
    run()

