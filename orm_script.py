import os
import django
from django.db import connection

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'learn_hub.settings')
django.setup()

import string
import random
from django.contrib.auth import get_user_model
from accounts.utils.tasks import expire_otp


User = get_user_model()



def run():
    print(expire_otp())
if __name__ == "__main__":
    run()

