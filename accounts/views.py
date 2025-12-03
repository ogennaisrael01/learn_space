from django.shortcuts import render
from .utils.tasks import send_notification_email
from django.conf import settings
from rest_framework.response import Response
from django.http import JsonResponse

def test_email(request):
    receiver = "ogennaisrael@gmail.com"
    subject = 'hello ogenna'
    content = {
        "name": "Ogenna",
        "url": "https://localhost:8000"
    }
    send_mail = send_notification_email.delay(subject, receiver, template="accounts/welcome.html", context=content)
    return JsonResponse(data={"message": True}, status=200) 