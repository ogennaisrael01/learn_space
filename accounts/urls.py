from django.urls import path
from . import views
from .auth_views import RegisterView


urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("email/", views.test_email, name="test_email")
]