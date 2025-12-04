from django.urls import path
from . import views
from .auth_views import (
    RegisterView, 
    ResendOtpView, 
    VerifyOTPView, 
    LoginView, 
    LogoutView, 
    DeactivateAccountView, 
    AccountUpdateView,
    PasswordResetRequestView,
    PasswordResetConfirmView
)
from rest_framework_simplejwt.views import TokenRefreshView

app_name = "accounts"
urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("resend/otp/", ResendOtpView.as_view(), name="resend-otp"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("login/", LoginView.as_view(), name="login"),
    path("verify/", VerifyOTPView.as_view(), name="verify-otp"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("email/", views.test_email, name="test_email"),
    path("deactivate/", DeactivateAccountView.as_view(), name="deactivate-account"),
    path("accounts/update/",  AccountUpdateView.as_view(), name="account-update"),
    path("password/reset/request/", PasswordResetRequestView.as_view(), name="password-reset"),
    path("password/reset/confirm/<token>/", PasswordResetConfirmView.as_view(), name="password-confirm")
]