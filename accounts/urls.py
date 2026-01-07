from django.urls import path, include
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
    PasswordResetConfirmView,
    GoogleAuthenticationView,
    OnboardingView,
    SwitchRoleView
)
from .profile_views import (
    ProfileBaseViewsets,
    CertificateViewsets,

)
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework.routers import DefaultRouter

app_name = "accounts"
urlpatterns = [
    path("auth/register/", RegisterView.as_view(), name="register"),
    path("auth/resend/otp/", ResendOtpView.as_view(), name="resend-otp"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("auth/login/", LoginView.as_view(), name="login"),
    path("auth/verify/", VerifyOTPView.as_view(), name="verify-otp"),
    path("auth/logout/", LogoutView.as_view(), name="logout"),
    path("auth/email/", views.test_email, name="test_email"),
    path("auth/deactivate/", DeactivateAccountView.as_view(), name="deactivate-account"),
    path("accounts/update/",  AccountUpdateView.as_view(), name="account-update"),
    path("auth/password/reset/request/", PasswordResetRequestView.as_view(), name="password-reset"),
    path("auth/password/reset/confirm/<token>/", PasswordResetConfirmView.as_view(), name="password-confirm"),
    path("auth/google/", GoogleAuthenticationView.as_view(), name="goole-auth"),
    path("auth/onboarding/", OnboardingView.as_view(), name="onboarding"),
    path("auth/role/update/", SwitchRoleView.as_view(), name="role-switch")
]

# profile urls
routers = DefaultRouter()
routers.register(r'', ProfileBaseViewsets, basename="profile")
routers.register("certificates", CertificateViewsets, basename="certificates")

urlpatterns += [
    path("profile/", include(routers.urls), name="profiles")
]

