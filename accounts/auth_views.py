from rest_framework.views import APIView
from django.db import transaction
from .serializers import (
    RegistrationSerializer,
    ResendOtpSerializer,
    VerifyOTPSerializer,
    CustomTokenObtainPairSerializer,
    LogoutSerializer,
    AccountUpdateSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer
)
from rest_framework import status, permissions
from rest_framework.response import Response
from .exceptions import RequestDataNotPassed
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from .utils.email_notif import EmailService
from .utils.tasks import send_notification_email
from django.conf import settings
from .utils.otp import otp_token
from .models import OTP, PasswordReset
from rest_framework_simplejwt.views import TokenObtainPairView
from .utils.helpers.helpers import get_username
from rest_framework_simplejwt.tokens import RefreshToken
from .permissions import IsOwerOrAdmin
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from  django.db.models import Q



APP_NAME = getattr(settings, "APP_NAME", None)
EXPIRES_AT = getattr(settings, "OTP_EXPIRY", None)
BASE_URL = getattr(settings, "BASE_URL", "http://127.0.0.1:8000")
User = get_user_model()


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = RegistrationSerializer
    http_method_names = ["post"]

    @transaction.atomic()
    def post(self, request, format=None):
        """ A simple view for account registrations"""
        if request.data is None:
            raise RequestDataNotPassed()
        
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(data={"message": "registrations successful. verify your account", "success": True
        }, status=201)

class ResendOtpView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = ResendOtpSerializer
    http_method_names = ["post"]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get("email")
        user = get_object_or_404(User, email=email)
        try:
            user_otps = user.otps.all().order_by("-created_at")
            newest_otp = user_otps.first() # get the first most recent otp

            if  newest_otp.is_used == False and newest_otp.is_expired == False:
                otp_code = newest_otp.otp_code

                # resend the otp to the user is not used or expired
                email_service = EmailService()
                user = get_username(user)
                otp_serviece = email_service.otp_email(user, APP_NAME, EXPIRES_AT, otp_code)
                subject = otp_serviece[0]
                context = otp_serviece[1]

                re_send_email = send_notification_email(
                    subject, 
                    email, 
                    template="accounts/otp_email.html",
                    context=context
                )
                if re_send_email.get("success"):
                    return Response(data={"success": True, "message": "OTP sent successfully"}, status=200)

            # generate new and send to the user if the most recent otp is used or expired
            new_otp = otp_token()
            if not new_otp.get("success"):
                return 
            code = new_otp.get("code")
            if OTP.objects.filter(otp_code=code).exists():
                super().post(self, request, *args, **kwargs)

            create_otp = OTP.objects.create(user=user, otp_code=code)
            if create_otp:
                # Notify user with the new otp code 
                email_service = EmailService()
                user = get_username(user)
                otp_serviece = email_service.otp_email(user, APP_NAME, EXPIRES_AT, code)
                subject = otp_serviece[0]
                context = otp_serviece[1]

                re_send_email = send_notification_email(
                    subject, 
                    email, 
                    template="accounts/otp_email.html",
                    context=context
                )
                if re_send_email.get("success"):
                    return Response(data={"success": True, "message": "OTP sent successfully"}, status=200)

        except Exception as e:
            return Response(
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                    data={
                        "success": False, "msg": f"Error: {e}"
                        }
                    )
        
class VerifyOTPView(APIView):
    http_method_names = ["post"]
    serializer_class = VerifyOTPSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        """ Verify user account with the provided OTP. return True  is correct otherwise regect request"""
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data.get("code")
        if code:
            try:
                otp =  get_object_or_404(OTP, otp_code=code) # Returns OTP and handle error if not found

                # check is otp is still valid to handle account verifications
                if otp.is_used or otp.is_expired:
                    return Response(status=status.HTTP_400_BAD_REQUEST,
                                    data={
                                        "success": False,
                                        "msg": "Invalid code provided, request for another code"
                                    }
                                    )
                # if otp is valid, then we handle account verifications
                user = otp.user
                # check is the user is still available in our database
                if not User.objects.filter(email=user.email).exists():
                    return Response(status=status.HTTP_404_NOT_FOUND, 
                                    data={
                                        "succes": False,
                                        "msg": "No account match this token. Invalid!!!"
                                    })
    
                user.is_active = True
                user.is_verified = True
                otp.is_used = True

                # save back after updating
                user.save(update_fields=["is_active", "is_verified"])
                otp.save(update_fields=["is_used"])
            except Exception as exc:
                return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                data={
                                    "success": True,
                                    "msg": f"Error occured on account verification: {exc}"
                                })

            # Update user with real time email notification after registration

            service = EmailService()
            username = get_username(user)
            login_url = BASE_URL + "/api/v1/login"
            email_service = service.verify_email(username, APP_NAME, login_url)

            subject = email_service[0]
            context = email_service[1]

            try:
                send_notif = send_notification_email(
                    subject, 
                    user.email,
                    template="accounts/verification_email.html",
                    context=context

                )    
            except Exception as exc:
                return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                data={
                                    "success": False,
                                    "message": f"Error occured which sending account verification email: {exc}"
                                })  
            if send_notif.get("success"):
                return Response(status=status.HTTP_200_OK,
                                data={
                                    "success": True,
                                    "msg": "Account verification successful. access guaranteed"
                                })      
    
class LoginView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = LogoutSerializer

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class
            serializer.is_valid(raise_exception=True)
            refresh_token = serializer.validated_data.get("refresh_token")
            token = RefreshToken(refresh_token)
            token.blacklist()
        except Exception as exc:
            return Response(status.HTTP_400_BAD_REQUEST,
                            data={"success": False, "msg": f"error occured while logging out: {exc}"})
        return Response(status=status.HTTP_205_RESET_CONTENT, 
                        data={"success": True, "msg": "Successfully logged out"})


class DeactivateAccountView(APIView):
    permission_classes = [permissions.IsAuthenticated, IsOwerOrAdmin]
    http_method_names = ["post"]

    def get_user_obj(self):
        user = get_object_or_404(User, email=self.request.user.email)
        return user

    def post(self, request, *args, **kwargs):
        current_user_obj = self.get_user_obj()
        if current_user_obj:
            current_user_obj.is_active = False
            current_user_obj.is_verified = False
            current_user_obj.is_deleted = True

            current_user_obj.save(update_fields=["is_active", "is_verified", "is_deleted"])
        return Response(status=status.HTTP_204_NO_CONTENT)


class AccountUpdateView(DeactivateAccountView):    
    permission_classes = [permissions.IsAuthenticated, IsOwerOrAdmin]
    http_method_names = ["put"]
    serializer_class = AccountUpdateSerializer

    def put(self, request, *args, **kwargs):
        user_obj = self.get_user_obj()
        if isinstance(user_obj, UserWarning):
            serializer = self.serializer_class(user_obj, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
        return Response(status=status.HTTP_200_OK, 
                        data={
                            "success": True,
                            "msg": "Account updated",
                            "data": serializer.validated_data
                        })
        
class PasswordResetRequestView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetRequestSerializer

    def post(self, request, *args, **kwargs):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        password_reset_identifier = serializer.validated_data.get("user_itentifier")
        if password_reset_identifier is not None:
            user = User.objects.filter(
                Q(email__iexact=password_reset_identifier) |
                Q(username__iexact=password_reset_identifier) |
                Q(phone__iexact=password_reset_identifier) 
            ).first()

            if not user:
                return Response(status=status.HTTP_400_BAD_REQUEST,
                                data={
                                    "success": False,
                                    "message": "No account  is accociated with this credentials, consider creating an account"
                                })

        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(user)
        reset_model = PasswordReset(user=user, token=token)
        reset_model.save()

        print(token)
        reset_url = BASE_URL + f"/api/v1/accounts/password/reset/confirm/{token}/"

        # send password reset email 

        username = get_username(user)
        service = EmailService()
        email_service = service.password_reset_email(username, APP_NAME, reset_url)

        subject = email_service[0]
        context = email_service[1]

        try:
            email_notification = send_notification_email(
                subject, 
                user.email,
                template="accounts/password_reset.html",
                context=context
            )
        except Exception as exc:
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            data={
                                "success": False,
                                "msg": f"error occured while sending email for password reset: {exc}"
                            })
        if email_notification.get("success"):
            return Response(status=status.HTTP_200_OK,
                            data={
                                "success": True,
                                "msg": "Reset password link sent to your inbox"
                            })

class PasswordResetConfirmView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, *args, **kwargs):
        token = kwargs.get("token").strip()

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        token_generator = PasswordResetTokenGenerator()

        token_model = PasswordReset.objects.filter(token=token).first()
        if token_model:
            user = token_model.user
            if not token_generator.check_token(user, token):
                return Response(status=status.HTTP_400_BAD_REQUEST,
                                data={
                                    "success": False,
                                    'msg': "Invalid token"
                                })

            password = serializer.validated_data.get("new_password")

            # Hash user password
            user.set_password(password)
            user.save(update_fields=["password"])

            token_model.delete()

            return Response(status=status.HTTP_200_OK, 
                            data={
                                "success": True,
                                "msg": "Password Reset successfull"
                            })